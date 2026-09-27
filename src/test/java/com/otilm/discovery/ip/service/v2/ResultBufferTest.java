package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

class ResultBufferTest {

    private static final long ITEM_BYTES = 3_000;

    private static BufferBudget budget(int maxRuns, long maxItems, long maxBytesPerRun, long maxTotalBytes,
            long waitMs) {
        return new BufferBudget(maxRuns, maxItems, maxBytesPerRun, maxTotalBytes, waitMs);
    }

    private static BufferBudget roomyBudget() {
        return budget(8, 100_000, 1L << 30, 1L << 31, 30_000);
    }

    private static DiscoveredItemDto item(String ref) {
        DiscoveredItemDto dto = new DiscoveredItemDto();
        dto.setUniqueRef(ref);
        return dto;
    }

    private static ResultBuffer buffer(BufferBudget budget, UUID runId, long startingSequence) {
        Assertions.assertTrue(budget.open(runId));
        return new ResultBuffer(runId, budget, startingSequence);
    }

    // --- sequencing ---

    /**
     * The contract requires dense sequences. Ordering across producing threads is irrelevant and deliberately not
     * asserted; a hole or a repeat is what would break Core's cursor.
     */
    @Test
    void assignsDenseSequencesUnderParallelProduction() throws Exception {
        UUID runId = UUID.randomUUID();
        ResultBuffer buffer = buffer(roomyBudget(), runId, 0);
        int producers = 64;
        int perProducer = 100;
        ConcurrentLinkedQueue<Long> assigned = new ConcurrentLinkedQueue<>();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Callable<Object>> work = IntStream
                    .range(0, producers)
                    .<Callable<Object>>mapToObj(p -> () -> {
                        for (int i = 0; i < perProducer; i++) {
                            assigned.add(buffer.add(item(p + "-" + i), ITEM_BYTES));
                        }
                        return null;
                    })
                    .toList();
            executor.invokeAll(work);
        }

        Set<Long> unique = Set.copyOf(assigned);
        Assertions.assertEquals(producers * perProducer, assigned.size(), "every insert must be numbered");
        Assertions.assertEquals(assigned.size(), unique.size(), "a sequence was handed out twice");
        Assertions
                .assertEquals(LongStream.rangeClosed(1, producers * perProducer).boxed().collect(Collectors.toSet()),
                        unique, "the sequence space has a hole in it");
    }

    /**
     * A resumed run continues its sequence space. Restarting at 1 would have every re-emitted item dropped by Core's
     * cursor filter, which is silent loss rather than a visible failure.
     */
    @Test
    void continuesTheSequenceSpaceOfAResumedRun() throws Exception {
        UUID runId = UUID.randomUUID();
        ResultBuffer buffer = buffer(roomyBudget(), runId, 9_000);

        Assertions.assertEquals(9_001, buffer.add(item("a"), ITEM_BYTES));
        Assertions.assertEquals(9_002, buffer.add(item("b"), ITEM_BYTES));
    }

    // --- paging ---

    @Test
    void servesOnlyWhatFollowsTheCursor() throws Exception {
        UUID runId = UUID.randomUUID();
        ResultBuffer buffer = buffer(roomyBudget(), runId, 0);
        for (int i = 0; i < 5; i++) {
            buffer.add(item("item-" + i), ITEM_BYTES);
        }

        ResultBuffer.Page page = buffer.page(2, 10, 1L << 20);

        Assertions.assertEquals(List.of(3L, 4L, 5L), page.items().stream().map(DiscoveredItemDto::getSequence).toList());
        Assertions.assertEquals(5, page.highestSequence());
        Assertions.assertFalse(page.more());
    }

    @Test
    void reportsMoreWhenThePageIsCappedRatherThanExhausted() throws Exception {
        UUID runId = UUID.randomUUID();
        ResultBuffer buffer = buffer(roomyBudget(), runId, 0);
        for (int i = 0; i < 10; i++) {
            buffer.add(item("item-" + i), ITEM_BYTES);
        }

        Assertions.assertTrue(buffer.page(0, 3, 1L << 20).more());
        Assertions.assertTrue(buffer.page(0, 100, ITEM_BYTES * 2).more());
    }

    /** A repeat of the same drain must return the same page: a tick can be published twice, with no lease. */
    @Test
    void servesTheSamePageTwice() throws Exception {
        UUID runId = UUID.randomUUID();
        ResultBuffer buffer = buffer(roomyBudget(), runId, 0);
        for (int i = 0; i < 4; i++) {
            buffer.add(item("item-" + i), ITEM_BYTES);
        }

        Assertions
                .assertEquals(buffer.page(1, 10, 1L << 20).items().stream().map(DiscoveredItemDto::getSequence).toList(),
                        buffer.page(1, 10, 1L << 20).items().stream().map(DiscoveredItemDto::getSequence).toList());
    }

    /**
     * Core advances its cursor to the highest sequence in a page, not to the contiguous end, so serving items as
     * though they followed a stale cursor would complete a run with everything in between missing.
     */
    @Test
    void answersACursorBelowTheWatermarkWithAnEmptyPage() throws Exception {
        UUID runId = UUID.randomUUID();
        ResultBuffer buffer = buffer(roomyBudget(), runId, 0);
        for (int i = 0; i < 6; i++) {
            buffer.add(item("item-" + i), ITEM_BYTES);
        }
        buffer.discardThrough(4);

        ResultBuffer.Page late = buffer.page(1, 10, 1L << 20);

        Assertions.assertTrue(late.items().isEmpty(), "a late drain must not be served across the discarded range");
        Assertions
                .assertEquals(4, late.highestSequence(),
                        "an empty page may only vouch for what was acknowledged; the sequencer covers items still held");
        Assertions.assertTrue(late.more(), "sequences 5 and 6 are still here, so the next tick has to come back");
    }

    @Test
    void discardsOnlyWhatTheCursorAcknowledged() throws Exception {
        UUID runId = UUID.randomUUID();
        ResultBuffer buffer = buffer(roomyBudget(), runId, 0);
        for (int i = 0; i < 6; i++) {
            buffer.add(item("item-" + i), ITEM_BYTES);
        }

        buffer.discardThrough(4);

        Assertions.assertEquals(2, buffer.held());
        Assertions.assertEquals(List.of(5L, 6L),
                buffer.page(4, 10, 1L << 20).items().stream().map(DiscoveredItemDto::getSequence).toList());
    }

    /** A re-published drain acknowledging a cursor already seen frees nothing the second time. */
    @Test
    void toleratesARepeatedDiscard() throws Exception {
        UUID runId = UUID.randomUUID();
        ResultBuffer buffer = buffer(roomyBudget(), runId, 0);
        for (int i = 0; i < 4; i++) {
            buffer.add(item("item-" + i), ITEM_BYTES);
        }

        buffer.discardThrough(3);
        buffer.discardThrough(3);
        buffer.discardThrough(1);

        Assertions.assertEquals(1, buffer.held());
    }

    // --- bounds ---

    /** Blocking rather than dropping is the whole design: Core drains from initiate, so a drain is always coming. */
    @Test
    void blocksProductionAtTheItemBoundRatherThanDropping() throws Exception {
        UUID runId = UUID.randomUUID();
        BufferBudget budget = budget(8, 2, 1L << 30, 1L << 31, 30_000);
        ResultBuffer buffer = buffer(budget, runId, 0);
        buffer.add(item("a"), ITEM_BYTES);
        buffer.add(item("b"), ITEM_BYTES);

        CountDownLatch started = new CountDownLatch(1);
        AtomicReference<Long> third = new AtomicReference<>();
        Thread producer = Thread.ofVirtual().start(() -> {
            started.countDown();
            try {
                third.set(buffer.add(item("c"), ITEM_BYTES));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        Assertions.assertTrue(started.await(5, TimeUnit.SECONDS));
        Assertions
                .assertTrue(waitFor(() -> budget.isBackpressured(runId)),
                        "the third insert should be parked on the item bound");
        Assertions.assertNull(third.get(), "it must block, not drop the item and carry on");
        Assertions.assertEquals(2, buffer.held());

        buffer.discardThrough(2);
        producer.join(Duration.ofSeconds(5));

        Assertions.assertEquals(3L, third.get(), "the drain should have released the parked producer");
        Assertions.assertFalse(budget.isBackpressured(runId));
    }

    /**
     * Status names the phase for the run it answers about. A producer parked on its own run's cap says nothing about
     * any other run, which is still free to insert.
     */
    @Test
    void reportsBackpressureOnlyForTheRunThatIsParked() throws Exception {
        UUID parked = UUID.randomUUID();
        UUID healthy = UUID.randomUUID();
        BufferBudget budget = budget(8, 1, 1L << 30, 1L << 31, 30_000);
        ResultBuffer full = buffer(budget, parked, 0);
        buffer(budget, healthy, 0);
        full.add(item("a"), ITEM_BYTES);

        Thread producer = Thread.ofVirtual().start(() -> {
            try {
                full.add(item("b"), ITEM_BYTES);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        Assertions.assertTrue(waitFor(() -> budget.isBackpressured(parked)));
        Assertions.assertFalse(budget.isBackpressured(healthy), "the other run is not waiting on anything");

        full.discardThrough(1);
        producer.join(Duration.ofSeconds(5));
    }

    /** The bound that cannot be waited out has to fail the run naming itself, not truncate its results. */
    @Test
    void failsNamingTheBoundWhenTheDrainNeverComes() throws Exception {
        UUID runId = UUID.randomUUID();
        BufferBudget budget = budget(8, 1, 1L << 30, 1L << 31, 150);
        ResultBuffer buffer = buffer(budget, runId, 0);
        buffer.add(item("a"), ITEM_BYTES);

        BufferBudget.BufferLimitExceededException thrown = Assertions
                .assertThrows(BufferBudget.BufferLimitExceededException.class, () -> buffer.add(item("b"), ITEM_BYTES));

        Assertions.assertTrue(thrown.getMessage().contains("max-items-per-run"), thrown.getMessage());
    }

    @Test
    void refusesAnItemThatCanNeverFit() {
        UUID runId = UUID.randomUUID();
        BufferBudget budget = budget(8, 100, 1_000, 1L << 31, 30_000);
        ResultBuffer buffer = buffer(budget, runId, 0);

        BufferBudget.BufferLimitExceededException thrown = Assertions
                .assertThrows(BufferBudget.BufferLimitExceededException.class, () -> buffer.add(item("big"), 5_000));

        Assertions.assertTrue(thrown.getMessage().contains("max-bytes-per-run"), thrown.getMessage());
    }

    /**
     * Refusing at initiate is the point. A run admitted past the cap would be starved by the others rather than told
     * this node cannot feed it.
     */
    @Test
    void refusesToOpenMoreRunsThanTheNodeCanFeed() {
        BufferBudget budget = budget(2, 100, 1L << 30, 1L << 31, 30_000);

        Assertions.assertTrue(budget.open(UUID.randomUUID()));
        Assertions.assertTrue(budget.open(UUID.randomUUID()));
        Assertions.assertFalse(budget.open(UUID.randomUUID()), "the third run must be refused, not queued");
        Assertions.assertEquals(2, budget.openRuns());
    }

    @Test
    void refusesToOpenTheSameRunTwice() {
        BufferBudget budget = roomyBudget();
        UUID runId = UUID.randomUUID();

        Assertions.assertTrue(budget.open(runId));
        Assertions.assertFalse(budget.open(runId));
    }

    @Test
    void releasesTheWholeBudgetWhenARunCloses() throws Exception {
        UUID runId = UUID.randomUUID();
        BufferBudget budget = budget(1, 100, 1L << 30, 1L << 31, 30_000);
        ResultBuffer buffer = buffer(budget, runId, 0);
        buffer.add(item("a"), ITEM_BYTES);

        buffer.close();

        Assertions.assertEquals(0, budget.openRuns());
        Assertions.assertTrue(budget.open(UUID.randomUUID()), "the slot must be free for the next run");
    }

    @Test
    void rejectsANonPositiveBoundAtConstruction() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> budget(0, 1, 1, 1, 1));
        Assertions.assertThrows(IllegalArgumentException.class, () -> budget(1, 0, 1, 1, 1));
        Assertions.assertThrows(IllegalArgumentException.class, () -> budget(1, 1, 0, 1, 1));
        Assertions.assertThrows(IllegalArgumentException.class, () -> budget(1, 1, 1, 0, 1));
        Assertions.assertThrows(IllegalArgumentException.class, () -> budget(1, 1, 1, 1, 0));
    }

    private static boolean waitFor(java.util.function.BooleanSupplier condition) {
        try {
            org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(2)).until(condition::getAsBoolean);
            return true;
        } catch (org.awaitility.core.ConditionTimeoutException e) {
            return false;
        }
    }

    // --- only what is published, and only contiguously ---

    /**
     * The failure this prevents completes successfully. A producer between its {@code incrementAndGet} and its
     * {@code put} has a sequence nothing can see yet; serving past it hands Core a cursor above an item it never
     * received, and Core's own filter then drops that item when it lands.
     */
    @Test
    void doesNotServePastASequenceThatIsNumberedButNotYetPublished() throws Exception {
        UUID runId = UUID.randomUUID();
        BufferBudget budget = new BufferBudget(4, 100_000, 1L << 30, 1L << 31, 30_000);
        budget.open(runId);
        ResultBuffer buffer = new ResultBuffer(runId, budget, 0);

        // Stands in for a producer inside add(): its sequence is taken, its put has not happened.
        reserveWithoutPublishing(buffer);
        buffer.add(item("published"), 100);

        ResultBuffer.Page page = buffer.page(0, 100, 1L << 20);

        Assertions.assertTrue(page.items().isEmpty(), "sequence 1 is missing, so nothing above it may be served");
        Assertions.assertTrue(page.more(), "there is more to come once the gap closes");
        Assertions
                .assertEquals(0, page.highestSequence(),
                        "the page vouches for nothing, so Core's cursor must not move");
    }

    /** Once the gap closes the whole run is servable, in order. */
    @Test
    void servesTheWholeRunOnceTheGapCloses() throws Exception {
        UUID runId = UUID.randomUUID();
        BufferBudget budget = new BufferBudget(4, 100_000, 1L << 30, 1L << 31, 30_000);
        budget.open(runId);
        ResultBuffer buffer = new ResultBuffer(runId, budget, 0);
        buffer.add(item("one"), 100);
        buffer.add(item("two"), 100);

        ResultBuffer.Page page = buffer.page(0, 100, 1L << 20);

        Assertions.assertEquals(2, page.items().size());
        Assertions.assertEquals(2, page.highestSequence());
        Assertions.assertFalse(page.more());
    }

    /**
     * An item no page can carry would otherwise answer empty with more=true, and Core would retry the same cursor
     * forever. The run has to end instead of pretending it is making progress.
     */
    @Test
    void failsRatherThanLoopingOnAnItemNoPageCanCarry() throws Exception {
        UUID runId = UUID.randomUUID();
        BufferBudget budget = new BufferBudget(4, 100_000, 1L << 30, 1L << 31, 30_000);
        budget.open(runId);
        ResultBuffer buffer = new ResultBuffer(runId, budget, 0);
        buffer.add(item("huge"), 8_000);

        BufferBudget.BufferLimitExceededException thrown = Assertions
                .assertThrows(BufferBudget.BufferLimitExceededException.class, () -> buffer.page(0, 100, 4_000));

        Assertions.assertTrue(thrown.getMessage().contains("8000"), thrown.getMessage());
    }

    private static void reserveWithoutPublishing(ResultBuffer buffer) throws Exception {
        java.lang.reflect.Field sequencer = ResultBuffer.class.getDeclaredField("sequencer");
        sequencer.setAccessible(true);
        ((java.util.concurrent.atomic.AtomicLong) sequencer.get(buffer)).incrementAndGet();
    }


    /**
     * A probe already past its budget reservation when the run ends would otherwise publish into a map that has just
     * been cleared, leaving an item nothing will ever read. Reaching that interleaving through the public API is not
     * possible -- a later add fails at the budget instead -- so the flag is set directly, which is the state a close
     * landing mid-add leaves behind.
     */
    @Test
    void refusesToPublishOnceTheRunHasClosedUnderneathIt() throws Exception {
        UUID runId = UUID.randomUUID();
        ResultBuffer buffer = buffer(roomyBudget(), runId, 0);
        buffer.add(item("before"), ITEM_BYTES);

        java.lang.reflect.Field closed = ResultBuffer.class.getDeclaredField("closed");
        closed.setAccessible(true);
        ((java.util.concurrent.atomic.AtomicBoolean) closed.get(buffer)).set(true);

        Assertions.assertThrows(InterruptedException.class, () -> buffer.add(item("after"), ITEM_BYTES));
        Assertions.assertEquals(1, buffer.held(), "the item published before the close is untouched");
    }


    /**
     * Acknowledging past what the run has issued would mark unissued numbers discarded, and every item later given
     * one of them would be answered as already taken — silent loss on a run that completes.
     */
    @Test
    void refusesAnAcknowledgementAboveTheSequencesItHasIssued() throws Exception {
        UUID runId = UUID.randomUUID();
        ResultBuffer buffer = buffer(roomyBudget(), runId, 0);
        buffer.add(item("one"), ITEM_BYTES);

        Assertions.assertThrows(IllegalArgumentException.class, () -> buffer.discardThrough(100));
        Assertions.assertDoesNotThrow(() -> buffer.discardThrough(1));
    }

    /** A resumed buffer continues a sequence space whose earlier items were handed over before the stop. */
    @Test
    void startsAResumedWatermarkWhereItsSequenceSpaceStarts() {
        UUID runId = UUID.randomUUID();
        ResultBuffer resumed = buffer(roomyBudget(), runId, 5000);

        ResultBuffer.Page page = resumed.page(4500, 10, 1L << 20);

        Assertions.assertTrue(page.items().isEmpty());
        Assertions
                .assertEquals(5000, page.highestSequence(),
                        "a cursor below the checkpoint is behind the watermark, not a gap to wait on");
        Assertions.assertFalse(page.more());
    }

}
