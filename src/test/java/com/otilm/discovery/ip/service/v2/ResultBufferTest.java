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
        Assertions.assertEquals(6, late.highestSequence());
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
                .assertTrue(waitFor(budget::isBackpressured), "the third insert should be parked on the item bound");
        Assertions.assertNull(third.get(), "it must block, not drop the item and carry on");
        Assertions.assertEquals(2, buffer.held());

        buffer.discardThrough(2);
        producer.join(Duration.ofSeconds(5));

        Assertions.assertEquals(3L, third.get(), "the drain should have released the parked producer");
        Assertions.assertFalse(budget.isBackpressured());
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

    private static boolean waitFor(java.util.function.BooleanSupplier condition) throws InterruptedException {
        for (int i = 0; i < 100; i++) {
            if (condition.getAsBoolean()) {
                return true;
            }
            Thread.sleep(20);
        }
        return false;
    }
}
