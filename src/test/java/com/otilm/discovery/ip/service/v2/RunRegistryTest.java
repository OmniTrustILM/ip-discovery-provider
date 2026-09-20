package com.otilm.discovery.ip.service.v2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.IntStream;

class RunRegistryTest {

    private final RunRegistry registry = new RunRegistry();

    private static RunHandle handle(long cursor) {
        return new RunHandle(RunHandle.RunState.RUNNING, cursor, cursor, "digest", cursor, 0L, Map.of());
    }

    @Test
    void holdsARunUnderTheIdCoreAssigned() {
        UUID runId = UUID.randomUUID();

        Assertions.assertTrue(registry.register(runId, handle(0)));
        Assertions.assertEquals(handle(0), registry.find(runId).orElseThrow());
        Assertions.assertEquals(1, registry.size());
    }

    /** A second initiate for a run already held is a repeat, not a new run, and the caller has to be able to tell. */
    @Test
    void refusesToRegisterTheSameRunTwice() {
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));

        Assertions.assertFalse(registry.register(runId, handle(99)));
        Assertions.assertEquals(handle(0), registry.find(runId).orElseThrow(), "the first handle must survive");
    }

    /**
     * A miss is not an error here. A stopped run holds nothing on this node — it is rebuilt from its replayed handle
     * on whichever replica the call reaches — so the registry reports absence and lets the caller decide.
     */
    @Test
    void reportsAnUnknownRunAsAbsent() {
        Assertions.assertEquals(Optional.empty(), registry.find(UUID.randomUUID()));
        Assertions.assertEquals(Optional.empty(), registry.update(UUID.randomUUID(), h -> h));
        Assertions.assertFalse(registry.forget(UUID.randomUUID()));
    }

    @Test
    void appliesAChangeAndReturnsTheResult() {
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));

        RunHandle updated = registry.update(runId, h -> h.withState(RunHandle.RunState.STOPPED)).orElseThrow();

        Assertions.assertEquals(RunHandle.RunState.STOPPED, updated.state());
        Assertions.assertEquals(RunHandle.RunState.STOPPED, registry.find(runId).orElseThrow().state());
    }

    @Test
    void tellsAFirstForgetFromARepeat() {
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));

        Assertions.assertTrue(registry.forget(runId));
        Assertions.assertFalse(registry.forget(runId));
        Assertions.assertEquals(0, registry.size());
    }

    /**
     * The scan advances the cursor while a lifecycle call may be stopping the run, so the update has to be one step.
     * A get-then-put would lose increments under exactly this interleaving.
     */
    @Test
    void losesNoConcurrentAdvanceOfTheCursor() throws Exception {
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));
        int advances = 500;

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Callable<Object>> work = IntStream
                    .range(0, advances)
                    .<Callable<Object>>mapToObj(i -> () -> registry
                            .update(runId,
                                    h -> new RunHandle(h.state(), h.cursorIndex() + 1, h.sequenceHighWater(),
                                            h.targetsDigest(), h.targetsProcessed(), h.targetsFailed(),
                                            h.yieldByResource())))
                    .toList();
            executor.invokeAll(work);
        }

        Assertions.assertEquals(advances, registry.find(runId).orElseThrow().cursorIndex());
    }

    // --- abandoning runs the platform stopped driving ---

    /** A movable clock: the deadline is measured in elapsed time, and the test should not have to wait it out. */
    private static final class Ticker implements java.util.function.LongSupplier {
        private final AtomicLong nanos = new AtomicLong();

        @Override
        public long getAsLong() {
            return nanos.get();
        }

        void advance(Duration by) {
            nanos.addAndGet(by.toNanos());
        }
    }

    @Test
    void abandonsARunThePlatformHasStoppedDriving() {
        Ticker ticker = new Ticker();
        RunRegistry registry = new RunRegistry(ticker);
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));

        ticker.advance(Duration.ofMinutes(31));
        List<UUID> abandoned = registry.abandonIdle(Duration.ofMinutes(30));

        Assertions.assertEquals(List.of(runId), abandoned);
        Assertions.assertEquals(0, registry.size());
    }

    /**
     * The deadline measures neglect, not duration. A wall-clock limit would kill a legitimate long scan, which is the
     * failure mode this connector is most likely to hit — a wide subnet takes hours.
     */
    @Test
    void keepsALongRunningScanThePlatformIsStillDriving() {
        Ticker ticker = new Ticker();
        RunRegistry registry = new RunRegistry(ticker);
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));

        for (int hour = 0; hour < 6; hour++) {
            ticker.advance(Duration.ofMinutes(20));
            registry.touch(runId);
            Assertions.assertEquals(List.of(), registry.abandonIdle(Duration.ofMinutes(30)));
        }

        Assertions.assertEquals(1, registry.size(), "a run being driven must survive however long it takes");
    }

    /** Abandoning has to release the scan, or the threads outlive the run that owned them. */
    @Test
    void stopsTheScanOfAnAbandonedRun() {
        Ticker ticker = new Ticker();
        RunRegistry registry = new RunRegistry(ticker);
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));
        ScanRunner runner = new ScanRunner(runId, com.otilm.discovery.ip.util.TargetEnumeration
                .of("10.0.0.1", "443", false), null, registry, null, 1,
                java.util.Set.of(com.otilm.api.model.core.auth.Resource.CERTIFICATE));
        registry.attach(runId, runner, null);

        ticker.advance(Duration.ofHours(1));
        registry.abandonIdle(Duration.ofMinutes(30));

        Assertions.assertTrue(runner.isStopping(), "the abandoned run's scan should have been told to stop");
    }

    @Test
    void abandonsNothingBeforeTheDeadline() {
        Ticker ticker = new Ticker();
        RunRegistry registry = new RunRegistry(ticker);
        registry.register(UUID.randomUUID(), handle(0));

        ticker.advance(Duration.ofMinutes(29));

        Assertions.assertEquals(List.of(), registry.abandonIdle(Duration.ofMinutes(30)));
    }

    /**
     * Abandoning has to hand the buffer's budget back. Without it the node keeps charging a run that no longer
     * exists, and refuses new ones long after it holds any.
     */
    @Test
    void handsBackTheBudgetOfAnAbandonedRun() {
        Ticker ticker = new Ticker();
        RunRegistry registry = new RunRegistry(ticker);
        BufferBudget budget = new BufferBudget(1, 100, 1L << 30, 1L << 31, 30_000);
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));
        Assertions.assertTrue(budget.open(runId));
        registry.attach(runId, null, new ResultBuffer(runId, budget, 0));

        ticker.advance(Duration.ofHours(1));
        registry.abandonIdle(Duration.ofMinutes(30));

        Assertions.assertEquals(0, budget.openRuns());
        Assertions.assertTrue(budget.open(UUID.randomUUID()), "the slot must be free for the next run");
    }
}
