package com.otilm.discovery.ip.service.v2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
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

    // --- state ---

    /** A registered run is running: nothing else would be true of a run Core has just been told to start. */
    @Test
    void startsARegisteredRunInTheRunningState() {
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));

        Assertions.assertEquals(DiscoveryRunState.RUNNING, registry.state(runId).orElseThrow());
        Assertions.assertEquals(Optional.empty(), registry.state(UUID.randomUUID()));
    }

    @Test
    void movesARunBetweenStates() {
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));

        registry.setState(runId, DiscoveryRunState.STOPPED);

        Assertions.assertEquals(DiscoveryRunState.STOPPED, registry.state(runId).orElseThrow());
    }

    /**
     * The transition is the lock. Two resumes both reading STOPPED and both starting a scan would put two
     * sequencers on one run, so only the caller that performs the move may act on it.
     */
    @Test
    void transitionsOnlyFromTheStateTheCallerBelievedItWasIn() {
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));
        registry.setState(runId, DiscoveryRunState.STOPPED);

        Assertions
                .assertTrue(registry
                        .compareAndSetState(runId, DiscoveryRunState.STOPPED, DiscoveryRunState.RUNNING));
        Assertions
                .assertFalse(
                        registry.compareAndSetState(runId, DiscoveryRunState.STOPPED, DiscoveryRunState.RUNNING),
                        "the second caller lost the race and must not also start a scan");
        Assertions
                .assertFalse(registry
                        .compareAndSetState(UUID.randomUUID(), DiscoveryRunState.STOPPED,
                                DiscoveryRunState.RUNNING),
                        "a run this node does not hold cannot be transitioned");
    }

    // --- what the run knows about itself ---

    /** Zero is not a total. Reporting it as one would read as a finished run rather than one still counting. */
    @Test
    void reportsAnUnknownTargetTotalAsAbsentRatherThanZero() {
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));

        Assertions.assertEquals(Optional.empty(), registry.targetsTotal(runId));

        registry.setTargetsTotal(runId, 4094);

        Assertions.assertEquals(4094L, registry.targetsTotal(runId).orElseThrow());
    }

    @Test
    void handsBackWhatWasAttachedToTheRun() {
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));
        ResultBuffer buffer = new ResultBuffer(runId, new BufferBudget(1, 100, 1L << 30, 1L << 31, 30_000), 0);

        Assertions.assertEquals(Optional.empty(), registry.buffer(runId), "nothing is attached yet");
        Assertions.assertEquals(Optional.empty(), registry.runner(runId));

        registry.attach(runId, null, buffer);

        Assertions.assertSame(buffer, registry.buffer(runId).orElseThrow());
    }

    // --- the scan in flight ---

    /**
     * A stop waits for the scan so it does not checkpoint while items are still being numbered. The wait is bounded
     * because a stop interrupts rather than quiesces: it is waiting for threads to unwind, not for probes to finish.
     */
    @Test
    void waitsForAScanToFinishAndSaysSoWhenItDoesNot() throws Exception {
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));

        Assertions
                .assertTrue(registry.awaitScan(runId, Duration.ofMillis(50)),
                        "a run with no scan attached has nothing to wait for");

        registry.attachScan(runId, CompletableFuture.completedFuture(null));
        Assertions.assertTrue(registry.awaitScan(runId, Duration.ofSeconds(5)));

        CountDownLatch release = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<?> stuck = executor.submit(() -> release.await(10, TimeUnit.SECONDS));
            registry.attachScan(runId, stuck);

            Assertions
                    .assertFalse(registry.awaitScan(runId, Duration.ofMillis(100)),
                            "a scan that outlasts the window is reported, not hidden");
            release.countDown();
        }
    }

    /** A cancelled or failed scan is no longer numbering items, which is all a stop needs to know. */
    @Test
    void treatsACancelledScanAsFinished() {
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));
        CompletableFuture<?> cancelled = new CompletableFuture<>();
        cancelled.cancel(true);

        registry.attachScan(runId, cancelled);

        Assertions.assertTrue(registry.awaitScan(runId, Duration.ofSeconds(5)));
    }

    // --- the rebuild verdict ---

    /**
     * The verdict cannot live in the rebuild call alone: status and resume rebuild too, and a run registered by
     * either would otherwise have every later drain served with no cursor check at all.
     */
    @Test
    void carriesTheRebuildVerdictUntilADrainSettlesIt() {
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));

        Assertions.assertEquals(Optional.empty(), registry.drainVerificationOwed(runId));

        registry.oweDrainVerification(runId, 40);

        Assertions.assertEquals(40L, registry.drainVerificationOwed(runId).orElseThrow());

        registry.drainVerified(runId);

        Assertions.assertEquals(Optional.empty(), registry.drainVerificationOwed(runId));
    }

    // --- release ---

    /**
     * A cancel and the deadline both come through here, and a run that is gone must leave nothing charged: the slot
     * it held is what the next run is refused for.
     */
    @Test
    void releaseHandsBackEverythingTheRunHeld() {
        BufferBudget budget = new BufferBudget(1, 100, 1L << 30, 1L << 31, 30_000);
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));
        Assertions.assertTrue(budget.open(runId));
        registry.attach(runId, null, new ResultBuffer(runId, budget, 0));

        Assertions.assertTrue(registry.release(runId));

        Assertions.assertEquals(0, registry.size());
        Assertions.assertEquals(0, budget.openRuns());
        Assertions.assertFalse(registry.release(runId), "a run already released is not released again");
    }

    /**
     * Zero is a real high water: it is what a run rebuilt before its first item reports, and exactly the run whose
     * cursor most needs checking. Sharing it with "nothing owed" turned the guard off for that case.
     */
    @Test
    void treatsAZeroHighWaterAsAVerificationThatIsOwed() {
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));

        registry.oweDrainVerification(runId, 0);

        Assertions
                .assertEquals(0L, registry.drainVerificationOwed(runId).orElseThrow(),
                        "a rebuilt run that produced nothing still owes the cursor check");

        registry.drainVerified(runId);

        Assertions.assertEquals(Optional.empty(), registry.drainVerificationOwed(runId));
    }

    /**
     * The reaper reads the timestamp, then removes. A lifecycle call landing in between must win: the alternative is
     * tearing down a run the platform is actively driving, buffer and all.
     */
    @Test
    void keepsARunThatWasDrivenAfterTheIdleCheckBegan() {
        Ticker ticker = new Ticker();
        RunRegistry registry = new RunRegistry(ticker);
        UUID runId = UUID.randomUUID();
        registry.register(runId, handle(0));

        ticker.advance(Duration.ofHours(1));
        registry.touch(runId);

        Assertions.assertEquals(List.of(), registry.abandonIdle(Duration.ofMinutes(30)));
        Assertions.assertTrue(registry.find(runId).isPresent(), "a run driven just now is not idle");
    }

}
