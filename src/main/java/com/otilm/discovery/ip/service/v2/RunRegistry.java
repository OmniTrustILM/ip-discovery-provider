package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;
import java.util.function.UnaryOperator;

/**
 * The runs this node is scanning, keyed by the {@code runId} Core assigns.
 *
 * <p>
 * Node-local and deliberately so: a running run's buffer cannot be shared, which is what makes running runs
 * single-replica. A stopped run holds nothing here — it is rebuilt from its replayed handle on whichever replica the
 * call reaches — so a miss is not automatically an error, and callers decide what a miss means.
 */
@Component
public class RunRegistry {

    private static final Logger logger = LoggerFactory.getLogger(RunRegistry.class);

    private final Map<UUID, Entry> runs = new ConcurrentHashMap<>();
    private final LongSupplier ticker;

    public RunRegistry() {
        this(System::nanoTime);
    }

    RunRegistry(LongSupplier ticker) {
        this.ticker = ticker;
    }

    private static final class Entry {
        private final AtomicReference<RunHandle> handle;
        private final AtomicReference<ScanRunner> runner = new AtomicReference<>();
        private final AtomicReference<ResultBuffer> buffer = new AtomicReference<>();
        private final AtomicReference<DiscoveryRunState> state = new AtomicReference<>(DiscoveryRunState.RUNNING);
        private final AtomicLong lastDriven;
        /** Zero means not yet known, which is why it is reported as absent rather than as a total of nought. */
        private final AtomicLong targetsTotal = new AtomicLong();
        private final AtomicReference<Future<?>> scan = new AtomicReference<>();
        /**
         * Set when a run is rebuilt from a replayed checkpoint, and cleared by the first drain that proves Core is
         * exactly at it. {@link #NOTHING_OWED} means none is owed -- not zero, which is the high water of a run
         * rebuilt before it produced anything, and precisely the run whose cursor most needs checking.
         */
        private final AtomicLong drainVerificationOwedAt = new AtomicLong(NOTHING_OWED);

        private Entry(RunHandle handle, long now) {
            this.handle = new AtomicReference<>(handle);
            this.lastDriven = new AtomicLong(now);
        }
    }

    /**
     * @return false if the run is already registered, which is a repeated initiate rather than a new run
     */
    public boolean register(UUID runId, RunHandle handle) {
        return runs.putIfAbsent(runId, new Entry(handle, ticker.getAsLong())) == null;
    }

    /**
     * Gives the registry the means to release a run it later has to abandon: the scan to stop, and the buffer whose
     * budget has to go back. Without the buffer the run's slot and bytes stay charged after it is gone, and the node
     * refuses new runs long after it has any.
     */
    public void attach(UUID runId, ScanRunner runner, ResultBuffer buffer) {
        Entry entry = runs.get(runId);
        if (entry != null) {
            entry.runner.set(runner);
            entry.buffer.set(buffer);
        }
    }

    /**
     * Records that the platform is still driving this run. Every lifecycle call does this, which is what makes the
     * deadline measure neglect rather than duration — a wall-clock limit would kill a legitimate long scan, and a
     * limit on scan time alone would misfire during a Core outage in the opposite direction.
     */
    public void touch(UUID runId) {
        Entry entry = runs.get(runId);
        if (entry != null) {
            entry.lastDriven.set(ticker.getAsLong());
        }
    }

    /**
     * The run's state as Core asks for it. Distinct from the handle's own marker, which carries only what a rebuild
     * needs: whether a checkpoint was written while stopped, or by a run still in flight.
     */
    public Optional<DiscoveryRunState> state(UUID runId) {
        Entry entry = runs.get(runId);
        return entry == null ? Optional.empty() : Optional.of(entry.state.get());
    }

    /**
     * Moves a run between states only if it is where the caller believed it was.
     *
     * <p>
     * A read followed by a write is not enough here: two resumes can both read STOPPED and both start a scan, which
     * puts two sequencers on one run issuing the same numbers, lets the cursor move backwards, and leaves the loser
     * buffer charging the budget with items nothing will ever serve.
     *
     * @return true if this call performed the transition
     */
    public boolean compareAndSetState(UUID runId, DiscoveryRunState expected, DiscoveryRunState next) {
        Entry entry = runs.get(runId);
        return entry != null && entry.state.compareAndSet(expected, next);
    }

    public void setState(UUID runId, DiscoveryRunState state) {
        Entry entry = runs.get(runId);
        if (entry != null) {
            entry.state.set(state);
        }
    }

    /**
     * The size of the run's enumeration, exact from the moment it is known. Absent rather than zero when it is not:
     * a total of nought would read as a finished run rather than an unknown one.
     */
    public Optional<Long> targetsTotal(UUID runId) {
        Entry entry = runs.get(runId);
        if (entry == null || entry.targetsTotal.get() <= 0) {
            return Optional.empty();
        }
        return Optional.of(entry.targetsTotal.get());
    }

    public void setTargetsTotal(UUID runId, long total) {
        Entry entry = runs.get(runId);
        if (entry != null) {
            entry.targetsTotal.set(total);
        }
    }

    public Optional<ResultBuffer> buffer(UUID runId) {
        Entry entry = runs.get(runId);
        return entry == null ? Optional.empty() : Optional.ofNullable(entry.buffer.get());
    }

    /** The scan in flight, so a stop can wait for it rather than answering while it is still numbering items. */
    public void attachScan(UUID runId, Future<?> scan) {
        Entry entry = runs.get(runId);
        if (entry != null) {
            entry.scan.set(scan);
        }
    }

    /**
     * Waits for the run's scan to finish. Bounded because a stop interrupts rather than quiesces, so the wait is for
     * threads to unwind and not for probes to complete.
     *
     * @return false if the scan did not finish inside the window, which the caller reports rather than hides
     */
    public boolean awaitScan(UUID runId, Duration within) {
        Entry entry = runs.get(runId);
        Future<?> scan = entry == null ? null : entry.scan.get();
        if (scan == null) {
            return true;
        }
        try {
            scan.get(within.toMillis(), TimeUnit.MILLISECONDS);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (TimeoutException e) {
            return false;
        } catch (ExecutionException | java.util.concurrent.CancellationException e) {
            // The scan ended badly or was cancelled; either way it is no longer numbering items, which is all a stop
            // needs to know.
            return true;
        }
    }

    /**
     * Records that this run was rebuilt and may not serve items until a drain arrives at exactly {@code highWater}.
     *
     * <p>
     * The verdict cannot live in the rebuild call alone: status and resume rebuild too, and a run registered by
     * either would otherwise have every later drain served with no cursor check at all.
     */
    /** Outside the sequence space, which starts at zero and only grows. */
    private static final long NOTHING_OWED = -1L;

    public void oweDrainVerification(UUID runId, long highWater) {
        Entry entry = runs.get(runId);
        if (entry != null) {
            entry.drainVerificationOwedAt.set(highWater);
        }
    }

    /** The high water a drain must match before this run may serve anything, or empty when none is owed. */
    public Optional<Long> drainVerificationOwed(UUID runId) {
        Entry entry = runs.get(runId);
        if (entry == null) {
            return Optional.empty();
        }
        long owed = entry.drainVerificationOwedAt.get();
        return owed == NOTHING_OWED ? Optional.empty() : Optional.of(owed);
    }

    public void drainVerified(UUID runId) {
        Entry entry = runs.get(runId);
        if (entry != null) {
            entry.drainVerificationOwedAt.set(NOTHING_OWED);
        }
    }

    public Optional<ScanRunner> runner(UUID runId) {
        Entry entry = runs.get(runId);
        return entry == null ? Optional.empty() : Optional.ofNullable(entry.runner.get());
    }

    public Optional<RunHandle> find(UUID runId) {
        Entry entry = runs.get(runId);
        return entry == null ? Optional.empty() : Optional.of(entry.handle.get());
    }

    /**
     * Applies a change to a run's handle atomically. The scan advances the cursor while a lifecycle call may be
     * stopping the run, so read-modify-write has to be a single step rather than a get followed by a put.
     *
     * @return the handle after the change, or empty if the run is not held here
     */
    public Optional<RunHandle> update(UUID runId, UnaryOperator<RunHandle> change) {
        Entry entry = runs.get(runId);
        return entry == null ? Optional.empty() : Optional.of(entry.handle.updateAndGet(change));
    }

    /**
     * @return true if this call removed the run, so a caller can tell a first cancel from a repeat
     */
    public boolean forget(UUID runId) {
        return runs.remove(runId) != null;
    }

    public int size() {
        return runs.size();
    }

    /**
     * Drops a run and hands back everything it held. Used by both the deadline and a cancel: a run that is gone must
     * leave nothing charged behind it.
     */
    public boolean release(UUID runId) {
        Entry entry = runs.remove(runId);
        if (entry == null) {
            return false;
        }
        release(entry);
        return true;
    }

    private static void release(Entry entry) {
        ScanRunner runner = entry.runner.get();
        if (runner != null) {
            runner.stop();
        }
        ResultBuffer buffer = entry.buffer.get();
        if (buffer != null) {
            // Undrained items go with it. A resume detects that as loss against Core's live cursor and refuses,
            // which is the honest answer -- re-serving from a rebuilt run would leave a hole Core cannot see.
            buffer.close();
        }
    }

    /**
     * Drops every run the platform has stopped driving for longer than {@code idleFor}, releasing what it held.
     *
     * <p>
     * Core is not guaranteed to clean up after itself: a start that fails after initiate succeeded calls cancel
     * best-effort and logs that the scan may keep running until the connector's own timeout. This is that timeout.
     *
     * @return the runs abandoned, for the caller to log
     */
    public List<UUID> abandonIdle(Duration idleFor) {
        long cutoff = ticker.getAsLong() - idleFor.toNanos();
        List<UUID> abandoned = new ArrayList<>();
        for (Map.Entry<UUID, Entry> run : runs.entrySet()) {
            if (run.getValue().lastDriven.get() > cutoff) {
                continue;
            }
            // Re-read the timestamp inside the map's own computation rather than trusting the one above. A two-arg
            // remove would not help: touch() mutates the entry in place, so the value is the same instance either
            // way, and a lifecycle call landing between the check and the removal would be dropped along with the
            // run it was driving.
            Entry[] taken = new Entry[1];
            runs.computeIfPresent(run.getKey(), (key, entry) -> {
                if (entry.lastDriven.get() > cutoff) {
                    return entry;
                }
                taken[0] = entry;
                return null;
            });
            // Released outside the computation: it stops a scan and closes a buffer, which is not work to do while
            // holding a bin of the map. By now the run is gone, so a lifecycle call finds nothing and is answered as
            // a forgotten run, which is the contract's expected answer.
            if (taken[0] != null) {
                release(taken[0]);
                abandoned.add(run.getKey());
                logger
                        .warn("Run {} abandoned after {} without a lifecycle call from the platform", run.getKey(),
                                idleFor);
            }
        }
        return abandoned;
    }
}
