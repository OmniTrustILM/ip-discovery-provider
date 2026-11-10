package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.connector.discovery.v2.DiscoveredCertificateDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.util.TargetEnumeration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.stereotype.Component;

/**
 * Turns a replayed checkpoint into one bounded page and the checkpoint after it.
 *
 * <p>
 * Probes are launched in enumeration order, as many at once as the run's parallelism and the node's probe permits
 * allow, until the scan budget runs out, the finished probes have produced a page, {@value #MAX_TARGETS_PER_SLICE}
 * targets have been launched, or the enumeration ends. Every launched probe then completes by its own deadline, so the
 * slice commits each of them unless the page limits cut it short, and a target cut off is scanned again by the next
 * slice. Nothing survives the call: the same checkpoint and the same probe outcomes give the same page.
 */
@Component
public class SliceScanner {

    private final TargetProber prober;
    private final SliceSettings settings;
    private final ProbePermits permits;

    public SliceScanner(TargetProber prober, SliceSettings settings, ProbePermits permits) {
        this.prober = prober;
        this.settings = settings;
        this.permits = permits;
    }

    /**
     * @param items numbered densely from the drain's afterSequence + 1
     * @param more whether targets remain beyond {@code next}
     */
    record Slice(List<DiscoveredItemDto> items, RunHandle next, boolean more) {
    }

    private record Launched(long index, CompletableFuture<TargetResult> probe, long deadlineNanos) {
    }

    /**
     * Targets one slice launches at most. Empty and failed targets add nothing to the page limits, so a sweep of closed
     * ports that answer at once would otherwise keep every outcome the budget allows. About one budget of a dark sweep
     * at parallelism 1000.
     */
    static final int MAX_TARGETS_PER_SLICE = 16_384;

    /** How often a slice with free slots but no permit looks again; its own probes finishing wake it sooner. */
    private static final long PERMIT_RETRY_NANOS = TimeUnit.MILLISECONDS.toNanos(20);

    /**
     * @throws TargetTooLargeException if the first target alone exceeds the page limits
     */
    Slice scan(RunHandle from, TargetEnumeration targets, long afterSequence, int maxItems, long maxBytes,
            int parallelism, Set<Resource> resources) {
        long total = targets.size();
        if (from.cursorIndex() >= total) {
            return new Slice(List.of(), from, false);
        }
        List<TargetResult> results = probe(from.cursorIndex(), targets, maxItems, maxBytes, parallelism, resources);
        return commit(from, results, total, afterSequence, maxItems, maxBytes);
    }

    /** @return one result per launched target, in enumeration order from {@code cursor} */
    private List<TargetResult> probe(long cursor, TargetEnumeration targets, int maxItems, long maxBytes,
            int parallelism, Set<Resource> resources) {
        long budgetEnds = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(settings.scanBudgetMs());
        long probeDeadline = TimeUnit.MILLISECONDS.toNanos(settings.probeDeadlineMs());
        TargetResult[] settled = new TargetResult[(int) Math.min(MAX_TARGETS_PER_SLICE, targets.size() - cursor)];
        // In launch order, which is deadline order too: every launch takes a later "now". A slice may have a thousand
        // probes in flight, so the loop finds the next one due at the head instead of scanning them all.
        Set<Launched> inFlight = new LinkedHashSet<>();
        BlockingQueue<Launched> finished = new LinkedBlockingQueue<>();
        // Probe callbacks reach the queue only through this, so a probe abandoned past its deadline does not keep the
        // queue, and the late results in it, alive after the slice has answered.
        AtomicReference<BlockingQueue<Launched>> sink = new AtomicReference<>(finished);
        long next = cursor;
        long finishedItems = 0;
        long finishedBytes = 0;

        try {
            while (true) {
                Launched done;
                while ((done = finished.poll()) != null) {
                    if (inFlight.remove(done)) {
                        TargetResult result = settle(done, cursor, settled);
                        finishedItems += result.items().size();
                        finishedBytes += result.itemBytes();
                    }
                }
                long now = System.nanoTime();
                for (Iterator<Launched> overdue = inFlight.iterator(); overdue.hasNext();) {
                    Launched launched = overdue.next();
                    if (now - launched.deadlineNanos() < 0) {
                        break;
                    }
                    overdue.remove();
                    TargetResult result = settle(launched, cursor, settled);
                    finishedItems += result.items().size();
                    finishedBytes += result.itemBytes();
                }
                // The first target always launches, so a slice moves the run forward however small its budget.
                boolean outOfBudget = next > cursor && now - budgetEnds >= 0;
                if (next - cursor >= settled.length || outOfBudget || finishedItems >= maxItems
                        || finishedBytes >= maxBytes) {
                    break;
                }
                long wakeAt = inFlight.isEmpty()
                        ? budgetEnds
                        : earlier(budgetEnds, inFlight.iterator().next().deadlineNanos());
                if (inFlight.size() < Math.max(1, parallelism)) {
                    boolean permitted = permits.tryAcquire();
                    // A node at its probe limit slows the slice down rather than failing it: the first target goes
                    // out without a permit once the budget is spent, so the run still moves and the answer stays in
                    // bound.
                    if (permitted || (next == cursor && now - budgetEnds >= 0)) {
                        inFlight
                                .add(launch(next, targets.target(next), resources, now + probeDeadline, permitted,
                                        sink));
                        next++;
                        continue;
                    }
                    awaitAny(finished, Math.min(wakeAt - now, PERMIT_RETRY_NANOS));
                    continue;
                }
                awaitAny(finished, wakeAt - now);
            }

            for (Launched launched : inFlight) {
                settle(launched, cursor, settled);
            }
        } finally {
            sink.set(null);
            finished.clear();
        }
        return Arrays.asList(settled).subList(0, (int) (next - cursor));
    }

    /**
     * The permit goes back when the probe's thread returns, not when the slice gives up on it: an abandoned probe still
     * holds its socket or its thread.
     */
    private Launched launch(long index, String url, Set<Resource> resources, long deadlineNanos, boolean permitted,
            AtomicReference<BlockingQueue<Launched>> sink) {
        CompletableFuture<TargetResult> probe;
        try {
            probe = prober.start(index, url, resources);
        } catch (RuntimeException e) {
            if (permitted) {
                permits.release();
            }
            throw e;
        }
        Launched launched = new Launched(index, probe, deadlineNanos);
        probe.whenComplete((result, failure) -> {
            if (permitted) {
                permits.release();
            }
            BlockingQueue<Launched> finished = sink.get();
            if (finished != null) {
                finished.add(launched);
            }
        });
        return launched;
    }

    private TargetResult settle(Launched launched, long cursor, TargetResult[] settled) {
        TargetResult result = prober.await(launched.probe(), launched.index(), launched.deadlineNanos());
        settled[(int) (launched.index() - cursor)] = result;
        return result;
    }

    private static long earlier(long oneNanos, long otherNanos) {
        return oneNanos - otherNanos <= 0 ? oneNanos : otherNanos;
    }

    /** Waits for a probe to finish, leaving it queued for the loop to settle. */
    private static void awaitAny(BlockingQueue<Launched> finished, long timeoutNanos) {
        if (timeoutNanos <= 0) {
            return;
        }
        try {
            Launched done = finished.poll(timeoutNanos, TimeUnit.NANOSECONDS);
            if (done != null) {
                finished.add(done);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while scanning a slice", e);
        }
    }

    /**
     * Commits the longest prefix that fits the page, and stops at a page that has reached a limit even when the next
     * target would add nothing: whether such a target was launched depends on timing, and the page must not.
     */
    private static Slice commit(RunHandle from, List<TargetResult> results, long total, long afterSequence,
            int maxItems, long maxBytes) {
        List<DiscoveredItemDto> items = new ArrayList<>();
        long bytes = 0;
        long committed = 0;
        long failed = 0;
        long empty = 0;
        Map<String, Long> produced = new HashMap<>();
        Map<String, Long> failures = new HashMap<>();

        for (TargetResult result : results) {
            boolean pageFull = items.size() >= maxItems || bytes >= maxBytes;
            boolean fits = items.size() + result.items().size() <= maxItems && bytes + result.itemBytes() <= maxBytes;
            if (pageFull || !fits) {
                if (!pageFull && committed == 0) {
                    throw new TargetTooLargeException(result.index(), result.items().size(), result.itemBytes(),
                            maxItems, maxBytes);
                }
                break;
            }
            for (DiscoveredItemDto item : result.items()) {
                item.setSequence(afterSequence + items.size() + 1);
                items.add(item);
                produced.merge(resourceOf(item).getCode(), 1L, Long::sum);
            }
            bytes += result.itemBytes();
            committed++;
            switch (result.outcome()) {
                case EMPTY -> empty++;
                case FAILED -> {
                    failed++;
                    failures.merge(result.failureReason(), 1L, Long::sum);
                }
                case FOUND -> {
                    // counted by its items
                }
            }
        }

        RunHandle next = from.advance(committed, failed, empty, items.size(), produced, failures);
        return new Slice(List.copyOf(items), next, next.cursorIndex() < total);
    }

    private static Resource resourceOf(DiscoveredItemDto item) {
        return item.getPayload() instanceof DiscoveredCertificateDto
                ? Resource.CERTIFICATE
                : Resource.CRYPTOGRAPHIC_KEY;
    }
}
