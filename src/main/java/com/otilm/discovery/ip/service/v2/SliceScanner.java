package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.connector.discovery.v2.DiscoveredCertificateDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.util.TargetEnumeration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Component;

/**
 * Turns a replayed checkpoint into one bounded page and the checkpoint after it.
 *
 * <p>
 * Probes are launched in enumeration order until the scan budget runs out, the finished probes have produced a page, or
 * the enumeration ends. Every launched probe then completes by its own deadline, so the slice commits each of them
 * unless the page limits cut it short, and a target cut off is scanned again by the next slice. Nothing survives the
 * call: the same checkpoint and the same probe outcomes give the same page.
 */
@Component
public class SliceScanner {

    private final TargetProber prober;
    private final SliceSettings settings;

    public SliceScanner(TargetProber prober, SliceSettings settings) {
        this.prober = prober;
        this.settings = settings;
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
        Map<Long, TargetResult> settled = new HashMap<>();
        List<Launched> inFlight = new ArrayList<>();
        BlockingQueue<Launched> finished = new LinkedBlockingQueue<>();
        long next = cursor;
        long finishedItems = 0;
        long finishedBytes = 0;

        while (true) {
            Launched done;
            while ((done = finished.poll()) != null) {
                if (inFlight.remove(done)) {
                    TargetResult result = settle(done, settled);
                    finishedItems += result.items().size();
                    finishedBytes += result.itemBytes();
                }
            }
            long now = System.nanoTime();
            for (Iterator<Launched> overdue = inFlight.iterator(); overdue.hasNext();) {
                Launched launched = overdue.next();
                if (now - launched.deadlineNanos() >= 0) {
                    overdue.remove();
                    TargetResult result = settle(launched, settled);
                    finishedItems += result.items().size();
                    finishedBytes += result.itemBytes();
                }
            }
            // The first target always launches, so a slice moves the run forward however small its budget.
            boolean outOfBudget = next > cursor && now - budgetEnds >= 0;
            if (next >= targets.size() || outOfBudget || finishedItems >= maxItems || finishedBytes >= maxBytes) {
                break;
            }
            if (inFlight.size() < Math.max(1, parallelism)) {
                Launched launched = new Launched(next, prober.start(next, targets.target(next), resources),
                        now + probeDeadline);
                launched.probe().whenComplete((result, failure) -> finished.add(launched));
                inFlight.add(launched);
                next++;
                continue;
            }
            long wakeAt = budgetEnds;
            for (Launched launched : inFlight) {
                if (launched.deadlineNanos() - wakeAt < 0) {
                    wakeAt = launched.deadlineNanos();
                }
            }
            awaitAny(finished, wakeAt - now);
        }

        for (Launched launched : inFlight) {
            settle(launched, settled);
        }
        List<TargetResult> ordered = new ArrayList<>((int) (next - cursor));
        for (long index = cursor; index < next; index++) {
            ordered.add(settled.get(index));
        }
        return ordered;
    }

    private TargetResult settle(Launched launched, Map<Long, TargetResult> settled) {
        TargetResult result = prober.await(launched.probe(), launched.index(), launched.deadlineNanos());
        settled.put(launched.index(), result);
        return result;
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
        Map<String, Long> yield = new HashMap<>();
        Map<String, Long> failures = new HashMap<>();

        for (TargetResult result : results) {
            if (items.size() >= maxItems || bytes >= maxBytes) {
                break;
            }
            if (items.size() + result.items().size() > maxItems || bytes + result.itemBytes() > maxBytes) {
                if (committed == 0) {
                    throw new TargetTooLargeException(result.index(), result.items().size(), result.itemBytes(),
                            maxItems, maxBytes);
                }
                break;
            }
            for (DiscoveredItemDto item : result.items()) {
                item.setSequence(afterSequence + items.size() + 1);
                items.add(item);
                yield.merge(resourceOf(item).getCode(), 1L, Long::sum);
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

        RunHandle next = from.advance(committed, failed, empty, items.size(), yield, failures);
        return new Slice(List.copyOf(items), next, next.cursorIndex() < total);
    }

    private static Resource resourceOf(DiscoveredItemDto item) {
        return item.getPayload() instanceof DiscoveredCertificateDto
                ? Resource.CERTIFICATE
                : Resource.CRYPTOGRAPHIC_KEY;
    }
}
