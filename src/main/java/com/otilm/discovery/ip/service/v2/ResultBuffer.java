package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * One run's undrained results, and the sequencer that numbers them.
 *
 * <p>
 * A sliding window rather than the whole run: Core drains from initiate onward, so steady-state occupancy is roughly
 * one drain interval of production. It is bounded regardless, through {@link BufferBudget}.
 *
 * <p>
 * Reads are non-destructive and items are discarded only when a later cursor proves they were taken. A drain tick can
 * be published twice without a lease, and the repeats may be concurrent, so serving a page must be safe to repeat.
 */
public class ResultBuffer {

    private static final Logger logger = LoggerFactory.getLogger(ResultBuffer.class);

    private final UUID runId;
    private final BufferBudget budget;

    /**
     * Sorted by sequence so a page above a cursor is a submap rather than a scan, and so a concurrent drain and a
     * concurrent insert do not contend.
     */
    private final ConcurrentSkipListMap<Long, Held> items = new ConcurrentSkipListMap<>();

    /**
     * One counter, incremented at insertion. The contract requires dense sequences; ordering across producing threads
     * is irrelevant, only density is, and a single atomic gives that however many threads produce at once.
     */
    private final AtomicLong sequencer;

    /** The highest cursor any drain has acknowledged. Items at or below it are the connector's to discard. */
    private final AtomicLong discardWatermark = new AtomicLong(0);

    private record Held(DiscoveredItemDto item, long bytes) {
    }

    /**
     * @param startingSequence the resumed run's {@code sequenceHighWater}; a resumed run continues its sequence space
     *                         and never restarts it, or Core's cursor filter drops every re-emitted item
     */
    public ResultBuffer(UUID runId, BufferBudget budget, long startingSequence) {
        this.runId = runId;
        this.budget = budget;
        this.sequencer = new AtomicLong(startingSequence);
    }

    /**
     * Numbers an item and holds it, blocking while the buffer is full.
     *
     * <p>
     * The weight is supplied rather than measured: the producer has just built the payload and knows its size, while
     * the buffer would have to serialize the item again to find out.
     *
     * @return the sequence assigned
     * @throws InterruptedException if the scan is stopped while blocked, which is how a stop reaches a parked probe
     */
    public long add(DiscoveredItemDto item, long weightBytes) throws InterruptedException {
        budget.acquire(runId, weightBytes);
        long sequence = sequencer.incrementAndGet();
        item.setSequence(sequence);
        items.put(sequence, new Held(item, weightBytes));
        return sequence;
    }

    /**
     * The items strictly above {@code afterSequence}, in sequence order.
     *
     * <p>
     * A cursor below the discard watermark is answered empty rather than refused. Core never sends a regressed
     * cursor, but arrival order is not send order: a redelivered drain or one stuck past Core's budget arrives late,
     * which is transport, not a defect. What must never happen is serving items as though they followed the stale
     * cursor — Core advances its cursor to the highest sequence in a page, so that would complete a run with the
     * items in between missing.
     */
    public Page page(long afterSequence, int maxItems, long maxBytes) {
        if (afterSequence < discardWatermark.get()) {
            logger
                    .info("Run {} drained at cursor {}, below the discard watermark {}; answering an empty page",
                            runId, afterSequence, discardWatermark.get());
            return new Page(List.of(), highestSequence(), false);
        }

        List<DiscoveredItemDto> page = new ArrayList<>();
        long bytes = 0;
        boolean more = false;
        for (Map.Entry<Long, Held> entry : items.tailMap(afterSequence, false).entrySet()) {
            if (page.size() >= maxItems || bytes + entry.getValue().bytes() > maxBytes) {
                more = true;
                break;
            }
            page.add(entry.getValue().item());
            bytes += entry.getValue().bytes();
        }
        return new Page(page, highestSequence(), more);
    }

    /**
     * Drops everything the given cursor has acknowledged. Idempotent: a repeated drain acknowledging the same cursor
     * frees nothing the second time, which is what makes a re-published tick harmless.
     */
    public void discardThrough(long sequence) {
        long previous = discardWatermark.getAndAccumulate(sequence, Math::max);
        if (sequence <= previous) {
            return;
        }
        long freedItems = 0;
        long freedBytes = 0;
        for (Map.Entry<Long, Held> entry : items.headMap(sequence, true).entrySet()) {
            if (items.remove(entry.getKey()) != null) {
                freedItems++;
                freedBytes += entry.getValue().bytes();
            }
        }
        if (freedItems > 0) {
            budget.release(runId, freedItems, freedBytes);
        }
    }

    /** The highest sequence assigned so far, which a resumed run continues from rather than restarting. */
    public long highestSequence() {
        return sequencer.get();
    }

    public int held() {
        return items.size();
    }

    /** Releases the whole run's budget. A cancelled or completed run holds nothing. */
    public void close() {
        items.clear();
        budget.close(runId);
    }

    public record Page(List<DiscoveredItemDto> items, long highestSequence, boolean more) {
    }
}
