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

    /** One counter, incremented at insertion: the contract requires dense sequences, not ordered ones. */
    private final AtomicLong sequencer;

    /**
     * The highest cursor any drain has acknowledged. Items at or below it are the connector's to discard. Seeded
     * from the resumed run's sequence space: everything up to the checkpoint was handed over before the stop.
     */
    private final AtomicLong discardWatermark;

    /** Set by {@link #close()}, so a producer past its reservation cannot publish into a cleared map. */
    private final java.util.concurrent.atomic.AtomicBoolean closed = new java.util.concurrent.atomic.AtomicBoolean();

    /**
     * Held across the closed check and the publication, and across the close that invalidates them. Checking the
     * flag and then putting as two steps leaves a window where a close lands between, and the item is published
     * into a map that has just been cleared.
     */
    private final Object publication = new Object();

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
        this.discardWatermark = new AtomicLong(startingSequence);
    }

    /**
     * Numbers an item and holds it, blocking while the buffer is full. The weight is supplied by the producer,
     * which has just built the payload.
     *
     * @return the sequence assigned
     * @throws InterruptedException if the scan is stopped while blocked, which is how a stop reaches a parked probe
     */
    public long add(DiscoveredItemDto item, long weightBytes) throws InterruptedException {
        budget.acquire(runId, weightBytes);
        long sequence = sequencer.incrementAndGet();
        item.setSequence(sequence);
        synchronized (publication) {
            if (closed.get()) {
                // The budget went back with the close, so there is nothing to release here.
                throw new InterruptedException("run " + runId + " closed while an item was being published");
            }
            items.put(sequence, new Held(item, weightBytes));
        }
        return sequence;
    }

    /**
     * The items strictly above {@code afterSequence}, in sequence order.
     *
     * <p>
     * Only a contiguous run of published sequences is served, and the page's {@code highestSequence} is the end of
     * that run rather than the sequencer's value.
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
            // The watermark, not the sequencer, which would let Core advance past items still held here.
            return new Page(List.of(), discardWatermark.get(), !items.isEmpty());
        }

        List<DiscoveredItemDto> page = new ArrayList<>();
        long bytes = 0;
        boolean more = false;
        long next = afterSequence + 1;
        for (Map.Entry<Long, Held> entry : items.tailMap(afterSequence, false).entrySet()) {
            if (entry.getKey() != next) {
                // A lower sequence is numbered but not yet published. Serving past it would put Core's cursor above
                // an item it never received, and Core drops anything at or below its cursor. The gap closes on its
                // own, since an add that has taken a sequence always reaches its put.
                more = true;
                break;
            }
            if (page.isEmpty() && entry.getValue().bytes() > maxBytes) {
                // An empty page with more=true would have Core retry this cursor forever.
                throw new BufferBudget.BufferLimitExceededException("Run " + runId + " holds an item of "
                        + entry.getValue().bytes() + " bytes at sequence " + entry.getKey()
                        + ", which exceeds the " + maxBytes + " bytes a page can carry");
            }
            if (page.size() >= maxItems || bytes + entry.getValue().bytes() > maxBytes) {
                more = true;
                break;
            }
            page.add(entry.getValue().item());
            bytes += entry.getValue().bytes();
            next++;
        }
        // What this page can vouch for, not the sequencer: that counts numbers taken but not yet published.
        return new Page(page, next - 1, more);
    }

    /**
     * Drops everything the given cursor has acknowledged. Idempotent: a repeated drain acknowledging the same cursor
     * frees nothing the second time, which is what makes a re-published tick harmless.
     */
    public void discardThrough(long sequence) {
        if (sequence > sequencer.get()) {
            // Acknowledging a sequence this run has never issued would mark the numbers up to it discarded, and every
            // item later given one of them would then be answered as already taken.
            throw new IllegalArgumentException("run " + runId + " was acknowledged through sequence " + sequence
                    + ", above the " + sequencer.get() + " it has issued");
        }
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
        synchronized (publication) {
            closed.set(true);
            items.clear();
        }
        budget.close(runId);
    }

    public record Page(List<DiscoveredItemDto> items, long highestSequence, boolean more) {
    }
}
