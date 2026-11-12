package com.otilm.discovery.ip.service.v2;

/**
 * One target produced more than a whole page may carry. Its items cannot be split across pages, and skipping it would
 * lose them, so the run cannot continue. Core's page floor makes this practically unreachable.
 */
public class TargetTooLargeException extends RuntimeException {

    private final long index;
    private final int items;
    private final long bytes;

    public TargetTooLargeException(long index, int items, long bytes, int maxItems, long maxBytes) {
        super("Target " + index + " produced " + items + " items (" + bytes + " bytes), more than a page of at most "
                + maxItems + " items and " + maxBytes + " bytes can carry");
        this.index = index;
        this.items = items;
        this.bytes = bytes;
    }

    public long index() {
        return index;
    }

    public int items() {
        return items;
    }

    public long bytes() {
        return bytes;
    }
}
