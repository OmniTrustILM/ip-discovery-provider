package com.otilm.discovery.ip.service.v2;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Bounds on one results call. A slice launches probes until its scan budget runs out and then waits for each launched
 * probe to its own deadline, so it answers within the budget plus one probe deadline. That sum is held under 18
 * seconds, which leaves room inside the 20 seconds the contract gives a results call.
 */
@Component
public class SliceSettings {

    static final long MAX_SLICE_MS = 18_000;

    private final long scanBudgetMs;
    private final int maxConcurrent;
    private final int maxAbandonedProbes;
    private final long probeDeadlineMs;

    public SliceSettings(@Value("${discovery.slice.scan-budget-ms:8000}") long scanBudgetMs,
            @Value("${discovery.slice.max-concurrent:32}") int maxConcurrent,
            @Value("${discovery.slice.max-abandoned-probes:256}") int maxAbandonedProbes,
            @Value("${discovery.probe.total-timeout-ms:10000}") long probeDeadlineMs) {
        requirePositive("discovery.slice.scan-budget-ms", scanBudgetMs);
        requirePositive("discovery.slice.max-concurrent", maxConcurrent);
        requirePositive("discovery.slice.max-abandoned-probes", maxAbandonedProbes);
        requirePositive("discovery.probe.total-timeout-ms", probeDeadlineMs);
        if (scanBudgetMs + probeDeadlineMs > MAX_SLICE_MS) {
            throw new IllegalArgumentException("discovery.slice.scan-budget-ms (" + scanBudgetMs
                    + ") plus discovery.probe.total-timeout-ms (" + probeDeadlineMs + ") must not exceed "
                    + MAX_SLICE_MS + " ms, or a results call can outlive the 20 seconds Core allows it");
        }
        this.scanBudgetMs = scanBudgetMs;
        this.maxConcurrent = maxConcurrent;
        this.maxAbandonedProbes = maxAbandonedProbes;
        this.probeDeadlineMs = probeDeadlineMs;
    }

    private static void requirePositive(String property, long value) {
        if (value <= 0) {
            throw new IllegalArgumentException(property + " must be positive, but was " + value);
        }
    }

    public long scanBudgetMs() {
        return scanBudgetMs;
    }

    public int maxConcurrent() {
        return maxConcurrent;
    }

    public int maxAbandonedProbes() {
        return maxAbandonedProbes;
    }

    public long probeDeadlineMs() {
        return probeDeadlineMs;
    }
}
