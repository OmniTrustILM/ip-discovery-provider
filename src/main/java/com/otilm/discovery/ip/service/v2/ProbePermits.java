package com.otilm.discovery.ip.service.v2;

import java.util.concurrent.Semaphore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Probes in flight on this node, across every slice it is scanning. A run may ask for a thousand probes at once, and
 * {@code discovery.slice.max-concurrent} slices may run together, so without a shared bound one node could open tens of
 * thousands of sockets. A slice that finds no permit launches fewer probes; it never fails the call for it.
 *
 * <p>
 * A probe holds its permit until its thread returns, not until its slice gives up on it, so probes abandoned past their
 * deadline count against the limit for as long as they really run.
 */
@Component
public class ProbePermits {

    private final Semaphore permits;

    public ProbePermits(@Value("${discovery.slice.max-probes-in-flight:2000}") int limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException(
                    "discovery.slice.max-probes-in-flight must be positive, but was " + limit);
        }
        this.permits = new Semaphore(limit);
    }

    boolean tryAcquire() {
        return permits.tryAcquire();
    }

    void release() {
        permits.release();
    }

    int available() {
        return permits.availablePermits();
    }
}
