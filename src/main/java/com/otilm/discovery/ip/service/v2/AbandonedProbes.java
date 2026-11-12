package com.otilm.discovery.ip.service.v2;

import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Probe threads still running after their slice gave up on them. A host-name lookup is the usual one: the JVM cannot
 * interrupt it, so its thread lives on past the probe's deadline. Counted so results calls can be refused while too
 * many pile up, rather than letting every slice add more.
 */
@Component
public class AbandonedProbes {

    private final Set<CompletableFuture<?>> running = ConcurrentHashMap.newKeySet();

    /** Counts the probe until it completes; a probe that has already completed is dropped at once. */
    void register(CompletableFuture<?> probe) {
        running.add(probe);
        probe.whenComplete((result, failure) -> running.remove(probe));
    }

    public int count() {
        return running.size();
    }
}
