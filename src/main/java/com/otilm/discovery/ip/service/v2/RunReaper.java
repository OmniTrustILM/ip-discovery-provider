package com.otilm.discovery.ip.service.v2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

/**
 * Releases runs the platform has stopped driving.
 *
 * <p>
 * The connector needs a deadline of its own because Core's cleanup is best-effort: a start that fails after initiate
 * succeeded calls cancel and, if that call does not land, logs that the scan may keep running until the connector's
 * own timeout. Without this there is no such timeout, and an orphaned scan holds its buffer and its threads until the
 * process restarts.
 */
@Component
public class RunReaper {

    private static final Logger logger = LoggerFactory.getLogger(RunReaper.class);

    private final RunRegistry registry;
    private final Duration idleDeadline;

    public RunReaper(RunRegistry registry, @Value("${discovery.run.idle-deadline-ms}") long idleDeadlineMs) {
        if (idleDeadlineMs <= 0) {
            throw new IllegalArgumentException("discovery.run.idle-deadline-ms must be positive, was " + idleDeadlineMs);
        }
        this.registry = registry;
        this.idleDeadline = Duration.ofMillis(idleDeadlineMs);
    }

    @Scheduled(fixedDelayString = "${discovery.run.reaper-interval-ms}")
    public void sweep() {
        List<UUID> abandoned = registry.abandonIdle(idleDeadline);
        if (!abandoned.isEmpty()) {
            logger.info("Abandoned {} run(s) the platform stopped driving: {}", abandoned.size(), abandoned);
        }
    }
}
