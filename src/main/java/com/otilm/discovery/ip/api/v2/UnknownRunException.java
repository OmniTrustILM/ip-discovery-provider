package com.otilm.discovery.ip.api.v2;

import java.util.UUID;

/**
 * The connector does not track this run. Answered as 404 with the contract's own not-tracked code, which is Core's
 * definitive signal that retrying cannot recover the run — including after a restart, where a running run's buffer
 * did not survive.
 */
public class UnknownRunException extends RuntimeException {

    private final transient UUID runId;

    public UnknownRunException(UUID runId) {
        super("Run " + runId + " is not tracked by this connector");
        this.runId = runId;
    }

    public UUID getRunId() {
        return runId;
    }
}
