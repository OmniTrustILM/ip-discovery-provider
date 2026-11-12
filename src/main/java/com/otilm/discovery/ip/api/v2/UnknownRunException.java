package com.otilm.discovery.ip.api.v2;

import java.util.UUID;

/**
 * The connector cannot serve this run from the request. Answered as 404 with the contract's own not-tracked code, which
 * is Core's definitive signal that retrying cannot recover the run: the replayed checkpoint disagrees with Core's
 * cursor, so it is stale or items were lost, or it indexes into a different set of targets.
 */
public class UnknownRunException extends RuntimeException {

    private final transient UUID runId;

    /** @param reason why the request cannot be served, as an operator reads it beside the failed run */
    public UnknownRunException(UUID runId, String reason) {
        super("Run " + runId + " cannot be continued from its checkpoint: " + reason);
        this.runId = runId;
    }

    public UUID getRunId() {
        return runId;
    }
}
