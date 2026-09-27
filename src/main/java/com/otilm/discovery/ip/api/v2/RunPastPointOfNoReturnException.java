package com.otilm.discovery.ip.api.v2;

import java.util.UUID;

/**
 * A stop arrived after the run had already ended. The contract answers that as past the point of no return, and Core
 * then keeps the run as it was: still draining a completed run to its end, or reporting a failed one as failed.
 */
public class RunPastPointOfNoReturnException extends RuntimeException {

    private final transient UUID runId;

    /**
     * @param endedAs the state the run ended in, as a person reads it
     */
    public RunPastPointOfNoReturnException(UUID runId, String endedAs) {
        super("Run " + runId + " has already ended as " + endedAs + ", so there is nothing left to stop");
        this.runId = runId;
    }

    public UUID getRunId() {
        return runId;
    }
}
