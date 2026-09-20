package com.otilm.discovery.ip.api.v2;

import java.util.UUID;

/**
 * The checkpoint cannot be continued because the enumeration it indexes into is no longer the same one. Any change to
 * how targets are ordered — a parsing fix, a sort change, an address-library upgrade — invalidates a cursor that is
 * just a position in that order.
 *
 * <p>
 * Distinct from a run the connector never knew: this run is recognised, and its checkpoint is refused rather than
 * resumed at the wrong offset. A connector upgrade therefore breaks stopped runs loudly instead of quietly scanning
 * the wrong targets.
 */
public class CheckpointLostException extends RuntimeException {

    private final transient UUID runId;

    public CheckpointLostException(UUID runId, String detail) {
        super("The checkpoint for run " + runId + " can no longer be resumed: " + detail);
        this.runId = runId;
    }

    public UUID getRunId() {
        return runId;
    }
}
