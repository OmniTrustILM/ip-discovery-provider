package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import java.util.List;

/**
 * What probing one target came to.
 *
 * @param index the target's position in the enumeration
 * @param items unsequenced: the slice that commits the target numbers them
 * @param itemBytes what the items weigh on the wire, held against the page's byte limit
 * @param failureReason null unless the outcome is failed
 */
record TargetResult(long index, TargetOutcome outcome, List<DiscoveredItemDto> items, long itemBytes,
        String failureReason) {

    static TargetResult failed(long index, String reason) {
        return new TargetResult(index, TargetOutcome.FAILED, List.of(), 0L, reason);
    }
}
