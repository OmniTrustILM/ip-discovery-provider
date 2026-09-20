package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackRequestDto;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackResponseDto;
import com.otilm.api.model.client.connector.v2.attribute.AttributeDefinitionsDto;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;

import java.util.List;
import java.util.UUID;

/**
 * The v2 attribute schema and its registry.
 *
 * <p>
 * Deliberately shares nothing with the v1 {@code AttributeService}: that one reaches the discovery history and the
 * certificate repository, and the v2 surface stores nothing. The two schemas are also different shapes — v1 splits
 * comma-separated strings, v2 takes lists — so a shared reader would have to serve both and would serve neither well.
 */
public interface DiscoveryAttributeService {

    /** The schema that configures a run as a whole. Every attribute this connector defines is run-level. */
    List<BaseAttribute> listRunAttributes();

    /** The registry: all definitions, or only those named. */
    AttributeDefinitionsDto listDefinitions(List<UUID> uuids);

    BaseAttribute getDefinition(UUID uuid);

    AttributeCallbackResponseDto callback(AttributeCallbackRequestDto request);

    /**
     * The hosts a run targets, one per entry, each already checked. Rejecting here rather than at the scan means a
     * malformed entry is refused while the operator is still looking at the form.
     *
     * @throws com.otilm.api.exception.ValidationException naming the offending entry, or if no host was given
     */
    List<String> readHosts(List<RequestAttribute> attributes);

    /**
     * The ports a run probes on each host. An omitted or empty list means the default, which is what the v1 schema
     * expressed as a preselected value and a list cannot.
     *
     * @throws com.otilm.api.exception.ValidationException naming the offending entry
     */
    List<String> readPorts(List<RequestAttribute> attributes);

    /** @throws com.otilm.api.exception.ValidationException if outside the published range */
    int readParallelExecutions(List<RequestAttribute> attributes);
}
