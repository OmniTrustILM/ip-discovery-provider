package com.otilm.discovery.ip.api.v2;

import com.otilm.api.interfaces.connector.common.v2.AttributesController;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackRequestDto;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackResponseDto;
import com.otilm.api.model.client.connector.v2.attribute.AttributeDefinitionsDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.discovery.ip.ConnectorV2Api;
import com.otilm.discovery.ip.service.v2.DiscoveryAttributeService;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * The definition registry. Distinct from {@code DiscoveryMetadataControllerImpl}, which publishes the same
 * definitions as the schema for configuring a run: this one addresses them individually, by UUID, which is how Core
 * resolves a definition when servicing a callback.
 *
 * <p>
 * Named explicitly because the v1 {@code AttributesControllerImpl} shares this simple name.
 */
@RestController("attributesControllerV2")
@ConnectorV2Api
public class AttributesControllerImpl implements AttributesController {

    private final DiscoveryAttributeService attributeService;

    public AttributesControllerImpl(DiscoveryAttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Override
    public AttributeDefinitionsDto listDefinitions(List<UUID> uuids) {
        return attributeService.listDefinitions(uuids);
    }

    @Override
    public BaseAttribute getDefinition(UUID uuid) {
        return attributeService.getDefinition(uuid);
    }

    @Override
    public AttributeCallbackResponseDto callback(AttributeCallbackRequestDto request) {
        return attributeService.callback(request);
    }
}
