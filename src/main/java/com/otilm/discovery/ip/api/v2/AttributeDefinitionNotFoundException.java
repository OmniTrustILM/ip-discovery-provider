package com.otilm.discovery.ip.api.v2;

import java.util.UUID;

/**
 * A requested attribute UUID is not one this connector defines. Unchecked because the {@code AttributesController}
 * interface declares no checked exceptions on its methods.
 */
public class AttributeDefinitionNotFoundException extends RuntimeException {

    private final transient UUID uuid;

    public AttributeDefinitionNotFoundException(UUID uuid) {
        super("Attribute definition not found for UUID: " + uuid);
        this.uuid = uuid;
    }

    public UUID getUuid() {
        return uuid;
    }
}
