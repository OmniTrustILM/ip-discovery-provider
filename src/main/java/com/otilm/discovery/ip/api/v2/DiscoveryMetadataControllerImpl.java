package com.otilm.discovery.ip.api.v2;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.connector.discovery.v2.DiscoveryMetadataController;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoverySupportedResourceDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.ConnectorV2Api;
import com.otilm.discovery.ip.service.v2.DiscoveryAttributeService;
import org.springframework.web.bind.annotation.RestController;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

@RestController
@ConnectorV2Api
public class DiscoveryMetadataControllerImpl implements DiscoveryMetadataController {

    /**
     * A scan reads a TLS chain, so a certificate and the public part of the key it carries come from the same probe.
     * Keys are not discovered independently.
     */
    private static final Set<Resource> SUPPORTED = EnumSet.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY);

    private final DiscoveryAttributeService attributeService;

    public DiscoveryMetadataControllerImpl(DiscoveryAttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Override
    public List<DiscoverySupportedResourceDto> listSupportedResources() {
        return SUPPORTED.stream().map(DiscoveryMetadataControllerImpl::describe).toList();
    }

    @Override
    public List<BaseAttribute> listRunAttributes() {
        return attributeService.listRunAttributes();
    }

    /**
     * Every attribute this connector defines configures the run as a whole — the addresses, the ports, the
     * parallelism — so neither resource refines it further. The route still validates its argument: answering an
     * empty list for a resource the connector does not discover would report "nothing to configure" where the honest
     * answer is "not offered here".
     */
    @Override
    public List<BaseAttribute> listResourceAttributes(Resource resource) {
        if (!SUPPORTED.contains(resource)) {
            throw new ValidationException("This connector does not discover " + resource.getLabel() + ". Supported: "
                    + SUPPORTED.stream().map(Resource::getCode).toList());
        }
        return List.of();
    }

    private static DiscoverySupportedResourceDto describe(Resource resource) {
        DiscoverySupportedResourceDto dto = new DiscoverySupportedResourceDto();
        dto.setResource(resource);
        return dto;
    }
}
