package com.otilm.discovery.ip.api.v2;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.connector.discovery.v2.DiscoverySupportedResourceDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.service.v2.impl.DiscoveryAttributeServiceImpl;
import org.springframework.boot.info.BuildProperties;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

class DiscoveryMetadataControllerImplTest {

    private final DiscoveryMetadataControllerImpl controller =
            new DiscoveryMetadataControllerImpl(new DiscoveryAttributeServiceImpl(buildProperties()));

    private static BuildProperties buildProperties() {
        Properties properties = new Properties();
        properties.setProperty("version", "2.20.0-SNAPSHOT");
        return new BuildProperties(properties);
    }

    private Set<Resource> supported() {
        return controller
                .listSupportedResources()
                .stream()
                .map(DiscoverySupportedResourceDto::getResource)
                .collect(Collectors.toSet());
    }

    @Test
    void discoversCertificatesAndTheKeysTheyCarry() {
        Assertions.assertEquals(Set.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY), supported());
    }

    /**
     * Core calls this on every run start, not only at registration, so the answer has to come from a constant rather
     * than from anything a run can change.
     */
    @Test
    void answersTheSameResourcesOnEveryCall() {
        Assertions.assertEquals(controller.listSupportedResources().size(), controller.listSupportedResources().size());
        Assertions.assertEquals(supported(), supported());
    }

    @Test
    void offersTheScanSettingsAsRunLevelAttributes() {
        List<String> names = controller.listRunAttributes().stream().map(attribute -> attribute.getName()).toList();

        Assertions
                .assertTrue(
                        names
                                .containsAll(List
                                        .of(DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_HOSTS_NAME,
                                                DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PORTS_NAME,
                                                DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_NAME)),
                        "the run-level schema must carry the settings a scan needs: " + names);
    }

    @Test
    void refinesNeitherResourceWithAttributesOfItsOwn() {
        Assertions.assertEquals(List.of(), controller.listResourceAttributes(Resource.CERTIFICATE));
        Assertions.assertEquals(List.of(), controller.listResourceAttributes(Resource.CRYPTOGRAPHIC_KEY));
    }

    /**
     * An empty list would read as "this resource needs no configuration", which is not the same answer as "this
     * connector does not discover it".
     */
    @Test
    void rejectsAResourceItDoesNotDiscover() {
        ValidationException thrown = Assertions
                .assertThrows(ValidationException.class, () -> controller.listResourceAttributes(Resource.SECRET));

        Assertions.assertTrue(thrown.getMessage().contains("certificates"), thrown.getMessage());
    }
}
