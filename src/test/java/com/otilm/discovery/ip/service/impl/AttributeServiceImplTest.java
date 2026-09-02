package com.otilm.discovery.ip.service.impl;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * The attribute service is stateless, so it is exercised directly rather than through a Spring
 * context. AttributeServiceTest covers the wiring; this covers the definitions and validation.
 */
class AttributeServiceImplTest {

    private static final String KIND = "IP-Hostname";

    private final AttributeServiceImpl attributeService = new AttributeServiceImpl();

    private static RequestAttributeV2 attribute(String uuid, String name, AttributeContentType type,
            BaseAttributeContentV2<?> content) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setUuid(UUID.fromString(uuid));
        attribute.setName(name);
        attribute.setContentType(type);
        attribute.setContent(List.of(content));
        return attribute;
    }

    private static RequestAttributeV2 ip(String value) {
        return attribute("1b6c48ad-c1c7-4c82-91ef-3b61bc9f52ac", AttributeServiceImpl.DATA_ATTRIBUTE_DISCOVERY_IP_NAME,
                AttributeContentType.STRING, new StringAttributeContentV2(value));
    }

    private static RequestAttributeV2 port(String value) {
        return attribute("a9091e0d-f9b9-4514-b275-1dd52aa870ec", AttributeServiceImpl.DATA_ATTRIBUTE_PORT_NAME,
                AttributeContentType.STRING, new StringAttributeContentV2(value));
    }

    private static RequestAttributeV2 allPorts(boolean value) {
        return attribute("3c70d728-e8c3-40f9-b9b2-5d7256f89ef0", AttributeServiceImpl.DATA_ATTRIBUTE_ALL_PORTS_NAME,
                AttributeContentType.BOOLEAN, new BooleanAttributeContentV2(value));
    }

    private static RequestAttributeV2 parallelExecutions(int value) {
        return attribute("1517c7a5-34cb-4f94-a0aa-1e9fe5b5b277",
                AttributeServiceImpl.DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_NAME,
                AttributeContentType.INTEGER, new IntegerAttributeContentV2(value));
    }

    // --- getAttributes ---

    @Test
    void publishesTheFiveDiscoveryAttributes() {
        List<BaseAttribute> attributes = attributeService.getAttributes(KIND);

        Assertions.assertEquals(5, attributes.size());
        Assertions.assertEquals(
                List.of(AttributeServiceImpl.INFO_ATTRIBUTE_IP_HOSTNAME_NAME,
                        AttributeServiceImpl.DATA_ATTRIBUTE_DISCOVERY_IP_NAME,
                        AttributeServiceImpl.DATA_ATTRIBUTE_PORT_NAME,
                        AttributeServiceImpl.DATA_ATTRIBUTE_ALL_PORTS_NAME,
                        AttributeServiceImpl.DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_NAME),
                attributes.stream().map(BaseAttribute::getName).toList());
    }

    @Test
    void marksTheFirstAttributeAsInfoAndTheRestAsData() {
        List<BaseAttribute> attributes = attributeService.getAttributes(KIND);

        Assertions.assertEquals(AttributeType.INFO, attributes.get(0).getType());
        Assertions.assertTrue(attributes.subList(1, attributes.size()).stream()
                .allMatch(a -> a.getType() == AttributeType.DATA));
    }

    @Test
    void keepsTheAttributeUuidsStable() {
        // These uuids identify stored attribute content, so a change breaks existing discoveries.
        List<BaseAttribute> attributes = attributeService.getAttributes(KIND);

        Assertions.assertEquals(
                List.of(AttributeServiceImpl.INFO_ATTRIBUTE_IP_HOSTNAME_UUID,
                        AttributeServiceImpl.DATA_ATTRIBUTE_DISCOVERY_IP_UUID,
                        AttributeServiceImpl.DATA_ATTRIBUTE_PORT_UUID,
                        AttributeServiceImpl.DATA_ATTRIBUTE_ALL_PORTS_UUID,
                        AttributeServiceImpl.DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_UUID),
                attributes.stream().map(BaseAttribute::getUuid).toList());
    }

    @Test
    void rejectsAnUnsupportedKind() {
        // ValidationException maps to 422; an IllegalArgumentException would surface as a 500.
        Assertions.assertThrows(ValidationException.class, () -> attributeService.getAttributes("Nope"));
    }

    // --- validateAttributes ---

    @Test
    void acceptsAWellFormedRequest() {
        List<RequestAttribute> attributes = new ArrayList<>(List.of(ip("10.0.0.1"), port("443"), allPorts(false)));

        Assertions.assertTrue(attributeService.validateAttributes(KIND, attributes));
    }

    @Test
    void rejectsAnUnsupportedKindOnValidation() {
        List<RequestAttribute> attributes = new ArrayList<>(List.of(ip("10.0.0.1")));

        Assertions.assertThrows(ValidationException.class, () -> attributeService.validateAttributes("Nope", attributes));
    }

    @Test
    void rejectsAMalformedIpValue() {
        List<RequestAttribute> attributes = new ArrayList<>(List.of(ip("10.0.0.999.7"), port("443")));

        Assertions.assertThrows(ValidationException.class, () -> attributeService.validateAttributes(KIND, attributes));
    }

    // --- content accessors ---

    @Test
    void readsTheIpValueBack() {
        Assertions.assertEquals("10.0.0.1",
                AttributeServiceImpl.getDiscoveryIpDataAttributeContentValue(List.of(ip("10.0.0.1"))));
    }

    @Test
    void failsWhenTheIpAttributeIsAbsent() {
        List<RequestAttribute> withoutIp = List.of(port("443"));

        Assertions.assertThrows(ValidationException.class,
                () -> AttributeServiceImpl.getDiscoveryIpDataAttributeContentValue(withoutIp));
    }

    @Test
    void readsThePortValueBack() {
        Assertions.assertEquals("8443", AttributeServiceImpl.getPortDataAttributeContentValue(List.of(port("8443"))));
    }

    @Test
    void fallsBackTo443WhenNoPortGiven() {
        Assertions.assertEquals("443", AttributeServiceImpl.getPortDataAttributeContentValue(List.of(ip("10.0.0.1"))));
    }

    @Test
    void readsTheAllPortsFlagBack() {
        Assertions.assertEquals(Boolean.TRUE,
                AttributeServiceImpl.getAllPortsDataAttributeContentValue(List.of(allPorts(true))));
    }

    @Test
    void fallsBackToFalseWhenAllPortsIsAbsent() {
        Assertions.assertEquals(Boolean.FALSE,
                AttributeServiceImpl.getAllPortsDataAttributeContentValue(List.of(ip("10.0.0.1"))));
    }

    @Test
    void readsTheParallelExecutionsValueBack() {
        Assertions.assertEquals(25,
                AttributeServiceImpl.getParallelExecutionsDataAttributeContentValue(List.of(parallelExecutions(25))));
    }

    @Test
    void fallsBackToSingleThreadedWhenParallelExecutionsIsAbsent() {
        Assertions.assertEquals(1,
                AttributeServiceImpl.getParallelExecutionsDataAttributeContentValue(List.of(ip("10.0.0.1"))));
    }
}
