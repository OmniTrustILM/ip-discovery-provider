package com.otilm.discovery.ip.util;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.connector.discovery.DiscoveryRequestDto;
import com.otilm.discovery.ip.service.impl.AttributeServiceImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Covers the URL-expansion logic directly, without a Spring context. The existing
 * DiscoverIpHandlerTest asserts the validation regexes; this one drives the parsing itself.
 */
class DiscoverIpHandlerParsingTest {

    private static RequestAttributeV2 attribute(String uuid, String name, AttributeContentType type,
            BaseAttributeContentV2<?> content) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setUuid(UUID.fromString(uuid));
        attribute.setName(name);
        attribute.setContentType(type);
        attribute.setContent(List.of(content));
        return attribute;
    }

    private static DiscoveryRequestDto request(String ips, String ports, boolean allPorts) {
        DiscoveryRequestDto request = new DiscoveryRequestDto();
        request.setName("parsing-test");
        request.setKind("IP-Hostname");
        request.setAttributes(List.<RequestAttribute>of(
                attribute("1b6c48ad-c1c7-4c82-91ef-3b61bc9f52ac", AttributeServiceImpl.DATA_ATTRIBUTE_DISCOVERY_IP_NAME,
                        AttributeContentType.STRING, new StringAttributeContentV2(ips)),
                attribute("a9091e0d-f9b9-4514-b275-1dd52aa870ec", AttributeServiceImpl.DATA_ATTRIBUTE_PORT_NAME,
                        AttributeContentType.STRING, new StringAttributeContentV2(ports)),
                attribute("3c70d728-e8c3-40f9-b9b2-5d7256f89ef0", AttributeServiceImpl.DATA_ATTRIBUTE_ALL_PORTS_NAME,
                        AttributeContentType.BOOLEAN, new BooleanAttributeContentV2(allPorts))));
        return request;
    }

    // --- getIpHostnameUrls ---

    @Test
    void keepsASingleHostnameAsIs() {
        Assertions.assertEquals(Set.of("www.example.com"), DiscoverIpHandler.getIpHostnameUrls("www.example.com"));
    }

    @Test
    void keepsASingleIpAddressAsIs() {
        Assertions.assertEquals(Set.of("192.168.1.1"), DiscoverIpHandler.getIpHostnameUrls("192.168.1.1"));
    }

    @Test
    void expandsAnInclusiveIpRange() {
        Set<String> ips = DiscoverIpHandler.getIpHostnameUrls("10.1.1.1-10.1.1.3");

        Assertions.assertEquals(Set.of("10.1.1.1", "10.1.1.2", "10.1.1.3"), ips);
    }

    @Test
    void expandsACidrSubnetToItsUsableHosts() {
        Set<String> ips = DiscoverIpHandler.getIpHostnameUrls("192.168.5.0/30");

        // SubnetUtils excludes network and broadcast by default
        Assertions.assertEquals(Set.of("192.168.5.1", "192.168.5.2"), ips);
    }

    @Test
    void deduplicatesRepeatedEntries() {
        Assertions.assertEquals(1, DiscoverIpHandler.getIpHostnameUrls("192.168.1.1,192.168.1.1").size());
    }

    @Test
    void rejectsAMalformedEntry() {
        ValidationException thrown = Assertions.assertThrows(ValidationException.class,
                () -> DiscoverIpHandler.getIpHostnameUrls("192.33.168.1.1"));

        Assertions.assertTrue(thrown.getMessage().contains("192.33.168.1.1"), thrown.getMessage());
    }

    // --- getIpRange ---

    @Test
    void expandsARangeGivenAsTwoAddresses() {
        Assertions.assertEquals(5, DiscoverIpHandler.getIpRange("10.0.0.1", "10.0.0.5").size());
    }

    @Test
    void treatsASingleAddressRangeAsOneAddress() {
        Assertions.assertEquals(Set.of("10.0.0.7"), DiscoverIpHandler.getIpRange("10.0.0.7", "10.0.0.7"));
    }

    @Test
    void rejectsAnUnparsableRangeBound() {
        Assertions.assertThrows(ValidationException.class, () -> DiscoverIpHandler.getIpRange("not-an-ip", "10.0.0.1"));
    }

    // --- getPorts ---

    @Test
    void readsASinglePort() {
        Assertions.assertEquals(Set.of("443"), DiscoverIpHandler.getPorts("443", false));
    }

    @Test
    void readsACommaSeparatedPortList() {
        Assertions.assertEquals(Set.of("80", "443", "8443"), DiscoverIpHandler.getPorts("80,443,8443", false));
    }

    @Test
    void expandsAnInclusivePortRange() {
        Assertions.assertEquals(Set.of("8080", "8081", "8082"), DiscoverIpHandler.getPorts("8080-8082", false));
    }

    @Test
    void combinesSinglePortsAndRanges() {
        Assertions.assertEquals(Set.of("22", "80", "81", "443"), DiscoverIpHandler.getPorts("22,80-81,443", false));
    }

    @Test
    void allPortsOverridesTheProvidedList() {
        Set<String> ports = DiscoverIpHandler.getPorts("443", true);

        Assertions.assertEquals(65535, ports.size());
        Assertions.assertTrue(ports.contains("0"));
        Assertions.assertTrue(ports.contains("65534"));
    }

    @Test
    void rejectsAMalformedPort() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> DiscoverIpHandler.getPorts("http", false));
    }

    @Test
    void rejectsAnOutOfRangePort() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> DiscoverIpHandler.getPorts("70000", false));
    }

    // --- buildUrls ---

    @Test
    void buildsTheCartesianProductOfHostsAndPorts() {
        Set<String> urls = DiscoverIpHandler.buildUrls(Set.of("10.0.0.1", "10.0.0.2"), Set.of("443", "8443"));

        Assertions.assertEquals(Set.of(
                "https://10.0.0.1:443", "https://10.0.0.1:8443",
                "https://10.0.0.2:443", "https://10.0.0.2:8443"), urls);
    }

    @Test
    void buildsNothingWhenThereAreNoPorts() {
        Assertions.assertTrue(DiscoverIpHandler.buildUrls(Set.of("10.0.0.1"), Set.of()).isEmpty());
    }

    // --- getAllIp ---

    @Test
    void expandsAWholeRequestIntoUrls() {
        Set<String> urls = DiscoverIpHandler.getAllIp(request("10.9.9.1-10.9.9.2", "443,8443", false));

        Assertions.assertEquals(Set.of(
                "https://10.9.9.1:443", "https://10.9.9.1:8443",
                "https://10.9.9.2:443", "https://10.9.9.2:8443"), urls);
    }

    @Test
    void rejectsARequestWithAnUnknownKind() {
        DiscoveryRequestDto request = request("10.0.0.1", "443", false);
        request.setKind("Nonsense");

        Assertions.assertThrows(ValidationException.class, () -> DiscoverIpHandler.getAllIp(request));
    }

    @Test
    void cannotBeInstantiated() throws NoSuchMethodException {
        Constructor<DiscoverIpHandler> constructor = DiscoverIpHandler.class.getDeclaredConstructor();
        constructor.setAccessible(true);

        InvocationTargetException thrown =
                Assertions.assertThrows(InvocationTargetException.class, constructor::newInstance);
        Assertions.assertInstanceOf(IllegalStateException.class, thrown.getCause());
    }
}
