package com.otilm.discovery.ip.service;

import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.connector.discovery.DiscoveryDataRequestDto;
import com.otilm.api.model.connector.discovery.DiscoveryRequestDto;
import com.otilm.discovery.ip.dao.DiscoveryHistory;
import com.otilm.discovery.ip.service.impl.AttributeServiceImpl;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ActiveProfiles;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@SpringBootTest
@Transactional
@Rollback
@ActiveProfiles(profiles = "non-async")
public class DiscoveryServiceTest {

    @Autowired
    private DiscoveryService discoveryService;

    private DiscoveryRequestDto discoveryProviderDtoTest;
    private DiscoveryDataRequestDto discoveryProviderDtoTestExists;
    private DiscoveryHistory discoveryHistory;

    @BeforeEach
    public void setUp() {
        discoveryProviderDtoTest = new DiscoveryRequestDto();
        discoveryProviderDtoTest.setName("test123");

        discoveryProviderDtoTestExists = new DiscoveryDataRequestDto();
        discoveryProviderDtoTestExists.setName("test123");
        discoveryProviderDtoTestExists.setPageNumber(0);
        discoveryProviderDtoTestExists.setItemsPerPage(100);

        RequestAttributeV2 kind = new RequestAttributeV2();
        kind.setUuid(UUID.fromString("72f1ce7d-3e63-458c-8954-2b950240ca33"));
        kind.setName("kind");
        kind.setContentType(AttributeContentType.STRING);
        kind.setContent(List.<BaseAttributeContentV2<?>>of(new StringAttributeContentV2("IP/Hostname")));

        RequestAttributeV2 ip = new RequestAttributeV2();
        ip.setUuid(UUID.fromString("1b6c48ad-c1c7-4c82-91ef-3b61bc9f52ac"));
        ip.setName(AttributeServiceImpl.DATA_ATTRIBUTE_DISCOVERY_IP_NAME);
        ip.setContentType(AttributeContentType.STRING);
        ip.setContent(List.<BaseAttributeContentV2<?>>of(new StringAttributeContentV2("google.com")));

        RequestAttributeV2 port = new RequestAttributeV2();
        port.setUuid(UUID.fromString("a9091e0d-f9b9-4514-b275-1dd52aa870ec"));
        port.setName(AttributeServiceImpl.DATA_ATTRIBUTE_PORT_NAME);
        port.setContentType(AttributeContentType.STRING);
        port.setContent(List.<BaseAttributeContentV2<?>>of(new StringAttributeContentV2("443")));

        RequestAttributeV2 allPorts = new RequestAttributeV2();
        allPorts.setUuid(UUID.fromString("3c70d728-e8c3-40f9-b9b2-5d7256f89ef0"));
        allPorts.setName(AttributeServiceImpl.DATA_ATTRIBUTE_ALL_PORTS_NAME);
        allPorts.setContentType(AttributeContentType.BOOLEAN);
        allPorts.setContent(List.<BaseAttributeContentV2<?>>of(new BooleanAttributeContentV2(false)));
        discoveryProviderDtoTest.setAttributes(Arrays.asList(kind, ip, port, allPorts));

        discoveryHistory = new DiscoveryHistory();
        discoveryHistory.setName("test");
    }

    @Test
    public void getProviderDtoDataTest(){
        Assertions.assertAll(() -> discoveryService.getProviderDtoData(discoveryProviderDtoTestExists, discoveryHistory));
    }

    @Test
    public void discoveryTest() {
        Assertions.assertAll(() -> discoveryService.discoverCertificate(discoveryProviderDtoTest, discoveryHistory));
    }
}
