package com.otilm.discovery.ip.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.connector.discovery.DiscoveryDataRequestDto;
import com.otilm.api.model.connector.discovery.DiscoveryProviderDto;
import com.otilm.api.model.connector.discovery.DiscoveryRequestDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.discovery.ip.dao.Certificate;
import com.otilm.discovery.ip.dao.DiscoveryHistory;
import com.otilm.discovery.ip.repository.CertificateRepository;
import com.otilm.discovery.ip.service.impl.AttributeServiceImpl;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.UUID;

/**
 * Covers the synchronous side of the discovery lifecycle - reading a discovery back, deleting it,
 * and the failure path that records a reason. The scanning itself needs the network and is left to
 * DiscoveryServiceTest.
 */
@SpringBootTest
@Transactional
@Rollback
@ActiveProfiles(profiles = "non-async")
class DiscoveryServiceLifecycleTest {

    @Autowired
    private DiscoveryService discoveryService;

    @Autowired
    private DiscoveryHistoryService discoveryHistoryService;

    @Autowired
    private CertificateRepository certificateRepository;

    private DiscoveryHistory history;

    @BeforeEach
    void setUp() {
        DiscoveryRequestDto request = new DiscoveryRequestDto();
        request.setName("lifecycle-" + UUID.randomUUID());
        history = discoveryHistoryService.addHistory(request);
    }

    private DiscoveryDataRequestDto dataRequest(int pageNumber) {
        DiscoveryDataRequestDto request = new DiscoveryDataRequestDto();
        request.setName(history.getName());
        request.setPageNumber(pageNumber);
        request.setItemsPerPage(10);
        return request;
    }

    private Certificate storeCertificate(String content) {
        Certificate certificate = new Certificate();
        certificate.setUuid(UUID.randomUUID().toString());
        certificate.setDiscoveryId(history.getId());
        certificate.setBase64Content(content);
        return certificateRepository.save(certificate);
    }

    @Test
    void reportsNoCertificatesWhileTheDiscoveryIsStillRunning() {
        storeCertificate("aW4tcHJvZ3Jlc3M=");
        history.setStatus(DiscoveryStatus.IN_PROGRESS);

        DiscoveryProviderDto dto = discoveryService.getProviderDtoData(dataRequest(1), history);

        // Partial results are deliberately withheld until the scan finishes.
        Assertions.assertEquals(DiscoveryStatus.IN_PROGRESS, dto.getStatus());
        Assertions.assertEquals(0, dto.getTotalCertificatesDiscovered());
        Assertions.assertTrue(dto.getCertificateData().isEmpty());
    }

    @Test
    void returnsStoredCertificatesOnceComplete() {
        storeCertificate("Y2VydC1vbmU=");
        storeCertificate("Y2VydC10d28=");
        history.setStatus(DiscoveryStatus.COMPLETED);

        DiscoveryProviderDto dto = discoveryService.getProviderDtoData(dataRequest(1), history);

        Assertions.assertEquals(DiscoveryStatus.COMPLETED, dto.getStatus());
        Assertions.assertEquals(2, dto.getTotalCertificatesDiscovered());
        Assertions.assertEquals(2, dto.getCertificateData().size());
        Assertions.assertEquals(history.getUuid(), dto.getUuid());
        Assertions.assertEquals(history.getName(), dto.getName());
    }

    @Test
    void treatsAZeroPageNumberAsTheFirstPage() {
        storeCertificate("cGFnZS16ZXJv");
        history.setStatus(DiscoveryStatus.COMPLETED);

        Assertions.assertEquals(1, discoveryService.getProviderDtoData(dataRequest(0), history).getCertificateData().size());
    }

    @Test
    void deserialisesStoredMetadataOntoTheResponse() {
        history.setStatus(DiscoveryStatus.COMPLETED);
        history.setMeta("[{\"uuid\":\"872ca286-601f-11ed-9b6a-0242ac120002\",\"name\":\"totalUrls\","
                + "\"type\":\"meta\",\"contentType\":\"integer\","
                + "\"content\":[{\"reference\":\"4\",\"data\":4}],"
                + "\"properties\":{\"label\":\"Total URLs\",\"visible\":true}}]");

        List<MetadataAttribute> meta = discoveryService.getProviderDtoData(dataRequest(1), history).getMeta();

        Assertions.assertNotNull(meta);
        Assertions.assertEquals(1, meta.size());
        Assertions.assertEquals("totalUrls", meta.get(0).getName());
    }

    @Test
    void leavesMetadataNullWhenNoneWasStored() {
        history.setStatus(DiscoveryStatus.COMPLETED);

        Assertions.assertNull(discoveryService.getProviderDtoData(dataRequest(1), history).getMeta());
    }

    @Test
    void deletingADiscoveryRemovesItsCertificates() throws Exception {
        storeCertificate("dG8tYmUtZGVsZXRlZA==");
        Long id = history.getId();

        discoveryService.deleteDiscovery(history.getUuid());

        Assertions.assertTrue(certificateRepository.findByDiscoveryId(id).isEmpty());
        Assertions.assertThrows(NotFoundException.class, () -> discoveryHistoryService.getHistoryByUuid(history.getUuid()));
    }

    @Test
    void deletingAnUnknownDiscoveryReportsNotFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> discoveryService.deleteDiscovery("00000000-0000-0000-0000-000000000000"));
    }

    @Test
    void recordsTheReasonWhenDiscoveryFails() throws Exception {
        // No IP attribute, so URL expansion fails and the failure path records why.
        DiscoveryRequestDto request = new DiscoveryRequestDto();
        request.setName(history.getName());
        request.setKind("IP-Hostname");
        RequestAttributeV2 port = new RequestAttributeV2();
        port.setUuid(UUID.fromString("a9091e0d-f9b9-4514-b275-1dd52aa870ec"));
        port.setName(AttributeServiceImpl.DATA_ATTRIBUTE_PORT_NAME);
        port.setContentType(AttributeContentType.STRING);
        port.setContent(List.<BaseAttributeContentV2<?>>of(new StringAttributeContentV2("443")));
        request.setAttributes(List.<RequestAttribute>of(port));

        discoveryService.discoverCertificate(request, history);

        // discoverCertificate is @Async and @EnableAsync is unconditional, so the failure handler
        // runs on a virtual thread. Wait for it rather than racing it.
        long deadline = System.currentTimeMillis() + 10_000;
        while (history.getStatus() != DiscoveryStatus.FAILED && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }

        Assertions.assertEquals(DiscoveryStatus.FAILED, history.getStatus());
        Assertions.assertNotNull(history.getMeta());
        Assertions.assertTrue(history.getMeta().contains("reason"), history.getMeta());
    }
}
