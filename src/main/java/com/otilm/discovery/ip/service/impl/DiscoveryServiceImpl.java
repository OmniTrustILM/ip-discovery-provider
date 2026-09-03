package com.otilm.discovery.ip.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.connector.discovery.DiscoveryDataRequestDto;
import com.otilm.api.model.connector.discovery.DiscoveryProviderDto;
import com.otilm.api.model.connector.discovery.DiscoveryRequestDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.discovery.ip.dao.Certificate;
import com.otilm.discovery.ip.dao.DiscoveryHistory;
import com.otilm.discovery.ip.dto.ConnectionResponse;
import com.otilm.discovery.ip.repository.CertificateRepository;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.service.DiscoveryHistoryService;
import com.otilm.discovery.ip.service.DiscoveryService;
import com.otilm.discovery.ip.util.DiscoverIpHandler;
import com.otilm.discovery.ip.util.TargetEnumeration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

@Service
@Transactional
public class DiscoveryServiceImpl implements DiscoveryService {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryServiceImpl.class);

    private ConnectionService connectionService;
    private CertificateRepository certificateRepository;
    private DiscoveryHistoryService discoveryHistoryService;

    @Autowired
    public void setConnectionService(ConnectionService connectionService) {
        this.connectionService = connectionService;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setDiscoveryHistoryService(DiscoveryHistoryService discoveryHistoryService) {
        this.discoveryHistoryService = discoveryHistoryService;
    }

    @Override
    public DiscoveryProviderDto getProviderDtoData(DiscoveryDataRequestDto request, DiscoveryHistory history) {
        DiscoveryProviderDto dto = new DiscoveryProviderDto();
        dto.setUuid(history.getUuid());
        dto.setName(history.getName());
        dto.setStatus(history.getStatus());
        dto.setMeta(AttributeDefinitionUtils.deserialize(history.getMeta(), MetadataAttribute.class));
        // A count, not a list: this loaded the full base64 content of every certificate the discovery ever
        // found, on every read of the detail, to produce a number.
        dto.setTotalCertificatesDiscovered((int) certificateRepository.countByDiscoveryId(history.getId()));
        if (history.getStatus() == DiscoveryStatus.IN_PROGRESS) {
            dto.setCertificateData(new ArrayList<>());
            dto.setTotalCertificatesDiscovered(0);
        } else {
            Pageable page = PageRequest.of(request.getPageNumber() <= 0 ? 0 : request.getPageNumber() - 1, request.getItemsPerPage(), Sort.by(Sort.Direction.ASC, "id"));
            dto.setCertificateData(certificateRepository.findAllByDiscoveryId(history.getId(), page).stream().map(Certificate::mapToDto).toList());
        }
        return dto;
    }

    @Override
    public void deleteDiscovery(String uuid) throws NotFoundException {
        DiscoveryHistory discoveryHistory = discoveryHistoryService.getHistoryByUuid(uuid);
        certificateRepository.deleteAllByDiscoveryId(discoveryHistory.getId());
        discoveryHistoryService.deleteHistory(discoveryHistory);
    }

    @Override
    @Async
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void discoverCertificate(DiscoveryRequestDto request, DiscoveryHistory history) throws NotFoundException {
        try {
            discoverCertificatesInternal(request, history);
        } catch (Exception e) {
            logger.error("Discovery failed for the request with name {}: {}", request.getName(), e.getMessage(), e);
            history.setStatus(DiscoveryStatus.FAILED);
            history.setMeta(AttributeDefinitionUtils.serialize(getReasonMeta(e.getMessage())));
            discoveryHistoryService.setHistory(history);
        }
    }

    private void discoverCertificatesInternal(DiscoveryRequestDto request, DiscoveryHistory history) {
        logger.info("Discovery initiated for the request with name {}", request.getName());
        TargetEnumeration targets = DiscoverIpHandler.getTargets(request);
        AtomicInteger successUrlCount = new AtomicInteger(0);
        AtomicInteger failedUrlCount = new AtomicInteger(0);
        AtomicInteger foundCertsCount = new AtomicInteger(0);
        Set<String> uniqueCerts = Collections.synchronizedSet(new HashSet<>()); // Thread-safe set

        boolean failed = false;
        List<Future<?>> futures = new ArrayList<>();
        int maxThreads = AttributeServiceImpl.getParallelExecutionsDataAttributeContentValue(request.getAttributes());
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (long i = 0; i < targets.size(); i++) {
                String url = targets.target(i);
                futures.add(executor.submit(() -> {
                    logger.debug("Discovering certificate for {}", url);
                    try {
                        processCertificatesForUrl(url, history.getId(), uniqueCerts, foundCertsCount);
                        successUrlCount.incrementAndGet();
                    } catch (Exception e) {
                        logger.error("Unable to process data or URL {}: {}", url, e.getMessage());
                        failedUrlCount.incrementAndGet();
                    }
                }));

                if (futures.size() == maxThreads) {
                    awaitBatch(futures, history.getName());
                }
            }
            if (!futures.isEmpty()) {
                awaitBatch(futures, history.getName());
            }
        } catch (Exception e) {
            failed = true;
            logger.error("An error occurred during discovery: {}", e.getMessage());
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        } finally {
            logger.info("Discovery {} has total of {} certificates, {} unique, from {} sources", request.getName(), foundCertsCount.get(), uniqueCerts.size(), targets.size());
            history.setStatus(failed ? DiscoveryStatus.FAILED : DiscoveryStatus.COMPLETED);
            history.setMeta(AttributeDefinitionUtils.serialize(getDiscoveryMetadata(targets.size(), successUrlCount.get(), failedUrlCount.get())));
            discoveryHistoryService.setHistory(history);
            logger.info("Discovery Completed. Name of the discovery is {}", request.getName());
        }
    }

    /**
     * Waits for the batch in flight, then clears it so the next one can be submitted.
     *
     * <p>
     * This wait is the scan's only backpressure. Targets are enumerated by index rather than materialised, so nothing
     * else bounds submission: without it a large range would hand millions of tasks to the executor at once. It used to
     * also commit a transaction opened around the loop, which covered no operations at all --
     * {@code TransactionSynchronizationManager} holds its resources in non-inheritable thread locals and the executor
     * has no {@code TaskDecorator}, so the worker threads never joined it and each certificate save committed on its
     * own. Reading as per-batch atomicity while providing none is worse than not claiming it, so the transaction is
     * gone and the wait -- which was doing the real work -- stays.
     */
    private void awaitBatch(List<Future<?>> futures, String discoveryName) throws ExecutionException, InterruptedException {
        logger.debug("Waiting for {} URL discovery tasks for discovery {}", futures.size(), discoveryName);
        for (Future<?> future : futures) {
            future.get();
        }
        logger.debug("{} URL discovery tasks for discovery {} finished", futures.size(), discoveryName);
        futures.clear();
    }

    private void processCertificatesForUrl(String url, Long historyId, Set<String> uniqueCerts, AtomicInteger foundCertsCount) throws IOException, NoSuchAlgorithmException, KeyManagementException, CertificateEncodingException {
        ConnectionResponse connection = connectionService.getCertificates(url);
        logger.debug("Connection to the url success. Certificates obtained");
        X509Certificate[] certificates = connection.getCertificates();
        for (X509Certificate certificate : certificates) {
            String base64Content = Base64.getEncoder().encodeToString(certificate.getEncoded());
            foundCertsCount.incrementAndGet(); // + to all certificates count
            if (uniqueCerts.add(base64Content)) {
                createCertificateEntry(certificate, historyId, url);
            }
        }
    }

    private void createCertificateEntry(X509Certificate certificate, Long discoveryId, String discoverySource) throws CertificateEncodingException {
        Certificate cert = new Certificate();
        String base64Content = Base64.getEncoder().encodeToString(certificate.getEncoded());
        if (certificateRepository.findByDiscoveryIdAndBase64Content(discoveryId, base64Content).isEmpty()) {
            cert.setDiscoveryId(discoveryId);
            cert.setMeta(AttributeDefinitionUtils.serialize(getCertificateMetadata(discoverySource)));
            cert.setBase64Content(base64Content);
            cert.setUuid(UUID.randomUUID().toString());
            certificateRepository.save(cert);
        }
    }

    private List<MetadataAttributeV2> getDiscoveryMetadata(long totalUrls, Integer successUrls, Integer failedUrls) {
        List<MetadataAttributeV2> attributes = new ArrayList<>();

        //Total URL
        MetadataAttributeV2 totalAttribute = new MetadataAttributeV2();
        totalAttribute.setName("totalUrls");
        totalAttribute.setUuid("872ca286-601f-11ed-9b6a-0242ac120002");
        totalAttribute.setContentType(AttributeContentType.INTEGER);
        totalAttribute.setType(AttributeType.META);
        totalAttribute.setDescription("Total number of URLs for the discovery");

        MetadataAttributeProperties totalAttributeProperties = new MetadataAttributeProperties();
        totalAttributeProperties.setLabel("Total URLs");
        totalAttributeProperties.setVisible(true);

        totalAttribute.setProperties(totalAttributeProperties);
        // The target count is a long -- a /16 on all ports is 4.29 billion -- but this metadata attribute has
        // been INTEGER since v1 and its type is part of that wire shape. Clamp rather than widen: a scan large
        // enough to saturate the clamp is one no operator reads an exact total off, and the reference is the
        // v1 shape, not the number.
        int reportableTotal = (int) Math.min(totalUrls, Integer.MAX_VALUE);
        totalAttribute
                .setContent(List.of(new IntegerAttributeContentV2(Long.toString(totalUrls), reportableTotal)));
        attributes.add(totalAttribute);

        //Success URL
        MetadataAttributeV2 successAttribute = new MetadataAttributeV2();
        successAttribute.setName("successUrls");
        successAttribute.setUuid("872ca600-601f-11ed-9b6a-0242ac120002");
        successAttribute.setContentType(AttributeContentType.INTEGER);
        successAttribute.setType(AttributeType.META);
        successAttribute.setDescription("Successful certificate discovery URLs");

        MetadataAttributeProperties successAttributeProperties = new MetadataAttributeProperties();
        successAttributeProperties.setLabel("No Of Success URLs");
        successAttributeProperties.setVisible(true);

        successAttribute.setProperties(successAttributeProperties);
        successAttribute.setContent(List.of(new IntegerAttributeContentV2(successUrls.toString(), successUrls)));
        attributes.add(successAttribute);

        //Failed URL
        MetadataAttributeV2 failedAttribute = new MetadataAttributeV2();
        failedAttribute.setName("failedUrls");
        failedAttribute.setUuid("872ca7ea-601f-11ed-9b6a-0242ac120002");
        failedAttribute.setContentType(AttributeContentType.INTEGER);
        failedAttribute.setType(AttributeType.META);
        failedAttribute.setDescription("Failed certificate discovery URLs");

        MetadataAttributeProperties failedAttributeProperties = new MetadataAttributeProperties();
        failedAttributeProperties.setLabel("No Of Failed URLs");
        failedAttributeProperties.setVisible(true);

        failedAttribute.setProperties(failedAttributeProperties);
        failedAttribute.setContent(List.of(new IntegerAttributeContentV2(failedUrls.toString(), failedUrls)));
        attributes.add(failedAttribute);

        return attributes;
    }

    private List<MetadataAttributeV2> getCertificateMetadata(String discoverySource) {
        List<MetadataAttributeV2> attributes = new ArrayList<>();

        //Total URL
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setName("discoverySource");
        attribute.setUuid("000043aa-6022-11ed-9b6a-0242ac120002");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setType(AttributeType.META);
        attribute.setDescription("Source from where the certificate is discovered");

        MetadataAttributeProperties attributeProperties = new MetadataAttributeProperties();
        attributeProperties.setLabel("Discovery Source");
        attributeProperties.setVisible(true);
        attributeProperties.setGlobal(true);

        attribute.setProperties(attributeProperties);
        attribute.setContent(List.of(new StringAttributeContentV2(discoverySource, discoverySource)));
        attributes.add(attribute);

        return attributes;
    }

    private List<MetadataAttributeV2> getReasonMeta(String exception) {
        List<MetadataAttributeV2> attributes = new ArrayList<>();

        //Exception Reason
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setName("reason");
        attribute.setUuid("abc0412a-60f6-11ed-9b6a-0242ac120002");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setType(AttributeType.META);
        attribute.setDescription("Reason for failure");

        MetadataAttributeProperties attributeProperties = new MetadataAttributeProperties();
        attributeProperties.setLabel("Reason");
        attributeProperties.setVisible(true);

        attribute.setProperties(attributeProperties);
        attribute.setContent(List.of(new StringAttributeContentV2(exception)));
        attributes.add(attribute);

        return attributes;
    }

}