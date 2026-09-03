package com.otilm.discovery.ip.service;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.connector.discovery.DiscoveryRequestDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.discovery.ip.dao.DiscoveryHistory;
import com.otilm.discovery.ip.service.impl.AttributeServiceImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.awaitility.Awaitility.await;

/**
 * The scan waits for each batch before submitting the next, and that wait is the only thing bounding work in flight.
 * Since targets are enumerated by index rather than materialised, nothing else would stop a large range from
 * submitting millions of tasks at once. This test makes the bound explicit.
 */
@SpringBootTest
class DiscoveryScanBoundednessTest {

    private static final int PARALLEL_EXECUTIONS = 5;
    private static final int TARGET_COUNT = 60;

    @Autowired
    private DiscoveryService discoveryService;

    @Autowired
    private DiscoveryHistoryService discoveryHistoryService;

    @Autowired
    private CountingConnectionService connectionService;

    @TestConfiguration
    static class StubConfig {
        @Bean
        @Primary
        CountingConnectionService countingConnectionService() {
            return new CountingConnectionService();
        }
    }

    /** Records peak in-flight probes, then fails: no certificate is the point. */
    static class CountingConnectionService implements ConnectionService {

        private final AtomicInteger inFlight = new AtomicInteger();
        private final AtomicInteger peakInFlight = new AtomicInteger();
        private final AtomicInteger completed = new AtomicInteger();

        @Override
        public com.otilm.discovery.ip.dto.ConnectionResponse getCertificates(String url) throws IOException {
            int now = inFlight.incrementAndGet();
            peakInFlight.accumulateAndGet(now, Math::max);
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                inFlight.decrementAndGet();
                completed.incrementAndGet();
            }
            throw new IOException("stub: no endpoint");
        }
    }

    @Test
    void keepsInFlightProbesWithinTheConfiguredParallelism() throws Exception {
        DiscoveryRequestDto request = scanRequest("boundedness-" + UUID.randomUUID());
        DiscoveryHistory history = discoveryHistoryService.addHistory(request);

        discoveryService.discoverCertificate(request, history);

        await()
                .atMost(Duration.ofSeconds(30))
                .until(() -> discoveryHistoryService
                        .getHistoryByUuid(history.getUuid())
                        .getStatus() != DiscoveryStatus.IN_PROGRESS);

        Assertions.assertEquals(TARGET_COUNT, connectionService.completed.get(), "every target should be probed");
        Assertions
                .assertTrue(connectionService.peakInFlight.get() <= PARALLEL_EXECUTIONS,
                        "peak in-flight probes was " + connectionService.peakInFlight.get() + ", above the configured "
                                + PARALLEL_EXECUTIONS);
    }

    private DiscoveryRequestDto scanRequest(String name) {
        DiscoveryRequestDto request = new DiscoveryRequestDto();
        request.setName(name);
        request.setKind("IP-Hostname");
        request
                .setAttributes(List
                        .<RequestAttribute>of(
                                attribute("1b6c48ad-c1c7-4c82-91ef-3b61bc9f52ac",
                                        AttributeServiceImpl.DATA_ATTRIBUTE_DISCOVERY_IP_NAME,
                                        AttributeContentType.STRING, new StringAttributeContentV2("127.0.0.1")),
                                attribute("a9091e0d-f9b9-4514-b275-1dd52aa870ec",
                                        AttributeServiceImpl.DATA_ATTRIBUTE_PORT_NAME, AttributeContentType.STRING,
                                        new StringAttributeContentV2("1-" + TARGET_COUNT)),
                                attribute("3c70d728-e8c3-40f9-b9b2-5d7256f89ef0",
                                        AttributeServiceImpl.DATA_ATTRIBUTE_ALL_PORTS_NAME,
                                        AttributeContentType.BOOLEAN, new BooleanAttributeContentV2(false)),
                                attribute("1517c7a5-34cb-4f94-a0aa-1e9fe5b5b277",
                                        AttributeServiceImpl.DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_NAME,
                                        AttributeContentType.INTEGER,
                                        new IntegerAttributeContentV2(PARALLEL_EXECUTIONS))));
        return request;
    }

    private static RequestAttributeV2 attribute(String uuid, String name, AttributeContentType type,
            BaseAttributeContentV2<?> content) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setUuid(UUID.fromString(uuid));
        attribute.setName(name);
        attribute.setContentType(type);
        attribute.setContent(List.of(content));
        return attribute;
    }
}
