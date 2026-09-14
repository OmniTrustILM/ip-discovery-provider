package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryProgressDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.dto.ConnectionResponse;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.service.v2.impl.DiscoveryAttributeServiceImpl;
import com.otilm.discovery.ip.util.TargetEnumeration;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.info.BuildProperties;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Progress has to move between chunk boundaries.
 *
 * <p>
 * The checkpoint advances only at a boundary, and must — counting per target would double-count the interrupted
 * chunk when a resumed run scans it again, letting a stop inflate its own run's completion. But a wide sweep at low
 * parallelism puts those boundaries minutes apart: a {@code /20} at the default parallelism of one is roughly twenty
 * minutes and sixteen boundaries, sampled by Core every five minutes. Reporting the checkpoint alone leaves a working
 * run looking frozen.
 */
class LiveProgressTest {

    /** One chunk's worth and no more, so nothing commits until the scan ends. */
    private static final String HOSTS = "10.0.0.1-10.0.0.12";

    private final RunRegistry registry = new RunRegistry();
    private final BufferBudget budget = new BufferBudget(4, 100_000, 1L << 30, 1L << 31, 30_000);

    private static DiscoveryAttributeServiceImpl attributeService() {
        Properties properties = new Properties();
        properties.setProperty("version", "2.20.0-SNAPSHOT");
        return new DiscoveryAttributeServiceImpl(new BuildProperties(properties));
    }

    /** Fails every probe, and holds the scan open once it has finished a nominated number of them. */
    private static class HoldsAfter implements ConnectionService {
        private final int holdAfter;
        private final AtomicInteger probed = new AtomicInteger();
        private final CountDownLatch reached = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);

        HoldsAfter(int holdAfter) {
            this.holdAfter = holdAfter;
        }

        @Override
        public ConnectionResponse getCertificates(String url) throws IOException {
            if (probed.incrementAndGet() > holdAfter) {
                reached.countDown();
                try {
                    release.await(30, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            throw new IOException("nothing listening");
        }
    }

    private static RequestAttribute listAttribute(String uuid, String name, String... values) {
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(UUID.fromString(uuid));
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute
                .setContent(Arrays.stream(values).<BaseAttributeContentV3<?>>map(StringAttributeContentV3::new)
                        .toList());
        return attribute;
    }

    private static List<RequestAttribute> scanAttributes() {
        return List
                .of(listAttribute(DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_HOSTS_UUID,
                        DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_HOSTS_NAME, HOSTS),
                        listAttribute(DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PORTS_UUID,
                                DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PORTS_NAME, "443"));
    }

    private static DiscoveryInitiateRequestDto initiateRequest(UUID runId) {
        DiscoveryInitiateRequestDto request = new DiscoveryInitiateRequestDto();
        request.setRunId(runId);
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setAttributes(scanAttributes());
        return request;
    }

    private static DiscoveryRunRequestDto runRequest(UUID runId) {
        DiscoveryRunRequestDto request = new DiscoveryRunRequestDto();
        request.setRunId(runId);
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setAttributes(scanAttributes());
        return request;
    }

    @Test
    void reportsWorkDoneBeforeTheChunkBoundaryIsReached() throws Exception {
        UUID runId = UUID.randomUUID();
        HoldsAfter probes = new HoldsAfter(5);
        DiscoveryRunService service = new DiscoveryRunService(registry, budget, attributeService(), probes);

        service.initiate(initiateRequest(runId));
        Assertions.assertTrue(probes.reached.await(20, TimeUnit.SECONDS), "the scan never reached the hold");

        Awaitility
                .await()
                .atMost(Duration.ofSeconds(10))
                .until(() -> service.status(runRequest(runId)).getProgress().getTargetsProcessed() >= 5L);

        DiscoveryProgressDto progress = service.status(runRequest(runId)).getProgress();

        Assertions
                .assertEquals(0L, registry.find(runId).orElseThrow().targetsProcessed(),
                        "the checkpoint must still be at the last boundary, which here is the start");
        Assertions
                .assertTrue(progress.getTargetsProcessed() >= 5L,
                        "progress should report the work in flight, was " + progress.getTargetsProcessed());
        Assertions
                .assertEquals(progress.getTargetsProcessed(), progress.getTargetsFailed(),
                        "every probe failed, and failures are counted within processed");
        Assertions.assertEquals(12L, progress.getTargetsTotal());

        probes.release.countDown();
        Awaitility
                .await()
                .atMost(Duration.ofSeconds(20))
                .until(() -> registry.state(runId).orElseThrow() != DiscoveryRunState.RUNNING);
    }

    /**
     * The in-flight figure is cleared as the chunk is absorbed into the checkpoint, never after. Clearing afterwards
     * would let both sources count the same chunk and report more targets than the run has.
     */
    @Test
    void neverReportsMoreTargetsThanTheRunHas() {
        UUID runId = UUID.randomUUID();
        DiscoveryRunService service = new DiscoveryRunService(registry, budget, attributeService(), url -> {
            throw new IOException("nothing listening");
        });

        service.initiate(initiateRequest(runId));

        long total = TargetEnumeration.of(HOSTS, "443", false).size();
        // Sampled throughout the run, which is when the two sources could overlap.
        for (int i = 0; i < 200; i++) {
            DiscoveryProgressDto progress = service.status(runRequest(runId)).getProgress();
            Assertions
                    .assertTrue(progress.getTargetsProcessed() <= total,
                            "reported " + progress.getTargetsProcessed() + " of " + total + " targets");
            Assertions
                    .assertTrue(progress.getTargetsFailed() <= progress.getTargetsProcessed(),
                            "failures must stay within processed");
        }

        Awaitility
                .await()
                .atMost(Duration.ofSeconds(20))
                .until(() -> registry.state(runId).orElseThrow() != DiscoveryRunState.RUNNING);

        Assertions
                .assertEquals(total, service.status(runRequest(runId)).getProgress().getTargetsProcessed(),
                        "a finished run reports every target exactly once");
    }

    /** A stopped run reports its checkpoint alone: the interrupted chunk is work it is about to redo. */
    @Test
    void stopsCountingTheChunkItAbandons() throws Exception {
        UUID runId = UUID.randomUUID();
        HoldsAfter probes = new HoldsAfter(5);
        DiscoveryRunService service = new DiscoveryRunService(registry, budget, attributeService(), probes);

        service.initiate(initiateRequest(runId));
        Assertions.assertTrue(probes.reached.await(20, TimeUnit.SECONDS));
        Awaitility
                .await()
                .atMost(Duration.ofSeconds(10))
                .until(() -> service.status(runRequest(runId)).getProgress().getTargetsProcessed() >= 5L);

        probes.release.countDown();
        service.stop(runRequest(runId));

        DiscoveryProgressDto progress = service.status(runRequest(runId)).getProgress();
        Assertions
                .assertEquals(registry.find(runId).orElseThrow().targetsProcessed(), progress.getTargetsProcessed(),
                        "a stopped run reports exactly what its checkpoint holds");
    }
}
