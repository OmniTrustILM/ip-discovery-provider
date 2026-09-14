package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDrainRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.api.v2.NodeAtCapacityException;
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
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

/**
 * Who gets admitted to this node, and what a refusal means. Both refusals used to be the same boolean, and the two
 * mean opposite things: a repeat must be answered idempotently, a full node must not be.
 */
class RunAdmissionTest {

    private static final String HOSTS = "10.0.0.1-10.0.0.8";

    private final RunRegistry registry = new RunRegistry();
    private final CountingProbes probes = new CountingProbes();

    private static DiscoveryAttributeServiceImpl attributeService() {
        Properties properties = new Properties();
        properties.setProperty("version", "2.20.0-SNAPSHOT");
        return new DiscoveryAttributeServiceImpl(new BuildProperties(properties));
    }

    /** Every probe fails, so no items are produced and the buffer stays empty; only the scan itself is counted. */
    private static class CountingProbes implements ConnectionService {
        private final AtomicInteger probed = new AtomicInteger();

        @Override
        public ConnectionResponse getCertificates(String url) throws IOException {
            probed.incrementAndGet();
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

    private static List<RequestAttribute> scanAttributes(String hosts) {
        return List
                .of(listAttribute(DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_HOSTS_UUID,
                        DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_HOSTS_NAME, hosts),
                        listAttribute(DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PORTS_UUID,
                                DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PORTS_NAME, "443"));
    }

    private static DiscoveryInitiateRequestDto initiateRequest(UUID runId, String hosts) {
        DiscoveryInitiateRequestDto request = new DiscoveryInitiateRequestDto();
        request.setRunId(runId);
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setAttributes(scanAttributes(hosts));
        return request;
    }

    private static RunHandle stoppedCheckpoint() {
        return new RunHandle(RunHandle.RunState.STOPPED, 4L, 40L, TargetEnumeration.of(HOSTS, "443", false).digest(),
                4L, 0L, Map.of());
    }

    private static DiscoveryRunRequestDto runRequest(UUID runId, List<MetadataAttribute> meta) {
        DiscoveryRunRequestDto request = new DiscoveryRunRequestDto();
        request.setRunId(runId);
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setAttributes(scanAttributes(HOSTS));
        request.setCheckpoint(meta);
        return request;
    }

    private static DiscoveryDrainRequestDto drainRequest(UUID runId, List<MetadataAttribute> meta, long after) {
        DiscoveryDrainRequestDto request = new DiscoveryDrainRequestDto();
        request.setRunId(runId);
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setAttributes(scanAttributes(HOSTS));
        request.setCheckpoint(meta);
        request.setAfterSequence(after);
        return request;
    }

    private DiscoveryRunService serviceWith(BufferBudget budget) {
        return new DiscoveryRunService(registry, budget, attributeService(), probes);
    }

    private void fill(DiscoveryRunService service, int runs) {
        for (int i = 0; i < runs; i++) {
            service.initiate(initiateRequest(UUID.randomUUID(), "10.0.0." + (100 + i)));
        }
    }

    // --- M2: one resume wins ---

    /**
     * Two resumes can both read STOPPED. Both starting a scan puts two sequencers on one run issuing the same
     * numbers, lets the cursor move backwards as their chunk commits interleave, and leaves the loser buffer
     * charging the budget with items nothing will ever serve.
     */
    @Test
    void onlyOneOfSeveralConcurrentResumesStartsAScan() throws Exception {
        UUID runId = UUID.randomUUID();
        DiscoveryRunService service = serviceWith(new BufferBudget(4, 100_000, 1L << 30, 1L << 31, 30_000));
        service.status(runRequest(runId, stoppedCheckpoint().encode()));
        Assertions.assertEquals(DiscoveryRunState.STOPPED, registry.state(runId).orElseThrow());

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Callable<Object>> resumes = IntStream
                    .range(0, 8)
                    .<Callable<Object>>mapToObj(i -> () -> service.resume(runRequest(runId, null)))
                    .toList();
            executor.invokeAll(resumes);
        }

        Awaitility
                .await()
                .atMost(Duration.ofSeconds(30))
                .until(() -> registry.state(runId).orElseThrow() != DiscoveryRunState.RUNNING);

        // Four targets remain after the checkpoint's cursor. A second scan would probe them again.
        Assertions
                .assertEquals(4, probes.probed.get(),
                        "a second scan would re-probe the remaining targets and renumber what the first produced");
        Assertions.assertEquals(8L, registry.find(runId).orElseThrow().cursorIndex());
    }

    /** A resume that fails validation must leave the run resumable, not marked running with nothing scanning it. */
    @Test
    void aRefusedResumeLeavesTheRunStopped() {
        UUID runId = UUID.randomUUID();
        DiscoveryRunService service = serviceWith(new BufferBudget(4, 100_000, 1L << 30, 1L << 31, 30_000));
        service.status(runRequest(runId, stoppedCheckpoint().encode()));

        DiscoveryRunRequestDto wrongEnumeration = runRequest(runId, null);
        wrongEnumeration.setAttributes(scanAttributes("10.0.0.1-10.0.0.9"));

        Assertions.assertThrows(RuntimeException.class, () -> service.resume(wrongEnumeration));
        Assertions
                .assertEquals(DiscoveryRunState.STOPPED, registry.state(runId).orElseThrow(),
                        "a corrected retry has to be able to resume it");
    }

    // --- M5: a stopped run is not competing for scanning capacity ---

    /**
     * Core drives a stopped run for its whole resume window. Refusing those ticks because the node is busy scanning
     * something else kills a healthy, resumable run: Core reads enough refusals as the run being unrecoverable.
     */
    @Test
    void aFullNodeStillAnswersForAStoppedRunItMustRebuild() {
        BufferBudget budget = new BufferBudget(2, 100_000, 1L << 30, 1L << 31, 30_000);
        DiscoveryRunService service = serviceWith(budget);
        fill(service, 2);
        Assertions.assertEquals(2, budget.openRuns(), "the node is at its run cap");

        UUID stopped = UUID.randomUUID();
        List<MetadataAttribute> checkpoint = stoppedCheckpoint().encode();

        Assertions.assertDoesNotThrow(() -> service.status(runRequest(stopped, checkpoint)));
        Assertions.assertDoesNotThrow(() -> service.results(drainRequest(stopped, checkpoint, 40)));
        Assertions.assertEquals(2, budget.openRuns(), "a rebuilt run holds nothing, so it takes no slot");
    }

    /** Production is what needs the budget, so a resume on a full node is refused — and refused retryably. */
    @Test
    void aFullNodeRefusesToResumeTheStoppedRunItCanStillAnswerFor() {
        BufferBudget budget = new BufferBudget(2, 100_000, 1L << 30, 1L << 31, 30_000);
        DiscoveryRunService service = serviceWith(budget);
        fill(service, 2);

        UUID stopped = UUID.randomUUID();
        service.status(runRequest(stopped, stoppedCheckpoint().encode()));

        Assertions.assertThrows(NodeAtCapacityException.class, () -> service.resume(runRequest(stopped, null)));
        Assertions
                .assertEquals(DiscoveryRunState.STOPPED, registry.state(stopped).orElseThrow(),
                        "the run stays resumable for when the node has room");
    }

    // --- M1: the two refusals mean different things ---

    @Test
    void tellsARepeatFromAFullNode() {
        BufferBudget budget = new BufferBudget(1, 100_000, 1L << 30, 1L << 31, 30_000);
        UUID held = UUID.randomUUID();

        Assertions.assertEquals(BufferBudget.Admission.ADMITTED, budget.admit(held));
        Assertions
                .assertEquals(BufferBudget.Admission.ALREADY_HELD, budget.admit(held),
                        "an already-held run is a repeat, whatever the node's occupancy");
        Assertions.assertEquals(BufferBudget.Admission.AT_CAPACITY, budget.admit(UUID.randomUUID()));
    }

    /**
     * The contract requires a repeated initiate to be answered idempotently. Conflating the two refusals answered a
     * concurrent duplicate with a 503 claiming the node was full, which is both wrong and misleading.
     */
    @Test
    void answersEveryOneOfSeveralConcurrentInitiatesIdempotently() throws Exception {
        UUID runId = UUID.randomUUID();
        DiscoveryRunService service = serviceWith(new BufferBudget(4, 100_000, 1L << 30, 1L << 31, 30_000));

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Callable<Object>> initiates = IntStream
                    .range(0, 8)
                    .<Callable<Object>>mapToObj(i -> () -> service.initiate(initiateRequest(runId, HOSTS)))
                    .toList();
            for (var result : executor.invokeAll(initiates)) {
                Assertions
                        .assertDoesNotThrow(() -> result.get(),
                                "no duplicate may be answered as a full node");
            }
        }

        Awaitility
                .await()
                .atMost(Duration.ofSeconds(30))
                .until(() -> registry.state(runId).orElseThrow() != DiscoveryRunState.RUNNING);

        Assertions.assertEquals(8, probes.probed.get(), "exactly one scan of the eight targets");
    }
}
