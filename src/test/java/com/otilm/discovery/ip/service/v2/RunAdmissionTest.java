package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDrainRequestDto;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStopResponseDto;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

/**
 * Who gets admitted to this node, and what a refusal means. The two refusals mean opposite things: a repeat must be
 * answered idempotently, a full node must not be.
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

    /**
     * Holds the first resume inside its validation: after it has claimed the run, before its scan starts. Whatever
     * reaches the run in that window is what the lifecycle lock exists for.
     */
    private static final class HoldsFirstResume extends DiscoveryAttributeServiceImpl {
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private final AtomicBoolean held = new AtomicBoolean();
        private final boolean refuseIt;

        HoldsFirstResume(boolean refuseIt) {
            super(buildProperties());
            this.refuseIt = refuseIt;
        }

        @Override
        public int readParallelExecutions(List<RequestAttribute> attributes) {
            if (held.compareAndSet(false, true)) {
                entered.countDown();
                try {
                    release.await(10, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                if (refuseIt) {
                    throw new ValidationException("the first resume is refused");
                }
            }
            return super.readParallelExecutions(attributes);
        }
    }

    private static BuildProperties buildProperties() {
        Properties properties = new Properties();
        properties.setProperty("version", "2.20.0-SNAPSHOT");
        return new BuildProperties(properties);
    }

    /** Parks every probe until a stop interrupts it, so a resumed scan is still running when the stop lands. */
    private static ConnectionService parkedProbes() {
        return url -> {
            try {
                Thread.sleep(Duration.ofSeconds(30));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            throw new IOException("interrupted");
        };
    }

    private DiscoveryRunService serviceWith(BufferBudget budget) {
        return new DiscoveryRunService(registry, budget, attributeService(), probes);
    }

    private void fill(DiscoveryRunService service, int runs) {
        for (int i = 0; i < runs; i++) {
            service.initiate(initiateRequest(UUID.randomUUID(), "10.0.0." + (100 + i)));
        }
    }

    // --- one resume wins ---

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
            for (var result : executor.invokeAll(resumes)) {
                Assertions.assertDoesNotThrow(() -> result.get(), "a losing resume is a no-op, not a failure");
            }
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

    /**
     * Two resumes can both pass Core's STOPPED check, and Core stores whichever answer it commits first as the run's
     * checkpoint. Answered before the first resume finishes, the duplicate hands back the STOPPED checkpoint it read
     * on arrival while the run is in fact scanning.
     */
    @Test
    void aDuplicateResumeAnswersWithWhatTheFirstLeft() throws Exception {
        UUID runId = UUID.randomUUID();
        HoldsFirstResume attributes = new HoldsFirstResume(false);
        DiscoveryRunService service = new DiscoveryRunService(registry,
                new BufferBudget(4, 100_000, 1L << 30, 1L << 31, 30_000), attributes, probes);
        service.status(runRequest(runId, stoppedCheckpoint().encode()));

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<DiscoveryInitiateResponseDto> first = executor.submit(() -> service.resume(runRequest(runId, null)));
            Assertions.assertTrue(attributes.entered.await(10, TimeUnit.SECONDS));
            Future<DiscoveryInitiateResponseDto> duplicate =
                    executor.submit(() -> service.resume(runRequest(runId, null)));

            Assertions
                    .assertThrows(TimeoutException.class, () -> duplicate.get(300, TimeUnit.MILLISECONDS),
                            "the duplicate must wait for the first resume rather than answer ahead of it");
            attributes.release.countDown();

            first.get(10, TimeUnit.SECONDS);
            RunHandle answered = RunHandle.from(duplicate.get(10, TimeUnit.SECONDS).getCheckpoint()).orElseThrow();
            Assertions.assertEquals(RunHandle.RunState.RUNNING, answered.state());
        }
    }

    /**
     * A duplicate that answered success while the first resume went on to fail would leave Core recording a running
     * run that nothing is scanning. Waiting instead, it finds the run put back to STOPPED and resumes it itself.
     */
    @Test
    void aDuplicateResumeTakesOverWhenTheFirstIsRefused() throws Exception {
        UUID runId = UUID.randomUUID();
        HoldsFirstResume attributes = new HoldsFirstResume(true);
        DiscoveryRunService service = new DiscoveryRunService(registry,
                new BufferBudget(4, 100_000, 1L << 30, 1L << 31, 30_000), attributes, probes);
        service.status(runRequest(runId, stoppedCheckpoint().encode()));

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<DiscoveryInitiateResponseDto> first = executor.submit(() -> service.resume(runRequest(runId, null)));
            Assertions.assertTrue(attributes.entered.await(10, TimeUnit.SECONDS));
            Future<DiscoveryInitiateResponseDto> duplicate =
                    executor.submit(() -> service.resume(runRequest(runId, null)));
            Assertions.assertThrows(TimeoutException.class, () -> duplicate.get(300, TimeUnit.MILLISECONDS));
            attributes.release.countDown();

            Assertions.assertThrows(java.util.concurrent.ExecutionException.class, () -> first.get(10, TimeUnit.SECONDS));
            duplicate.get(10, TimeUnit.SECONDS);
        }

        Awaitility.await().atMost(Duration.ofSeconds(10)).until(() -> probes.probed.get() == 4);
        Assertions.assertEquals(8L, registry.find(runId).orElseThrow().cursorIndex(), "the duplicate's scan finished");
    }

    /**
     * A stop landing while a resume is still validating would checkpoint a run that nothing is scanning yet, and the
     * resume would then start a scan under a run the stop has just reported stopped. Waiting, the stop finds the scan
     * the resume started and stops that.
     */
    @Test
    void aStopArrivingMidResumeStopsTheScanThatResumeStarts() throws Exception {
        UUID runId = UUID.randomUUID();
        HoldsFirstResume attributes = new HoldsFirstResume(false);
        DiscoveryRunService service = new DiscoveryRunService(registry,
                new BufferBudget(4, 100_000, 1L << 30, 1L << 31, 30_000), attributes, parkedProbes());
        service.status(runRequest(runId, stoppedCheckpoint().encode()));

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<DiscoveryInitiateResponseDto> resume = executor.submit(() -> service.resume(runRequest(runId, null)));
            Assertions.assertTrue(attributes.entered.await(10, TimeUnit.SECONDS));
            Future<DiscoveryStopResponseDto> stop = executor.submit(() -> service.stop(runRequest(runId, null)));

            Assertions
                    .assertThrows(TimeoutException.class, () -> stop.get(300, TimeUnit.MILLISECONDS),
                            "the stop must wait for the resume to finish rather than land inside it");
            attributes.release.countDown();

            resume.get(10, TimeUnit.SECONDS);
            RunHandle stopped = RunHandle.from(stop.get(20, TimeUnit.SECONDS).getCheckpoint()).orElseThrow();
            Assertions.assertEquals(RunHandle.RunState.STOPPED, stopped.state());
        }

        Assertions.assertEquals(DiscoveryRunState.STOPPED, registry.state(runId).orElseThrow());
        Assertions
                .assertTrue(registry.runner(runId).orElseThrow().isStopping(),
                        "the scan the resume started is the one the stop must reach");
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

    // --- a stopped run is not competing for scanning capacity ---

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

        var resume = runRequest(stopped, null);
        Assertions.assertThrows(NodeAtCapacityException.class, () -> service.resume(resume));
        Assertions
                .assertEquals(DiscoveryRunState.STOPPED, registry.state(stopped).orElseThrow(),
                        "the run stays resumable for when the node has room");
    }

    // --- the two refusals mean different things ---

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
     * A slot left open with no run behind it is reclaimed rather than answered from. Answering from it would report a
     * run that nothing is scanning, and Core's first drain of it would be a 404.
     */
    @Test
    void reclaimsASlotThatOutlivedItsRun() {
        BufferBudget budget = new BufferBudget(4, 100_000, 1L << 30, 1L << 31, 30_000);
        DiscoveryRunService service = serviceWith(budget);
        UUID runId = UUID.randomUUID();
        budget.admit(runId);

        service.initiate(initiateRequest(runId, HOSTS));

        Assertions.assertTrue(registry.find(runId).isPresent(), "the run must actually be started");
        Assertions.assertEquals(1, budget.openRuns(), "the stale slot is reused, not doubled");
        Awaitility.await().atMost(Duration.ofSeconds(10)).until(() -> probes.probed.get() == 8);
    }

    /**
     * The contract requires a repeated initiate to be answered idempotently. A concurrent duplicate is a repeat, and
     * answering it with a 503 would claim a full node that is not.
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
