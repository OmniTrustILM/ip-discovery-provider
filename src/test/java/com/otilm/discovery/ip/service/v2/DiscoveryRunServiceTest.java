package com.otilm.discovery.ip.service.v2;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDrainRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.api.v2.NodeAtCapacityException;
import com.otilm.discovery.ip.api.v2.UnknownRunException;
import com.otilm.discovery.ip.dto.ConnectionResponse;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.service.v2.impl.DiscoveryAttributeServiceImpl;
import org.awaitility.Awaitility;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.info.BuildProperties;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

class DiscoveryRunServiceTest {

    private static X509Certificate certificate;

    private final RunRegistry registry = new RunRegistry();
    private final BufferBudget budget = new BufferBudget(2, 100_000, 1L << 30, 1L << 31, 30_000);
    private final CountingProbes probes = new CountingProbes();
    private final DiscoveryRunService service =
            new DiscoveryRunService(registry, budget, attributeService(), probes);

    @BeforeAll
    static void mintCertificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        X500Principal subject = new X500Principal("CN=run-service-test");
        certificate = new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
                        Date.from(Instant.now().minus(Duration.ofDays(1))),
                        Date.from(Instant.now().plus(Duration.ofDays(1))), subject, pair.getPublic())
                                .build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())));
    }

    private static DiscoveryAttributeServiceImpl attributeService() {
        Properties properties = new Properties();
        properties.setProperty("version", "2.20.0-SNAPSHOT");
        return new DiscoveryAttributeServiceImpl(new BuildProperties(properties));
    }

    private static class CountingProbes implements ConnectionService {
        private final AtomicInteger probed = new AtomicInteger();

        @Override
        public ConnectionResponse getCertificates(String url) throws IOException {
            probed.incrementAndGet();
            return new ConnectionResponse("TLS_AES_256_GCM_SHA384", new X509Certificate[] {certificate});
        }
    }

    private static RequestAttribute listAttribute(String uuid, String name, String... values) {
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(UUID.fromString(uuid));
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute
                .setContent(java.util.Arrays
                        .stream(values)
                        .<BaseAttributeContentV3<?>>map(StringAttributeContentV3::new)
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

    private static DiscoveryRunRequestDto runRequest(UUID runId) {
        DiscoveryRunRequestDto request = new DiscoveryRunRequestDto();
        request.setRunId(runId);
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setAttributes(scanAttributes("10.0.0.1-10.0.0.4"));
        return request;
    }

    private void awaitCompletion(UUID runId) {
        Awaitility
                .await()
                .atMost(Duration.ofSeconds(20))
                .until(() -> registry.state(runId).orElse(DiscoveryRunState.RUNNING) != DiscoveryRunState.RUNNING);
    }

    // --- initiate ---

    @Test
    void startsAScanAndAnswersWithItsCheckpoint() {
        UUID runId = UUID.randomUUID();

        DiscoveryInitiateResponseDto response = service.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.4"));

        Assertions.assertEquals(Boolean.TRUE, response.getStoppable());
        RunHandle handle = RunHandle.from(response.getCheckpoint()).orElseThrow();
        Assertions.assertEquals(RunHandle.RunState.RUNNING, handle.state());
        Assertions.assertEquals(0L, handle.cursorIndex());

        awaitCompletion(runId);
        Assertions.assertEquals(DiscoveryRunState.COMPLETED, registry.state(runId).orElseThrow());
        Assertions.assertEquals(4, probes.probed.get());
    }

    /**
     * The contract requires the repeat to be answered idempotently, and it must not start a second scan: that would
     * renumber from 1 and Core's cursor filter would drop every re-emitted item without reporting anything wrong.
     */
    @Test
    void answersARepeatedInitiateWithoutStartingASecondScan() {
        UUID runId = UUID.randomUUID();
        service.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.4"));
        awaitCompletion(runId);
        int afterFirst = probes.probed.get();
        long sequenceAfterFirst = registry.buffer(runId).orElseThrow().highestSequence();

        DiscoveryInitiateResponseDto repeat = service.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.4"));

        Assertions.assertEquals(afterFirst, probes.probed.get(), "a repeat must not rescan");
        Assertions
                .assertEquals(sequenceAfterFirst, registry.buffer(runId).orElseThrow().highestSequence(),
                        "a repeat must not reseed the sequence counter");
        Assertions.assertNotNull(RunHandle.from(repeat.getCheckpoint()).orElseThrow());
    }

    /**
     * {@code resources} is read from the request. Inferring it from {@code resourceAttributes} would silently narrow
     * the run, because that map omits any resource with no attributes of its own — which here is both of them.
     */
    @Test
    void refusesARunThatNamesNoResources() {
        DiscoveryInitiateRequestDto request = initiateRequest(UUID.randomUUID(), "10.0.0.1");
        request.setResources(List.of());

        Assertions.assertThrows(ValidationException.class, () -> service.initiate(request));
    }

    @Test
    void refusesAResourceItDoesNotDiscover() {
        DiscoveryInitiateRequestDto request = initiateRequest(UUID.randomUUID(), "10.0.0.1");
        request.setResources(List.of(Resource.SECRET));

        ValidationException thrown = Assertions.assertThrows(ValidationException.class, () -> service.initiate(request));
        Assertions.assertTrue(thrown.getMessage().contains("secrets"), thrown.getMessage());
    }

    @Test
    void refusesARunWhenTheNodeIsFull() {
        service.initiate(initiateRequest(UUID.randomUUID(), "10.0.0.1"));
        service.initiate(initiateRequest(UUID.randomUUID(), "10.0.0.2"));

        Assertions
                .assertThrows(NodeAtCapacityException.class,
                        () -> service.initiate(initiateRequest(UUID.randomUUID(), "10.0.0.3")));
    }

    @Test
    void rejectsAMalformedHostBeforeStartingAnything() {
        DiscoveryInitiateRequestDto request = initiateRequest(UUID.randomUUID(), "10.0.0.999");

        Assertions.assertThrows(ValidationException.class, () -> service.initiate(request));
        Assertions.assertEquals(0, budget.openRuns(), "a refused run must not hold a slot");
    }

    // --- status, results ---

    @Test
    void reportsTheStateAndTheHighestSequence() {
        UUID runId = UUID.randomUUID();
        service.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.4"));
        awaitCompletion(runId);

        var status = service.status(runRequest(runId));

        Assertions.assertEquals(DiscoveryRunState.COMPLETED, status.getState());
        Assertions.assertEquals(4L, status.getHighestSequence());
    }

    @Test
    void servesItemsAfterTheCursorAndDropsWhatTheCursorAcknowledged() {
        UUID runId = UUID.randomUUID();
        service.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.4"));
        awaitCompletion(runId);

        DiscoveryDrainRequestDto drain = new DiscoveryDrainRequestDto();
        drain.setRunId(runId);
        drain.setResources(List.of(Resource.CERTIFICATE));
        drain.setAfterSequence(2);

        DiscoveryResultsResponseDto results = service.results(drain);

        Assertions.assertEquals(2, results.getItems().size());
        Assertions.assertEquals(4L, results.getHighestSequence());
        Assertions.assertEquals(Boolean.FALSE, results.getMore());
        Assertions.assertEquals(2, registry.buffer(runId).orElseThrow().held(), "the acknowledged items are gone");
    }

    /**
     * A drain arriving below the watermark is a redelivered or late request, not a defect. Serving it would be worse
     * than answering nothing: Core advances its cursor to the highest sequence in a page, so it would skip whatever
     * lay in between.
     */
    @Test
    void answersALateDrainWithAnEmptyPageRatherThanFailingTheRun() {
        UUID runId = UUID.randomUUID();
        service.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.4"));
        awaitCompletion(runId);

        DiscoveryDrainRequestDto ahead = new DiscoveryDrainRequestDto();
        ahead.setRunId(runId);
        ahead.setResources(List.of(Resource.CERTIFICATE));
        ahead.setAfterSequence(3);
        service.results(ahead);

        DiscoveryDrainRequestDto late = new DiscoveryDrainRequestDto();
        late.setRunId(runId);
        late.setResources(List.of(Resource.CERTIFICATE));
        late.setAfterSequence(1);

        DiscoveryResultsResponseDto results = service.results(late);

        Assertions.assertTrue(results.getItems().isEmpty());
        Assertions
                .assertEquals(4L, results.getHighestSequence(),
                        "the field is run-wide and never page-scoped, whatever this page could serve");
        Assertions.assertEquals(Boolean.TRUE, results.getMore(), "sequence 4 is still here");
    }

    // --- stop, resume, cancel ---

    /**
     * Core allows a stop while its own status is still IN_PROGRESS, which it stays through the tail drain after this
     * connector has reported the run complete. Relabelling then would tell Core a finished run is merely stopped,
     * and it would sit there until somebody resumed it. Stopping a run that is genuinely scanning is what
     * StopResumeSeamTest covers.
     */
    @Test
    void leavesARunThatHasAlreadyFinishedAlone() {
        UUID runId = UUID.randomUUID();
        service.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.4"));
        awaitCompletion(runId);

        var stopped = service.stop(runRequest(runId));

        Assertions
                .assertEquals(DiscoveryRunState.COMPLETED, registry.state(runId).orElseThrow(),
                        "a completed run must not be relabelled by a late stop");
        RunHandle handle = RunHandle.from(stopped.getCheckpoint()).orElseThrow();
        Assertions.assertEquals(4L, handle.sequenceHighWater(), "the checkpoint still describes what it produced");
    }

    @Test
    void resumeOfARunningRunIsANoOp() {
        UUID runId = UUID.randomUUID();
        service.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.4"));
        awaitCompletion(runId);
        service.stop(runRequest(runId));
        registry.setState(runId, DiscoveryRunState.RUNNING);
        int probedBefore = probes.probed.get();

        service.resume(runRequest(runId));

        Assertions.assertEquals(probedBefore, probes.probed.get(), "a resume of a running run must not rescan");
    }

    @Test
    void cancelForgetsTheRunAndALaterCallDoesNotFindIt() {
        UUID runId = UUID.randomUUID();
        service.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.4"));
        awaitCompletion(runId);

        service.cancel(runRequest(runId));

        Assertions.assertThrows(UnknownRunException.class, () -> service.status(runRequest(runId)));
        Assertions.assertThrows(UnknownRunException.class, () -> service.cancel(runRequest(runId)));
        Assertions.assertEquals(0, budget.openRuns(), "a cancelled run leaves nothing charged");
    }

    @Test
    void everyLifecycleCallOnAnUnknownRunSaysItIsNotTracked() {
        DiscoveryRunRequestDto unknown = runRequest(UUID.randomUUID());
        DiscoveryDrainRequestDto drain = new DiscoveryDrainRequestDto();
        drain.setRunId(unknown.getRunId());
        drain.setResources(List.of(Resource.CERTIFICATE));

        Assertions.assertThrows(UnknownRunException.class, () -> service.status(unknown));
        Assertions.assertThrows(UnknownRunException.class, () -> service.results(drain));
        Assertions.assertThrows(UnknownRunException.class, () -> service.stop(unknown));
        Assertions.assertThrows(UnknownRunException.class, () -> service.resume(unknown));
        Assertions.assertThrows(UnknownRunException.class, () -> service.cancel(unknown));
    }

    @Test
    void aLifecycleCallKeepsTheRunFromBeingAbandoned() {
        UUID runId = UUID.randomUUID();
        service.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.4"));
        awaitCompletion(runId);

        service.status(runRequest(runId));

        Assertions.assertEquals(List.of(), registry.abandonIdle(Duration.ofMinutes(30)));
    }

    // --- progress ---

    @Test
    void reportsWorkInTargetsAndYieldInItems() {
        UUID runId = UUID.randomUUID();
        service.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.4"));
        awaitCompletion(runId);

        var progress = service.status(runRequest(runId)).getProgress();

        Assertions.assertEquals(4L, progress.getTargetsTotal(), "the total is exact from initiate");
        Assertions.assertEquals(4L, progress.getTargetsProcessed());
        Assertions.assertEquals(0L, progress.getTargetsFailed());
        Assertions
                .assertEquals(4L, progress.getByResource().get(Resource.CERTIFICATE).getProduced(),
                        "yield is counted in items, which is a different unit from the work counters");
        Assertions
                .assertNull(progress.getByResource().get(Resource.CERTIFICATE).getTotalEstimate(),
                        "one target yields anywhere from nothing to a whole chain, so an estimate would be a guess");
    }

    /**
     * Failures are counted within processed rather than beside it. A sweep that reached every target and found
     * nothing listening is a complete run, not a degraded one, and must not read as stuck at less than 100 per cent.
     */
    @Test
    void anAllFailedSweepStillReachesEveryTarget() {
        UUID runId = UUID.randomUUID();
        DiscoveryRunService failing = new DiscoveryRunService(registry, budget, attributeService(), url -> {
            throw new IOException("nothing listening");
        });
        failing.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.4"));
        awaitCompletion(runId);

        var progress = failing.status(runRequest(runId)).getProgress();

        Assertions.assertEquals(progress.getTargetsTotal(), progress.getTargetsProcessed(), "the sweep is complete");
        Assertions.assertEquals(4L, progress.getTargetsFailed());
        Assertions.assertNull(progress.getByResource(), "a run that found nothing reports no per-resource yield");
        Assertions
                .assertEquals(DiscoveryRunState.COMPLETED, registry.state(runId).orElseThrow(),
                        "failing to reach a target does not degrade the run");
    }

    /**
     * Core keeps the last progress it was given and cannot tell an empty report from a missing one, so an all-null
     * object would overwrite a real measurement with silence.
     */
    @Test
    void omitsProgressEntirelyWhenThereIsNothingToReport() {
        UUID runId = UUID.randomUUID();
        registry.register(runId, RunHandle.initial("digest"));

        Assertions.assertNull(service.status(runRequest(runId)).getProgress());
    }

    /** A run parked on the buffer is diagnosable from Core; a healthy one carries no phase to keep. */
    @Test
    void namesThePhaseOnlyWhenItExplainsAStalledRun() {
        UUID runId = UUID.randomUUID();
        service.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.4"));
        awaitCompletion(runId);

        Assertions.assertNull(service.status(runRequest(runId)).getProgress().getPhase());
    }

    /**
     * The run has to end FAILED rather than COMPLETED. A completed run that quietly dropped most of its items is the
     * failure mode the whole buffer design exists to avoid.
     */
    @Test
    void aRunThatOutgrowsItsBufferEndsFailedRatherThanComplete() {
        UUID runId = UUID.randomUUID();
        BufferBudget tight = new BufferBudget(4, 1, 1L << 30, 1L << 31, 150);
        DiscoveryRunService starved = new DiscoveryRunService(registry, tight, attributeService(), probes);

        starved.initiate(initiateRequest(runId, "10.0.0.1-10.0.0.8"));
        Awaitility
                .await()
                .atMost(Duration.ofSeconds(30))
                .until(() -> registry.state(runId).orElseThrow() != DiscoveryRunState.RUNNING);

        Assertions.assertEquals(DiscoveryRunState.FAILED, registry.state(runId).orElseThrow());
    }
}
