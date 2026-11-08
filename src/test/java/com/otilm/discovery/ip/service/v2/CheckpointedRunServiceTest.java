package com.otilm.discovery.ip.service.v2;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDrainRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryProgressDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStatusResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStopResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryV2ScopedRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.api.v2.CheckpointLostException;
import com.otilm.discovery.ip.api.v2.ConnectorBusyException;
import com.otilm.discovery.ip.api.v2.RunPastPointOfNoReturnException;
import com.otilm.discovery.ip.api.v2.UnknownRunException;
import com.otilm.discovery.ip.dto.ConnectionResponse;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.service.v2.impl.DiscoveryAttributeServiceImpl;
import com.otilm.discovery.ip.util.TargetEnumeration;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.info.BuildProperties;

class CheckpointedRunServiceTest {

    private static final String HOSTS = "10.0.0.1-10.0.0.4";
    private static final TargetEnumeration TARGETS = TargetEnumeration.of(HOSTS, "443", false);
    private static final List<DiscoveryDeliveryMode> OFFER = List
            .of(DiscoveryDeliveryMode.CHECKPOINTED, DiscoveryDeliveryMode.BUFFERED);

    private static X509Certificate certificate;

    private final AbandonedProbes abandoned = new AbandonedProbes();
    private final AtomicInteger probed = new AtomicInteger();

    @BeforeAll
    static void mintCertificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair pair = generator.generateKeyPair();
        X500Principal subject = new X500Principal("CN=checkpointed-run-service-test");
        certificate = new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
                        Date.from(Instant.now().minus(Duration.ofDays(1))),
                        Date.from(Instant.now().plus(Duration.ofDays(1))), subject, pair.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())));
    }

    private CheckpointedRunService service(SliceSettings settings, ConnectionService probes) {
        return new CheckpointedRunService(new SliceScanner(new TargetProber(probes, abandoned), settings), settings,
                abandoned, attributeService());
    }

    private CheckpointedRunService service(ConnectionService probes) {
        return service(new SliceSettings(8_000, 32, 256, 10_000), probes);
    }

    /** Two certificates on every target. */
    private CheckpointedRunService service() {
        return service(url -> {
            probed.incrementAndGet();
            return chainOf(2);
        });
    }

    private static ConnectionResponse chainOf(int certificates) {
        X509Certificate[] chain = new X509Certificate[certificates];
        Arrays.fill(chain, certificate);
        return new ConnectionResponse("TLS_AES_256_GCM_SHA384", chain);
    }

    private static DiscoveryAttributeServiceImpl attributeService() {
        Properties properties = new Properties();
        properties.setProperty("version", "1.8.0-SNAPSHOT");
        return new DiscoveryAttributeServiceImpl(new BuildProperties(properties));
    }

    private static RequestAttribute listAttribute(String uuid, String name, String... values) {
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(UUID.fromString(uuid));
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute
                .setContent(
                        Arrays.stream(values).<BaseAttributeContentV3<?>>map(StringAttributeContentV3::new).toList());
        return attribute;
    }

    private static <T extends DiscoveryV2ScopedRequestDto> T scoped(T request, String hosts, RunHandle handle) {
        request.setRunId(UUID.randomUUID());
        request.setResources(List.of(Resource.CERTIFICATE));
        request
                .setAttributes(List
                        .of(listAttribute(DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_HOSTS_UUID,
                                DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_HOSTS_NAME, hosts),
                                listAttribute(DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PORTS_UUID,
                                        DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PORTS_NAME, "443")));
        request.setDeliveryModes(OFFER);
        request.setCheckpoint(handle == null ? null : handle.encode());
        return request;
    }

    private static DiscoveryInitiateRequestDto initiate() {
        return scoped(new DiscoveryInitiateRequestDto(), HOSTS, null);
    }

    private static DiscoveryRunRequestDto run(RunHandle handle) {
        return scoped(new DiscoveryRunRequestDto(), HOSTS, handle);
    }

    private static DiscoveryDrainRequestDto drain(RunHandle handle, long afterSequence) {
        DiscoveryDrainRequestDto request = scoped(new DiscoveryDrainRequestDto(), HOSTS, handle);
        request.setAfterSequence(afterSequence);
        request.setMaxItems(500);
        request.setMaxBytes(DiscoveryDrainRequestDto.MAX_BYTES_CAP);
        return request;
    }

    private static RunHandle at(long cursor, long highWater) {
        return new RunHandle(RunHandle.RunState.RUNNING, cursor, highWater, TARGETS.digest(), cursor, 0L, 0L,
                Map.of(Resource.CERTIFICATE.getCode(), highWater), Map.of());
    }

    private static RunHandle checkpointOf(List<MetadataAttribute> checkpoint) {
        return RunHandle.from(checkpoint).orElseThrow();
    }

    // --- initiate ---

    /** Nothing starts on initiate: the first results call scans the first slice. */
    @Test
    void initiateAnswersTheInitialCheckpointAndChoosesCheckpointed() {
        DiscoveryInitiateResponseDto response = service().initiate(initiate());

        Assertions.assertEquals(RunHandle.initial(TARGETS.digest()), checkpointOf(response.getCheckpoint()));
        Assertions.assertEquals(DiscoveryDeliveryMode.CHECKPOINTED, response.getDeliveryMode());
        Assertions.assertTrue(response.getStoppable());
        Assertions.assertEquals(0, probed.get());
    }

    @Test
    void initiateWithoutCheckpointedOnOfferIsRefused() {
        DiscoveryInitiateRequestDto buffered = initiate();
        buffered.setDeliveryModes(List.of(DiscoveryDeliveryMode.BUFFERED));
        DiscoveryInitiateRequestDto olderCore = initiate();
        olderCore.setDeliveryModes(null);
        CheckpointedRunService service = service();

        ValidationException refused = Assertions
                .assertThrows(ValidationException.class, () -> service.initiate(buffered));
        Assertions.assertTrue(refused.getMessage().contains("2.21.0"), refused.getMessage());
        Assertions.assertThrows(ValidationException.class, () -> service.initiate(olderCore));
    }

    @Test
    void initiateRefusesAResourceItDoesNotDiscover() {
        DiscoveryInitiateRequestDto request = initiate();
        request.setResources(List.of(Resource.CERTIFICATE, Resource.SECRET));
        CheckpointedRunService service = service();

        Assertions.assertThrows(ValidationException.class, () -> service.initiate(request));
    }

    @Test
    void initiateRefusesAMalformedHost() {
        DiscoveryInitiateRequestDto request = scoped(new DiscoveryInitiateRequestDto(), "not a host!", null);
        CheckpointedRunService service = service();

        Assertions.assertThrows(ValidationException.class, () -> service.initiate(request));
    }

    // --- status ---

    @Test
    void statusReportsRunningFromTheReplayedCheckpoint() {
        DiscoveryStatusResponseDto status = service().status(run(at(2, 4)));

        Assertions.assertEquals(DiscoveryRunState.RUNNING, status.getState());
        Assertions.assertEquals(4L, status.getHighestSequence());
        DiscoveryProgressDto progress = status.getProgress();
        Assertions.assertEquals(4L, progress.getTargetsTotal());
        Assertions.assertEquals(2L, progress.getTargetsProcessed());
        Assertions.assertEquals(4L, progress.getByResource().get(Resource.CERTIFICATE).getProduced());
        Assertions.assertNull(progress.getPhase());
        Assertions.assertNull(status.getMeta(), "nothing failed, so there is nothing to explain");
        Assertions.assertEquals(0, probed.get(), "status scans nothing");
    }

    @Test
    void statusReportsCompletedOnceTheCursorReachedTheEnd() {
        DiscoveryStatusResponseDto status = service().status(run(at(4, 8)));

        Assertions.assertEquals(DiscoveryRunState.COMPLETED, status.getState());
        Assertions.assertEquals(8L, status.getHighestSequence());
    }

    @Test
    void statusOfADifferentEnumerationIsNotTracked() {
        DiscoveryRunRequestDto request = scoped(new DiscoveryRunRequestDto(), "10.0.0.1-10.0.0.5", at(2, 4));
        CheckpointedRunService service = service();

        Assertions.assertThrows(UnknownRunException.class, () -> service.status(request));
    }

    @Test
    void statusSaysWhyTargetsFailed() {
        RunHandle failing = new RunHandle(RunHandle.RunState.RUNNING, 4L, 0L, TARGETS.digest(), 4L, 4L, 0L, Map.of(),
                Map.of("TLS alert handshake_failure", 4L));

        DiscoveryStatusResponseDto status = service().status(run(failing));

        Assertions.assertEquals(4L, status.getProgress().getTargetsFailed());
        MetadataAttribute reasons = status.getMeta().getFirst();
        Assertions.assertTrue(reasons.getProperties().isVisible());
        Assertions
                .assertEquals(List.of("4 x TLS alert handshake_failure"),
                        ((List<?>) reasons.getContent())
                                .stream()
                                .map(content -> ((AttributeContent) content).getData())
                                .toList());
    }

    /** Core keeps the last progress it was given, so an all-null object would overwrite a real one with silence. */
    @Test
    void progressIsOmittedWhenThereIsNothingToReport() {
        Assertions.assertNull(CheckpointedRunService.progressOf(RunHandle.initial("digest"), 0));
        Assertions.assertNotNull(CheckpointedRunService.progressOf(RunHandle.initial("digest"), 4));
    }

    // --- results ---

    @Test
    void resultsServesAPageAndTheCheckpointAfterIt() {
        DiscoveryResultsResponseDto page = service().results(drain(at(1, 2), 2));

        Assertions
                .assertEquals(List.of(3L, 4L, 5L, 6L, 7L, 8L),
                        page.getItems().stream().map(DiscoveredItemDto::getSequence).toList());
        Assertions.assertEquals(8L, page.getHighestSequence());
        Assertions.assertFalse(page.getMore());
        RunHandle next = checkpointOf(page.getCheckpoint());
        Assertions.assertEquals(4L, next.cursorIndex());
        Assertions.assertEquals(8L, next.sequenceHighWater());
        Assertions.assertEquals(RunHandle.RunState.RUNNING, next.state());
        Assertions.assertEquals(Map.of(Resource.CERTIFICATE.getCode(), 8L), next.yieldByResource());
    }

    @Test
    void resultsOnAFinishedRunAnswerAnEmptyPageWithTheSameCheckpoint() {
        RunHandle finished = at(4, 8);

        DiscoveryResultsResponseDto page = service().results(drain(finished, 8));

        Assertions.assertEquals(List.of(), page.getItems());
        Assertions.assertFalse(page.getMore());
        Assertions.assertEquals(8L, page.getHighestSequence());
        Assertions.assertEquals(finished, checkpointOf(page.getCheckpoint()));
    }

    /** The drain comes from a Core that would ignore the page's checkpoint; a newer Core takes the retry. */
    @Test
    void resultsWithoutCheckpointedOnOfferAreBusy() {
        DiscoveryDrainRequestDto buffered = drain(at(0, 0), 0);
        buffered.setDeliveryModes(List.of(DiscoveryDeliveryMode.BUFFERED));
        DiscoveryDrainRequestDto olderCore = drain(at(0, 0), 0);
        olderCore.setDeliveryModes(null);
        CheckpointedRunService service = service();

        Assertions.assertThrows(ConnectorBusyException.class, () -> service.results(buffered));
        Assertions.assertThrows(ConnectorBusyException.class, () -> service.results(olderCore));
        Assertions.assertEquals(0, probed.get());
    }

    /** Core keeps the two equal, so a mismatch is a stale checkpoint or lost items, and a page would hide either. */
    @Test
    void resultsWithAfterSequenceOffTheCheckpointAreNotTracked() {
        CheckpointedRunService service = service();
        DiscoveryDrainRequestDto below = drain(at(1, 2), 1);
        DiscoveryDrainRequestDto above = drain(at(1, 2), 3);

        Assertions.assertThrows(UnknownRunException.class, () -> service.results(below));
        Assertions.assertThrows(UnknownRunException.class, () -> service.results(above));
        Assertions.assertEquals(0, probed.get());
    }

    @Test
    void resultsOfADifferentEnumerationAreNotTracked() {
        DiscoveryDrainRequestDto request = scoped(new DiscoveryDrainRequestDto(), "10.0.0.1-10.0.0.5", at(1, 2));
        request.setAfterSequence(2);
        CheckpointedRunService service = service();

        Assertions.assertThrows(UnknownRunException.class, () -> service.results(request));
    }

    @Test
    void resultsWithoutACheckpointAreRefused() {
        DiscoveryDrainRequestDto request = drain(null, 0);
        CheckpointedRunService service = service();

        Assertions.assertThrows(ValidationException.class, () -> service.results(request));
    }

    @Test
    void resultsBeyondMaxConcurrentSlicesAreBusy() throws Exception {
        CountDownLatch reached = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CheckpointedRunService service = service(new SliceSettings(8_000, 1, 256, 10_000), url -> {
            reached.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted", e);
            }
            return chainOf(1);
        });
        CompletableFuture<DiscoveryResultsResponseDto> first = CompletableFuture
                .supplyAsync(() -> service.results(drain(at(0, 0), 0)));
        Assertions.assertTrue(reached.await(10, TimeUnit.SECONDS));

        try {
            DiscoveryDrainRequestDto second = drain(at(0, 0), 0);
            Assertions.assertThrows(ConnectorBusyException.class, () -> service.results(second));
        } finally {
            release.countDown();
        }

        Assertions.assertEquals(4, first.get(10, TimeUnit.SECONDS).getItems().size());
        Assertions
                .assertEquals(4, service.results(drain(at(0, 0), 0)).getItems().size(),
                        "the slot is given back when the slice ends");
    }

    @Test
    void resultsWhileTooManyProbesAreAbandonedAreBusy() {
        CheckpointedRunService service = service(new SliceSettings(8_000, 32, 1, 10_000), url -> chainOf(1));
        CompletableFuture<TargetResult> stuck = new CompletableFuture<>();
        abandoned.register(stuck);
        DiscoveryDrainRequestDto request = drain(at(0, 0), 0);

        Assertions.assertThrows(ConnectorBusyException.class, () -> service.results(request));

        stuck.complete(TargetResult.failed(0, "late"));
        Assertions.assertEquals(4, service.results(drain(at(0, 0), 0)).getItems().size());
    }

    /** A 2.20 stop checkpointed sequences its buffer had numbered; Core never received 38 to 40. */
    @Test
    void stoppedTwentyTwentyCheckpointWithLostItemsAnswers404() {
        RunHandle stopped = at(2, 40).withState(RunHandle.RunState.STOPPED);
        CheckpointedRunService service = service();
        DiscoveryDrainRequestDto request = drain(stopped, 37);

        Assertions.assertThrows(UnknownRunException.class, () -> service.results(request));
    }

    @Test
    void stoppedTwentyTwentyCheckpointResumesAboveItsHighWater() {
        RunHandle stopped = at(2, 40).withState(RunHandle.RunState.STOPPED);
        CheckpointedRunService service = service();

        service.resume(run(stopped));
        DiscoveryResultsResponseDto page = service.results(drain(stopped, 40));

        Assertions.assertEquals(41L, page.getItems().getFirst().getSequence());
        Assertions.assertEquals(RunHandle.RunState.RUNNING, checkpointOf(page.getCheckpoint()).state());
    }

    // --- stop, resume, cancel ---

    @Test
    void stopBeforeTheEndAnswersWithoutACheckpoint() {
        DiscoveryStopResponseDto response = service().stop(run(at(2, 4)));

        Assertions.assertNull(response.getCheckpoint(), "Core keeps the checkpoint it stored with the last page");
    }

    @Test
    void stopAtTheEndIsPastThePointOfNoReturn() {
        CheckpointedRunService service = service();
        DiscoveryRunRequestDto request = run(at(4, 8));

        Assertions.assertThrows(RunPastPointOfNoReturnException.class, () -> service.stop(request));
    }

    @Test
    void resumeChoosesCheckpointedWithoutACheckpoint() {
        DiscoveryInitiateResponseDto response = service().resume(run(at(2, 4)));

        Assertions.assertEquals(DiscoveryDeliveryMode.CHECKPOINTED, response.getDeliveryMode());
        Assertions.assertTrue(response.getStoppable());
        Assertions.assertNull(response.getCheckpoint());
        Assertions.assertEquals(0, probed.get());
    }

    @Test
    void resumeWithoutCheckpointedOnOfferIsRefused() {
        DiscoveryRunRequestDto request = run(at(2, 4));
        request.setDeliveryModes(List.of(DiscoveryDeliveryMode.BUFFERED));
        CheckpointedRunService service = service();

        Assertions.assertThrows(ValidationException.class, () -> service.resume(request));
    }

    @Test
    void resumeOfADifferentEnumerationLosesTheCheckpoint() {
        DiscoveryRunRequestDto request = scoped(new DiscoveryRunRequestDto(), "10.0.0.1-10.0.0.5", at(2, 4));
        CheckpointedRunService service = service();

        Assertions.assertThrows(CheckpointLostException.class, () -> service.resume(request));
    }

    /** Nothing is held, so there is nothing to discard, and a run this node never saw is no error. */
    @Test
    void cancelIsANoOp() {
        CheckpointedRunService service = service();
        DiscoveryRunRequestDto request = run(at(2, 4));

        Assertions.assertDoesNotThrow(() -> service.cancel(request));
        Assertions.assertEquals(0, probed.get());
    }
}
