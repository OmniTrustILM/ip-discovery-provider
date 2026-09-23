package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDrainRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.api.v2.UnknownRunException;
import com.otilm.discovery.ip.dto.ConnectionResponse;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.service.v2.impl.DiscoveryAttributeServiceImpl;
import com.otilm.discovery.ip.util.TargetEnumeration;
import org.awaitility.Awaitility;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.info.BuildProperties;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The seam where the checkpoint, the buffer and the scan meet. Three call sites — stop, resume and rebuild — each
 * have to leave the same invariant standing: the checkpoint's high water equals the buffer's sequencer whenever Core
 * can observe either. When they disagree the run does not fail; it completes, with items missing.
 */
class StopResumeSeamTest {

    /** Well inside one chunk, so a stop lands mid-chunk with items numbered and no boundary crossed. */
    private static final String HOSTS = "10.0.0.1-10.0.0.12";

    private static X509Certificate certificate;

    private final RunRegistry registry = new RunRegistry();
    private final BufferBudget budget = new BufferBudget(4, 100_000, 1L << 30, 1L << 31, 30_000);

    @BeforeAll
    static void mintCertificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        X500Principal subject = new X500Principal("CN=stop-resume-seam");
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

    /** Answers every probe, and can be told to hold the rest of the scan open at a chosen target. */
    private static class HoldsAtTarget implements ConnectionService {
        private final String holdUrl;
        private final CountDownLatch reached = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private final AtomicInteger probed = new AtomicInteger();

        HoldsAtTarget(String holdUrl) {
            this.holdUrl = holdUrl;
        }

        @Override
        public ConnectionResponse getCertificates(String url) {
            probed.incrementAndGet();
            if (url.equals(holdUrl)) {
                reached.countDown();
                try {
                    release.await(30, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            return new ConnectionResponse("TLS_AES_256_GCM_SHA384", new X509Certificate[] {certificate});
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

    private static DiscoveryRunRequestDto runRequest(UUID runId, List<?> meta) {
        DiscoveryRunRequestDto request = new DiscoveryRunRequestDto();
        request.setRunId(runId);
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setAttributes(scanAttributes());
        if (meta != null) {
            @SuppressWarnings("unchecked")
            List<com.otilm.api.model.common.attribute.common.MetadataAttribute> typed =
                    (List<com.otilm.api.model.common.attribute.common.MetadataAttribute>) meta;
            request.setCheckpoint(typed);
        }
        return request;
    }

    private static DiscoveryDrainRequestDto drainRequest(UUID runId, List<?> meta, long afterSequence) {
        DiscoveryDrainRequestDto request = new DiscoveryDrainRequestDto();
        request.setRunId(runId);
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setAttributes(scanAttributes());
        if (meta != null) {
            @SuppressWarnings("unchecked")
            List<com.otilm.api.model.common.attribute.common.MetadataAttribute> typed =
                    (List<com.otilm.api.model.common.attribute.common.MetadataAttribute>) meta;
            request.setCheckpoint(typed);
        }
        request.setAfterSequence(afterSequence);
        return request;
    }

    /**
     * A stop lands inside a chunk in practice — chunks are 256 targets wide, so landing exactly on a boundary is
     * vanishingly rare. The checkpoint must therefore cover the items the interrupted chunk already numbered, not the
     * last boundary value.
     */
    @Test
    void checkpointsEveryItemTheInterruptedChunkAlreadyNumbered() throws Exception {
        UUID runId = UUID.randomUUID();
        HoldsAtTarget probes = new HoldsAtTarget(TargetEnumeration.of(HOSTS, "443", false).target(6));
        DiscoveryRunService service = new DiscoveryRunService(registry, budget, attributeService(), probes);

        service.initiate(initiateRequest(runId));
        Assertions.assertTrue(probes.reached.await(20, TimeUnit.SECONDS), "the scan never reached the held target");
        // Several probes of this chunk have completed and been numbered while one is held open.
        Awaitility.await().atMost(Duration.ofSeconds(10)).until(() -> registry.buffer(runId).orElseThrow().held() > 0);

        long numbered = registry.buffer(runId).orElseThrow().highestSequence();
        Assertions
                .assertEquals(0L, registry.find(runId).orElseThrow().sequenceHighWater(),
                        "no chunk boundary has been crossed, so the handle still reads zero");

        // Stopped while the probe is still held: the stop interrupts it, which is what releases the await. Letting
        // it go first lets the scan finish every target before the stop lands, and the assertion below then passes
        // without ever exercising the mid-chunk path this test exists for.
        var stopped = service.stop(runRequest(runId, null));

        RunHandle handle = RunHandle.from(stopped.getCheckpoint()).orElseThrow();
        Assertions
                .assertTrue(handle.sequenceHighWater() >= numbered,
                        "the checkpoint said " + handle.sequenceHighWater() + " but " + numbered
                                + " items had already been numbered; a later drain reads that gap as loss and kills a "
                                + "run that lost nothing");
        Assertions
                .assertEquals(0L, handle.cursorIndex(),
                        "the interrupted chunk never committed, so the cursor stays at the boundary it started from");
    }

    /**
     * Resuming a run this node still holds must keep its buffer. Replacing it drops whatever Core has not drained and
     * reseeds the sequencer below its own counter, so the resumed run reissues numbers Core has already ingested and
     * its cursor filter discards them with nothing but a debug line.
     */
    @Test
    void resumeKeepsTheBufferAndTheSequenceSpaceOfARunThisNodeHolds() throws Exception {
        UUID runId = UUID.randomUUID();
        HoldsAtTarget probes = new HoldsAtTarget(TargetEnumeration.of(HOSTS, "443", false).target(6));
        DiscoveryRunService service = new DiscoveryRunService(registry, budget, attributeService(), probes);

        service.initiate(initiateRequest(runId));
        Assertions.assertTrue(probes.reached.await(20, TimeUnit.SECONDS));
        Awaitility.await().atMost(Duration.ofSeconds(10)).until(() -> registry.buffer(runId).orElseThrow().held() > 0);
        probes.release.countDown();
        service.stop(runRequest(runId, null));

        ResultBuffer beforeResume = registry.buffer(runId).orElseThrow();
        int heldBeforeResume = beforeResume.held();
        long sequenceBeforeResume = beforeResume.highestSequence();
        Assertions.assertTrue(heldBeforeResume > 0, "the run should still hold undrained items");

        registry.setState(runId, DiscoveryRunState.STOPPED);
        service.resume(runRequest(runId, null));

        ResultBuffer afterResume = registry.buffer(runId).orElseThrow();
        Assertions.assertSame(beforeResume, afterResume, "resume must not replace the buffer");
        Assertions
                .assertTrue(afterResume.highestSequence() >= sequenceBeforeResume,
                        "the sequencer must never move backwards, or Core discards what follows");
        Assertions
                .assertTrue(afterResume.page(0, 1000, 1L << 20).items().size() >= heldBeforeResume,
                        "the items Core had not drained must still be servable");
    }

    /**
     * The verdict on whether a rebuilt run lost anything has to apply however the run was rebuilt. Core expedites the
     * drain on a successful resume, so it arrives at a run resume has already registered, and the cursor check must
     * still apply there.
     */
    @Test
    void refusesToServeARunRebuiltByResumeUntilADrainProvesNothingWasLost() {
        UUID runId = UUID.randomUUID();
        DiscoveryRunService service = new DiscoveryRunService(registry, budget, attributeService(), url -> {
            throw new java.io.IOException("nothing listening");
        });
        RunHandle checkpoint = new RunHandle(RunHandle.RunState.STOPPED, 4L, 40L,
                TargetEnumeration.of(HOSTS, "443", false).digest(), 4L, 0L, java.util.Map.of());

        service.resume(runRequest(runId, checkpoint.encode()));

        // Core is behind the checkpoint: items 31..40 were produced and never handed over.
        var behind = drainRequest(runId, checkpoint.encode(), 30);
        Assertions
                .assertThrows(UnknownRunException.class, () -> service.results(behind),
                        "a resumed-then-rebuilt run must not serve across the gap");
    }

    /**
     * The verification is owed once. Left owed, every later drain would be checked against the rebuild's high water,
     * and the first one after a resume produced anything would be refused as a gap.
     */
    @Test
    void servesARebuiltRunOnceADrainArrivesAtTheCheckpoint() {
        UUID runId = UUID.randomUUID();
        DiscoveryRunService service = new DiscoveryRunService(registry, budget, attributeService(), url -> {
            throw new java.io.IOException("nothing listening");
        });
        RunHandle checkpoint = new RunHandle(RunHandle.RunState.STOPPED, 4L, 40L,
                TargetEnumeration.of(HOSTS, "443", false).digest(), 4L, 0L, java.util.Map.of());

        service.status(runRequest(runId, checkpoint.encode()));

        Assertions.assertDoesNotThrow(() -> service.results(drainRequest(runId, checkpoint.encode(), 40)));
        Assertions.assertTrue(registry.drainVerificationOwed(runId).isEmpty(), "the first matching drain settles it");
        Assertions.assertDoesNotThrow(() -> service.results(drainRequest(runId, checkpoint.encode(), 40)));
    }
}
