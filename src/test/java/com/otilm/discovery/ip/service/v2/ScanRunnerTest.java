package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.dto.ConnectionResponse;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.util.TargetEnumeration;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

class ScanRunnerTest {

    private static X509Certificate certificate;

    private final RunRegistry registry = new RunRegistry();

    @BeforeAll
    static void mintCertificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        X500Principal subject = new X500Principal("CN=scan-runner-test");
        certificate = new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
                        Date.from(Instant.now().minus(Duration.ofDays(1))),
                        Date.from(Instant.now().plus(Duration.ofDays(1))), subject, pair.getPublic())
                                .build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())));
    }

    /** Answers every probe with one certificate, counting the targets it was asked for. */
    private static class AlwaysAnswers implements ConnectionService {
        private final AtomicInteger probed = new AtomicInteger();

        @Override
        public ConnectionResponse getCertificates(String url) {
            probed.incrementAndGet();
            return new ConnectionResponse("TLS_AES_256_GCM_SHA384", new X509Certificate[] {certificate});
        }
    }

    /** Blocks forever on one nominated target, which is what a stop has to be able to cut through. */
    private static class StallsOnOneTarget implements ConnectionService {
        private final String stallingUrl;
        private final CountDownLatch reached = new CountDownLatch(1);
        private final AtomicBoolean interrupted = new AtomicBoolean();

        StallsOnOneTarget(String stallingUrl) {
            this.stallingUrl = stallingUrl;
        }

        @Override
        public ConnectionResponse getCertificates(String url) throws IOException {
            if (!url.equals(stallingUrl)) {
                return new ConnectionResponse("TLS_AES_256_GCM_SHA384", new X509Certificate[] {certificate});
            }
            reached.countDown();
            try {
                Thread.sleep(Duration.ofMinutes(5));
            } catch (InterruptedException e) {
                interrupted.set(true);
                Thread.currentThread().interrupt();
                throw new IOException("probe interrupted");
            }
            return null;
        }
    }

    private static class AlwaysFails implements ConnectionService {
        @Override
        public ConnectionResponse getCertificates(String url) throws IOException {
            throw new IOException("nothing listening");
        }
    }

    private ScanRunner runner(UUID runId, TargetEnumeration targets, ResultBuffer buffer, ConnectionService probes,
            int chunkSize) {
        return runner(runId, targets, buffer, probes, chunkSize, Set.of(Resource.CERTIFICATE));
    }

    private ScanRunner runner(UUID runId, TargetEnumeration targets, ResultBuffer buffer, ConnectionService probes,
            int chunkSize, Set<Resource> resources) {
        return new ScanRunner(runId, targets, buffer, registry, probes, 8, chunkSize, resources);
    }

    private ResultBuffer openBuffer(UUID runId, BufferBudget budget, long startingSequence) {
        Assertions.assertTrue(budget.open(runId));
        return new ResultBuffer(runId, budget, startingSequence);
    }

    private static BufferBudget roomyBudget() {
        return new BufferBudget(8, 1_000_000, 1L << 30, 1L << 31, 30_000);
    }

    @Test
    void scansEveryTargetAndCheckpointsAtTheEnd() {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.10", "443", false);
        registry.register(runId, RunHandle.initial(targets.digest()));
        ResultBuffer buffer = openBuffer(runId, roomyBudget(), 0);
        AlwaysAnswers probes = new AlwaysAnswers();

        Assertions.assertTrue(runner(runId, targets, buffer, probes, 4).scan());

        RunHandle handle = registry.find(runId).orElseThrow();
        Assertions.assertEquals(10, probes.probed.get());
        Assertions.assertEquals(10, handle.cursorIndex());
        Assertions.assertEquals(10, handle.targetsProcessed());
        Assertions.assertEquals(0, handle.targetsFailed());
        Assertions.assertEquals(Map.of(Resource.CERTIFICATE.getCode(), 10L), handle.yieldByResource());
    }

    @Test
    void countsAnUnreachableTargetAsProcessedAndFailed() {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);
        registry.register(runId, RunHandle.initial(targets.digest()));
        ResultBuffer buffer = openBuffer(runId, roomyBudget(), 0);

        Assertions.assertTrue(runner(runId, targets, buffer, new AlwaysFails(), 4).scan());

        RunHandle handle = registry.find(runId).orElseThrow();
        Assertions.assertEquals(4, handle.targetsProcessed());
        Assertions.assertEquals(4, handle.targetsFailed());
        Assertions.assertEquals(0, buffer.held(), "a failed probe yields no item");
    }

    /**
     * The test Task 2's deadline exists for. A quiesce has nothing to wait for — under backpressure the chunk
     * proceeds at Core's drain cadence, or not at all while the platform is unreachable, which is the situation an
     * operator reaches for stop in.
     */
    @Test
    void stopReturnsWhileATargetIsStillStalling() throws Exception {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.8", "443", false);
        registry.register(runId, RunHandle.initial(targets.digest()));
        ResultBuffer buffer = openBuffer(runId, roomyBudget(), 0);
        StallsOnOneTarget probes = new StallsOnOneTarget(targets.target(2));
        ScanRunner runner = runner(runId, targets, buffer, probes, 8);

        AtomicReference<Boolean> completed = new AtomicReference<>();
        Thread scan = Thread.ofVirtual().start(() -> completed.set(runner.scan()));

        Assertions.assertTrue(probes.reached.await(10, TimeUnit.SECONDS), "the stalling target was never probed");
        runner.stop();
        scan.join(Duration.ofSeconds(10));

        Assertions.assertFalse(scan.isAlive(), "stop must not wait for the stalled probe");
        Assertions.assertEquals(Boolean.FALSE, completed.get(), "an interrupted scan did not run to completion");
        // Awaited rather than read: stop cancels and returns without waiting for the probe, which is the behaviour
        // under test, so the probe can still be unwinding when scan() has already returned.
        Awaitility
                .await("the in-flight probe should have been interrupted")
                .atMost(Duration.ofSeconds(10))
                .untilTrue(probes.interrupted);
    }

    /** The cursor is a chunk boundary, so an interrupted chunk leaves it where the last completed one ended. */
    @Test
    void leavesTheCursorAtTheLastCompletedBoundaryWhenStopped() throws Exception {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.12", "443", false);
        registry.register(runId, RunHandle.initial(targets.digest()));
        ResultBuffer buffer = openBuffer(runId, roomyBudget(), 0);
        // Chunk size 4, stalling on the first target of the third chunk: two chunks complete, the third is cut.
        StallsOnOneTarget probes = new StallsOnOneTarget(targets.target(8));
        ScanRunner runner = runner(runId, targets, buffer, probes, 4);

        Thread scan = Thread.ofVirtual().start(runner::scan);
        Assertions.assertTrue(probes.reached.await(10, TimeUnit.SECONDS));
        runner.stop();
        scan.join(Duration.ofSeconds(10));

        RunHandle handle = registry.find(runId).orElseThrow();
        Assertions.assertEquals(8, handle.cursorIndex(), "the cursor must sit on a completed boundary");
        Assertions
                .assertEquals(8, handle.targetsProcessed(),
                        "the interrupted chunk contributes nothing, or a resume would double-count it");
    }

    /**
     * Resume re-scans the interrupted chunk. The duplicates are contract-legal — Core collapses them on uniqueRef —
     * and the sequence space continues rather than restarting, which is what keeps them visible to Core at all.
     */
    @Test
    void resumesFromTheBoundaryAndContinuesTheSequenceSpace() {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.12", "443", false);
        BufferBudget budget = roomyBudget();

        registry.register(runId, new RunHandle(RunHandle.RunState.RUNNING, 8L, 8L, targets.digest(), 8L, 0L,
                Map.of(Resource.CERTIFICATE.getCode(), 8L)));
        ResultBuffer buffer = openBuffer(runId, budget, 8L);
        AlwaysAnswers probes = new AlwaysAnswers();

        Assertions.assertTrue(runner(runId, targets, buffer, probes, 4).scan());

        RunHandle handle = registry.find(runId).orElseThrow();
        Assertions.assertEquals(4, probes.probed.get(), "only the targets after the boundary should be re-scanned");
        Assertions.assertEquals(12, handle.cursorIndex());
        Assertions.assertEquals(12, handle.targetsProcessed(), "the carried counters continue rather than reset");
        Assertions.assertEquals(Map.of(Resource.CERTIFICATE.getCode(), 12L), handle.yieldByResource());

        List<Long> sequences = buffer.page(8, 100, 1L << 20).items().stream().map(DiscoveredItemDto::getSequence)
                .toList();
        Assertions.assertEquals(List.of(9L, 10L, 11L, 12L), sequences, "a resumed run continues its sequence space");
    }

    @Test
    void doesNothingWhenTheCursorIsAlreadyAtTheEnd() {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);
        registry
                .register(runId, new RunHandle(RunHandle.RunState.RUNNING, 4L, 4L, targets.digest(), 4L, 0L, Map.of()));
        ResultBuffer buffer = openBuffer(runId, roomyBudget(), 4L);
        AlwaysAnswers probes = new AlwaysAnswers();

        Assertions.assertTrue(runner(runId, targets, buffer, probes, 4).scan());

        Assertions.assertEquals(0, probes.probed.get());
    }

    // --- keys ---

    /**
     * The keys are the certificates' own, derived from a chain the scan already has. Emitting them is driven by the
     * run's resource set because a key per certificate roughly doubles item count and buffer occupancy.
     */
    @Test
    void emitsAKeyBesideEachCertificateWhenTheRunAsksForBoth() throws Exception {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);
        registry.register(runId, RunHandle.initial(targets.digest()));
        ResultBuffer buffer = openBuffer(runId, roomyBudget(), 0);

        runner(runId, targets, buffer, new AlwaysAnswers(), 4,
                Set.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY)).scan();

        RunHandle handle = registry.find(runId).orElseThrow();
        Assertions
                .assertEquals(Map.of(Resource.CERTIFICATE.getCode(), 4L, Resource.CRYPTOGRAPHIC_KEY.getCode(), 4L),
                        handle.yieldByResource());
        Assertions.assertEquals(8, buffer.held(), "one certificate item and one key item per target");
    }

    /** A run that did not ask for keys must not be charged for them, in items, sequences or buffer. */
    @Test
    void emitsNoKeyItemsForACertificatesOnlyRun() throws Exception {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);
        registry.register(runId, RunHandle.initial(targets.digest()));
        ResultBuffer buffer = openBuffer(runId, roomyBudget(), 0);

        runner(runId, targets, buffer, new AlwaysAnswers(), 4, Set.of(Resource.CERTIFICATE)).scan();

        Assertions
                .assertEquals(Map.of(Resource.CERTIFICATE.getCode(), 4L),
                        registry.find(runId).orElseThrow().yieldByResource());
        Assertions.assertEquals(4, buffer.held());
    }

    /** A keys-only run is satisfiable: it returns the public keys of the certificates it would otherwise have got. */
    @Test
    void emitsOnlyKeysForAKeysOnlyRun() throws Exception {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);
        registry.register(runId, RunHandle.initial(targets.digest()));
        ResultBuffer buffer = openBuffer(runId, roomyBudget(), 0);

        runner(runId, targets, buffer, new AlwaysAnswers(), 4, Set.of(Resource.CRYPTOGRAPHIC_KEY)).scan();

        Assertions
                .assertEquals(Map.of(Resource.CRYPTOGRAPHIC_KEY.getCode(), 4L),
                        registry.find(runId).orElseThrow().yieldByResource());
        Assertions
                .assertEquals(com.otilm.discovery.ip.util.KeyMapper.toKey(certificate).getFingerprint(),
                        buffer.page(0, 10, 1L << 20).items().get(0).getUniqueRef(),
                        "a key item is correlated by its fingerprint");
    }

    // --- item source, and a bound the run cannot continue past ---

    /**
     * Where an item was found. v1 attached this per certificate as discoverySource; without it an operator has an
     * inventory of certificates and no way to tell which host and port produced any of them.
     */
    @Test
    void recordsWhereEachItemWasFound() throws Exception {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1", "443,8443", false);
        registry.register(runId, RunHandle.initial(targets.digest()));
        ResultBuffer buffer = openBuffer(runId, roomyBudget(), 0);

        runner(runId, targets, buffer, new AlwaysAnswers(), 4,
                Set.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY)).scan();

        List<String> sources = buffer
                .page(0, 100, 1L << 20)
                .items()
                .stream()
                .map(item -> (String) ((com.otilm.api.model.common.attribute.v3.MetadataAttributeV3) item
                        .getMeta()
                        .get(0)).getContent().get(0).getData())
                .distinct()
                .sorted()
                .toList();

        Assertions.assertEquals(List.of("https://10.0.0.1:443", "https://10.0.0.1:8443"), sources);
        Assertions
                .assertEquals("meta_discoverySource",
                        buffer.page(0, 1, 1L << 20).items().get(0).getMeta().get(0).getName());
    }

    /**
     * A bound that cannot be waited out ends the run. Counting it as one more failed target would be silent
     * truncation: a legitimate dark sweep also reports enormous failed-target counts, so a buffer-starved run would
     * be indistinguishable from one that simply found nothing listening.
     */
    @Test
    void failsTheRunWhenTheBufferCannotHoldWhatItProduces() {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.8", "443", false);
        registry.register(runId, RunHandle.initial(targets.digest()));
        // Room for one item, and no time to wait for a drain that is never coming.
        BufferBudget tight = new BufferBudget(4, 1, 1L << 30, 1L << 31, 150);
        ResultBuffer buffer = openBuffer(runId, tight, 0);

        BufferBudget.BufferLimitExceededException thrown = Assertions
                .assertThrows(BufferBudget.BufferLimitExceededException.class,
                        () -> runner(runId, targets, buffer, new AlwaysAnswers(), 8).scan());

        Assertions.assertTrue(thrown.getMessage().contains("max-items-per-run"), thrown.getMessage());
        Assertions
                .assertTrue(registry.find(runId).orElseThrow().targetsFailed() < 8,
                        "the run must end on the limit, not grind through every target reporting failures");
    }

    // --- why a sweep failed, not just how much of it ---

    /** A healthy sweep says nothing extra: the summary exists to explain failures, not to pad every line. */
    @Test
    void saysNothingWhenEveryTargetAnswered() throws Exception {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);
        registry.register(runId, RunHandle.initial(targets.digest()));
        ResultBuffer buffer = openBuffer(runId, roomyBudget(), 0);
        ScanRunner runner = runner(runId, targets, buffer, new AlwaysAnswers(), 4);

        runner.scan();

        Assertions.assertEquals(4, registry.find(runId).orElseThrow().targetsProcessed());
        Assertions.assertEquals(0, registry.find(runId).orElseThrow().targetsFailed());
        Assertions.assertEquals("", runner.failureSummary());
    }

    @Test
    void summarisesTheDominantFailureReason() throws Exception {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);
        registry.register(runId, RunHandle.initial(targets.digest()));
        ResultBuffer buffer = openBuffer(runId, roomyBudget(), 0);
        ScanRunner runner = runner(runId, targets, buffer, new AlwaysFails(), 4);

        runner.scan();

        Assertions
                .assertEquals(": 4 x IOException", runner.failureSummary(),
                        "the count and the reason belong together, or the log says nothing new");
    }

    /**
     * A certificate this connector cannot map is its own defect, and it must not read as a target that did not
     * answer. Both end the target as failed -- nothing usable came of it either way -- but the reason distinguishes
     * them, so a mapping that throws for every certificate cannot hide inside an unreachable-looking sweep.
     */
    @Test
    void tellsACertificateItCannotMapFromATargetThatNeverAnswered() throws Exception {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);
        registry.register(runId, RunHandle.initial(targets.digest()));
        ResultBuffer buffer = openBuffer(runId, roomyBudget(), 0);

        X509Certificate unmappable = Mockito.mock(X509Certificate.class);
        Mockito.when(unmappable.getEncoded()).thenThrow(new CertificateEncodingException("no encoding"));
        ScanRunner runner = runner(runId, targets, buffer,
                url -> new ConnectionResponse("TLS_AES_256_GCM_SHA384", new X509Certificate[] {unmappable}), 4);

        runner.scan();

        Assertions
                .assertEquals(": 4 x item:CertificateEncodingException", runner.failureSummary(),
                        "an item this connector could not build is marked as ours");
        RunHandle handle = registry.find(runId).orElseThrow();
        Assertions.assertEquals(4, handle.targetsProcessed());
        Assertions.assertEquals(4, handle.targetsFailed(), "nothing usable came of the target either way");
        Assertions.assertEquals(0, buffer.held());
    }

    /**
     * The buffer trusts this number to keep a page inside what the transport carries, so it has to cover the whole
     * serialised item rather than most of it. A 1000-byte certificate serialises to about 1981 bytes once its base64,
     * its reference, its timestamp and its source metadata are counted; the previous estimate charged 1845.
     */
    @Test
    void chargesAtLeastWhatACertificateItemSerialisesTo() {
        Assertions.assertTrue(ScanRunner.weightOf(1000) > 1981,
                "a 1000-byte certificate must not be charged less than it serialises to, was "
                        + ScanRunner.weightOf(1000));
        Assertions.assertEquals(4, ScanRunner.base64Length(3), "base64 is four characters per three bytes");
        Assertions.assertEquals(8, ScanRunner.base64Length(4), "a partial group still costs a whole group");
    }


    /**
     * A keys-only run needs the public key, not the DER. Reading the encoding before the resource set is consulted
     * failed such a run over something it never asked for.
     */
    @Test
    void producesKeysFromACertificateWhoseEncodingCannotBeRead() throws Exception {
        UUID runId = UUID.randomUUID();
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.2", "443", false);
        registry.register(runId, RunHandle.initial(targets.digest()));
        ResultBuffer buffer = openBuffer(runId, roomyBudget(), 0);

        X509Certificate unencodable = Mockito.mock(X509Certificate.class);
        Mockito.when(unencodable.getEncoded()).thenThrow(new CertificateEncodingException("no encoding"));
        Mockito.when(unencodable.getPublicKey()).thenReturn(certificate.getPublicKey());
        ScanRunner runner = runner(runId, targets, buffer,
                url -> new ConnectionResponse("TLS_AES_256_GCM_SHA384", new X509Certificate[] {unencodable}), 4,
                Set.of(Resource.CRYPTOGRAPHIC_KEY));

        runner.scan();

        Assertions.assertEquals(2, buffer.held(), "both targets should have yielded their key");
        Assertions.assertEquals(0, registry.find(runId).orElseThrow().targetsFailed());
        Assertions.assertEquals("", runner.failureSummary());
    }

}
