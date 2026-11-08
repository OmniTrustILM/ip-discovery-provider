package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.dto.ConnectionResponse;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.util.TargetEnumeration;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ConnectException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class SliceScannerTest {

    private static final Set<Resource> CERTIFICATES = Set.of(Resource.CERTIFICATE);
    private static final int ROOMY_ITEMS = 10_000;
    private static final long ROOMY_BYTES = 1L << 30;

    private static X509Certificate certificate;

    private final AbandonedProbes abandoned = new AbandonedProbes();

    @BeforeAll
    static void mintCertificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair pair = generator.generateKeyPair();
        X500Principal subject = new X500Principal("CN=slice-scanner-test");
        certificate = new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
                        Date.from(Instant.now().minus(Duration.ofDays(1))),
                        Date.from(Instant.now().plus(Duration.ofDays(1))), subject, pair.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())));
    }

    private SliceScanner scanner(long scanBudgetMs, long probeDeadlineMs, ConnectionService probes) {
        return new SliceScanner(new TargetProber(probes, abandoned),
                new SliceSettings(scanBudgetMs, 32, 256, probeDeadlineMs));
    }

    private SliceScanner scanner(ConnectionService probes) {
        return scanner(8_000, 10_000, probes);
    }

    private static ConnectionResponse chainOf(int certificates) {
        X509Certificate[] chain = new X509Certificate[certificates];
        Arrays.fill(chain, certificate);
        return new ConnectionResponse("TLS_AES_256_GCM_SHA384", chain);
    }

    private static ConnectionService answering(int certificatesPerTarget) {
        return url -> chainOf(certificatesPerTarget);
    }

    private static void sleep(long millis) throws IOException {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted", e);
        }
    }

    private static RunHandle at(TargetEnumeration targets, long cursor, long highWater) {
        return new RunHandle(RunHandle.RunState.RUNNING, cursor, highWater, targets.digest(), cursor, 0L, 0L, Map.of(),
                Map.of());
    }

    private static String sourceOf(DiscoveredItemDto item) {
        return (String) ((MetadataAttributeV3) item.getMeta().getFirst()).getContent().getFirst().getData();
    }

    /** What makes two pages the same page: the discovery timestamp is the moment of the probe, not part of it. */
    private static List<String> identity(SliceScanner.Slice slice) {
        return slice
                .items()
                .stream()
                .map(item -> item.getSequence() + " " + item.getUniqueRef() + " " + sourceOf(item))
                .toList();
    }

    @Test
    void numbersDenselyFromAfterSequenceInTargetOrder() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);
        // The first target answers last and the last one first.
        ConnectionService probes = url -> {
            sleep(200 - 50L * indexOf(targets, url));
            return chainOf(1);
        };

        SliceScanner.Slice slice = scanner(probes)
                .scan(at(targets, 0, 10), targets, 10, ROOMY_ITEMS, ROOMY_BYTES, 4, CERTIFICATES);

        Assertions
                .assertEquals(List.of(11L, 12L, 13L, 14L),
                        slice.items().stream().map(DiscoveredItemDto::getSequence).toList());
        Assertions
                .assertEquals(List.of(targets.target(0), targets.target(1), targets.target(2), targets.target(3)),
                        slice.items().stream().map(SliceScannerTest::sourceOf).toList());
        Assertions.assertEquals(14, slice.next().sequenceHighWater());
        Assertions.assertEquals(4, slice.next().cursorIndex());
        Assertions.assertFalse(slice.more());
    }

    private static long indexOf(TargetEnumeration targets, String url) {
        for (long index = 0; index < targets.size(); index++) {
            if (targets.target(index).equals(url)) {
                return index;
            }
        }
        throw new IllegalArgumentException(url);
    }

    @Test
    void sameCheckpointAndOutcomesGiveTheSameSlice() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.20", "443", false);
        ConnectionService probes = url -> {
            long index = indexOf(targets, url);
            if (index % 3 == 0) {
                throw new ConnectException("Connection refused");
            }
            if (index % 5 == 0) {
                throw new IOException("no usable answer");
            }
            return chainOf((int) (index % 2) + 1);
        };
        RunHandle from = at(targets, 4, 9);

        SliceScanner.Slice first = scanner(probes).scan(from, targets, 9, 12, ROOMY_BYTES, 3, CERTIFICATES);
        SliceScanner.Slice second = scanner(probes).scan(from, targets, 9, 12, ROOMY_BYTES, 3, CERTIFICATES);

        Assertions.assertEquals(identity(first), identity(second));
        Assertions.assertEquals(first.next(), second.next());
        Assertions.assertEquals(first.more(), second.more());
    }

    @Test
    void pageLimitCutsAtATargetBoundary() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);

        SliceScanner.Slice slice = scanner(answering(3))
                .scan(at(targets, 0, 0), targets, 0, 4, ROOMY_BYTES, 1, CERTIFICATES);

        Assertions.assertEquals(3, slice.items().size(), "the second target's items would not fit beside the first's");
        Assertions.assertEquals(1, slice.next().cursorIndex());
        Assertions.assertEquals(3, slice.next().sequenceHighWater());
        Assertions.assertTrue(slice.more());
    }

    @Test
    void byteLimitCutsAtATargetBoundary() throws Exception {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);
        long oneTarget = 2 * TargetProber.weightOf(certificate.getEncoded().length);

        SliceScanner.Slice slice = scanner(answering(2))
                .scan(at(targets, 0, 0), targets, 0, ROOMY_ITEMS, oneTarget + 1, 1, CERTIFICATES);

        Assertions.assertEquals(2, slice.items().size());
        Assertions.assertEquals(1, slice.next().cursorIndex());
    }

    @Test
    void exactFitCommitsTheTarget() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);

        SliceScanner.Slice slice = scanner(answering(3))
                .scan(at(targets, 0, 0), targets, 0, 3, ROOMY_BYTES, 1, CERTIFICATES);

        Assertions.assertEquals(3, slice.items().size());
        Assertions.assertEquals(1, slice.next().cursorIndex());
        Assertions.assertTrue(slice.more());
    }

    /**
     * A page that has reached its limit ends there, even when the next target would add nothing. Otherwise whether an
     * empty target joins the page depends on whether its probe happened to be launched, and two answers to the same
     * request would differ.
     */
    @Test
    void fullPageEndsTheSliceEvenBeforeAnEmptyTarget() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);
        ConnectionService probes = url -> {
            if (url.equals(targets.target(0))) {
                sleep(100);
                return chainOf(3);
            }
            throw new ConnectException("Connection refused");
        };

        SliceScanner.Slice slice = scanner(probes).scan(at(targets, 0, 0), targets, 0, 3, ROOMY_BYTES, 2, CERTIFICATES);

        Assertions.assertEquals(1, slice.next().cursorIndex());
        Assertions.assertEquals(0, slice.next().targetsEmpty());
    }

    /** Splitting the target across pages is not allowed, and skipping it would lose its items. */
    @Test
    void oversizedFirstTargetThrows() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);

        TargetTooLargeException thrown = Assertions
                .assertThrows(TargetTooLargeException.class, () -> scanner(answering(3))
                        .scan(at(targets, 2, 5), targets, 5, 2, ROOMY_BYTES, 1, CERTIFICATES));

        Assertions.assertEquals(2, thrown.index());
        Assertions.assertEquals(3, thrown.items());
        Assertions.assertTrue(thrown.getMessage().contains("2 items"), thrown.getMessage());
    }

    @Test
    void budgetStopsLaunchingButEveryLaunchedTargetCommits() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.50", "443", false);
        AtomicInteger probed = new AtomicInteger();
        ConnectionService probes = url -> {
            probed.incrementAndGet();
            sleep(60);
            return chainOf(1);
        };

        SliceScanner.Slice slice = scanner(100, 2_000, probes)
                .scan(at(targets, 0, 0), targets, 0, ROOMY_ITEMS, ROOMY_BYTES, 2, CERTIFICATES);

        Assertions.assertTrue(slice.next().cursorIndex() < targets.size(), "the budget stopped the slice early");
        Assertions
                .assertEquals(probed.get(), slice.next().cursorIndex(),
                        "every launched target is committed, none is probed only to be thrown away");
        Assertions.assertEquals(probed.get(), slice.items().size());
        Assertions.assertTrue(slice.more());
    }

    /** A dark range at parallelism 1 is the slowest case there is, and a slice must still move the run forward. */
    @Test
    void parallelismOneDarkRangeAlwaysCommits() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.100", "443", false);
        ConnectionService dark = url -> {
            sleep(20);
            throw new ConnectException("Connection refused");
        };
        RunHandle from = at(targets, 10, 3);

        SliceScanner.Slice slice = scanner(1, 500, dark)
                .scan(from, targets, 3, ROOMY_ITEMS, ROOMY_BYTES, 1, CERTIFICATES);

        Assertions.assertTrue(slice.next().cursorIndex() > from.cursorIndex());
        Assertions.assertEquals(slice.next().cursorIndex() - 10, slice.next().targetsEmpty());
        Assertions.assertEquals(List.of(), slice.items());
        Assertions.assertEquals(3, slice.next().sequenceHighWater());
    }

    /** A host name that never resolves fails at its deadline and is committed, so the run moves past it. */
    @Test
    void stuckFirstTargetCommitsAsFailedAtItsDeadline() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.3", "443", false);
        CountDownLatch release = new CountDownLatch(1);
        ConnectionService probes = url -> {
            if (url.equals(targets.target(0))) {
                while (release.getCount() > 0) {
                    try {
                        release.await();
                    } catch (InterruptedException ignored) {
                        // a lookup the JVM cannot interrupt
                    }
                }
            }
            return chainOf(1);
        };

        SliceScanner.Slice slice = scanner(1_000, 200, probes)
                .scan(at(targets, 0, 0), targets, 0, ROOMY_ITEMS, ROOMY_BYTES, 3, CERTIFICATES);

        Assertions.assertEquals(3, slice.next().cursorIndex());
        Assertions.assertEquals(1, slice.next().targetsFailed());
        Assertions.assertEquals(Map.of("probe deadline exceeded", 1L), slice.next().failedByReason());
        Assertions
                .assertEquals(List.of(targets.target(1), targets.target(2)),
                        slice.items().stream().map(SliceScannerTest::sourceOf).toList());
        Assertions.assertEquals(1, abandoned.count());
        release.countDown();
    }

    @Test
    void finishedRunAnswersEmptyAndNotMore() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);
        AtomicInteger probed = new AtomicInteger();
        RunHandle finished = at(targets, 4, 7).withState(RunHandle.RunState.STOPPED);

        SliceScanner.Slice slice = scanner(url -> {
            probed.incrementAndGet();
            return chainOf(1);
        }).scan(finished, targets, 7, ROOMY_ITEMS, ROOMY_BYTES, 4, CERTIFICATES);

        Assertions.assertEquals(List.of(), slice.items());
        Assertions.assertSame(finished, slice.next());
        Assertions.assertFalse(slice.more());
        Assertions.assertEquals(0, probed.get());
    }

    @Test
    void countsYieldPerResourceAndOutcomesPerTarget() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.4", "443", false);
        ConnectionService probes = url -> switch ((int) indexOf(targets, url)) {
            case 0 -> chainOf(2);
            case 1 -> throw new ConnectException("Connection refused");
            case 2 -> throw new IOException("no usable answer");
            default -> chainOf(1);
        };

        SliceScanner.Slice slice = scanner(probes)
                .scan(at(targets, 0, 0), targets, 0, ROOMY_ITEMS, ROOMY_BYTES, 4,
                        Set.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));

        RunHandle next = slice.next();
        Assertions
                .assertEquals(Map.of(Resource.CERTIFICATE.getCode(), 3L, Resource.CRYPTOGRAPHIC_KEY.getCode(), 3L),
                        next.yieldByResource());
        Assertions.assertEquals(4, next.targetsProcessed());
        Assertions.assertEquals(1, next.targetsEmpty());
        Assertions.assertEquals(1, next.targetsFailed());
        Assertions.assertEquals(Map.of("IOException", 1L), next.failedByReason());
        Assertions.assertEquals(RunHandle.RunState.RUNNING, next.state());
    }
}
