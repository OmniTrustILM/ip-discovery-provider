package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveredCertificateDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.dto.ConnectionResponse;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.util.KeyMapper;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ConnectException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import javax.net.ssl.SSLHandshakeException;
import javax.security.auth.x500.X500Principal;
import org.awaitility.Awaitility;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class TargetProberTest {

    private static final String URL = "https://10.0.0.1:443";
    private static final long GENEROUS_DEADLINE_MS = 10_000;

    private static X509Certificate certificate;

    private final AbandonedProbes abandoned = new AbandonedProbes();

    @BeforeAll
    static void mintCertificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        X500Principal subject = new X500Principal("CN=target-prober-test");
        certificate = new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
                        Date.from(Instant.now().minus(Duration.ofDays(1))),
                        Date.from(Instant.now().plus(Duration.ofDays(1))), subject, pair.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())));
    }

    private TargetProber proberWith(ConnectionService probes) {
        return new TargetProber(probes, abandoned);
    }

    private static ConnectionResponse chainOf(X509Certificate... chain) {
        return new ConnectionResponse("TLS_AES_256_GCM_SHA384", chain);
    }

    private TargetResult probeOnce(ConnectionService probes, Set<Resource> resources) {
        TargetProber prober = proberWith(probes);
        CompletableFuture<TargetResult> probe = prober.start(7, URL, resources);
        return prober.await(probe, 7, System.nanoTime() + Duration.ofMillis(GENEROUS_DEADLINE_MS).toNanos());
    }

    // --- the deadline ---

    /**
     * A probe whose thread will not let go, such as a host-name lookup the JVM cannot interrupt. The slice still has to
     * end on time, so the probe completes as failed at its deadline and its thread is counted until it returns.
     */
    @Test
    void stuckProbeCompletesAsFailedAtItsDeadline() {
        CountDownLatch release = new CountDownLatch(1);
        TargetProber prober = proberWith(url -> {
            awaitUninterruptibly(release);
            return chainOf(certificate);
        });

        CompletableFuture<TargetResult> probe = prober.start(0, "stuck.example:443", Set.of(Resource.CERTIFICATE));
        TargetResult result = prober.await(probe, 0, System.nanoTime() + Duration.ofMillis(200).toNanos());

        Assertions.assertEquals(TargetOutcome.FAILED, result.outcome());
        Assertions.assertEquals("probe deadline exceeded", result.failureReason());
        Assertions.assertEquals(List.of(), result.items(), "a late result is never used");
        Assertions.assertEquals(1, abandoned.count());

        release.countDown();
        Awaitility.await().atMost(Duration.ofSeconds(2)).until(() -> abandoned.count() == 0);
    }

    @Test
    void aProbeThatFinishedIsNotCountedAsAbandoned() {
        TargetResult result = probeOnce(url -> chainOf(certificate), Set.of(Resource.CERTIFICATE));

        Assertions.assertEquals(TargetOutcome.FOUND, result.outcome());
        Assertions.assertEquals(7, result.index());
        Assertions.assertEquals(0, abandoned.count());
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        boolean interrupted = false;
        while (latch.getCount() > 0) {
            try {
                latch.await();
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    // --- items ---

    @Test
    void buildsACertificateItemFromTheChain() throws Exception {
        TargetResult result = probeOnce(url -> chainOf(certificate), Set.of(Resource.CERTIFICATE));

        Assertions.assertEquals(1, result.items().size());
        DiscoveredItemDto item = result.items().getFirst();
        Assertions.assertNull(item.getSequence(), "items are numbered by the slice that commits them");
        Assertions
                .assertEquals(
                        HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded())),
                        item.getUniqueRef());
        Assertions
                .assertEquals(Base64.getEncoder().encodeToString(certificate.getEncoded()),
                        ((DiscoveredCertificateDto) item.getPayload()).getCertificateData());
        Assertions.assertNotNull(item.getDiscoveredAt());
        Assertions.assertNull(result.failureReason());
    }

    /**
     * The keys are the certificates' own. A run that asks for both gets one key item beside each certificate item.
     */
    @Test
    void buildsAKeyItemBesideEachCertificateWhenTheRunAsksForBoth() {
        TargetResult result = probeOnce(url -> chainOf(certificate, certificate),
                Set.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));

        Assertions
                .assertEquals(
                        List
                                .of(DiscoveredCertificateDto.class, DiscoveredKeyDto.class,
                                        DiscoveredCertificateDto.class, DiscoveredKeyDto.class),
                        result.items().stream().map(item -> item.getPayload().getClass()).toList());
    }

    /**
     * The platform correlates staged keys on SHA-256 over the base64 SPKI text, so the same key on two hosts is one.
     */
    @Test
    void keyItemIsReferencedByItsFingerprintOverTheBase64Text() throws Exception {
        TargetResult result = probeOnce(url -> chainOf(certificate), Set.of(Resource.CRYPTOGRAPHIC_KEY));

        Assertions.assertEquals(1, result.items().size());
        String spki = Base64.getEncoder().encodeToString(certificate.getPublicKey().getEncoded());
        Assertions.assertEquals(KeyMapper.fingerprintOf(spki), result.items().getFirst().getUniqueRef());
    }

    /** Where an item was found; without it an inventory cannot say which host and port produced a certificate. */
    @Test
    void recordsWhereEachItemWasFound() {
        TargetResult result = probeOnce(url -> chainOf(certificate),
                Set.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));

        for (DiscoveredItemDto item : result.items()) {
            MetadataAttributeV3 source = (MetadataAttributeV3) item.getMeta().getFirst();
            Assertions.assertEquals("meta_discoverySource", source.getName());
            Assertions.assertEquals(URL, source.getContent().getFirst().getData());
        }
    }

    /** The slice holds pages to maxBytes with this figure, so it has to cover each whole serialised item. */
    @Test
    void chargesEachItemAtLeastWhatItSerialisesTo() throws Exception {
        TargetResult result = probeOnce(url -> chainOf(certificate),
                Set.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));

        long expected = TargetProber.weightOf(certificate.getEncoded().length)
                + TargetProber.base64Length(certificate.getPublicKey().getEncoded().length) + 1_024;
        Assertions.assertEquals(expected, result.itemBytes());
        Assertions
                .assertTrue(TargetProber.weightOf(1000) > 1981,
                        "a 1000-byte certificate serialises to about 1981 bytes");
        Assertions.assertEquals(4, TargetProber.base64Length(3), "base64 is four characters per three bytes");
        Assertions.assertEquals(8, TargetProber.base64Length(4), "a partial group still costs a whole group");
    }

    /** A keys-only run needs the public key, not the DER, and must not fail over an encoding it never asked for. */
    @Test
    void buildsKeysFromACertificateWhoseEncodingCannotBeRead() throws Exception {
        X509Certificate unencodable = Mockito.mock(X509Certificate.class);
        Mockito.when(unencodable.getEncoded()).thenThrow(new CertificateEncodingException("no encoding"));
        Mockito.when(unencodable.getPublicKey()).thenReturn(certificate.getPublicKey());

        TargetResult result = probeOnce(url -> chainOf(unencodable), Set.of(Resource.CRYPTOGRAPHIC_KEY));

        Assertions.assertEquals(TargetOutcome.FOUND, result.outcome());
        Assertions.assertEquals(1, result.items().size());
    }

    // --- outcomes and failure reasons ---

    /**
     * A certificate this connector cannot use is its own defect. The target answered, so it fails rather than counting
     * as empty, under a reason that marks the failure as ours.
     */
    @Test
    void failsATargetWhoseCertificateCannotBeUsed() throws Exception {
        X509Certificate unmappable = Mockito.mock(X509Certificate.class);
        Mockito.when(unmappable.getEncoded()).thenThrow(new CertificateEncodingException("no encoding"));

        TargetResult result = probeOnce(url -> chainOf(unmappable), Set.of(Resource.CERTIFICATE));

        Assertions.assertEquals(TargetOutcome.FAILED, result.outcome());
        Assertions
                .assertEquals("Certificate this connector could not use (CertificateEncodingException)",
                        result.failureReason());
        Assertions.assertEquals(List.of(), result.items());
    }

    /**
     * Each certificate in a chain is its own item. When a later one cannot be used, the target fails under that reason,
     * and the certificates before it still reach Core rather than being lost with it.
     */
    @Test
    void keepsTheCertificatesBeforeOneItCannotUse() throws Exception {
        X509Certificate unmappable = Mockito.mock(X509Certificate.class);
        Mockito.when(unmappable.getEncoded()).thenThrow(new CertificateEncodingException("no encoding"));

        TargetResult result = probeOnce(url -> chainOf(certificate, unmappable), Set.of(Resource.CERTIFICATE));

        Assertions.assertEquals(TargetOutcome.FAILED, result.outcome());
        Assertions
                .assertEquals("Certificate this connector could not use (CertificateEncodingException)",
                        result.failureReason());
        Assertions.assertEquals(1, result.items().size());
        Assertions
                .assertEquals(Base64.getEncoder().encodeToString(certificate.getEncoded()),
                        ((DiscoveredCertificateDto) result.items().getFirst().getPayload()).getCertificateData());
        Assertions.assertEquals(TargetProber.weightOf(certificate.getEncoded().length), result.itemBytes());
    }

    /** Publishing the certificate and then failing on its key would hand Core half of a failed target's pair. */
    @Test
    void buildsNeitherItemWhenTheKeyCannotBeMapped() throws Exception {
        PublicKey unreadable = Mockito.mock(PublicKey.class);
        Mockito.when(unreadable.getEncoded()).thenReturn(null);
        X509Certificate half = Mockito.mock(X509Certificate.class);
        Mockito.when(half.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        Mockito.when(half.getPublicKey()).thenReturn(unreadable);

        TargetResult result = probeOnce(url -> chainOf(half), Set.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));

        Assertions.assertEquals(TargetOutcome.FAILED, result.outcome());
        Assertions.assertEquals(List.of(), result.items());
        Assertions.assertTrue(result.failureReason().startsWith("Certificate this connector could not use"));
    }

    @Test
    void countsATargetWithNothingListeningAsEmpty() {
        TargetResult result = probeOnce(url -> {
            throw new ConnectException("Connection refused");
        }, Set.of(Resource.CERTIFICATE));

        Assertions.assertEquals(TargetOutcome.EMPTY, result.outcome());
        Assertions.assertNull(result.failureReason(), "an address with nothing on it is not a failure");
    }

    @Test
    void countsATlsAnswerWithoutCertificatesAsEmpty() {
        TargetResult result = probeOnce(url -> chainOf(), Set.of(Resource.CERTIFICATE));

        Assertions.assertEquals(TargetOutcome.EMPTY, result.outcome());
        Assertions.assertEquals(List.of(), result.items());
    }

    @Test
    void namesTheTlsAlertAFailedTargetAnsweredWith() {
        TargetResult result = probeOnce(url -> {
            throw new SSLHandshakeException("Received fatal alert: handshake_failure");
        }, Set.of(Resource.CERTIFICATE));

        Assertions.assertEquals(TargetOutcome.FAILED, result.outcome());
        Assertions.assertEquals("TLS alert handshake_failure", result.failureReason());
    }

    @Test
    void namesTheExceptionForAFailureItDoesNotRecognise() {
        TargetResult result = probeOnce(url -> {
            throw new IOException("no usable answer");
        }, Set.of(Resource.CERTIFICATE));

        Assertions.assertEquals(TargetOutcome.FAILED, result.outcome());
        Assertions.assertEquals("IOException", result.failureReason());
    }
}
