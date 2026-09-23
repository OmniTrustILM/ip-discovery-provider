package com.otilm.discovery.ip.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.Locale;

class KeyMapperTest {

    private static X509Certificate certificateFor(KeyPair pair, String signatureAlgorithm) throws Exception {
        X500Principal subject = new X500Principal("CN=key-mapper-test");
        return new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
                        Date.from(Instant.now().minus(Duration.ofDays(1))),
                        Date.from(Instant.now().plus(Duration.ofDays(1))), subject, pair.getPublic())
                                .build(new JcaContentSignerBuilder(signatureAlgorithm).build(pair.getPrivate())));
    }

    private static X509Certificate rsaCertificate(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return certificateFor(generator.generateKeyPair(), "SHA256withRSA");
    }

    private static X509Certificate ecCertificate(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return certificateFor(generator.generateKeyPair(), "SHA256withECDSA");
    }

    /**
     * The fingerprint has to be what the platform correlates on: SHA-256 over the UTF-8 bytes of the base64 SPKI,
     * lowercase hex. Hashing the DER instead matches nothing, and the symptom is not an error — every discovered key
     * is reported as newly discovered, forever.
     */
    @Test
    void fingerprintsTheBase64TextTheWayThePlatformDoes() throws Exception {
        X509Certificate certificate = rsaCertificate(2048);
        byte[] spkiDer = certificate.getPublicKey().getEncoded();
        String base64 = Base64.getEncoder().encodeToString(spkiDer);

        String expected = HexFormat
                .of()
                .formatHex(MessageDigest.getInstance("SHA-256").digest(base64.getBytes(StandardCharsets.UTF_8)));
        String derBased = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(spkiDer));

        DiscoveredKeyDto key = KeyMapper.toKey(certificate);

        Assertions.assertEquals(expected, key.getFingerprint());
        Assertions
                .assertNotEquals(derBased, key.getFingerprint(),
                        "hashing the DER is the mistake this test exists to catch");
    }

    /**
     * A pinned value rather than the recipe run twice. The test above derives its expectation the way the code does,
     * so a misreading of the recipe satisfies both; this one cannot be satisfied by anything but the recipe Core
     * uses, since the digest was computed outside this codebase.
     */
    @Test
    void fingerprintMatchesAValueComputedOutsideThisCodebase() throws Exception {
        String spki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEN5vbOLMJZ0yBHHdchjTLLyOdCxwmUMGjMli+69gd+JTy"
                + "9/OAt1hXkairU621ARNCBjdwUKTqoNM/me1r4TjH1w==";

        Assertions
                .assertEquals("0ecddec47f6febd61848e207476fdf2a42877145c0462d30e95442ccc6293a79",
                        KeyMapper.fingerprintOf(spki));
    }

    @Test
    void fingerprintIsLowercaseHex() throws Exception {
        String fingerprint = KeyMapper.toKey(rsaCertificate(2048)).getFingerprint();

        Assertions.assertEquals(64, fingerprint.length());
        Assertions.assertEquals(fingerprint.toLowerCase(), fingerprint);
    }

    @Test
    void reportsThePublicHalfOfTheChainsKeyInSpkiForm() throws Exception {
        X509Certificate certificate = rsaCertificate(2048);

        DiscoveredKeyDto key = KeyMapper.toKey(certificate);

        Assertions.assertEquals(KeyType.PUBLIC_KEY, key.getType());
        Assertions.assertEquals(KeyFormat.SPKI, key.getPublicKeyFormat());
        Assertions
                .assertEquals(Base64.getEncoder().encodeToString(certificate.getPublicKey().getEncoded()),
                        key.getPublicKey());
    }

    @Test
    void readsTheLengthOfAnRsaKey() throws Exception {
        Assertions.assertEquals(2048, KeyMapper.toKey(rsaCertificate(2048)).getLength());
        Assertions.assertEquals(3072, KeyMapper.toKey(rsaCertificate(3072)).getLength());
    }

    @Test
    void readsTheFieldSizeOfAnEcKey() throws Exception {
        Assertions.assertEquals(256, KeyMapper.toKey(ecCertificate("secp256r1")).getLength());
        Assertions.assertEquals(384, KeyMapper.toKey(ecCertificate("secp384r1")).getLength());
    }

    @Test
    void mapsTheAlgorithmsAChainRealisticallyCarries() throws Exception {
        Assertions.assertEquals(KeyAlgorithm.RSA, KeyMapper.toKey(rsaCertificate(2048)).getAlgorithm());
        Assertions.assertEquals(KeyAlgorithm.ECDSA, KeyMapper.toKey(ecCertificate("secp256r1")).getAlgorithm());
    }

    @Test
    void mapsThePostQuantumNamesTheEnumCarries() {
        Assertions.assertEquals(KeyAlgorithm.MLDSA, KeyMapper.algorithmOf("ML-DSA"));
        Assertions.assertEquals(KeyAlgorithm.MLKEM, KeyMapper.algorithmOf("ML-KEM"));
        Assertions.assertEquals(KeyAlgorithm.SLHDSA, KeyMapper.algorithmOf("SLH-DSA"));
        Assertions.assertEquals(KeyAlgorithm.FALCON, KeyMapper.algorithmOf("Falcon"));
        Assertions.assertEquals(KeyAlgorithm.SPHINCSPLUS, KeyMapper.algorithmOf("SPHINCS+"));
        Assertions.assertEquals(KeyAlgorithm.DILITHIUM, KeyMapper.algorithmOf("Dilithium"));
    }

    /**
     * An algorithm the enum does not carry is still a key worth reporting. Dropping the item or failing the run both
     * lose something the operator asked for, so the fallback is explicit rather than incidental.
     */
    @Test
    void fallsBackToUnknownRatherThanLosingTheKey() {
        Assertions.assertEquals(KeyAlgorithm.UNKNOWN, KeyMapper.algorithmOf("Ed25519"));
        Assertions.assertEquals(KeyAlgorithm.UNKNOWN, KeyMapper.algorithmOf("X25519"));
        Assertions.assertEquals(KeyAlgorithm.UNKNOWN, KeyMapper.algorithmOf("DSA"));
        Assertions.assertEquals(KeyAlgorithm.UNKNOWN, KeyMapper.algorithmOf("something-new"));
        Assertions.assertEquals(KeyAlgorithm.UNKNOWN, KeyMapper.algorithmOf(null));
    }

    @Test
    void cannotBeInstantiated() throws NoSuchMethodException {
        Constructor<KeyMapper> constructor = KeyMapper.class.getDeclaredConstructor();
        constructor.setAccessible(true);

        InvocationTargetException thrown =
                Assertions.assertThrows(InvocationTargetException.class, constructor::newInstance);
        Assertions.assertInstanceOf(IllegalStateException.class, thrown.getCause());
    }

    /**
     * Upper-casing with the default locale turns "Dilithium" into a dotted-I form under tr and az, which matches
     * nothing and reports a recognised algorithm as UNKNOWN depending on where the JVM runs.
     */
    @Test
    void mapsTheSameWhateverLocaleTheJvmRunsIn() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(new Locale("tr", "TR"));
            Assertions.assertEquals(KeyAlgorithm.DILITHIUM, KeyMapper.algorithmOf("Dilithium"));
            Assertions.assertEquals(KeyAlgorithm.MLDSA, KeyMapper.algorithmOf("ML-DSA"));
        } finally {
            Locale.setDefault(original);
        }
    }

    /**
     * A provider names a parameter set, not a family. Matching exactly reported every real post-quantum name as
     * UNKNOWN, which is indistinguishable from not mapping them at all.
     */
    @Test
    void mapsTheParameterSetNamesProvidersActuallyUse() {
        Assertions.assertEquals(KeyAlgorithm.SLHDSA, KeyMapper.algorithmOf("SLH-DSA-SHA2-128F"));
        Assertions.assertEquals(KeyAlgorithm.MLDSA, KeyMapper.algorithmOf("ML-DSA-65"));
        Assertions.assertEquals(KeyAlgorithm.MLKEM, KeyMapper.algorithmOf("ML-KEM-768"));
        Assertions.assertEquals(KeyAlgorithm.FALCON, KeyMapper.algorithmOf("Falcon-512"));
        Assertions.assertEquals(KeyAlgorithm.DILITHIUM, KeyMapper.algorithmOf("CRYSTALS-Dilithium"));
        Assertions.assertEquals(KeyAlgorithm.UNKNOWN, KeyMapper.algorithmOf("something-new"));
    }

}
