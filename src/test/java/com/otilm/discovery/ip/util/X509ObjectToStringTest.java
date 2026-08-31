package com.otilm.discovery.ip.util;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.security.auth.x500.X500Principal;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

class X509ObjectToStringTest {

    private static X509Certificate selfSigned() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        X500Principal subject = new X500Principal("CN=x509-to-string-test");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.ONE,
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(1, ChronoUnit.DAYS)),
                subject,
                keyPair.getPublic());

        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())));
    }

    @Test
    void writesTheCertificateAsPem() throws Exception {
        String pem = X509ObjectToString.toPem(selfSigned());

        Assertions.assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----"), pem);
        Assertions.assertTrue(pem.trim().endsWith("-----END CERTIFICATE-----"), pem);
    }

    @Test
    void pemRoundTripsBackToTheSameCertificate() throws Exception {
        X509Certificate certificate = selfSigned();

        String pem = X509ObjectToString.toPem(certificate);
        String body = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");

        Assertions.assertArrayEquals(certificate.getEncoded(), java.util.Base64.getDecoder().decode(body));
    }

    @Test
    void surfacesACertificateThatCannotBeEncoded() throws Exception {
        X509Certificate broken = Mockito.mock(X509Certificate.class);
        Mockito.when(broken.getEncoded()).thenThrow(new CertificateEncodingException("unencodable"));

        // JcaPEMWriter wraps the encoding failure in an IllegalArgumentException, so it bypasses the
        // IOException catch in toPem and reaches the caller. That catch only covers writer IO faults,
        // which a StringWriter cannot produce.
        IllegalArgumentException thrown =
                Assertions.assertThrows(IllegalArgumentException.class, () -> X509ObjectToString.toPem(broken));
        Assertions.assertTrue(thrown.getMessage().contains("Cannot encode object"), thrown.getMessage());
    }

    @Test
    void cannotBeInstantiated() throws NoSuchMethodException {
        Constructor<X509ObjectToString> constructor = X509ObjectToString.class.getDeclaredConstructor();
        constructor.setAccessible(true);

        InvocationTargetException thrown =
                Assertions.assertThrows(InvocationTargetException.class, constructor::newInstance);
        Assertions.assertInstanceOf(IllegalStateException.class, thrown.getCause());
    }
}
