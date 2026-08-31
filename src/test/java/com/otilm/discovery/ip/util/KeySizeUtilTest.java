package com.otilm.discovery.ip.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

class KeySizeUtilTest {

    @Test
    void rsaKeyReportsModulusLength() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        Assertions.assertEquals(2048, KeySizeUtil.getKeyLength(generator.generateKeyPair().getPublic()));
    }

    @Test
    void ecKeyReportsCurveOrderLength() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));

        Assertions.assertEquals(256, KeySizeUtil.getKeyLength(generator.generateKeyPair().getPublic()));
    }

    @Test
    void ecKeyOnLargerCurveReportsThatCurvesLength() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));

        Assertions.assertEquals(384, KeySizeUtil.getKeyLength(generator.generateKeyPair().getPublic()));
    }

    @Test
    void dsaKeyReportsPrimeLength() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        generator.initialize(1024);

        Assertions.assertEquals(1024, KeySizeUtil.getKeyLength(generator.generateKeyPair().getPublic()));
    }

    @Test
    void unrecognisedKeyTypeReportsMinusOne() {
        PublicKey opaque = new PublicKey() {
            @Override
            public String getAlgorithm() {
                return "XYZ";
            }

            @Override
            public String getFormat() {
                return "RAW";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };

        Assertions.assertEquals(-1, KeySizeUtil.getKeyLength(opaque));
    }
}
