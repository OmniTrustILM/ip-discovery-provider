package com.otilm.discovery.ip.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HexFormat;

/**
 * The public key a scanned certificate already carries.
 *
 * <p>
 * These are the certificates' own keys, not independently discovered ones: a run asking for {@code keys} gets the
 * public keys of the certificates it would otherwise have got, at no extra network cost, because a TLS handshake
 * yields the whole chain.
 */
public final class KeyMapper {

    private KeyMapper() {
        throw new IllegalStateException("Utility Class");
    }

    /**
     * The fingerprint the platform correlates on: SHA-256 over the UTF-8 bytes of the <em>base64</em> SPKI text,
     * lowercase hex.
     *
     * <p>
     * Not over the DER. Core hashes the serialized key value, and its staged-key correlation compares exactly those
     * values, so a DER-based hash matches nothing and every discovered key looks newly discovered forever — a defect
     * that produces no error, only endless duplicates.
     */
    public static String fingerprintOf(String base64Spki) throws NoSuchAlgorithmException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(base64Spki.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest);
    }

    public static DiscoveredKeyDto toKey(X509Certificate certificate) throws NoSuchAlgorithmException {
        PublicKey publicKey = certificate.getPublicKey();
        String spki = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        DiscoveredKeyDto key = new DiscoveredKeyDto();
        key.setType(KeyType.PUBLIC_KEY);
        key.setAlgorithm(algorithmOf(publicKey.getAlgorithm()));
        key.setLength(lengthOf(publicKey));
        key.setPublicKeyFormat(KeyFormat.SPKI);
        key.setPublicKey(spki);
        key.setFingerprint(fingerprintOf(spki));
        return key;
    }

    /**
     * Maps a JCA algorithm name onto the platform's enum.
     *
     * <p>
     * The fallback is deliberate and is {@code UNKNOWN} rather than dropping the item or failing the run: an
     * algorithm this enum does not carry is still a key worth reporting, and reporting what is known beats reporting
     * nothing. Both alternatives lose information an operator asked for.
     */
    public static KeyAlgorithm algorithmOf(String jcaName) {
        if (jcaName == null) {
            return KeyAlgorithm.UNKNOWN;
        }
        return switch (jcaName.toUpperCase().replace("-", "").replace("+", "PLUS")) {
            case "RSA" -> KeyAlgorithm.RSA;
            // JCA says EC for the key; the platform names the signature family it belongs to.
            case "EC", "ECDSA" -> KeyAlgorithm.ECDSA;
            case "FALCON" -> KeyAlgorithm.FALCON;
            case "MLDSA" -> KeyAlgorithm.MLDSA;
            case "MLKEM" -> KeyAlgorithm.MLKEM;
            case "SLHDSA" -> KeyAlgorithm.SLHDSA;
            case "DILITHIUM" -> KeyAlgorithm.DILITHIUM;
            case "SPHINCSPLUS" -> KeyAlgorithm.SPHINCSPLUS;
            default -> KeyAlgorithm.UNKNOWN;
        };
    }

    /**
     * Key size in bits, or null when it cannot be read from the key alone.
     *
     * <p>
     * Null rather than a guess: length is used for compliance decisions, and a wrong number there is worse than an
     * absent one. RSA and EC cover every key a TLS chain realistically presents today.
     */
    public static Integer lengthOf(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength();
        }
        if (publicKey instanceof ECPublicKey ec) {
            return ec.getParams().getCurve().getField().getFieldSize();
        }
        return null;
    }
}
