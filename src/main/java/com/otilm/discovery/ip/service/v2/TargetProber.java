package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveredCertificateDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.dto.ConnectionResponse;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.util.KeyMapper;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Probes one target and turns what it presented into items.
 *
 * <p>
 * A probe always completes by its deadline. The connection's own watchdog closes a socket at the probe's total timeout,
 * but it cannot stop a thread blocked where closing a socket does not reach, such as a host-name lookup. Such a probe
 * completes as failed at its deadline whether or not its thread has let go, and whatever the thread produces later is
 * never used.
 */
@Component
public class TargetProber {

    private static final Logger logger = LoggerFactory.getLogger(TargetProber.class);

    /** Lets the connection's own watchdog, which fires at the same deadline, report first. */
    static final Duration GRACE = Duration.ofMillis(250);

    static final String DEADLINE_EXCEEDED = "probe deadline exceeded";

    private final ConnectionService connectionService;
    private final AbandonedProbes abandoned;

    public TargetProber(ConnectionService connectionService, AbandonedProbes abandoned) {
        this.connectionService = connectionService;
        this.abandoned = abandoned;
    }

    /** Starts the probe on its own virtual thread. */
    CompletableFuture<TargetResult> start(long index, String url, Set<Resource> resources) {
        CompletableFuture<TargetResult> probe = new CompletableFuture<>();
        Thread.ofVirtual().start(() -> {
            try {
                probe.complete(probe(index, url, resources));
            } catch (Throwable failure) {
                probe.completeExceptionally(failure);
            }
        });
        return probe;
    }

    /**
     * Waits for the probe until its deadline plus a short grace, and no longer.
     *
     * @throws IllegalStateException if the calling thread is interrupted; nothing about the target is known then, and
     * reporting it failed would skip it
     */
    TargetResult await(CompletableFuture<TargetResult> probe, long index, long deadlineNanos) {
        long waitNanos = Math.max(0L, deadlineNanos + GRACE.toNanos() - System.nanoTime());
        try {
            return probe.get(waitNanos, TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            abandoned.register(probe);
            logger
                    .warn("Probe of target {} is still running past its deadline; abandoned it ({} abandoned)", index,
                            abandoned.count());
            return TargetResult.failed(index, DEADLINE_EXCEEDED);
        } catch (ExecutionException e) {
            logger.warn("Probe of target {} ended with {}", index, e.getCause().toString());
            return TargetResult.failed(index, TargetOutcome.reasonOf(e.getCause()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            abandoned.register(probe);
            throw new IllegalStateException("Interrupted while waiting for the probe of target " + index, e);
        }
    }

    private TargetResult probe(long index, String url, Set<Resource> resources) {
        List<DiscoveredItemDto> items = new ArrayList<>();
        long bytes = 0;
        try {
            ConnectionResponse response = connectionService.getCertificates(url);
            X509Certificate[] chain = response.getCertificates();
            if (chain.length == 0) {
                return new TargetResult(index, TargetOutcome.EMPTY, List.of(), 0L, null);
            }
            for (X509Certificate certificate : chain) {
                bytes += emit(certificate, url, resources, items);
            }
            return new TargetResult(index, TargetOutcome.FOUND, List.copyOf(items), bytes, null);
        } catch (ItemNotMappedException e) {
            // Failed rather than empty: the target answered with a certificate, and it is this connector that could
            // not use it. The certificates before it in the chain are still sent.
            return new TargetResult(index, TargetOutcome.FAILED, List.copyOf(items), bytes, e.reason);
        } catch (Exception e) {
            logger.debug("Probe of {} ended without certificates: {}", url, e.getMessage());
            if (TargetOutcome.ofProbeFailure(e) == TargetOutcome.EMPTY) {
                return new TargetResult(index, TargetOutcome.EMPTY, List.of(), 0L, null);
            }
            return TargetResult.failed(index, TargetOutcome.reasonOf(e));
        }
    }

    /**
     * Turns one scanned certificate into the items the run asked for.
     *
     * <p>
     * Its own failure is kept apart from the probe's: it fails the target under a reason naming it as this connector's
     * defect, so a mapping that throws for every certificate cannot pass for hosts that refused the probe.
     *
     * @return the weight of the items added
     */
    private static long emit(X509Certificate certificate, String url, Set<Resource> resources,
            List<DiscoveredItemDto> items) {
        // Both items are built before either is added, so a certificate and its key reach Core together or not at all.
        // Certificates earlier in the chain are items of their own and are kept when a later one fails.
        DiscoveredItemDto certificateItem = null;
        long certificateWeight = 0;
        DiscoveredItemDto keyItem = null;
        long keyWeight = 0;
        try {
            if (resources.contains(Resource.CERTIFICATE)) {
                // A keys-only run needs the public key, not the encoding, and reading the DER first would fail such
                // a run over something it never asked for.
                byte[] der = certificate.getEncoded();
                certificateItem = certificateItem(der, url);
                certificateWeight = weightOf(der.length);
            }
            // Driven by the run's resource set rather than always on: a key per certificate roughly doubles item
            // count and sequence consumption.
            if (resources.contains(Resource.CRYPTOGRAPHIC_KEY)) {
                keyItem = keyItem(certificate, url);
                // From the key's own material rather than a constant: a post-quantum SPKI runs to several kilobytes,
                // which a fixed figure sized for RSA would charge as though it were a few hundred bytes.
                keyWeight = base64Length(certificate.getPublicKey().getEncoded().length) + ENVELOPE_BYTES;
            }
        } catch (Exception e) {
            logger.warn("Could not map a certificate from {}: {}", url, e.toString());
            throw new ItemNotMappedException(TargetOutcome.unusableCertificate(e));
        }
        if (certificateItem != null) {
            items.add(certificateItem);
        }
        if (keyItem != null) {
            items.add(keyItem);
        }
        return certificateWeight + keyWeight;
    }

    /** Carries a mapping fault out to the probe, which counts the target as failed. */
    private static final class ItemNotMappedException extends RuntimeException {
        private final String reason;

        private ItemNotMappedException(String reason) {
            super(reason, null, false, false);
            this.reason = reason;
        }
    }

    private static final String SOURCE_ATTRIBUTE_UUID = "c1f0e6a2-3d5b-4a17-9f8c-6b2e0d4a7e31";

    /**
     * Where the item was found, which the contract asks for as typed metadata and v1 attached per certificate as
     * discoverySource. Without it an operator has an inventory of certificates and no way to tell which host and port
     * produced any of them.
     */
    private static List<MetadataAttribute> sourceOf(String url) {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid(SOURCE_ATTRIBUTE_UUID);
        attribute.setName("meta_discoverySource");
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setDescription("The address and port this item was discovered on");

        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel("Discovery source");
        properties.setVisible(true);
        properties.setGlobal(false);
        attribute.setProperties(properties);

        attribute.setContent(List.of(new StringAttributeContentV3(url, url)));
        return List.of(attribute);
    }

    private static DiscoveredItemDto certificateItem(byte[] der, String url) throws NoSuchAlgorithmException {
        DiscoveredCertificateDto payload = new DiscoveredCertificateDto();
        payload.setCertificateData(Base64.getEncoder().encodeToString(der));

        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setUniqueRef(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(der)));
        item.setPayload(payload);
        item.setMeta(sourceOf(url));
        item.setDiscoveredAt(OffsetDateTime.now(ZoneOffset.UTC));
        return item;
    }

    /**
     * The key a certificate already carries. Its uniqueRef is the fingerprint, which is what the platform correlates
     * staged keys on, so the same key seen on two hosts collapses to one item rather than two.
     */
    private static DiscoveredItemDto keyItem(X509Certificate certificate, String url) throws NoSuchAlgorithmException {
        DiscoveredKeyDto payload = KeyMapper.toKey(certificate);

        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setUniqueRef(payload.getFingerprint());
        item.setPayload(payload);
        item.setMeta(sourceOf(url));
        item.setDiscoveredAt(OffsetDateTime.now(ZoneOffset.UTC));
        return item;
    }

    /**
     * Everything an item carries besides its payload: reference, timestamp, resource, source metadata and JSON quoting.
     * Measured against a serialised item and rounded up, since the error has to fall on the safe side.
     */
    private static final long ENVELOPE_BYTES = 1_024;

    /** Base64 is four characters per three bytes, rounded up to the next group. */
    static long base64Length(int rawBytes) {
        return 4L * ((rawBytes + 2) / 3);
    }

    /** The slice takes the weight rather than serialising the item again to measure it. */
    static long weightOf(int derLength) {
        return base64Length(derLength) + ENVELOPE_BYTES;
    }
}
