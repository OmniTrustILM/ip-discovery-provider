package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.connector.discovery.v2.DiscoveredCertificateDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.dto.ConnectionResponse;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.util.KeyMapper;
import com.otilm.discovery.ip.util.TargetEnumeration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * One run's scan: targets in chunks, results into the buffer, position into the handle.
 *
 * <p>
 * The cursor advances only at a chunk boundary, and a stop interrupts the chunk in flight rather than waiting for it.
 * A quiesce would have no bound to wait for — under backpressure the chunk proceeds at Core's drain cadence, or not
 * at all while the platform is unreachable, which is exactly the situation an operator reaches for stop in.
 *
 * <p>
 * Resume therefore re-scans the interrupted chunk. That is contract-legal: the duplicates collapse on
 * {@code uniqueRef}, at the cost of inflating {@code highestSequence} slightly against the true item count.
 */
public class ScanRunner {

    private static final Logger logger = LoggerFactory.getLogger(ScanRunner.class);

    /** Small enough that a stop discards little work, large enough that the handle is not rewritten per target. */
    static final int CHUNK_SIZE = 256;

    private final UUID runId;
    private final TargetEnumeration targets;
    private final ResultBuffer buffer;
    private final RunRegistry registry;
    private final ConnectionService connectionService;
    private final int parallelism;
    private final int chunkSize;
    private final Set<Resource> resources;

    private final AtomicBoolean stopping = new AtomicBoolean();
    /** A bound the run cannot continue past. Held so the scan ends deliberately rather than as a failed target. */
    private final AtomicReference<RuntimeException> fatal = new AtomicReference<>();

    /**
     * The chunk being scanned right now, readable while it runs.
     *
     * <p>
     * The checkpoint only advances at a boundary, and must: counting per target would double-count the interrupted
     * chunk when a resumed run scans it again, letting a stop inflate its own run. Progress has no such obligation —
     * it is advisory, recomputed on every read — so it reports the committed figure plus whatever this chunk has
     * done, and moves on every poll instead of once per 256 targets.
     */
    private final AtomicReference<ChunkTally> inFlightChunk = new AtomicReference<>();

    /** Run-level failure reasons, accumulated across chunks so the summary describes the whole sweep. */
    private final Map<String, AtomicLong> failureReasons = new java.util.concurrent.ConcurrentHashMap<>();
    private final List<Future<?>> inFlight = new ArrayList<>();

    public ScanRunner(UUID runId, TargetEnumeration targets, ResultBuffer buffer, RunRegistry registry,
            ConnectionService connectionService, int parallelism, Set<Resource> resources) {
        this(runId, targets, buffer, registry, connectionService, parallelism, CHUNK_SIZE, resources);
    }

    ScanRunner(UUID runId, TargetEnumeration targets, ResultBuffer buffer, RunRegistry registry,
            ConnectionService connectionService, int parallelism, int chunkSize, Set<Resource> resources) {
        this.resources = resources;
        this.runId = runId;
        this.targets = targets;
        this.buffer = buffer;
        this.registry = registry;
        this.connectionService = connectionService;
        this.parallelism = parallelism;
        this.chunkSize = chunkSize;
    }

    /**
     * Scans from the handle's cursor to the end of the enumeration, or until stopped. Blocking: the caller decides
     * which thread carries it.
     *
     * @return true if the enumeration was exhausted, false if a stop ended it early
     */
    public boolean scan() {
        long cursor = registry.find(runId).map(RunHandle::cursorIndex).orElse(0L);
        Semaphore concurrency = new Semaphore(parallelism);

        try (ExecutorService probes = Executors.newVirtualThreadPerTaskExecutor()) {
            while (cursor < targets.size()) {
                if (stopping.get()) {
                    return false;
                }
                long chunkEnd = Math.min(cursor + chunkSize, targets.size());
                ChunkTally tally = runChunk(probes, concurrency, cursor, chunkEnd);
                if (tally == null) {
                    // Interrupted mid-chunk. The cursor stays at the boundary, so resume re-scans this chunk; the
                    // items already buffered from it are duplicates Core collapses on uniqueRef.
                    return false;
                }
                cursor = chunkEnd;
                inFlightChunk.set(null);
                commit(cursor, tally);
            }
        }
        raiseIfFatal();
        return true;
    }

    /**
     * A buffer bound that cannot be waited out ends the run, naming the limit. Counting it as one more failed target
     * would be silent truncation: a legitimate dark sweep also reports millions of failed targets, so a
     * buffer-starved run would be indistinguishable from one that simply found nothing listening.
     */
    private void raiseIfFatal() {
        RuntimeException limit = fatal.get();
        if (limit != null) {
            throw limit;
        }
    }

    /** Interrupts whatever is in flight. The probes are on virtual threads, where a socket read does unblock. */
    public void stop() {
        stopping.set(true);
        cancelInFlight();
    }

    private void cancelInFlight() {
        synchronized (inFlight) {
            inFlight.forEach(future -> future.cancel(true));
        }
    }

    public boolean isStopping() {
        return stopping.get();
    }

    /** Targets finished inside the chunk in flight, not yet in the checkpoint. */
    public long inFlightProcessed() {
        ChunkTally tally = inFlightChunk.get();
        return tally == null ? 0L : tally.processed.get();
    }

    /** Failures among them, counted within the processed figure above rather than beside it. */
    public long inFlightFailed() {
        ChunkTally tally = inFlightChunk.get();
        return tally == null ? 0L : tally.failed.get();
    }

    /** @return the chunk's tally, or null if a stop interrupted it before every probe finished */
    private ChunkTally runChunk(ExecutorService probes, Semaphore concurrency, long from, long to) {
        ChunkTally tally = new ChunkTally();
        inFlightChunk.set(tally);
        List<Future<?>> futures = new ArrayList<>();
        synchronized (inFlight) {
            inFlight.clear();
        }
        for (long index = from; index < to; index++) {
            String url = targets.target(index);
            Future<?> future = probes.submit(() -> probe(url, concurrency, tally));
            futures.add(future);
            // Published one at a time rather than after the loop: a stop arriving mid-submission would otherwise
            // find nothing to cancel and wait out the whole chunk it was meant to cut through.
            synchronized (inFlight) {
                inFlight.add(future);
            }
        }
        if (stopping.get()) {
            // Lost the race the other way: stop ran before these were submitted, so it cancelled an empty list.
            cancelInFlight();
        }

        boolean complete = true;
        for (Future<?> future : futures) {
            try {
                future.get();
            } catch (java.util.concurrent.CancellationException e) {
                complete = false;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                inFlightChunk.set(null);
                return null;
            } catch (java.util.concurrent.ExecutionException e) {
                // A probe that threw has already been counted as failed; the run continues.
                logger.debug("Probe in run {} ended with {}", runId, e.getCause().toString());
            }
        }
        raiseIfFatal();
        if (!complete || stopping.get()) {
            // The chunk is being abandoned. Its work is not in the checkpoint and never will be, so it must stop
            // counting towards progress too, or a stopped run would keep reporting work it is about to redo.
            inFlightChunk.set(null);
            return null;
        }
        return tally;
    }

    private void probe(String url, Semaphore concurrency, ChunkTally tally) {
        try {
            concurrency.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        }
        try {
            ConnectionResponse response = connectionService.getCertificates(url);
            for (X509Certificate certificate : response.getCertificates()) {
                emit(certificate, url, tally);
            }
            tally.processed.incrementAndGet();
        } catch (InterruptedException e) {
            // A stop reaches a probe parked on backpressure exactly here. Nothing is counted: the cursor has not
            // advanced past this chunk, so the target is scanned again on resume.
            Thread.currentThread().interrupt();
        } catch (BufferBudget.BufferLimitExceededException e) {
            // Not a failed target: the run cannot hold what it is producing, and has to say so rather than report a
            // short scan that looks complete.
            if (fatal.compareAndSet(null, e)) {
                logger.error("Run {} cannot continue: {}", runId, e.getMessage());
            }
            stop();
        } catch (ItemNotMappedException e) {
            // The reason is already recorded, against the mapping rather than the probe. Counted the same way a
            // target that never answered is, since nothing usable came of it either way.
            tally.processed.incrementAndGet();
            tally.failed.incrementAndGet();
        } catch (Exception e) {
            logger.debug("Probe of {} in run {} failed: {}", url, runId, e.getMessage());
            recordFailure(tally, e.getClass().getSimpleName());
            tally.processed.incrementAndGet();
            tally.failed.incrementAndGet();
        } finally {
            concurrency.release();
        }
    }

    /**
     * Turns one scanned certificate into the items the run asked for.
     *
     * <p>
     * Its own failure is kept apart from the probe's. A target that did not answer and a certificate this connector
     * could not map both end as a failed target, but only one of them is our defect, and reporting them the same way
     * hides it: a mapping that threw for every certificate looks exactly like a range where nothing was listening.
     */
    private void emit(X509Certificate certificate, String url, ChunkTally tally) throws InterruptedException {
        try {
            byte[] der = certificate.getEncoded();
            if (resources.contains(Resource.CERTIFICATE)) {
                buffer.add(certificateItem(der, url), weightOf(der.length));
                counted(tally, Resource.CERTIFICATE);
            }
            // Driven by the run's resource set rather than always on: a key per certificate roughly doubles item
            // count, sequence consumption and buffer occupancy.
            if (resources.contains(Resource.CRYPTOGRAPHIC_KEY)) {
                buffer.add(keyItem(certificate, url), KEY_ITEM_WEIGHT);
                counted(tally, Resource.CRYPTOGRAPHIC_KEY);
            }
        } catch (InterruptedException | BufferBudget.BufferLimitExceededException e) {
            // Both mean the run itself is ending. Neither is a mapping fault, so they travel to the probe's handling.
            throw e;
        } catch (Exception e) {
            // Warned rather than debugged: the target answered, so this is the connector failing to use what it got.
            logger.warn("Run {} could not map a certificate from {}: {}", runId, url, e.toString());
            recordFailure(tally, ITEM_FAILURE_PREFIX + e.getClass().getSimpleName());
            throw new ItemNotMappedException(e);
        }
    }

    /** Carries a mapping fault out to the probe, which counts the target the same way it counts an unreachable one. */
    private static final class ItemNotMappedException extends RuntimeException {
        private ItemNotMappedException(Throwable cause) {
            super(cause);
        }
    }

    private static void recordFailure(ChunkTally tally, String reason) {
        tally.failures.computeIfAbsent(reason, key -> new AtomicLong()).incrementAndGet();
    }

    /**
     * The reasons this run's targets failed, commonest first, as "{@code 4094 x SSLHandshakeException}".
     *
     * <p>
     * Without it a wide sweep reports only a count, and every cause reads alike -- a range that is not listening, a
     * TLS stack that refuses a bare IP, and a bug in this connector all print the same number.
     */
    String failureSummary() {
        if (failureReasons.isEmpty()) {
            return "";
        }
        return ": " + failureReasons
                .entrySet()
                .stream()
                .sorted(Map.Entry.<String, AtomicLong>comparingByValue(Comparator.comparingLong(AtomicLong::get))
                        .reversed())
                .limit(TOP_FAILURE_REASONS)
                .map(reason -> reason.getValue().get() + " x " + reason.getKey())
                .collect(Collectors.joining(", "));
    }

    /**
     * Writes the chunk's work into the handle in one step, at the boundary. Counting per target instead would
     * double-count the interrupted chunk when a resumed run scans it again.
     */
    private void commit(long cursor, ChunkTally tally) {
        tally.failures
                .forEach((reason, count) -> failureReasons
                        .computeIfAbsent(reason, key -> new AtomicLong())
                        .addAndGet(count.get()));
        registry
                .update(runId, handle -> {
                    // A chunk finishing after a stop was recorded must not move the checkpoint: the stop has already
                    // answered with one, and Core would be left holding a handle the connector had moved past.
                    // Leaving the cursor where it was only costs re-scanning this chunk on resume.
                    if (handle.state() == RunHandle.RunState.STOPPED) {
                        return handle;
                    }
                    Map<String, Long> yield = new HashMap<>(handle.yieldByResource());
                    tally.yield.forEach((resource, count) -> yield.merge(resource, count.get(), Long::sum));
                    return new RunHandle(handle.state(), cursor, buffer.highestSequence(), handle.targetsDigest(),
                            handle.targetsProcessed() + tally.processed.get(),
                            handle.targetsFailed() + tally.failed.get(), Map.copyOf(yield));
                })
                .ifPresent(committed -> logger
                        // Per chunk rather than per target: a wide sweep is otherwise silent for its whole duration.
                        .info("Run {} at {}/{} targets ({} failed{}), {} items held", runId, committed.cursorIndex(),
                                targets.size(), committed.targetsFailed(), failureSummary(), buffer.held()));
    }

    private static void counted(ChunkTally tally, Resource resource) {
        tally.yield.computeIfAbsent(resource.getCode(), key -> new AtomicLong()).incrementAndGet();
    }

    /** Enough to name what is happening without turning one log line into a report. */
    private static final int TOP_FAILURE_REASONS = 3;

    /** Marks a reason as this connector failing to use a certificate, not a target failing to answer. */
    private static final String ITEM_FAILURE_PREFIX = "item:";

    private static final String SOURCE_ATTRIBUTE_UUID = "c1f0e6a2-3d5b-4a17-9f8c-6b2e0d4a7e31";

    /**
     * Where the item was found, which the contract asks for as typed metadata and v1 attached per certificate as
     * discoverySource. Without it an operator has an inventory of certificates and no way to tell which host and
     * port produced any of them.
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
        item.setDiscoveredAt(OffsetDateTime.now());
        return item;
    }

    /**
     * The key a certificate already carries. Its uniqueRef is the fingerprint, which is what the platform correlates
     * staged keys on, so the same key seen on two hosts collapses to one item rather than two.
     */
    private static DiscoveredItemDto keyItem(X509Certificate certificate, String url)
            throws NoSuchAlgorithmException {
        DiscoveredKeyDto payload = KeyMapper.toKey(certificate);

        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setUniqueRef(payload.getFingerprint());
        item.setPayload(payload);
        item.setMeta(sourceOf(url));
        item.setDiscoveredAt(OffsetDateTime.now());
        return item;
    }

    /** An SPKI, a hex fingerprint and four small fields; the largest realistic SPKI is an RSA-4096 at ~800 bytes. */
    private static final long KEY_ITEM_WEIGHT = 1_536;

    /**
     * The buffer takes the weight rather than measuring it, and this is the caller that owes it a truthful number.
     * The DER dominates a certificate item: base64 inflates it by a third, and the rest is a digest, a timestamp and
     * an enum.
     */
    private static long weightOf(int derLength) {
        return (derLength * 4L / 3) + 512;
    }

    private static final class ChunkTally {
        private final AtomicLong processed = new AtomicLong();
        private final AtomicLong failed = new AtomicLong();
        private final Map<String, AtomicLong> yield = new java.util.concurrent.ConcurrentHashMap<>();
        /** Why targets failed in this chunk, keyed by exception name; merged into the run's totals at the boundary. */
        private final Map<String, AtomicLong> failures = new java.util.concurrent.ConcurrentHashMap<>();
    }
}
