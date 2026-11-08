package com.otilm.discovery.ip.service.v2;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDrainRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryProgressDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResourceProgressDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStatusResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStopResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryV2ScopedRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.api.v2.CheckpointLostException;
import com.otilm.discovery.ip.api.v2.ConnectorBusyException;
import com.otilm.discovery.ip.api.v2.RunPastPointOfNoReturnException;
import com.otilm.discovery.ip.api.v2.UnknownRunException;
import com.otilm.discovery.ip.util.TargetEnumeration;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * The run lifecycle: initiate, status, results, stop, resume, cancel.
 *
 * <p>
 * Every call is a function of its request. Core replays the run's configuration and its checkpoint on each one, so this
 * node holds nothing between calls and any replica can serve any call. A results call scans one bounded slice from the
 * replayed checkpoint and answers it together with the checkpoint after it.
 */
@Service
public class CheckpointedRunService {

    private static final Logger logger = LoggerFactory.getLogger(CheckpointedRunService.class);

    /**
     * What a scan of this connector can produce. A run asking for anything else is refused rather than shortchanged.
     */
    private static final Set<Resource> SUPPORTED = EnumSet.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY);

    /** The bounds a drain that names none gets. */
    private static final int DEFAULT_MAX_ITEMS = 500;
    private static final long DEFAULT_MAX_BYTES = 5L * 1024 * 1024;

    private final SliceScanner scanner;
    private final SliceSettings settings;
    private final AbandonedProbes abandoned;
    private final DiscoveryAttributeService attributes;
    private final Semaphore slices;

    public CheckpointedRunService(SliceScanner scanner, SliceSettings settings, AbandonedProbes abandoned,
            DiscoveryAttributeService attributes) {
        this.scanner = scanner;
        this.settings = settings;
        this.abandoned = abandoned;
        this.attributes = attributes;
        this.slices = new Semaphore(settings.maxConcurrent());
    }

    /** Validates the run and mints its first checkpoint. Nothing starts, so a repeated initiate is harmless. */
    public DiscoveryInitiateResponseDto initiate(DiscoveryInitiateRequestDto request) {
        requireSupported(request.getResources());
        TargetEnumeration targets = enumerate(request);
        int parallelism = attributes.readParallelExecutions(request.getAttributes());
        requireCheckpointedOffered(request);

        logger
                .info("Run {} initiated: {} targets over {}, parallelism {}", request.getRunId(), targets.size(),
                        request.getResources().stream().map(Resource::getCode).toList(), parallelism);
        DiscoveryInitiateResponseDto response = accepted();
        response.setCheckpoint(RunHandle.initial(targets.digest()).encode());
        return response;
    }

    public DiscoveryStatusResponseDto status(DiscoveryRunRequestDto request) {
        requireSupported(request.getResources());
        RunHandle handle = requireHandle(request);
        TargetEnumeration targets = enumerate(request);
        if (!targets.digest().equals(handle.targetsDigest())) {
            logger.warn("Run {} replayed a checkpoint for a different set of targets", request.getRunId());
            throw new UnknownRunException(request.getRunId());
        }

        DiscoveryStatusResponseDto response = new DiscoveryStatusResponseDto();
        response
                .setState(handle.cursorIndex() >= targets.size()
                        ? DiscoveryRunState.COMPLETED
                        : DiscoveryRunState.RUNNING);
        response.setHighestSequence(handle.sequenceHighWater());
        response.setProgress(progressOf(handle, targets.size()));
        response.setMeta(failureReasonsOf(handle));
        return response;
    }

    /**
     * Scans one slice from the replayed checkpoint.
     *
     * <p>
     * Core keeps afterSequence equal to the checkpoint's high water, so any difference means the checkpoint is stale or
     * items were lost, and serving a page anyway would hide that.
     */
    public DiscoveryResultsResponseDto results(DiscoveryDrainRequestDto request) {
        UUID runId = request.getRunId();
        if (!offersCheckpointed(request)) {
            // From a Core that would not store this page's checkpoint. Its retry can reach one that does.
            throw new ConnectorBusyException("this drain does not offer checkpointed delivery, which this connector "
                    + "requires; a Core that offers it can take the retry");
        }
        requireSupported(request.getResources());
        RunHandle from = requireHandle(request);
        TargetEnumeration targets = enumerate(request);
        if (!targets.digest().equals(from.targetsDigest())) {
            logger.warn("Run {} replayed a checkpoint for a different set of targets", runId);
            throw new UnknownRunException(runId);
        }
        if (request.getAfterSequence() != from.sequenceHighWater()) {
            logger
                    .warn("Refusing to serve run {}: Core is at sequence {} and the checkpoint at {}", runId,
                            request.getAfterSequence(), from.sequenceHighWater());
            throw new UnknownRunException(runId);
        }
        int parallelism = attributes.readParallelExecutions(request.getAttributes());

        if (abandoned.count() >= settings.maxAbandonedProbes()) {
            throw new ConnectorBusyException(abandoned.count()
                    + " probes are still blocked past their deadline on this node; retry once they drain");
        }
        if (!slices.tryAcquire()) {
            throw new ConnectorBusyException(
                    "this node is already scanning " + settings.maxConcurrent() + " slices; retry shortly");
        }
        SliceScanner.Slice slice;
        try {
            slice = scanner
                    .scan(from, targets, request.getAfterSequence(),
                            request.getMaxItems() == null ? DEFAULT_MAX_ITEMS : request.getMaxItems(),
                            request.getMaxBytes() == null ? DEFAULT_MAX_BYTES : request.getMaxBytes(), parallelism,
                            EnumSet.copyOf(request.getResources()));
        } finally {
            slices.release();
        }

        RunHandle next = slice.next();
        if (next.cursorIndex() > from.cursorIndex()) {
            logger
                    .info("Run {} scanned targets {} to {} of {}: {} items above sequence {} ({} empty, {} failed{})",
                            runId, from.cursorIndex(), next.cursorIndex(), targets.size(), slice.items().size(),
                            request.getAfterSequence(), next.targetsEmpty() - from.targetsEmpty(),
                            next.targetsFailed() - from.targetsFailed(), summaryOf(next.failedByReason()));
        }

        DiscoveryResultsResponseDto response = new DiscoveryResultsResponseDto();
        response.setItems(slice.items());
        response.setHighestSequence(next.sequenceHighWater());
        response.setMore(slice.more());
        response.setCheckpoint(next.encode());
        return response;
    }

    /** Answers without a checkpoint: Core keeps the one it stored with the last page. */
    public DiscoveryStopResponseDto stop(DiscoveryRunRequestDto request) {
        requireSupported(request.getResources());
        RunHandle handle = requireHandle(request);
        long total = enumerate(request).size();
        if (handle.cursorIndex() >= total) {
            // Core allows a stop while its own status is still in progress, after this connector has reported the run
            // completed. A success would have Core record a finished run as stopped.
            throw new RunPastPointOfNoReturnException(request.getRunId(), DiscoveryRunState.COMPLETED.getLabel());
        }
        logger.info("Run {} stopped at target {} of {}", request.getRunId(), handle.cursorIndex(), total);
        return new DiscoveryStopResponseDto();
    }

    /**
     * Answers without a checkpoint, so Core keeps the one it holds. A stopped checkpoint written by the buffered engine
     * is accepted too; the first drain's position check catches anything its buffer lost.
     */
    public DiscoveryInitiateResponseDto resume(DiscoveryRunRequestDto request) {
        requireSupported(request.getResources());
        TargetEnumeration targets = enumerate(request);
        attributes.readParallelExecutions(request.getAttributes());
        requireCheckpointedOffered(request);
        RunHandle handle = requireHandle(request);
        if (!targets.digest().equals(handle.targetsDigest())) {
            throw new CheckpointLostException(request.getRunId(), "the scan's target enumeration has changed");
        }
        logger
                .info("Run {} resumed at target {} of {}, continuing sequences above {}", request.getRunId(),
                        handle.cursorIndex(), targets.size(), handle.sequenceHighWater());
        return accepted();
    }

    /** Nothing is held, so there is nothing to discard. A slice still scanning elsewhere ends on its own. */
    public void cancel(DiscoveryRunRequestDto request) {
        logger.info("Run {} cancelled", request.getRunId());
    }

    private static DiscoveryInitiateResponseDto accepted() {
        DiscoveryInitiateResponseDto response = new DiscoveryInitiateResponseDto();
        response.setDeliveryMode(DiscoveryDeliveryMode.CHECKPOINTED);
        // A slice is the only work there is, and it ends by itself, so a run can always stop.
        response.setStoppable(true);
        return response;
    }

    /** An absent offer is a Core older than delivery modes, which offers buffered only. */
    private static boolean offersCheckpointed(DiscoveryV2ScopedRequestDto request) {
        return request.getDeliveryModes() != null
                && request.getDeliveryModes().contains(DiscoveryDeliveryMode.CHECKPOINTED);
    }

    private static void requireCheckpointedOffered(DiscoveryV2ScopedRequestDto request) {
        if (!offersCheckpointed(request)) {
            throw new ValidationException("this connector requires platform 2.21.0 or later (checkpointed delivery)");
        }
    }

    /** The checkpoint carries the run's position, so a call without one cannot be served at all. */
    private static RunHandle requireHandle(DiscoveryV2ScopedRequestDto request) {
        return RunHandle
                .from(request.getCheckpoint())
                .orElseThrow(() -> new ValidationException("Run " + request.getRunId() + " carries no checkpoint"));
    }

    /**
     * The targets come from the request every time rather than from the checkpoint. The checkpoint carries a digest of
     * them instead, so each call can prove the enumeration it indexes into is the one the run started with.
     */
    private TargetEnumeration enumerate(DiscoveryV2ScopedRequestDto request) {
        List<String> hosts = attributes.readHosts(request.getAttributes());
        List<String> ports = attributes.readPorts(request.getAttributes());
        return TargetEnumeration.of(String.join(",", hosts), String.join(",", ports), false);
    }

    /**
     * Read from {@code resources} on the request, never inferred from {@code resourceAttributes}: that map omits any
     * resource with no attributes of its own, so inferring from it would silently narrow the run's scope.
     */
    private static void requireSupported(List<Resource> resources) {
        if (resources == null || resources.isEmpty()) {
            throw new ValidationException("resources is required and must name at least one resource type");
        }
        List<String> unsupported = resources
                .stream()
                .filter(r -> !SUPPORTED.contains(r))
                .map(Resource::getCode)
                .toList();
        if (!unsupported.isEmpty()) {
            throw new ValidationException("this connector does not discover " + unsupported + "; supported: "
                    + SUPPORTED.stream().map(Resource::getCode).toList());
        }
    }

    /**
     * Work in targets, yield in items, and nothing at all when there is nothing to say.
     *
     * <p>
     * The whole object is omitted rather than sent with every field absent. Core keeps the last progress it was given
     * and cannot tell an empty report from a missing one, so an all-null object would overwrite a real measurement with
     * silence.
     */
    static DiscoveryProgressDto progressOf(RunHandle handle, long total) {
        Map<String, Long> discovered = handle.yieldByResource();
        if (total == 0 && handle.targetsProcessed() == 0 && discovered.isEmpty()) {
            return null;
        }
        DiscoveryProgressDto progress = new DiscoveryProgressDto();
        progress.setTargetsTotal(total);
        progress.setTargetsProcessed(handle.targetsProcessed());
        // Both counted within processed rather than beside it, so a sweep that found nothing listening still reaches
        // 100 per cent. Such a run is complete, not degraded: its targets are empty, not failed.
        progress.setTargetsFailed(handle.targetsFailed());
        progress.setTargetsEmpty(handle.targetsEmpty());

        if (!discovered.isEmpty()) {
            Map<Resource, DiscoveryResourceProgressDto> byResource = new LinkedHashMap<>();
            discovered.forEach((code, items) -> {
                DiscoveryResourceProgressDto resourceProgress = new DiscoveryResourceProgressDto();
                resourceProgress.setProduced(items);
                // No estimate: one target yields anywhere from no items to a whole chain, so any total would be a
                // guess Core would render as a percentage.
                byResource.put(Resource.findByCode(code), resourceProgress);
            });
            progress.setByResource(byResource);
        }
        return progress;
    }

    /**
     * Stable across versions. Core replaces the run's whole metadata with every statement, so any other run-metadata
     * attribute must be sent together with this one on each answer, or the two erase each other.
     */
    static final String FAILURE_REASONS_UUID = "8d3f2c6e-5a41-4b9e-a7c2-1e6f0b9d4a53";

    /** Enough to name every kind of failure a sweep meets, and a bound on what one answer carries. */
    private static final int MAX_FAILURE_REASONS = 10;

    /** Enough to name what is happening without turning one log line into a report. */
    private static final int TOP_FAILURE_REASONS = 3;

    /**
     * Why targets failed, as metadata an operator reads beside the run, commonest first. Counts alone cannot say
     * whether a range refused this client or this connector could not use what it was given. Left out while nothing has
     * failed, which the contract reads as "no change" rather than "clear what you hold"; failures only ever add up, so
     * there is nothing to clear.
     */
    private static List<MetadataAttribute> failureReasonsOf(RunHandle handle) {
        Map<String, Long> reasons = handle.failedByReason();
        if (reasons.isEmpty()) {
            return null;
        }
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid(FAILURE_REASONS_UUID);
        attribute.setName("meta_targetFailureReasons");
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setDescription("Why the targets this discovery could not read failed, and how often");

        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel("Why targets failed");
        properties.setVisible(true);
        properties.setGlobal(false);
        attribute.setProperties(properties);

        attribute
                .setContent(byFrequency(reasons, MAX_FAILURE_REASONS)
                        .stream()
                        .map(StringAttributeContentV3::new)
                        .map(BaseAttributeContentV3.class::cast)
                        .toList());
        return List.of(attribute);
    }

    /**
     * The reasons the run's targets failed, commonest first, as "{@code 4094 x TLS alert handshake_failure}". Without
     * it a TLS stack refusing a bare IP and a bug here print the same number.
     */
    private static String summaryOf(Map<String, Long> reasons) {
        if (reasons.isEmpty()) {
            return "";
        }
        return ": " + String.join(", ", byFrequency(reasons, TOP_FAILURE_REASONS));
    }

    /**
     * The reasons as "{@code 4094 x TLS alert handshake_failure}", commonest first, then by name, at most
     * {@code limit}.
     */
    static List<String> byFrequency(Map<String, Long> reasons, int limit) {
        return reasons
                .entrySet()
                .stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
                .limit(limit)
                .map(reason -> reason.getValue() + " x " + reason.getKey())
                .toList();
    }
}
