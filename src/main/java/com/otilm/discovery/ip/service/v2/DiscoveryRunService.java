package com.otilm.discovery.ip.service.v2;

import com.otilm.api.exception.ValidationException;
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
import com.otilm.discovery.ip.api.v2.NodeAtCapacityException;
import com.otilm.discovery.ip.api.v2.UnknownRunException;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.util.TargetEnumeration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.time.Duration;

/**
 * The run lifecycle: initiate, status, results, stop, resume, cancel.
 *
 * <p>
 * Every call replays the run's whole configuration, so nothing here is read from storage. What the node keeps is the
 * live run — its buffer and its scan — and only for as long as it is scanning or has items nobody has taken.
 */
@Service
public class DiscoveryRunService {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryRunService.class);

    /** What a scan of this connector can produce. A run asking for anything else is refused rather than shortchanged. */
    private static final Set<Resource> SUPPORTED = EnumSet.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY);

    private final RunRegistry registry;
    private final BufferBudget budget;
    private final DiscoveryAttributeService attributes;
    private final ConnectionService connectionService;
    private final ExecutorService scans = Executors.newVirtualThreadPerTaskExecutor();

    public DiscoveryRunService(RunRegistry registry, BufferBudget budget, DiscoveryAttributeService attributes,
            ConnectionService connectionService) {
        this.registry = registry;
        this.budget = budget;
        this.attributes = attributes;
        this.connectionService = connectionService;
    }

    /**
     * Starts a run, or recognises one already started.
     *
     * <p>
     * The contract requires the repeat to be answered idempotently, and it has to be answered without starting a
     * second scan: a second scan would renumber from 1, and Core's cursor filter would drop every item it re-emitted
     * without reporting anything wrong.
     */
    public DiscoveryInitiateResponseDto initiate(DiscoveryInitiateRequestDto request) {
        UUID runId = request.getRunId();
        var known = registry.find(runId);
        if (known.isPresent()) {
            logger.info("Run {} is already tracked; answering the repeated initiate without starting a second scan",
                    runId);
            return accepted(known.get());
        }

        requireSupported(request.getResources());
        TargetEnumeration targets = enumerate(request);
        int parallelism = attributes.readParallelExecutions(request.getAttributes());

        RunHandle handle = RunHandle.initial(targets.digest());
        switch (budget.admit(runId)) {
            case AT_CAPACITY ->
                throw new NodeAtCapacityException("this node is already scanning as many runs as it can feed");
            case ALREADY_HELD -> {
                // A concurrent initiate for the same run got here first and is still registering. The contract wants
                // the repeat answered idempotently, so it is answered with the same checkpoint the winner started
                // from -- not with a claim that the node is full, which is what conflating the two refusals produced.
                logger.info("Run {} is already being started; answering the concurrent initiate idempotently", runId);
                return accepted(registry.find(runId).orElse(handle));
            }
            case ADMITTED -> {
                if (!registry.register(runId, handle)) {
                    budget.close(runId);
                    return accepted(registry.find(runId).orElse(handle));
                }
            }
        }

        start(runId, targets, handle, parallelism, request.getResources());
        return accepted(handle);
    }

    /**
     * Rebuilds unconditionally when this node does not hold the run. Status hands nothing over, so it cannot lose
     * anything — and refusing it is what kills the run: Core keeps polling a stopped run, and the first 404 ends it
     * FAILED before anyone can press resume.
     */
    public DiscoveryStatusResponseDto status(DiscoveryRunRequestDto request) {
        UUID runId = request.getRunId();
        if (registry.find(runId).isEmpty()) {
            rebuild(request);
        }
        registry.touch(runId);

        DiscoveryStatusResponseDto response = new DiscoveryStatusResponseDto();
        response.setState(registry.state(runId).orElse(DiscoveryRunState.RUNNING));
        response.setHighestSequence(registry.buffer(runId).map(ResultBuffer::highestSequence).orElse(0L));
        response.setProgress(progressOf(runId));
        return response;
    }

    /**
     * Serves the items after the given cursor, and drops what the cursor says Core already has.
     *
     * <p>
     * Discarding first is what makes a repeat cheap, and the buffer decides what a cursor below its watermark means —
     * a late or redelivered drain is transport, not a defect.
     */
    public DiscoveryResultsResponseDto results(DiscoveryDrainRequestDto request) {
        UUID runId = request.getRunId();
        if (registry.find(runId).isEmpty()) {
            rebuildForDrain(request);
        }
        registry.touch(runId);
        requireDrainVerified(runId, request.getAfterSequence());
        ResultBuffer buffer = registry.buffer(runId).orElseThrow(() -> new UnknownRunException(runId));

        buffer.discardThrough(request.getAfterSequence());
        ResultBuffer.Page page = buffer
                .page(request.getAfterSequence(), request.getMaxItems() == null ? 500 : request.getMaxItems(),
                        request.getMaxBytes() == null ? 5L * 1024 * 1024 : request.getMaxBytes());

        DiscoveryResultsResponseDto response = new DiscoveryResultsResponseDto();
        response.setItems(page.items());
        response.setHighestSequence(page.highestSequence());
        response.setMore(page.more());
        return response;
    }

    /**
     * Stops the scan and answers with the checkpoint. The scan is interrupted rather than quiesced, so this returns
     * inside the control envelope even when every probe is stalled or parked on backpressure.
     */
    public DiscoveryStopResponseDto stop(DiscoveryRunRequestDto request) {
        UUID runId = request.getRunId();
        registry.find(runId).orElseThrow(() -> new UnknownRunException(runId));
        registry.touch(runId);

        // Marked stopped before the scan is asked to stop, so a chunk finishing in between cannot move the
        // checkpoint after this call has answered with one.
        registry.update(runId, handle -> handle.withState(RunHandle.RunState.STOPPED));
        registry.setState(runId, DiscoveryRunState.STOPPED);
        registry.runner(runId).ifPresent(ScanRunner::stop);

        // Waited for rather than raced. The scan is interrupted, not quiesced, so this is a wait for threads to
        // unwind; while any probe is still running it may number another item, and the checkpoint would miss it.
        if (!registry.awaitScan(runId, SCAN_SETTLE)) {
            logger.warn("Run {} did not settle within {} of the stop; checkpointing anyway", runId, SCAN_SETTLE);
        }

        // From the buffer, not from the last chunk boundary. Probes inside the interrupted chunk have already been
        // numbered, and a checkpoint that omitted them would be read as a mismatch by the next drain -- killing a run
        // that lost nothing -- and would have a resumed run reissue those numbers.
        long highWater = registry.buffer(runId).map(ResultBuffer::highestSequence).orElse(0L);
        RunHandle stopped = registry
                .update(runId, handle -> handle.stoppedAt(Math.max(highWater, handle.sequenceHighWater())))
                .orElseThrow(() -> new UnknownRunException(runId));

        DiscoveryStopResponseDto response = new DiscoveryStopResponseDto();
        response.setMeta(stopped.encode());
        return response;
    }

    /**
     * Resumes a stopped run this node still holds. A run it does not hold has to be rebuilt from its replayed
     * checkpoint, which is not implemented yet, so it answers 404 rather than pretending.
     */
    public DiscoveryInitiateResponseDto resume(DiscoveryRunRequestDto request) {
        UUID runId = request.getRunId();
        // Accepted optimistically: resume carries no cursor, so the verdict on whether anything was lost comes from
        // the first drain, which arrives within seconds because Core expedites the drain row on a successful resume.
        RunHandle handle = registry.find(runId).orElseGet(() -> rebuild(request));
        registry.touch(runId);

        // One winner. Two resumes can both read STOPPED, and both would start a scan.
        if (!registry.compareAndSetState(runId, DiscoveryRunState.STOPPED, DiscoveryRunState.RUNNING)) {
            logger.info("Run {} is already running; the resume is a no-op", runId);
            return accepted(handle);
        }

        try {
            requireSupported(request.getResources());
            TargetEnumeration targets = enumerate(request);
            requireSameEnumeration(runId, handle, targets);
            int parallelism = attributes.readParallelExecutions(request.getAttributes());

            // The budget opens here rather than at rebuild, because this is where the run starts producing. A
            // rebuilt run that only answers status and drains holds nothing, and charging it against the scanning
            // cap is what let a busy node refuse -- and so kill -- a run it merely could not scan.
            if (budget.admit(runId) == BufferBudget.Admission.AT_CAPACITY) {
                throw new NodeAtCapacityException("this node is already scanning as many runs as it can feed");
            }

            RunHandle running = registry
                    .update(runId, current -> current.withState(RunHandle.RunState.RUNNING))
                    .orElseThrow(() -> new UnknownRunException(runId));
            start(runId, targets, running, parallelism, request.getResources());
            return accepted(running);
        } catch (RuntimeException e) {
            // Put the run back where it was, so a corrected retry can still resume it rather than finding a run
            // marked running that nothing is scanning.
            registry.compareAndSetState(runId, DiscoveryRunState.RUNNING, DiscoveryRunState.STOPPED);
            throw e;
        }
    }

    /** Forgets the run and everything it held. A later call finds nothing, which is the contract's expected answer. */
    public void cancel(DiscoveryRunRequestDto request) {
        UUID runId = request.getRunId();
        if (!registry.release(runId)) {
            throw new UnknownRunException(runId);
        }
        logger.info("Run {} cancelled and forgotten", runId);
    }

    /**
     * Reconstructs a run this node does not hold, from the checkpoint Core replayed.
     *
     * <p>
     * Only a handle that says {@code stopped} may be rebuilt. A {@code running} one describes a run whose in-flight
     * state is genuinely gone, and rebuilding on it is silent loss: an initiate-time handle reads cursor 0 and high
     * water 0, indistinguishable from a stopped run checkpointed before it scanned anything, so the rebuilt run
     * renumbers from 1 while Core's cursor sits at N and every re-emitted item is discarded without an error
     * anywhere.
     */
    private RunHandle rebuild(DiscoveryV2ScopedRequestDto request) {
        UUID runId = request.getRunId();
        RunHandle handle = RunHandle.from(request.getMeta()).orElseThrow(() -> new UnknownRunException(runId));
        if (handle.state() != RunHandle.RunState.STOPPED) {
            throw new UnknownRunException(runId);
        }

        requireSupported(request.getResources());
        // No budget is taken. A rebuilt run holds no items -- whatever it had was in memory this node no longer has
        // -- and it may only answer status and drains until a resume starts production, which is where the budget is
        // taken instead. Charging it here meant a node at its run cap refused the very ticks that keep a stopped run
        // alive, and Core reads a refusal often enough as the run being unrecoverable.
        if (!registry.register(runId, handle)) {
            return registry.find(runId).orElseThrow(() -> new UnknownRunException(runId));
        }
        registry.setState(runId, DiscoveryRunState.STOPPED);
        // A rebuilt run holds no items: whatever it had was in memory this node no longer has. The buffer exists so
        // a resume numbers from where the checkpoint left off rather than from one.
        registry.attach(runId, null, new ResultBuffer(runId, budget, handle.sequenceHighWater()));
        registry.oweDrainVerification(runId, handle.sequenceHighWater());
        // The enumeration is rebuilt from the same replayed request, so a rebuilt run reports a total like any other.
        registry.setTargetsTotal(runId, enumerate(request).size());
        logger.info("Rebuilt stopped run {} from its replayed checkpoint at cursor {}", runId, handle.cursorIndex());
        return handle;
    }

    /**
     * A rebuilt run serves nothing until a drain proves Core is exactly at the checkpoint it was rebuilt from.
     *
     * <p>
     * The check cannot live in the rebuild call alone. Status and resume rebuild too, and after either of those the
     * run is registered, so every later drain would take the ordinary path with no cursor check at all -- including
     * the resume flow the verdict exists for, where Core expedites the drain straight into a registered run.
     */
    private void requireDrainVerified(UUID runId, long afterSequence) {
        Long owed = registry.drainVerificationOwed(runId).orElse(null);
        if (owed == null) {
            return;
        }
        if (afterSequence != owed) {
            logger
                    .warn("Refusing to serve rebuilt run {}: Core is at sequence {} and the checkpoint at {}", runId,
                            afterSequence, owed);
            throw new UnknownRunException(runId);
        }
        registry.drainVerified(runId);
    }

    /**
     * A drain for a run this node lost may only be served when Core's cursor proves nothing is missing.
     *
     * <p>
     * {@code afterSequence} is Core's live cursor. Equal to the checkpoint's high water means Core already holds
     * everything the run produced, so the rebuilt run can serve — an empty page, then whatever a resume produces.
     * Below it means items were produced and never handed over, and they cannot be regenerated. Above it means the
     * handle is stale, left behind by a resume Core failed to record.
     *
     * <p>
     * Both of those answer 404 rather than serving. Core advances its cursor to the highest sequence in a page, not
     * to the end of a contiguous run, so serving across a hole would let the run finish clean with items missing.
     */
    private void rebuildForDrain(DiscoveryDrainRequestDto request) {
        UUID runId = request.getRunId();
        RunHandle handle = RunHandle.from(request.getMeta()).orElseThrow(() -> new UnknownRunException(runId));
        if (request.getAfterSequence() != handle.sequenceHighWater()) {
            logger
                    .warn("Refusing to serve rebuilt run {}: Core is at sequence {} and the checkpoint at {}", runId,
                            request.getAfterSequence(), handle.sequenceHighWater());
            throw new UnknownRunException(runId);
        }
        rebuild(request);
    }

    /** How long a stop waits for an interrupted scan to unwind before checkpointing regardless. */
    private static final Duration SCAN_SETTLE = Duration.ofSeconds(10);

    /**
     * The checkpoint indexes into an enumeration, so it can only be continued against the same one. ND3's guard:
     * any change to enumeration order invalidates the cursor, and the run is refused loudly rather than resumed at
     * the wrong offset.
     */
    private static void requireSameEnumeration(UUID runId, RunHandle handle, TargetEnumeration targets) {
        if (!targets.digest().equals(handle.targetsDigest())) {
            throw new CheckpointLostException(runId, "the scan's target enumeration has changed");
        }
    }

    /**
     * Work in targets, yield in items, and nothing at all when there is nothing to say.
     *
     * <p>
     * The whole object is omitted rather than sent with every field absent. Core keeps the last progress it was
     * given and cannot tell an empty report from a missing one, so an all-null object would overwrite a real
     * measurement with silence.
     */
    private DiscoveryProgressDto progressOf(UUID runId) {
        RunHandle handle = registry.find(runId).orElseThrow(() -> new UnknownRunException(runId));
        Long total = registry.targetsTotal(runId).orElse(null);
        Map<String, Long> yield = handle.yieldByResource();

        if (total == null && handle.targetsProcessed() == 0 && yield.isEmpty()) {
            return null;
        }

        DiscoveryProgressDto progress = new DiscoveryProgressDto();
        progress.setTargetsTotal(total);
        progress.setTargetsProcessed(handle.targetsProcessed());
        // Counted within processed rather than beside it, so an all-failed sweep still reaches 100 per cent. A run
        // that reached every target and found nothing listening is complete, not degraded.
        progress.setTargetsFailed(handle.targetsFailed());
        // Named only when it explains a run that looks stalled; a phase on a healthy run is noise Core would keep.
        progress.setPhase(budget.isBackpressured() ? "backpressured" : null);

        if (!yield.isEmpty()) {
            Map<Resource, DiscoveryResourceProgressDto> byResource = new LinkedHashMap<>();
            yield.forEach((code, items) -> {
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

    private void start(UUID runId, TargetEnumeration targets, RunHandle handle, int parallelism,
            List<Resource> resources) {
        registry.setTargetsTotal(runId, targets.size());
        // Reused when this node already holds one. Replacing it would drop the items Core has not drained yet and
        // reseed the sequencer below its own counter, so the resumed run would reissue numbers Core has already
        // ingested and every one of them would be discarded by its cursor filter.
        ResultBuffer buffer = registry
                .buffer(runId)
                .orElseGet(() -> new ResultBuffer(runId, budget, handle.sequenceHighWater()));
        ScanRunner runner = new ScanRunner(runId, targets, buffer, registry, connectionService, parallelism,
                EnumSet.copyOf(resources));
        registry.attach(runId, runner, buffer);
        Future<?> scan = scans.submit(() -> {
            try {
                if (runner.scan()) {
                    registry.setState(runId, DiscoveryRunState.COMPLETED);
                    logger.info("Run {} scanned every target", runId);
                }
            } catch (Exception e) {
                registry.setState(runId, DiscoveryRunState.FAILED);
                logger.error("Run {} failed: {}", runId, e.getMessage(), e);
            }
        });
        registry.attachScan(runId, scan);
    }

    /**
     * The targets come from the request every time rather than from the checkpoint. The checkpoint carries a digest
     * of them instead, so a resumed run can prove the enumeration it is about to continue is the one it left.
     */
    private TargetEnumeration enumerate(com.otilm.api.model.connector.discovery.v2.DiscoveryV2ScopedRequestDto request) {
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
        List<String> unsupported = resources.stream().filter(r -> !SUPPORTED.contains(r)).map(Resource::getCode)
                .toList();
        if (!unsupported.isEmpty()) {
            throw new ValidationException("this connector does not discover " + unsupported + "; supported: "
                    + SUPPORTED.stream().map(Resource::getCode).toList());
        }
    }

    private static DiscoveryInitiateResponseDto accepted(RunHandle handle) {
        DiscoveryInitiateResponseDto response = new DiscoveryInitiateResponseDto();
        response.setMeta(handle.encode());
        // Stop is honoured per run rather than declared once: this connector can always stop, because its scan is
        // interruptible.
        response.setStoppable(true);
        return response;
    }
}
