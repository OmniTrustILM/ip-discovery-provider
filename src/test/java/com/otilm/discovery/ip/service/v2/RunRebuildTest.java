package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDrainRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStatusResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.api.v2.CheckpointLostException;
import com.otilm.discovery.ip.api.v2.UnknownRunException;
import com.otilm.discovery.ip.dto.ConnectionResponse;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.service.v2.impl.DiscoveryAttributeServiceImpl;
import com.otilm.discovery.ip.util.TargetEnumeration;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.info.BuildProperties;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A restart loses the runs this node was holding. Core keeps driving a stopped one for the whole resume window, so a
 * connector that answers 404 does not merely lose the ability to resume — the next tick ends the run FAILED before
 * anyone can press resume.
 *
 * <p>
 * Rebuilding is therefore necessary and also the most dangerous thing here, because the failure it risks completes
 * <em>successfully</em>: Core advances its cursor to the highest sequence in a page rather than the end of a
 * contiguous run, so a rebuilt run that served across a hole would let the run finish clean with items missing.
 */
class RunRebuildTest {

    private static final String HOSTS = "10.0.0.1-10.0.0.8";

    /** A fresh node: nothing in the registry, exactly as after a restart. */
    private final RunRegistry registry = new RunRegistry();
    private final BufferBudget budget = new BufferBudget(4, 100_000, 1L << 30, 1L << 31, 30_000);
    private final CountingProbes probes = new CountingProbes();
    private final DiscoveryRunService service =
            new DiscoveryRunService(registry, budget, attributeService(), probes);

    private static DiscoveryAttributeServiceImpl attributeService() {
        Properties properties = new Properties();
        properties.setProperty("version", "2.20.0-SNAPSHOT");
        return new DiscoveryAttributeServiceImpl(new BuildProperties(properties));
    }

    private static class CountingProbes implements ConnectionService {
        private final AtomicInteger probed = new AtomicInteger();

        @Override
        public ConnectionResponse getCertificates(String url) throws IOException {
            probed.incrementAndGet();
            throw new IOException("nothing listening");
        }
    }

    private static String digest() {
        return TargetEnumeration.of(HOSTS, "443", false).digest();
    }

    private static RequestAttribute listAttribute(String uuid, String name, String... values) {
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(UUID.fromString(uuid));
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute
                .setContent(Arrays.stream(values).<BaseAttributeContentV3<?>>map(StringAttributeContentV3::new)
                        .toList());
        return attribute;
    }

    private static List<RequestAttribute> scanAttributes(String hosts) {
        return List
                .of(listAttribute(DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_HOSTS_UUID,
                        DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_HOSTS_NAME, hosts),
                        listAttribute(DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PORTS_UUID,
                                DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PORTS_NAME, "443"));
    }

    private static RunHandle stoppedHandle(long cursor, long highWater) {
        return new RunHandle(RunHandle.RunState.STOPPED, cursor, highWater, digest(), cursor, 0L,
                Map.of(Resource.CERTIFICATE.getCode(), highWater));
    }

    private static DiscoveryRunRequestDto runRequest(UUID runId, RunHandle handle, String hosts) {
        DiscoveryRunRequestDto request = new DiscoveryRunRequestDto();
        request.setRunId(runId);
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setAttributes(scanAttributes(hosts));
        request.setCheckpoint(handle.encode());
        return request;
    }

    private static DiscoveryDrainRequestDto drainRequest(UUID runId, RunHandle handle, long afterSequence) {
        DiscoveryDrainRequestDto request = new DiscoveryDrainRequestDto();
        request.setRunId(runId);
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setAttributes(scanAttributes(HOSTS));
        request.setCheckpoint(handle.encode());
        request.setAfterSequence(afterSequence);
        return request;
    }

    // --- the rule that makes the deferred verdict safe ---

    /**
     * The highest-value test here: the failure it prevents completes successfully. Core is behind the checkpoint, so
     * items exist that it never received and that cannot be regenerated — sequence to target is not a function.
     */
    @Test
    void neverServesARebuiltRunWhileCoreIsBehindTheCheckpoint() {
        UUID runId = UUID.randomUUID();
        RunHandle handle = stoppedHandle(8, 40);

        Assertions
                .assertThrows(UnknownRunException.class, () -> service.results(drainRequest(runId, handle, 30)),
                        "items between Core's cursor and the high water are missing and cannot be reproduced");
        Assertions.assertEquals(0, budget.openRuns(), "a refused drain must not leave a run charged");
    }

    /** Above the high water means the handle is stale, left behind by a resume Core failed to record. */
    @Test
    void refusesADrainWhoseCursorIsAheadOfTheCheckpoint() {
        UUID runId = UUID.randomUUID();
        RunHandle handle = stoppedHandle(8, 40);

        Assertions.assertThrows(UnknownRunException.class, () -> service.results(drainRequest(runId, handle, 41)));
    }

    /** Equal means Core already holds everything the run produced, so the rebuilt run has nothing to hide. */
    @Test
    void rebuildsAndServesWhenCoreHoldsEverythingTheRunProduced() {
        UUID runId = UUID.randomUUID();
        RunHandle handle = stoppedHandle(8, 40);

        DiscoveryResultsResponseDto results = service.results(drainRequest(runId, handle, 40));

        Assertions.assertTrue(results.getItems().isEmpty(), "a rebuilt run holds no items of its own");
        Assertions.assertEquals(40L, results.getHighestSequence());
        Assertions.assertEquals(Boolean.FALSE, results.getMore());
        Assertions.assertEquals(DiscoveryRunState.STOPPED, registry.state(runId).orElseThrow());
    }

    // --- what may be rebuilt at all ---

    /**
     * A running handle describes a run whose in-flight state is genuinely gone. Rebuilding on it is silent loss: an
     * initiate-time handle reads cursor 0 and high water 0, indistinguishable from a stopped run checkpointed before
     * it scanned anything, so the rebuilt run renumbers from 1 while Core's cursor sits at N.
     */
    @Test
    void refusesToRebuildARunningHandle() {
        UUID runId = UUID.randomUUID();
        RunHandle running = new RunHandle(RunHandle.RunState.RUNNING, 0L, 0L, digest(), 0L, 0L, Map.of());

        Assertions.assertThrows(UnknownRunException.class, () -> service.status(runRequest(runId, running, HOSTS)));
        Assertions.assertThrows(UnknownRunException.class, () -> service.resume(runRequest(runId, running, HOSTS)));
    }

    @Test
    void refusesToRebuildWithoutACheckpoint() {
        DiscoveryRunRequestDto request = new DiscoveryRunRequestDto();
        request.setRunId(UUID.randomUUID());
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setAttributes(scanAttributes(HOSTS));

        Assertions.assertThrows(UnknownRunException.class, () -> service.status(request));
    }

    /**
     * Status hands nothing over, so it cannot lose anything, and refusing it is what kills the run: Core polls a
     * stopped run for the whole resume window and reads the first 404 as terminal.
     */
    @Test
    void statusRebuildsWhateverTheCursorWouldHaveSaid() {
        UUID runId = UUID.randomUUID();
        RunHandle handle = stoppedHandle(8, 40);

        DiscoveryStatusResponseDto status = service.status(runRequest(runId, handle, HOSTS));

        Assertions.assertEquals(DiscoveryRunState.STOPPED, status.getState());
        Assertions.assertEquals(40L, status.getHighestSequence(), "numbering continues from the checkpoint");
    }

    // --- resume ---

    /**
     * Resume carries no cursor, so it is accepted and the first drain gives the verdict — which arrives within
     * seconds, because Core expedites the drain row on a successful resume.
     */
    @Test
    void resumesARebuiltRunFromItsCursorAndKeepsItsSequenceSpace() {
        UUID runId = UUID.randomUUID();
        // Four of the eight targets already scanned, and forty items already handed to Core.
        RunHandle handle = stoppedHandle(4, 40);

        service.resume(runRequest(runId, handle, HOSTS));

        Awaitility
                .await()
                .atMost(Duration.ofSeconds(20))
                .until(() -> registry.state(runId).orElseThrow() == DiscoveryRunState.COMPLETED);

        Assertions.assertEquals(4, probes.probed.get(), "only the targets after the cursor should be scanned");
        Assertions.assertEquals(8L, registry.find(runId).orElseThrow().cursorIndex());
        Assertions
                .assertEquals(40L, registry.buffer(runId).orElseThrow().highestSequence(),
                        "the sequence space continues from the checkpoint rather than restarting at one");
        Assertions
                .assertEquals(8L, registry.find(runId).orElseThrow().targetsProcessed(),
                        "the carried work counters continue rather than reset");
    }

    /**
     * The checkpoint is an index into an enumeration, so continuing it against a different one would scan the wrong
     * targets. 410 rather than 404: the run is recognised, its checkpoint is not.
     */
    @Test
    void refusesToResumeAgainstADifferentEnumeration() {
        UUID runId = UUID.randomUUID();
        RunHandle handle = stoppedHandle(8, 40);

        Assertions
                .assertThrows(CheckpointLostException.class,
                        () -> service.resume(runRequest(runId, handle, "10.0.0.1-10.0.0.9")));
    }
}
