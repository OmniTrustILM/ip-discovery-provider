package com.otilm.discovery.ip.service.v2;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The checkpoint. Returned from initiate, stop and resume, replayed by Core on every later call, and the only place a
 * run's position survives — the connector keeps no storage of its own.
 *
 * <p>
 * Carried as a single metadata attribute holding JSON rather than one attribute per field. Two reasons: the cursor and
 * the sequence are {@code long}, which the integer content type cannot hold, and a checkpoint is opaque to Core, so
 * spreading it over labelled attributes would dress internal state as something an operator is meant to read.
 *
 * @param state             separates a stopped run that can be rebuilt from a running one that must not be — without
 *                          it, a run checkpointed before it scanned anything is indistinguishable from one that never
 *                          started
 * @param cursorIndex       next target index to scan
 * @param sequenceHighWater highest sequence assigned; a resumed run continues this space and never restarts it
 * @param targetsDigest     the resume guard: any change to enumeration order invalidates it, and the run is refused
 *                          loudly rather than resumed at the wrong offset
 * @param yieldByResource   items produced per resource wire code, so per-resource progress survives a stop
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RunHandle(RunState state, long cursorIndex, long sequenceHighWater, String targetsDigest,
        long targetsProcessed, long targetsFailed, Map<String, Long> yieldByResource) {

    /** Stable across versions: Core replays what it was given, and a rename would orphan every live checkpoint. */
    public static final String ATTRIBUTE_UUID = "52cf88e4-6b87-40f5-a89d-9b6e6d676119";
    public static final String ATTRIBUTE_NAME = "meta_runHandle";

    /**
     * Unknown properties are ignored rather than rejected. A handle is replayed from Core exactly as it was stored, so
     * one written by a newer connector can arrive at an older one, and refusing it would fail a run over a field that
     * older code simply does not need.
     */
    private static final ObjectMapper MAPPER =
            new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    public enum RunState {
        RUNNING, STOPPED
    }

    /** The handle a run starts from, before a single target has been probed. */
    public static RunHandle initial(String targetsDigest) {
        return new RunHandle(RunState.RUNNING, 0L, 0L, targetsDigest, 0L, 0L, Map.of());
    }

    /**
     * The checkpoint a stop answers with. The high water comes from the buffer's own sequencer rather than the last
     * chunk boundary: probes inside the interrupted chunk have already been numbered, and freezing the boundary value
     * instead leaves those sequences outside the checkpoint — which a later drain then reads as a mismatch, and a
     * resumed run reissues.
     */
    public RunHandle stoppedAt(long sequenceHighWater) {
        return new RunHandle(RunState.STOPPED, cursorIndex, sequenceHighWater, targetsDigest, targetsProcessed,
                targetsFailed, yieldByResource);
    }

    public RunHandle withState(RunState newState) {
        return new RunHandle(newState, cursorIndex, sequenceHighWater, targetsDigest, targetsProcessed, targetsFailed,
                yieldByResource);
    }

    /** The checkpoint as Core will replay it. */
    public List<MetadataAttribute> encode() {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid(ATTRIBUTE_UUID);
        attribute.setName(ATTRIBUTE_NAME);
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setDescription("Discovery v2 run checkpoint");

        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel("Run checkpoint");
        // Not shown and not merged into anything the platform owns: this is connector state in transit.
        properties.setVisible(false);
        properties.setGlobal(false);
        properties.setOverwrite(true);
        attribute.setProperties(properties);

        attribute.setContent(List.of(new StringAttributeContentV3(toJson())));
        return List.of(attribute);
    }

    /**
     * Reads the checkpoint out of a replayed {@code checkpoint} list. Other attributes alongside it are left alone:
     * Core is free to carry its own, and a connector that choked on them would break the day it did.
     *
     * @return empty when no checkpoint is present, which is the initiate case rather than an error
     * @throws ValidationException if the checkpoint is present but unreadable
     */
    public static Optional<RunHandle> from(List<MetadataAttribute> meta) {
        if (meta == null) {
            return Optional.empty();
        }
        // Matched on the UUID, which is what identifies an attribute definition. Core is free to carry metadata of
        // its own, and one of it sharing our name would otherwise be parsed as the checkpoint and fail the run.
        return meta
                .stream()
                .filter(attribute -> ATTRIBUTE_UUID.equals(attribute.getUuid()))
                .findFirst()
                .map(RunHandle::readContent);
    }

    private static RunHandle readContent(MetadataAttribute attribute) {
        Object content = attribute.getContent();
        if (!(content instanceof List<?> items) || items.isEmpty()) {
            throw new ValidationException("Run checkpoint carries no content");
        }
        Object data = ((com.otilm.api.model.common.attribute.common.AttributeContent) items.get(0)).getData();
        if (!(data instanceof String json) || json.isBlank()) {
            throw new ValidationException("Run checkpoint content is not readable text");
        }
        RunHandle handle;
        try {
            handle = MAPPER.readValue(json, RunHandle.class);
        } catch (JsonProcessingException e) {
            throw new ValidationException("Run checkpoint is not readable: " + e.getOriginalMessage());
        }
        return handle.validated();
    }

    /**
     * What a checkpoint has to mean, not just parse as. Jackson fills a missing field with null or zero, so a
     * truncated or hostile checkpoint reaches the scan as a negative cursor indexing the enumeration, a sequence
     * space that runs backwards, or a null map that fails later with nothing naming the cause. The contract
     * documents a validation failure for an unreadable checkpoint, and this is the other half of unreadable.
     */
    private RunHandle validated() {
        if (state == null) {
            throw new ValidationException("Run checkpoint names no state");
        }
        if (targetsDigest == null || targetsDigest.isBlank()) {
            throw new ValidationException("Run checkpoint carries no target digest");
        }
        if (cursorIndex < 0 || sequenceHighWater < 0 || targetsProcessed < 0 || targetsFailed < 0) {
            throw new ValidationException("Run checkpoint counts backwards: cursor " + cursorIndex + ", sequence "
                    + sequenceHighWater + ", processed " + targetsProcessed + ", failed " + targetsFailed);
        }
        if (targetsFailed > targetsProcessed) {
            throw new ValidationException("Run checkpoint reports " + targetsFailed + " failed targets within "
                    + targetsProcessed + " processed");
        }
        // Normalised rather than refused: an absent map is a run that has produced nothing, which is a state a
        // checkpoint legitimately describes.
        return yieldByResource == null
                ? new RunHandle(state, cursorIndex, sequenceHighWater, targetsDigest, targetsProcessed, targetsFailed,
                        Map.of())
                : this;
    }

    private String toJson() {
        try {
            return MAPPER.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            // Every field is a primitive, a string or a map of them, so this cannot fail on well-formed state.
            throw new IllegalStateException("Run checkpoint could not be written", e);
        }
    }
}
