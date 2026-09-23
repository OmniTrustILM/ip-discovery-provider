package com.otilm.discovery.ip.service.v2;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.core.util.AttributeDefinitionUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

class RunHandleTest {

    /** Core's own cap on a replayed checkpoint. */
    private static final int MAX_META_BYTES = 64 * 1024;

    private static RunHandle handle() {
        // Cursor and processed count match, as every committed chunk leaves them, and both run past an int.
        return new RunHandle(RunHandle.RunState.RUNNING, 4_000_000_000L, 987_654_321L,
                "b1946ac92492d2347c6235b4d2611184", 4_000_000_000L, 12L, Map.of("certificates", 42L, "keys", 7L));
    }

    private static MetadataAttribute foreignAttribute() {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid("11111111-1111-4111-8111-111111111111");
        attribute.setName("meta_somethingCoreOwns");
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV3("not ours")));
        return attribute;
    }

    @Test
    void survivesTheRoundTripThroughTheMetadataEnvelope() {
        RunHandle original = handle();

        RunHandle read = RunHandle.from(original.encode()).orElseThrow();

        Assertions.assertEquals(original, read);
    }

    /**
     * The cursor and the sequence outgrow an {@code int} on any wide scan — a {@code /16} with all ports is over four
     * billion targets — which is why the checkpoint is JSON in one attribute rather than typed integer content.
     */
    @Test
    void carriesPositionsBeyondTheRangeOfAnInt() {
        RunHandle read = RunHandle.from(handle().encode()).orElseThrow();

        Assertions.assertEquals(4_000_000_000L, read.cursorIndex());
        Assertions.assertEquals(4_000_000_000L, read.targetsProcessed());
        Assertions.assertTrue(read.targetsProcessed() > Integer.MAX_VALUE);
    }

    /**
     * Measured the way Core measures it — the serialized attribute list, not the raw JSON — because the envelope is
     * far more verbose than its content and the cap applies to the envelope.
     */
    @Test
    void staysFarInsideTheMetaCapWhenMeasuredAsCoreMeasuresIt() {
        String serialized = AttributeDefinitionUtils.serialize(handle().encode());
        int bytes = serialized.getBytes(StandardCharsets.UTF_8).length;

        Assertions.assertTrue(bytes < MAX_META_BYTES / 10,
                "the checkpoint should be an order of magnitude inside the " + MAX_META_BYTES + " byte cap, was "
                        + bytes);
    }

    /**
     * A handle written by a newer connector reaches an older one unchanged, because Core replays exactly what it
     * stored. Refusing it would fail the run over a field the older code does not need.
     */
    @Test
    void toleratesAFieldItDoesNotKnow() {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid(RunHandle.ATTRIBUTE_UUID);
        attribute.setName(RunHandle.ATTRIBUTE_NAME);
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute
                .setContent(List
                        .of(new StringAttributeContentV3("{\"state\":\"STOPPED\",\"cursorIndex\":7,"
                                + "\"sequenceHighWater\":9,\"targetsDigest\":\"abc\",\"targetsProcessed\":7,"
                                + "\"targetsFailed\":0,\"yieldByResource\":{},\"somethingNewer\":\"ignored\"}")));

        RunHandle read = RunHandle.from(List.<MetadataAttribute>of(attribute)).orElseThrow();

        Assertions.assertEquals(RunHandle.RunState.STOPPED, read.state());
        Assertions.assertEquals(7L, read.cursorIndex());
    }

    /** Core may carry metadata of its own; a connector that choked on it would break the day it did. */
    @Test
    void ignoresMetadataThatIsNotItsCheckpoint() {
        List<MetadataAttribute> meta = new ArrayList<>();
        meta.add(foreignAttribute());
        meta.addAll(handle().encode());

        Assertions.assertEquals(handle(), RunHandle.from(meta).orElseThrow());
    }

    /** No checkpoint is the initiate case, not a failure. */
    @Test
    void reportsAnAbsentCheckpointAsAbsentRatherThanBroken() {
        Assertions.assertEquals(Optional.empty(), RunHandle.from(null));
        Assertions.assertEquals(Optional.empty(), RunHandle.from(List.of()));
        Assertions.assertEquals(Optional.empty(), RunHandle.from(List.of(foreignAttribute())));
    }

    /** A checkpoint that is present but unreadable is the opposite case: the run cannot continue, and must say so. */
    @Test
    void refusesACheckpointItCannotRead() {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid(RunHandle.ATTRIBUTE_UUID);
        attribute.setName(RunHandle.ATTRIBUTE_NAME);
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV3("{ this is not json")));
        List<MetadataAttribute> meta = List.of(attribute);

        Assertions.assertThrows(ValidationException.class, () -> RunHandle.from(meta));
    }

    @Test
    void startsARunAtTheBeginningOfItsEnumeration() {
        RunHandle initial = RunHandle.initial("digest");

        Assertions.assertEquals(RunHandle.RunState.RUNNING, initial.state());
        Assertions.assertEquals(0L, initial.cursorIndex());
        Assertions.assertEquals(0L, initial.sequenceHighWater());
        Assertions.assertEquals(Map.of(), initial.yieldByResource());
    }

    @Test
    void changesStateWithoutDisturbingThePosition() {
        RunHandle stopped = handle().withState(RunHandle.RunState.STOPPED);

        Assertions.assertEquals(RunHandle.RunState.STOPPED, stopped.state());
        Assertions.assertEquals(handle().cursorIndex(), stopped.cursorIndex());
        Assertions.assertEquals(handle().sequenceHighWater(), stopped.sequenceHighWater());
    }

    // --- what identifies the checkpoint, and what it has to mean ---

    /**
     * The UUID is what identifies an attribute definition. Core carries metadata of its own, and one of it sharing
     * this name would otherwise be read as the checkpoint and fail a run that was recoverable.
     */
    @Test
    void ignoresAForeignAttributeWearingTheCheckpointsName() {
        MetadataAttributeV3 impostor = new MetadataAttributeV3();
        impostor.setUuid("11111111-2222-3333-4444-555555555555");
        impostor.setName(RunHandle.ATTRIBUTE_NAME);
        impostor.setType(AttributeType.META);
        impostor.setContentType(AttributeContentType.STRING);
        impostor.setContent(List.of(new StringAttributeContentV3("not a checkpoint")));

        Assertions
                .assertEquals(Optional.empty(), RunHandle.from(List.of(impostor)),
                        "a name collision must not be read as the checkpoint");
    }

    @Test
    void findsTheCheckpointByItsUuidAlongsideOtherMetadata() {
        MetadataAttributeV3 other = new MetadataAttributeV3();
        other.setUuid("11111111-2222-3333-4444-555555555555");
        other.setName("meta_somethingCoreCarries");
        other.setType(AttributeType.META);
        other.setContentType(AttributeContentType.STRING);
        other.setContent(List.of(new StringAttributeContentV3("x")));

        RunHandle handle = new RunHandle(RunHandle.RunState.STOPPED, 4, 40, "digest", 4, 1, Map.of());
        List<MetadataAttribute> meta = new java.util.ArrayList<>(List.of(other));
        meta.addAll(handle.encode());

        Assertions.assertEquals(handle, RunHandle.from(meta).orElseThrow());
    }

    /**
     * Jackson fills what is absent with null or zero, so a truncated or hostile checkpoint parses cleanly and then
     * fails somewhere with nothing naming the cause -- a negative cursor indexing the enumeration, a sequence space
     * that runs backwards, a null map dereferenced. The contract documents a validation failure for a checkpoint it
     * cannot read, and this is the other half of unreadable.
     */
    @Test
    void refusesACheckpointThatParsesButCannotBeTrue() {
        Assertions.assertThrows(ValidationException.class, () -> decode("{\"state\":\"STOPPED\",\"cursorIndex\":-1,"
                + "\"sequenceHighWater\":0,\"targetsDigest\":\"d\",\"targetsProcessed\":0,\"targetsFailed\":0}"));
        Assertions.assertThrows(ValidationException.class, () -> decode("{\"state\":\"STOPPED\",\"cursorIndex\":0,"
                + "\"sequenceHighWater\":-5,\"targetsDigest\":\"d\",\"targetsProcessed\":0,\"targetsFailed\":0}"));
        Assertions
                .assertThrows(ValidationException.class,
                        () -> decode("{\"cursorIndex\":0,\"sequenceHighWater\":0,\"targetsDigest\":\"d\"}"),
                        "a checkpoint with no state cannot say whether it may be rebuilt");
        Assertions
                .assertThrows(ValidationException.class,
                        () -> decode("{\"state\":\"STOPPED\",\"cursorIndex\":0,\"sequenceHighWater\":0}"),
                        "without a digest there is nothing to check the enumeration against");
        Assertions
                .assertThrows(ValidationException.class,
                        () -> decode("{\"state\":\"STOPPED\",\"cursorIndex\":0,\"sequenceHighWater\":0,"
                                + "\"targetsDigest\":\"d\",\"targetsProcessed\":2,\"targetsFailed\":5}"),
                        "more failures than processed targets is not a state a run can reach");
        Assertions
                .assertThrows(ValidationException.class,
                        () -> decode("{\"state\":\"STOPPED\",\"cursorIndex\":100,\"sequenceHighWater\":0,"
                                + "\"targetsDigest\":\"d\",\"targetsProcessed\":0,\"targetsFailed\":0}"),
                        "a cursor ahead of the count would resume past targets nothing scanned");
    }

    /** An absent yield map is a run that produced nothing, which a checkpoint may legitimately describe. */
    @Test
    void readsACheckpointThatHasProducedNothingYet() {
        RunHandle handle = decode("{\"state\":\"STOPPED\",\"cursorIndex\":0,\"sequenceHighWater\":0,"
                + "\"targetsDigest\":\"d\",\"targetsProcessed\":0,\"targetsFailed\":0}");

        Assertions.assertEquals(Map.of(), handle.yieldByResource());
    }

    /** Built outside the assertion lambda so only the call under test can throw from inside it. */
    private static MetadataAttribute checkpointOf(String json) {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid(RunHandle.ATTRIBUTE_UUID);
        attribute.setName(RunHandle.ATTRIBUTE_NAME);
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV3(json)));
        return attribute;
    }

    private static RunHandle decode(String json) {
        return RunHandle.from(List.of(checkpointOf(json))).orElseThrow();
    }


    /** The content list is Object-typed, so a foreign shape must fail as validation rather than as a raw cast. */
    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void refusesContentThatIsNotAnAttributeContent() {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid(RunHandle.ATTRIBUTE_UUID);
        attribute.setName(RunHandle.ATTRIBUTE_NAME);
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent((List) new java.util.ArrayList<>(List.of("not an attribute content")));
        List<MetadataAttribute> meta = List.of(attribute);

        Assertions.assertThrows(ValidationException.class, () -> RunHandle.from(meta));
    }

}
