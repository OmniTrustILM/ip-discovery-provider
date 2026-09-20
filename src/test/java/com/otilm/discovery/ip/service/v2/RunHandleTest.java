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
        return new RunHandle(RunHandle.RunState.RUNNING, 1_234_567_890L, 987_654_321L,
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

        Assertions.assertEquals(1_234_567_890L, read.cursorIndex());
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

        Assertions
                .assertThrows(ValidationException.class, () -> RunHandle.from(List.<MetadataAttribute>of(attribute)));
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
}
