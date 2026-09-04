package com.otilm.discovery.ip.service.impl;

import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

/**
 * The scan counts targets in longs, but the metadata attributes have been INTEGER since v1 and their type is part of
 * that wire shape, so the numeric value is clamped while the reference keeps the exact figure. No reachable scan
 * reaches the boundary — 2.1 billion probes is weeks — so it is only ever exercised here.
 */
class DiscoveryMetadataCountTest {

    @Test
    void reportsACountBelowTheBoundaryExactly() {
        IntegerAttributeContentV2 content = contentOf(DiscoveryServiceImpl.reportableCount(4_200L));

        Assertions.assertEquals(4_200, content.getData());
        Assertions.assertEquals("4200", content.getReference());
    }

    @Test
    void reportsTheBoundaryItselfExactly() {
        IntegerAttributeContentV2 content = contentOf(DiscoveryServiceImpl.reportableCount(Integer.MAX_VALUE));

        Assertions.assertEquals(Integer.MAX_VALUE, content.getData());
        Assertions.assertEquals(String.valueOf(Integer.MAX_VALUE), content.getReference());
    }

    /**
     * Past the boundary the numeric value saturates rather than wrapping negative, and the reference still carries
     * the true count — which is the whole point of clamping instead of narrowing.
     */
    @Test
    void clampsPastTheBoundaryWhileKeepingTheTrueCountInTheReference() {
        long beyond = Integer.MAX_VALUE + 1L;

        IntegerAttributeContentV2 content = contentOf(DiscoveryServiceImpl.reportableCount(beyond));

        Assertions.assertEquals(Integer.MAX_VALUE, content.getData());
        Assertions.assertEquals("2147483648", content.getReference());
    }

    @Test
    void clampsAWholeAllPortsSubnetScan() {
        // 65534 usable hosts on 65535 ports -- the /16 the metadata comment names, and far past an int.
        long targets = 65_534L * 65_535L;

        IntegerAttributeContentV2 content = contentOf(DiscoveryServiceImpl.reportableCount(targets));

        Assertions.assertEquals(Integer.MAX_VALUE, content.getData());
        Assertions.assertEquals(Long.toString(targets), content.getReference());
    }

    private static IntegerAttributeContentV2 contentOf(List<BaseAttributeContentV2<?>> content) {
        Assertions.assertEquals(1, content.size());
        return Assertions.assertInstanceOf(IntegerAttributeContentV2.class, content.get(0));
    }
}
