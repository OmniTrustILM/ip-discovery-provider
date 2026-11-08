package com.otilm.discovery.ip.service.v2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SliceSettingsTest {

    @Test
    void defaultsFitTheEighteenSecondBound() {
        SliceSettings settings = new SliceSettings(8000, 32, 256, 10000);

        Assertions.assertEquals(8000, settings.scanBudgetMs());
        Assertions.assertEquals(32, settings.maxConcurrent());
        Assertions.assertEquals(256, settings.maxAbandonedProbes());
        Assertions.assertEquals(10000, settings.probeDeadlineMs());
    }

    /**
     * A slice answers within the scan budget plus one probe deadline, and the contract wants an answer inside 20
     * seconds. Refused at startup rather than discovered as timed-out drains.
     */
    @Test
    void budgetPlusDeadlineOverEighteenSecondsIsRefused() {
        IllegalArgumentException refused = Assertions
                .assertThrows(IllegalArgumentException.class, () -> new SliceSettings(9000, 32, 256, 10000));

        Assertions.assertTrue(refused.getMessage().contains("discovery.slice.scan-budget-ms"), refused.getMessage());
        Assertions.assertTrue(refused.getMessage().contains("discovery.probe.total-timeout-ms"), refused.getMessage());
    }

    @Test
    void nonPositiveValuesAreRefused() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new SliceSettings(0, 32, 256, 10000));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new SliceSettings(8000, 0, 256, 10000));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new SliceSettings(8000, 32, -1, 10000));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new SliceSettings(8000, 32, 256, 0));
    }
}
