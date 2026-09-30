package com.otilm.discovery.ip.enums;

import com.otilm.api.exception.ValidationException;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class DiscoveryKindTest {

    @Test
    void resolvesTheSupportedKindByItsCode() {
        Assertions.assertEquals(DiscoveryKind.IP_Hostname, DiscoveryKind.findByCode("IP-Hostname"));
    }

    @Test
    void rejectsAnUnknownCode() {
        Assertions.assertThrows(ValidationException.class, () -> DiscoveryKind.findByCode("Carrier-Pigeon"));
    }

    @Test
    void rejectsACodeDifferingOnlyByCase() {
        Assertions.assertThrows(ValidationException.class, () -> DiscoveryKind.findByCode("ip-hostname"));
    }

    @Test
    void listsTheSupportedKinds() {
        List<String> kinds = DiscoveryKind.getKinds();

        Assertions.assertEquals(List.of("IP-Hostname"), kinds);
    }

    @Test
    void exposesTheCodeUsedOnTheWire() {
        Assertions.assertEquals("IP-Hostname", DiscoveryKind.IP_Hostname.getCode());
    }
}
