package com.otilm.discovery.ip.util;

import com.otilm.api.exception.ValidationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

/** The enumeration's order is frozen because a discovery v2 checkpoint is an index into it. These tests freeze it. */
class TargetEnumerationTest {

    // --- it does not materialise ---

    @Test
    void sizesAWholeSubnetOnEveryPortWithoutMaterialisingIt() {
        // 254 usable hosts (network and broadcast excluded) x 65535 ports.
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.0/24", "443", true);

        Assertions.assertEquals(254L * 65535L, targets.size());
        Assertions.assertEquals("https://10.0.0.1:1", targets.target(0));
        Assertions.assertEquals("https://10.0.0.254:65535", targets.target(targets.size() - 1));
    }

    @Test
    void addressesAnArbitraryIndexInTheMiddle() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.0/24", "80,443", false);

        // Host-major: index / portCount selects the host, index % portCount the port.
        Assertions.assertEquals("https://10.0.0.1:80", targets.target(0));
        Assertions.assertEquals("https://10.0.0.1:443", targets.target(1));
        Assertions.assertEquals("https://10.0.0.2:80", targets.target(2));
    }

    @Test
    void rejectsAnIndexOutsideTheEnumeration() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1", "443", false);

        Assertions.assertThrows(IndexOutOfBoundsException.class, () -> targets.target(1));
        Assertions.assertThrows(IndexOutOfBoundsException.class, () -> targets.target(-1));
    }

    // --- the order is frozen ---

    /**
     * Pinned deliberately: a stopped discovery v2 run carries this in its checkpoint and refuses to resume when it no
     * longer matches. Changing it invalidates every stopped run in the field, so change it only with a version bump.
     */
    private static final String GOLDEN_DIGEST_FOR_10_0_0_0_30_ON_80_443 =
            "7c072d0d9a892c9f5812716a991f3f339b4abb8860773f7a581b6bfa6cf95f20";

    @Test
    void producesTheSameDigestForTheSameScan() {
        TargetEnumeration first = TargetEnumeration.of("10.0.0.0/30", "80,443", false);
        TargetEnumeration second = TargetEnumeration.of("10.0.0.0/30", "80,443", false);

        Assertions.assertEquals(first.digest(), second.digest());
        Assertions.assertEquals(GOLDEN_DIGEST_FOR_10_0_0_0_30_ON_80_443, first.digest());
    }

    @Test
    void producesTheSameOrderForTheSameScan() {
        TargetEnumeration first = TargetEnumeration.of("10.1.0.0/29,host.example.com", "80-82", false);
        TargetEnumeration second = TargetEnumeration.of("10.1.0.0/29,host.example.com", "80-82", false);

        Assertions.assertEquals(first.size(), second.size());
        for (long i = 0; i < first.size(); i++) {
            Assertions.assertEquals(first.target(i), second.target(i), "target " + i);
        }
    }

    @Test
    void normalisesTheSpecSoTwoSpellingsOfOneScanAgree() {
        // Order of entries, and a subnet against the range it denotes, are the same scan.
        Assertions
                .assertEquals(TargetEnumeration.of("10.0.0.1,10.0.0.2", "443", false).digest(),
                        TargetEnumeration.of("10.0.0.2,10.0.0.1", "443", false).digest());
        Assertions
                .assertEquals(TargetEnumeration.of("192.168.5.0/30", "443", false).digest(),
                        TargetEnumeration.of("192.168.5.1-192.168.5.2", "443", false).digest());
        Assertions
                .assertEquals(TargetEnumeration.of("10.0.0.1", "80,443", false).digest(),
                        TargetEnumeration.of("10.0.0.1", "443,80", false).digest());
    }

    @Test
    void aDifferentScanProducesADifferentDigest() {
        String base = TargetEnumeration.of("10.0.0.1", "443", false).digest();

        Assertions.assertNotEquals(base, TargetEnumeration.of("10.0.0.2", "443", false).digest());
        Assertions.assertNotEquals(base, TargetEnumeration.of("10.0.0.1", "8443", false).digest());
        Assertions.assertNotEquals(base, TargetEnumeration.of("10.0.0.1", "443", true).digest());
    }

    // --- overlap ---

    @Test
    void countsAnOverlappingSpecOnce() {
        // A subnet and an address inside it are one scan; unmerged, the overlap would be scanned twice.
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.0/24,10.0.0.5", "443", false);

        Assertions.assertEquals(254L, targets.size());
    }

    @Test
    void mergesAdjacentRangesIntoOne() {
        TargetEnumeration targets = TargetEnumeration.of("10.0.0.1-10.0.0.5,10.0.0.6-10.0.0.9", "443", false);

        Assertions.assertEquals(9L, targets.size());
        Assertions.assertEquals("https://10.0.0.1:443", targets.target(0));
        Assertions.assertEquals("https://10.0.0.9:443", targets.target(8));
    }

    @Test
    void deduplicatesRepeatedHostnames() {
        TargetEnumeration targets = TargetEnumeration.of("a.example.com,a.example.com", "443", false);

        Assertions.assertEquals(1L, targets.size());
    }

    // --- parity with the path it replaces ---

    @Test
    void enumeratesExactlyWhatTheSetBasedPathProduced() {
        String hosts = "10.9.9.1-10.9.9.4,192.168.5.0/30,host.example.com";
        String ports = "80,443,8443";

        Set<String> legacy = DiscoverIpHandler
                .buildUrls(DiscoverIpHandler.getIpHostnameUrls(hosts), DiscoverIpHandler.getPorts(ports, false));

        TargetEnumeration targets = TargetEnumeration.of(hosts, ports, false);
        Set<String> enumerated = new HashSet<>();
        for (long i = 0; i < targets.size(); i++) {
            enumerated.add(targets.target(i));
        }

        Assertions.assertEquals(legacy, enumerated);
    }

    // --- octet bounds ---

    /**
     * The subnet regex bounds octets only to one-to-three digits, so an out-of-range octet reaches the parser and
     * unchecked yields a different network: 999.1.1.0/24 enumerated 231.1.1.0/24.
     */
    @Test
    void rejectsASubnetWithAnOutOfRangeOctet() {
        Assertions
                .assertThrows(ValidationException.class,
                        () -> TargetEnumeration.of("999.999.999.999/24", "443", false));
        Assertions.assertThrows(ValidationException.class, () -> TargetEnumeration.of("999.1.1.0/24", "443", false));
        Assertions.assertThrows(ValidationException.class, () -> TargetEnumeration.of("300.1.1.0/24", "443", false));
    }

    /** The prefix is optional in that regex, so a bare out-of-range quad reaches the subnet branch and silently vanishes. */
    @Test
    void rejectsABareAddressWithAnOutOfRangeOctet() {
        Assertions.assertThrows(ValidationException.class, () -> TargetEnumeration.of("10.0.0.999", "443", false));
    }

    @Test
    void acceptsTheBoundaryOctets() {
        Assertions.assertEquals(1L, TargetEnumeration.of("255.255.255.255", "443", false).size());
        Assertions.assertEquals(254L, TargetEnumeration.of("0.0.0.0/24", "443", false).size());
    }

    // --- hostname casing ---

    /** DNS names are case-insensitive, so two casings are one scan and must agree on order and digest. */
    @Test
    void treatsHostnameCasingAsTheSameScan() {
        TargetEnumeration upper = TargetEnumeration.of("EXAMPLE.com,Other.Example.COM", "443", false);
        TargetEnumeration lower = TargetEnumeration.of("example.com,other.example.com", "443", false);

        Assertions.assertEquals(lower.digest(), upper.digest());
        Assertions.assertEquals(lower.size(), upper.size());
        Assertions.assertEquals(lower.target(0), upper.target(0));
    }

    @Test
    void collapsesTheSameHostnameSpelledTwoWays() {
        Assertions.assertEquals(1L, TargetEnumeration.of("Example.COM,example.com", "443", false).size());
    }

    // --- validation ---

    @Test
    void rejectsAMalformedHostEntry() {
        Assertions
                .assertThrows(ValidationException.class, () -> TargetEnumeration.of("192.33.168.1.1", "443", false));
    }

    @Test
    void rejectsAMalformedPort() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> TargetEnumeration.of("10.0.0.1", "http", false));
    }

    @Test
    void hasNoTargetsWhenThePortListIsEmptyOfValidEntries() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> TargetEnumeration.of("10.0.0.1", "", false));
    }
}
