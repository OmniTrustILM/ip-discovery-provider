package com.otilm.discovery.ip.util;

import com.otilm.api.exception.ValidationException;
import com.otilm.discovery.ip.service.impl.AttributeServiceImpl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * The scan's targets, addressed by index rather than held in memory: only the parsed host blocks and the port list are
 * kept, and the nth target is computed arithmetically. A {@code /24} on all ports is 16,645,890 targets.
 *
 * <p>
 * <b>The order is frozen.</b> A discovery v2 checkpoint is an index into this enumeration, so a resume against a
 * different order would resume at the wrong target. {@link #digest()} detects that and refuses the resume.
 *
 * <p>
 * Addresses are IPv4 throughout, which the validation regexes require, so an address fits in a {@code long} and blocks
 * merge with interval arithmetic.
 */
public final class TargetEnumeration {

    /** Bump only with a deliberate change to the enumeration order: every stopped run in the field then refuses to resume. */
    private static final String ENUMERATION_VERSION = "1";

    private static final Pattern HOSTNAME_PATTERN = Pattern.compile(AttributeServiceImpl.HOSTNAME_VALIDATION_REGEX);
    private static final Pattern IP_ADDRESS_PATTERN = Pattern.compile(AttributeServiceImpl.IP_ADDRESS_VALIDATION_REGEX);
    private static final Pattern IP_ADDRESS_RANGE_PATTERN =
            Pattern.compile(AttributeServiceImpl.IP_ADDRESS_RANGE_VALIDATION_REGEX);
    private static final Pattern IP_SUBNET_PATTERN = Pattern.compile(AttributeServiceImpl.IP_SUBNET_VALIDATION_REGEX);
    private static final Pattern PORT_PATTERN = Pattern.compile(AttributeServiceImpl.PORT_VALIDATION_REGEX);
    private static final Pattern PORT_RANGE_PATTERN =
            Pattern.compile(AttributeServiceImpl.PORT_RANGE_VALIDATION_REGEX);

    private static final int MAX_OCTET = 255;
    private static final int MIN_PORT = 1;
    private static final int MAX_PORT = 65535;

    /** Sorted and distinct. Enumerated before the address blocks. */
    private final List<String> hostnames;

    /** Merged, ascending, inclusive. Parallel arrays rather than objects: there are few blocks and many addresses. */
    private final long[] blockLow;
    private final long[] blockHigh;

    /** Addresses enumerated before each block, so a block is found by binary search rather than by walking. */
    private final long[] blockStart;

    private final long hostCount;
    private final int[] ports;
    private final String digest;

    private TargetEnumeration(List<String> hostnames, long[] blockLow, long[] blockHigh, int[] ports, String digest) {
        this.hostnames = hostnames;
        this.blockLow = blockLow;
        this.blockHigh = blockHigh;
        this.ports = ports;
        this.digest = digest;
        this.blockStart = new long[blockLow.length];
        long running = hostnames.size();
        for (int i = 0; i < blockLow.length; i++) {
            blockStart[i] = running;
            running += blockHigh[i] - blockLow[i] + 1;
        }
        this.hostCount = running;
    }

    /**
     * Parses a scan spec. The exception types are what attribute validation depends on.
     *
     * @throws ValidationException if a host entry is not an address, range, subnet or hostname
     * @throws IllegalArgumentException if a port entry is not a port or a port range
     */
    public static TargetEnumeration of(String hostSpec, String portSpec, Boolean allPorts) {
        Set<String> names = new TreeSet<>();
        List<long[]> blocks = new ArrayList<>();
        parseHosts(hostSpec, names, blocks);

        long[][] merged = merge(blocks);
        int[] portList = parsePorts(portSpec, allPorts);

        List<String> nameList = List.copyOf(names);
        return new TargetEnumeration(nameList, merged[0], merged[1], portList,
                digestOf(nameList, merged[0], merged[1], portList));
    }

    /** Total targets: hosts x ports. A {@code long} because an all-ports subnet scan overflows an {@code int}. */
    public long size() {
        return hostCount * ports.length;
    }

    /**
     * The nth target, host-major: {@code index / portCount} selects the host and {@code index % portCount} the port.
     *
     * @throws IndexOutOfBoundsException if {@code index} is outside the enumeration
     */
    public String target(long index) {
        if (index < 0 || index >= size()) {
            throw new IndexOutOfBoundsException("Target index " + index + " outside enumeration of " + size());
        }
        return "https://" + hostAt(index / ports.length) + ":" + ports[(int) (index % ports.length)];
    }

    /** Identity of the scan and its enumeration order, stable until {@link #ENUMERATION_VERSION} changes. */
    public String digest() {
        return digest;
    }

    private String hostAt(long n) {
        if (n < hostnames.size()) {
            return hostnames.get((int) n);
        }
        int block = Arrays.binarySearch(blockStart, n);
        if (block < 0) {
            // -(insertion point) - 1; the containing block is the one before the insertion point.
            block = -block - 2;
        }
        return toDottedQuad(blockLow[block] + (n - blockStart[block]));
    }

    private static void parseHosts(String hostSpec, Set<String> names, List<long[]> blocks) {
        for (String entry : hostSpec.split(",")) {
            if (HOSTNAME_PATTERN.matcher(entry).matches()) {
                // Case-folded: DNS names are case-insensitive, so two casings are one scan and must agree on
                // order and digest.
                names.add(entry.toLowerCase(Locale.ROOT));
            } else if (IP_ADDRESS_PATTERN.matcher(entry).matches()) {
                long address = toLong(entry);
                blocks.add(new long[] {address, address});
            } else if (IP_ADDRESS_RANGE_PATTERN.matcher(entry).matches()) {
                String[] bounds = entry.split("-");
                long low = toLong(bounds[0]);
                long high = toLong(bounds[1]);
                blocks.add(new long[] {Math.min(low, high), Math.max(low, high)});
            } else if (IP_SUBNET_PATTERN.matcher(entry).matches()) {
                addSubnet(entry, blocks);
            } else {
                throw new ValidationException(
                        "Invalid input format for IP address, hostname, range, or subnet: " + entry);
            }
        }
    }

    /**
     * Adds a CIDR block's <em>usable</em> addresses, network and broadcast excluded. A {@code /31} or {@code /32}
     * therefore contributes nothing.
     */
    private static void addSubnet(String entry, List<long[]> blocks) {
        String[] parts = entry.split("/");
        long address = toLong(parts[0]);
        // The regex admits a bare address with no prefix; treat it as the single host it names.
        int prefix = parts.length > 1 ? Integer.parseInt(parts[1]) : 32;
        long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        long network = address & mask;
        long broadcast = network | (~mask & 0xFFFFFFFFL);
        if (broadcast - network >= 2) {
            blocks.add(new long[] {network + 1, broadcast - 1});
        }
    }

    /**
     * Merges overlapping and adjacent blocks, so an overlapping spec — a subnet plus an address inside it — is not
     * scanned twice and does not inflate {@link #size()}.
     */
    private static long[][] merge(List<long[]> blocks) {
        if (blocks.isEmpty()) {
            return new long[][] {new long[0], new long[0]};
        }
        blocks.sort((a, b) -> Long.compare(a[0], b[0]));
        List<long[]> mergedBlocks = new ArrayList<>();
        long[] current = blocks.get(0).clone();
        for (long[] next : blocks.subList(1, blocks.size())) {
            if (next[0] <= current[1] + 1) {
                current[1] = Math.max(current[1], next[1]);
            } else {
                mergedBlocks.add(current);
                current = next.clone();
            }
        }
        mergedBlocks.add(current);

        long[] low = new long[mergedBlocks.size()];
        long[] high = new long[mergedBlocks.size()];
        for (int i = 0; i < mergedBlocks.size(); i++) {
            low[i] = mergedBlocks.get(i)[0];
            high[i] = mergedBlocks.get(i)[1];
        }
        return new long[][] {low, high};
    }

    private static int[] parsePorts(String portSpec, Boolean allPorts) {
        if (Boolean.TRUE.equals(allPorts)) {
            int[] all = new int[MAX_PORT];
            for (int i = 0; i < MAX_PORT; i++) {
                // 1..65535 inclusive: port 0 is not scannable and PORT_VALIDATION_REGEX rejects it.
                all[i] = i + MIN_PORT;
            }
            return all;
        }
        Set<Integer> parsed = new TreeSet<>();
        for (String port : portSpec.split(",")) {
            if (PORT_PATTERN.matcher(port).matches()) {
                parsed.add(Integer.parseInt(port));
            } else if (PORT_RANGE_PATTERN.matcher(port).matches()) {
                String[] bounds = port.split("-");
                int from = Integer.parseInt(bounds[0]);
                int to = Integer.parseInt(bounds[1]);
                for (int i = Math.min(from, to); i <= Math.max(from, to); i++) {
                    parsed.add(i);
                }
            } else {
                throw new IllegalArgumentException("Invalid input format for port: " + port);
            }
        }
        return parsed.stream().mapToInt(Integer::intValue).toArray();
    }

    /** Hashes the normalised spec — canonical order, blocks merged, ports as ranges — so two spellings of one scan agree. */
    private static String digestOf(List<String> hostnames, long[] low, long[] high, int[] ports) {
        StringBuilder canonical = new StringBuilder(ENUMERATION_VERSION).append("|H:");
        canonical.append(String.join(",", hostnames)).append("|A:");
        for (int i = 0; i < low.length; i++) {
            canonical.append(toDottedQuad(low[i])).append('-').append(toDottedQuad(high[i])).append(';');
        }
        canonical.append("|P:").append(asRanges(ports));

        try {
            byte[] hash = MessageDigest
                    .getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JLS platform requirements; its absence is not a runtime condition.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Collapses a sorted port list into ranges, so an all-ports scan canonicalises to {@code 1-65535}. */
    private static String asRanges(int[] ports) {
        StringBuilder ranges = new StringBuilder();
        for (int i = 0; i < ports.length;) {
            int from = i;
            while (i + 1 < ports.length && ports[i + 1] == ports[i] + 1) {
                i++;
            }
            ranges.append(ports[from]);
            if (i > from) {
                ranges.append('-').append(ports[i]);
            }
            ranges.append(',');
            i++;
        }
        return ranges.toString();
    }

    /**
     * Packs a dotted quad into a {@code long}, rejecting an octet outside 0-255.
     *
     * <p>
     * The check is load-bearing: {@code IP_SUBNET_VALIDATION_REGEX} bounds octets only to one-to-three digits and makes
     * the prefix optional, so {@code 999.1.1.0/24} reaches here and unchecked would bleed across the byte boundary into
     * {@code 231.1.1.0/24} — a different network.
     */
    private static long toLong(String dottedQuad) {
        String[] octets = dottedQuad.split("\\.");
        if (octets.length != 4) {
            throw new ValidationException("Invalid IP address: " + dottedQuad);
        }
        long value = 0;
        for (String octet : octets) {
            int parsed = Integer.parseInt(octet);
            if (parsed > MAX_OCTET) {
                throw new ValidationException(
                        "Invalid IP address, octet " + parsed + " is outside 0-" + MAX_OCTET + ": " + dottedQuad);
            }
            value = (value << 8) | parsed;
        }
        return value;
    }

    private static String toDottedQuad(long address) {
        return ((address >> 24) & 0xFF) + "." + ((address >> 16) & 0xFF) + "." + ((address >> 8) & 0xFF) + "."
                + (address & 0xFF);
    }

    /**
     * Parses a host spec for its exceptions alone, materialising nothing. Attribute validation runs on every discovery
     * creation, on the request thread, and only needs to know the spec is well formed.
     *
     * @throws ValidationException if a host entry is not an address, range, subnet or hostname
     */
    public static void validateHostSpec(String hostSpec) {
        parseHosts(hostSpec, new TreeSet<>(), new ArrayList<>());
    }
}
