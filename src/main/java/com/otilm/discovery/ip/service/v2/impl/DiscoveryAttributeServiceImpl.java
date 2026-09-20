package com.otilm.discovery.ip.service.v2.impl;

import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackRequestDto;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackResponseDto;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.connector.v2.attribute.AttributeDefinitionsDto;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.constraint.BaseAttributeConstraint;
import com.otilm.api.model.common.attribute.common.constraint.RangeAttributeConstraint;
import com.otilm.api.model.common.attribute.common.constraint.data.RangeAttributeConstraintData;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.InfoAttributeProperties;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.InfoAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.discovery.ip.api.v2.AttributeCallbackNotSupportedException;
import com.otilm.discovery.ip.api.v2.AttributeDefinitionNotFoundException;
import com.otilm.discovery.ip.service.v2.DiscoveryAttributeService;
import com.otilm.discovery.ip.util.TargetEnumeration;
import com.otilm.core.util.AttributeDefinitionUtils;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
public class DiscoveryAttributeServiceImpl implements DiscoveryAttributeService {

    public static final String DATA_ATTRIBUTE_HOSTS_UUID = "2cc7b1ee-7656-4844-a651-aed2300b750b";
    public static final String DATA_ATTRIBUTE_HOSTS_NAME = "data_hosts";

    public static final String DATA_ATTRIBUTE_PORTS_UUID = "acc48fc4-803e-45b1-951f-02764abcbbe8";
    public static final String DATA_ATTRIBUTE_PORTS_NAME = "data_ports";

    public static final String DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_UUID = "8bccc906-1ebc-4ab6-9115-25d5492a9340";
    public static final String DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_NAME = "data_parallelExecutions";

    public static final String INFO_ATTRIBUTE_SCAN_TARGETS_UUID = "7f412886-f7de-4a0b-babc-43eaf40bfdf4";
    public static final String INFO_ATTRIBUTE_SCAN_TARGETS_NAME = "info_scanTargets";

    public static final int PARALLEL_EXECUTIONS_MIN = 1;
    public static final int PARALLEL_EXECUTIONS_MAX = 100;

    /** Applied when a run supplies no ports at all, which is what v1 got from a single-valued default. */
    public static final String DEFAULT_PORT = "443";

    /**
     * Offered, never enforced. Core stores an extensible list without its content precisely so the UI can show these
     * as suggestions, so revising them needs no definition migration, and an entry outside them is accepted, or the
     * list would be a closed one wearing the wrong flag.
     */
    private static final List<String> SUGGESTED_PORTS = List.of("443", "8443", "1-1024", "1-65535");

    private final BuildProperties buildProperties;

    public DiscoveryAttributeServiceImpl(BuildProperties buildProperties) {
        this.buildProperties = buildProperties;
    }

    @Override
    public List<BaseAttribute> listRunAttributes() {
        return List.of(hostsHelp(), hosts(), ports(), parallelExecutions());
    }

    @Override
    public AttributeDefinitionsDto listDefinitions(List<UUID> uuids) {
        List<BaseAttribute> definitions = listRunAttributes();
        if (uuids != null && !uuids.isEmpty()) {
            Set<UUID> wanted = new HashSet<>(uuids);
            definitions = definitions.stream().filter(definition -> wanted.contains(uuidOf(definition))).toList();
        }

        AttributeDefinitionsDto dto = new AttributeDefinitionsDto();
        dto.setConnectorVersion(buildProperties.getVersion());
        dto.setDefinitions(definitions);
        return dto;
    }

    @Override
    public BaseAttribute getDefinition(UUID uuid) {
        return listRunAttributes()
                .stream()
                .filter(definition -> uuid.equals(uuidOf(definition)))
                .findFirst()
                .orElseThrow(() -> new AttributeDefinitionNotFoundException(uuid));
    }

    /**
     * No attribute here declares a callback: every value is typed by the operator rather than chosen from a set the
     * connector computes. The route exists because Core resolves a declared callback through it, so declaring one
     * without implementing this would be a broken definition.
     */
    @Override
    public AttributeCallbackResponseDto callback(AttributeCallbackRequestDto request) {
        throw new AttributeCallbackNotSupportedException(request == null ? null : request.getAttributeName());
    }

    @Override
    public List<String> readHosts(List<RequestAttribute> attributes) {
        List<String> entries = entriesOf(DATA_ATTRIBUTE_HOSTS_NAME, attributes);
        if (entries.isEmpty()) {
            throw new ValidationException("At least one host is required");
        }
        entries.forEach(entry -> checked(DATA_ATTRIBUTE_HOSTS_NAME, entry,
                () -> TargetEnumeration.validateHostSpec(entry)));
        return entries;
    }

    @Override
    public List<String> readPorts(List<RequestAttribute> attributes) {
        List<String> entries = entriesOf(DATA_ATTRIBUTE_PORTS_NAME, attributes);
        if (entries.isEmpty()) {
            return List.of(DEFAULT_PORT);
        }
        entries.forEach(entry -> checked(DATA_ATTRIBUTE_PORTS_NAME, entry,
                () -> TargetEnumeration.validatePortSpec(entry, false)));
        return entries;
    }

    @Override
    public int readParallelExecutions(List<RequestAttribute> attributes) {
        List<IntegerAttributeContentV3> content = AttributeDefinitionUtils
                .getAttributeContentValue(DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_NAME, attributes,
                        IntegerAttributeContentV3.class);
        if (content == null || content.isEmpty() || content.get(0).getData() == null) {
            return PARALLEL_EXECUTIONS_MIN;
        }

        int requested = content.get(0).getData();
        if (requested < PARALLEL_EXECUTIONS_MIN || requested > PARALLEL_EXECUTIONS_MAX) {
            throw new ValidationException("Invalid value for parallel executions, it can be between "
                    + PARALLEL_EXECUTIONS_MIN + " and " + PARALLEL_EXECUTIONS_MAX);
        }
        return requested;
    }

    /**
     * Blank entries are dropped rather than rejected: a list widget leaves one behind when a row is cleared, and
     * refusing the run for it would blame the operator for the widget.
     */
    private static List<String> entriesOf(String name, List<RequestAttribute> attributes) {
        List<StringAttributeContentV3> content = AttributeDefinitionUtils
                .getAttributeContentValue(name, attributes, StringAttributeContentV3.class);
        if (content == null) {
            return List.of();
        }
        return content
                .stream()
                .map(StringAttributeContentV3::getData)
                .filter(data -> data != null && !data.isBlank())
                .map(String::trim)
                .toList();
    }

    /**
     * The whole point of a list schema: the rejection names the entry that is wrong. A comma-separated string could
     * only say the value was bad, leaving the operator to find which part of it.
     */
    private static void checked(String name, String entry, Runnable validation) {
        try {
            validation.run();
        } catch (ValidationException | IllegalArgumentException e) {
            throw new ValidationException(name + " entry \"" + entry + "\" is not valid: " + e.getMessage());
        }
    }

    private static UUID uuidOf(BaseAttribute definition) {
        return UUID.fromString(definition.getUuid());
    }

    private static InfoAttributeV3 hostsHelp() {
        InfoAttributeV3 attribute = new InfoAttributeV3();
        attribute.setUuid(INFO_ATTRIBUTE_SCAN_TARGETS_UUID);
        attribute.setName(INFO_ATTRIBUTE_SCAN_TARGETS_NAME);
        attribute.setType(AttributeType.INFO);
        attribute.setContentType(AttributeContentType.TEXT);
        attribute.setDescription("How a scan is targeted.");

        InfoAttributeProperties properties = new InfoAttributeProperties();
        properties.setLabel("Targeting a scan");
        properties.setVisible(true);
        attribute.setProperties(properties);

        attribute.setContent(List.of(new TextAttributeContentV3(HELP_TEXT)));
        return attribute;
    }

    private static final String HELP_TEXT = """
            Each entry under **Hosts** is one target, given as any of:
            - IP address (`10.100.2.14`)
            - Hostname (`www.example.com`)
            - IP address range (`10.1.1.20-10.1.1.150`)
            - CIDR subnet (`172.16.1.0/24`)

            Each entry under **Ports** is a single port (`443`) or a range (`9000-10000`).
            Leave Ports empty to scan 443.

            A scan probes every combination of a host and a port, so a wide subnet with a wide port range is a
            large scan: `1-65535` against a `/24` is over sixteen million probes. Narrow either side where you
            can.

            Probes run sequentially unless **Number of parallel executions** is raised, up to 100.
            """;

    private static DataAttributeV3 hosts() {
        DataAttributeV3 attribute = openList(DATA_ATTRIBUTE_HOSTS_UUID, DATA_ATTRIBUTE_HOSTS_NAME, "Hosts");
        attribute.setDescription("Addresses, hostnames, ranges or subnets to scan. One target per entry.");
        attribute.getProperties().setRequired(true);
        // No suggestions: there is no host every deployment would want.
        return attribute;
    }

    private static DataAttributeV3 ports() {
        DataAttributeV3 attribute = openList(DATA_ATTRIBUTE_PORTS_UUID, DATA_ATTRIBUTE_PORTS_NAME, "Ports");
        attribute
                .setDescription("Ports to probe on each host, as a single port or a range. One per entry; leave "
                        + "empty to scan " + DEFAULT_PORT + ".");
        attribute.getProperties().setRequired(false);
        attribute.setContent(SUGGESTED_PORTS.stream().map(port -> new StringAttributeContentV3(port, port)).toList());
        return attribute;
    }

    /**
     * Not a list, so its content is what a list cannot carry: a real default, which Core stores with the definition
     * and the form comes up holding.
     */
    private static DataAttributeV3 parallelExecutions() {
        DataAttributeV3 attribute = new DataAttributeV3();
        attribute.setUuid(DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_UUID);
        attribute.setName(DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_NAME);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.INTEGER);
        attribute.setDescription("How many probes run at once. Higher finishes sooner and presses the network harder.");

        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("Number of parallel executions");
        properties.setRequired(false);
        properties.setReadOnly(false);
        properties.setVisible(true);
        attribute.setProperties(properties);

        attribute.setContent(List.of(new IntegerAttributeContentV3(PARALLEL_EXECUTIONS_MIN)));

        RangeAttributeConstraintData range = new RangeAttributeConstraintData();
        range.setFrom(PARALLEL_EXECUTIONS_MIN);
        range.setTo(PARALLEL_EXECUTIONS_MAX);
        RangeAttributeConstraint constraint = new RangeAttributeConstraint();
        constraint.setData(range);
        constraint.setDescription("Allowed values for parallel executions");
        constraint.setErrorMessage("Invalid value for parallel executions, it can be between "
                + PARALLEL_EXECUTIONS_MIN + " and " + PARALLEL_EXECUTIONS_MAX);
        attribute.setConstraints(List.<BaseAttributeConstraint<?>>of(constraint));

        return attribute;
    }

    /**
     * A list an operator can extend. All three properties travel together: Core refuses {@code multiSelect} or
     * {@code extensibleList} on an attribute that is not a list, and without {@code extensibleList} the content
     * becomes the only permitted values, which for hosts and ports cannot be enumerated in advance.
     */
    private static DataAttributeV3 openList(String uuid, String name, String label) {
        DataAttributeV3 attribute = new DataAttributeV3();
        attribute.setUuid(uuid);
        attribute.setName(name);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);

        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(label);
        properties.setReadOnly(false);
        properties.setVisible(true);
        properties.setList(true);
        properties.setMultiSelect(true);
        properties.setExtensibleList(true);
        attribute.setProperties(properties);

        return attribute;
    }
}
