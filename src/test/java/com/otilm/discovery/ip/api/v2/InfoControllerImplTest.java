package com.otilm.discovery.ip.api.v2;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorInterfaceInfo;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.info.BuildProperties;

import java.util.EnumSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

class InfoControllerImplTest {

    private final InfoControllerImpl controller = new InfoControllerImpl(buildProperties());

    private static BuildProperties buildProperties() {
        Properties properties = new Properties();
        properties.setProperty("version", "2.20.0-SNAPSHOT");
        return new BuildProperties(properties);
    }

    private ConnectorInterfaceInfo declarationOf(ConnectorInterface code) {
        return controller
                .getConnectorInfo()
                .getInterfaces()
                .stream()
                .filter(declared -> declared.getCode() == code)
                .findFirst()
                .orElseThrow(() -> new AssertionError(code.getLabel() + " is not advertised"));
    }

    private Set<ConnectorInterface> advertised() {
        return controller
                .getConnectorInfo()
                .getInterfaces()
                .stream()
                .map(ConnectorInterfaceInfo::getCode)
                .collect(Collectors.toSet());
    }

    /**
     * Core refuses to register a v2 connector whose info response omits any of these, throwing "Connector is missing
     * mandatory interfaces" out of {@code ConnectorV2Adapter.validateConnection}. Dropping one fails here instead,
     * where the cause is visible — at registration the only symptom is a connector Core will not accept.
     */
    @Test
    void advertisesEveryInterfaceCoreRequiresBeforeItWillRegisterTheConnector() {
        Set<ConnectorInterface> advertised = advertised();

        Assertions
                .assertTrue(
                        advertised
                                .containsAll(EnumSet.of(ConnectorInterface.INFO, ConnectorInterface.HEALTH,
                                        ConnectorInterface.METRICS)),
                        "Core rejects a connector missing any mandatory interface; advertised: " + advertised);
    }

    @Test
    void advertisesAFunctionalInterface() {
        Assertions
                .assertTrue(
                        advertised()
                                .stream()
                                .anyMatch(code -> code
                                        .getCategory() == ConnectorInterface.InterfaceCategory.FUNCTIONAL),
                        "Core rejects a connector that implements only common interfaces");
    }

    /**
     * The metrics API is versioned independently of the connector interface hosting it: {@code MetricsController}
     * maps to {@code /v1/metrics} and its {@code METRICS_CONFIG} carries {@code version=1}, while info and health map
     * to {@code /v2/*}. Declaring metrics as v2 would name an endpoint this connector does not serve.
     */
    @Test
    void declaresMetricsAtTheMetricsApiOwnVersion() {
        ConnectorInterfaceInfo metrics = declarationOf(ConnectorInterface.METRICS);

        Assertions.assertEquals("v1", metrics.getVersion());
        Assertions.assertEquals(List.of(FeatureFlag.OPEN_METRICS), metrics.getFeatures());
    }

    @Test
    void declaresTheConnectorInterfacesAtV2() {
        Assertions.assertEquals("v2", declarationOf(ConnectorInterface.INFO).getVersion());
        Assertions.assertEquals("v2", declarationOf(ConnectorInterface.HEALTH).getVersion());
        Assertions.assertEquals("v2", declarationOf(ConnectorInterface.ATTRIBUTES).getVersion());
        Assertions.assertEquals("v2", declarationOf(ConnectorInterface.DISCOVERY).getVersion());
    }

    /**
     * The list is what a consumer reads to know which interfaces exist. This connector mounts the whole v2 attribute
     * surface, so omitting it reports an implemented interface as absent.
     */
    @Test
    void advertisesTheAttributeInterfaceItServes() {
        Assertions.assertTrue(advertised().contains(ConnectorInterface.ATTRIBUTES));
    }

    /**
     * Stop and resume are advertised because a stopped run survives the connector restarting: the scan is
     * interruptible, the checkpoint travels in the run's meta, and a run this node no longer holds is rebuilt from
     * it. Streaming is not, and must not be — Core has no stream client, so the flag would promise a path nothing
     * uses and the endpoint answers as unsupported.
     */
    @Test
    void advertisesStopAndResumeButNotStreaming() {
        List<FeatureFlag> features = declarationOf(ConnectorInterface.DISCOVERY).getFeatures();

        Assertions.assertEquals(List.of(FeatureFlag.DISCOVERY_STOP_RESUME), features);
        Assertions
                .assertFalse(features.contains(FeatureFlag.DISCOVERY_STREAMING),
                        "streaming is unimplemented, so advertising it would be a false claim");
    }
}
