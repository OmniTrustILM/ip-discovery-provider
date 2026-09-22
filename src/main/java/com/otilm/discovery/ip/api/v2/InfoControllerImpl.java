package com.otilm.discovery.ip.api.v2;

import com.otilm.api.interfaces.connector.common.v2.InfoController;
import com.otilm.api.model.client.connector.v2.ConnectorInfo;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorInterfaceInfo;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.connector.v2.InfoResponse;
import com.otilm.discovery.ip.Application;
import com.otilm.discovery.ip.ConnectorV2Api;
import org.springframework.boot.info.BuildProperties;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Advertises the v2 surface only.
 *
 * <p>
 * The v1 info endpoint keeps returning its own {@code FunctionGroupCode}-based response, and the two are never merged:
 * a Core that has not migrated reads v1's answer, and one that has reads this. Both surfaces serve until the
 * platform-level sunset.
 */
@RestController("infoControllerV2")
@ConnectorV2Api
public class InfoControllerImpl implements InfoController {

    private final BuildProperties buildProperties;

    public InfoControllerImpl(BuildProperties buildProperties) {
        this.buildProperties = buildProperties;
    }

    @Override
    public InfoResponse getConnectorInfo() {
        ConnectorInfo connector = new ConnectorInfo();
        connector.setId(Application.class.getPackageName());
        connector.setName("Network Discovery Provider");
        connector.setVersion(buildProperties.getVersion());

        InfoResponse response = new InfoResponse();
        response.setConnector(connector);
        response
                .setInterfaces(List
                        .of(declare(ConnectorInterface.INFO), declare(ConnectorInterface.HEALTH),
                                declare(ConnectorInterface.ATTRIBUTES), metrics()));
        return response;
    }

    private static ConnectorInterfaceInfo declare(ConnectorInterface code) {
        ConnectorInterfaceInfo info = new ConnectorInterfaceInfo();
        info.setCode(code);
        info.setVersion("v2");
        return info;
    }

    /**
     * Metrics is declared at {@code v1}, not {@code v2}: {@code MetricsController} maps to {@code /v1/metrics} and
     * {@code METRICS_CONFIG} carries {@code version=1}, so the metrics API is versioned independently of the connector
     * interface that hosts it. The other connectors on the v2 surface declare it the same way.
     */
    private static ConnectorInterfaceInfo metrics() {
        ConnectorInterfaceInfo info = new ConnectorInterfaceInfo();
        info.setCode(ConnectorInterface.METRICS);
        info.setVersion("v1");
        info.setFeatures(List.of(FeatureFlag.OPEN_METRICS));
        return info;
    }
}
