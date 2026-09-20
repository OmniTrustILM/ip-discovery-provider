package com.otilm.discovery.ip.api.v2;

import com.otilm.api.interfaces.connector.common.v2.HealthController;
import com.otilm.api.model.client.connector.v2.HealthInfo;
import com.otilm.api.model.client.connector.v2.HealthStatus;
import com.otilm.discovery.ip.ConnectorV2Api;
import org.springframework.web.bind.annotation.RestController;

@RestController("healthControllerV2")
@ConnectorV2Api
public class HealthControllerImpl implements HealthController {

    @Override
    public HealthInfo checkHealth() {
        return up();
    }

    @Override
    public HealthInfo checkHealthLiveness() {
        return up();
    }

    @Override
    public HealthInfo checkHealthReadiness() {
        // Readiness is not distinguished from liveness: the connector holds no run state to warm up and no upstream
        // to reach. It answers a scan request as soon as it answers at all.
        return up();
    }

    private static HealthInfo up() {
        HealthInfo info = new HealthInfo();
        info.setStatus(HealthStatus.UP);
        return info;
    }
}
