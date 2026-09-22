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
        // Readiness is not distinguished from liveness today: a v2 run holds no state here to warm up, since the
        // checkpoint lives in Core. That is not the whole picture -- the process still owns a datasource and the v1
        // repositories -- so neither probe can currently answer 503, which the contract allows for.
        return up();
    }

    private static HealthInfo up() {
        HealthInfo info = new HealthInfo();
        info.setStatus(HealthStatus.UP);
        return info;
    }
}
