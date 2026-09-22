package com.otilm.discovery.ip.api;

import com.otilm.api.interfaces.connector.HealthController;
import com.otilm.api.model.common.HealthDto;
import com.otilm.api.model.common.HealthStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * @deprecated by {@code com.otilm.discovery.ip.api.v2.HealthControllerImpl}, which answers at
 *             {@code /v2/health} and separates liveness from readiness. Both surfaces serve until the platform-level
 *             sunset, so this one keeps working unchanged.
 */
@Deprecated(since = "2.20.0", forRemoval = true)
@RestController
public class HealthControllerImpl implements HealthController {

    @Override
    public HealthDto checkHealth() {
        HealthDto health = new HealthDto();
        health.setStatus(HealthStatus.OK);
        health.setDescription("Connector is online and available to serve requests");
        return health;
    }
}
