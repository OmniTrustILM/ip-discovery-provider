package com.otilm.discovery.ip.api;

import com.otilm.api.interfaces.connector.HealthController;
import com.otilm.api.model.common.HealthDto;
import com.otilm.api.model.common.HealthStatus;
import org.springframework.web.bind.annotation.RestController;

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
