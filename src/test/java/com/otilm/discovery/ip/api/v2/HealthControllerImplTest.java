package com.otilm.discovery.ip.api.v2;

import com.otilm.api.model.client.connector.v2.HealthInfo;
import com.otilm.api.model.client.connector.v2.HealthStatus;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class HealthControllerImplTest {

    private final HealthControllerImpl controller = new HealthControllerImpl();

    /** The contract permits 503, so the current unconditional UP is asserted rather than assumed. */
    @Test
    void reportsEveryProbeAsUp() {
        Assertions.assertEquals(HealthStatus.UP, controller.checkHealth().getStatus());
        Assertions.assertEquals(HealthStatus.UP, controller.checkHealthLiveness().getStatus());
        Assertions.assertEquals(HealthStatus.UP, controller.checkHealthReadiness().getStatus());
    }

    /** Each call builds its own response: a shared instance would let one caller's mutation reach another's. */
    @Test
    void doesNotShareOneResponseBetweenCallers() {
        HealthInfo first = controller.checkHealth();
        HealthInfo second = controller.checkHealth();

        Assertions.assertNotSame(first, second);
    }

    /** components is optional in the schema, and this connector publishes none rather than inventing one. */
    @Test
    void publishesNoComponents() {
        Assertions.assertNull(controller.checkHealth().getComponents());
    }
}
