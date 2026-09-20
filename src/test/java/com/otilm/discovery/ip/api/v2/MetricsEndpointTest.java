package com.otilm.discovery.ip.api.v2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * The metrics interface has no controller class — the contract's endpoint is the Prometheus scrape itself, so the
 * implementation is the actuator's exposure and its path mapping. That makes it configuration, which fails silently:
 * a mistyped property name is ignored rather than rejected, and the endpoint simply is not there.
 *
 * <p>
 * The scrape's own config is repeated in the test {@code application.yml}, which shadows the shipped one, so this
 * proves the property names and the served format rather than the shipped values.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureObservability // Boot turns metrics export off under test; without this the scrape endpoint is absent.
class MetricsEndpointTest {

    @Autowired
    private TestRestTemplate rest;

    private String scrape() {
        // The server-request timer has no samples until a request has been served, and the histogram is the point.
        rest.getForEntity("/v2/info", String.class);

        ResponseEntity<String> response = rest.getForEntity("/v1/metrics", String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode(), "the scrape endpoint must exist at the path "
                + "MetricsController maps to, or Core registers a connector whose metrics interface answers 404");
        return response.getBody();
    }

    @Test
    void servesAPrometheusScrapeAtThePathTheMetricsInterfaceMapsTo() {
        Assertions.assertTrue(scrape().contains("jvm_memory_used_bytes"), "expected a Prometheus exposition body");
    }

    /**
     * {@code METRICS_CONFIG} prescribes these boundaries as {@code http_server_latency_buckets_seconds}. Micrometer
     * emits none of them unless both distribution properties are spelled correctly, so an empty bucket set here means
     * the configuration is being ignored.
     */
    @Test
    void emitsTheServerLatencyBucketsTheContractPrescribes() {
        String scrape = scrape();

        Assertions.assertTrue(scrape.contains("http_server_requests_seconds_bucket"),
                "no server-latency histogram in the scrape");
        for (String boundary : new String[] {"0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0", "2.5",
                "5.0", "10.0"}) {
            Assertions.assertTrue(scrape.contains("le=\"" + boundary + "\""),
                    "prescribed bucket boundary " + boundary + " is missing from the scrape");
        }
    }
}
