package com.otilm.discovery.ip;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/**
 * Asserts both error shapes against the same class of failure, so neither advice can widen beyond its own surface.
 * The boundary itself is explained on {@link com.otilm.discovery.ip.ProblemDetailsHandlingAdvice}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ErrorModelBoundaryTest {

    @Autowired
    private TestRestTemplate rest;

    @Test
    void answersAV2FailureWithProblemJson() {
        ResponseEntity<String> response =
                rest.getForEntity("/v2/discoveryProvider/secrets/attributes", String.class);

        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, response.getStatusCode());
        Assertions
                .assertTrue(
                        response.getHeaders().getContentType()
                                .equalsTypeAndSubtype(MediaType.APPLICATION_PROBLEM_JSON),
                        "expected problem+json, got " + response.getHeaders().getContentType());
        Assertions.assertTrue(response.getBody().contains("\"status\":422"), response.getBody());
    }

    /**
     * A body that will not parse is handled by the base class unless the advice overrides it, and that answer omits
     * the {@code errorCode} a caller acts on. This is the only POST on the v2 surface, so it is the path where a
     * malformed body actually arrives.
     */
    @Test
    void answersAnUnreadableBodyInTheSameShapeAsEveryOtherV2Failure() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<String> response = rest
                .postForEntity("/v2/attributes/callback", new HttpEntity<>("{\"attributeUuid\": ", headers),
                        String.class);

        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, response.getStatusCode());
        Assertions
                .assertTrue(
                        response.getHeaders().getContentType()
                                .equalsTypeAndSubtype(MediaType.APPLICATION_PROBLEM_JSON),
                        "expected problem+json, got " + response.getHeaders().getContentType());
        Assertions
                .assertTrue(response.getBody().contains("\"errorCode\""),
                        "the extended envelope carries the code a caller acts on: " + response.getBody());
    }

    @Test
    void answersTheSameFailureOnV1WithTheV1ErrorShape() {
        ResponseEntity<String> response =
                rest.getForEntity("/v1/discoveryProvider/Nonsense/attributes", String.class);

        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, response.getStatusCode());
        Assertions
                .assertTrue(response.getBody().startsWith("["),
                        "v1 answers a validation failure with its own array of descriptions: " + response.getBody());
        Assertions
                .assertFalse(response.getBody().contains("\"status\":422"),
                        "the v2 advice has leaked onto the v1 surface: " + response.getBody());
    }

    /**
     * The resource path variable is an {@code IPlatformEnum}, which Spring binds by constant name unless the platform
     * converter factory is registered. Without it {@code certificates} does not bind and this route is unreachable.
     */
    @Test
    void bindsTheResourcePathByItsWireCode() {
        ResponseEntity<String> response =
                rest.getForEntity("/v2/discoveryProvider/certificates/attributes", String.class);

        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        Assertions.assertEquals("[]", response.getBody());
    }

    @Test
    void rejectsAPathThatNamesNoResourceAtAll() {
        ResponseEntity<String> response =
                rest.getForEntity("/v2/discoveryProvider/nonsense/attributes", String.class);

        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, response.getStatusCode());
    }

    @Test
    void servesTheRunLevelAttributeSchema() {
        ResponseEntity<String> response = rest.getForEntity("/v2/discoveryProvider/attributes", String.class);

        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        Assertions.assertTrue(response.getBody().contains("data_hosts"), response.getBody());
        Assertions
                .assertTrue(response.getBody().contains("\"version\":3"),
                        "the schema must go out as v3, or Core reads it as v2 without complaint");
    }

    @Test
    void listsTheSupportedResourcesByWireCode() {
        ResponseEntity<String> response = rest.getForEntity("/v2/discoveryProvider/resources", String.class);

        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        Assertions.assertTrue(response.getBody().contains("certificates"), response.getBody());
        Assertions.assertTrue(response.getBody().contains("keys"), response.getBody());
    }
}
