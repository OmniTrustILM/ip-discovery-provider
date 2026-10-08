package com.otilm.discovery.ip;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Holds the REST JSON of both surfaces to goldens recorded on the Spring Boot 3.5 line, so a change of JSON library
 * cannot alter what Core reads. Record with {@code -Dwire.golden.write=true} on the 3.5 line only.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class WireGoldenTest {

    private static final Path GOLDENS = Path.of("src/test/resources/wire");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern UUID_PATTERN = Pattern
            .compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern TIMESTAMP = Pattern
            .compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}(:\\d{2})?(\\.\\d+)?(Z|[+-]\\d{2}:?\\d{2})?");
    private static final Pattern DIGEST = Pattern.compile("(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])");
    private static final String RUN_ID = "5b1c7d9e-0f3a-4c2b-9d8e-7a6f5e4d3c2b";
    private static final String TERMINAL_V1 = "\"status\":\"inProgress\"";

    private static HttpsServer tls;
    private static int tlsPort;

    private final HttpClient http = HttpClient.newHttpClient();
    private final Set<String> stableUuids = new HashSet<>(Set.of(RUN_ID));

    @Value("${local.server.port}")
    private int port;

    @BeforeAll
    static void serveTheGoldenCertificate() throws Exception {
        char[] password = "changeit".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(GOLDENS.resolve("tls.p12"))) {
            keyStore.load(in, password);
        }
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keyStore, password);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers.getKeyManagers(), null, null);

        tls = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        tls.setHttpsConfigurator(new HttpsConfigurator(sslContext));
        tls.createContext("/", exchange -> {
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        tls.start();
        tlsPort = tls.getAddress().getPort();
    }

    @AfterAll
    static void stopServing() {
        tls.stop(0);
    }

    /** The definitions' UUIDs are constants, so they stay in the goldens; every other UUID is generated per run. */
    @BeforeEach
    void collectStableUuids() throws Exception {
        stableUuids.addAll(uuidsIn(get("/v1/discoveryProvider/IP-Hostname/attributes").body()));
        stableUuids.addAll(uuidsIn(get("/v2/attributes").body()));
    }

    @Test
    void attributeDefinitions() throws Exception {
        assertGolden("v1-attributes", get("/v1/discoveryProvider/IP-Hostname/attributes"));
        assertGolden("v2-run-attributes", get("/v2/discoveryProvider/attributes"));
        assertGolden("v2-resources", get("/v2/discoveryProvider/resources"));
        assertGolden("v2-definitions", get("/v2/attributes"));
        assertGolden("v2-definition", get("/v2/attributes/2cc7b1ee-7656-4844-a651-aed2300b750b"));
    }

    @Test
    void infoAndHealth() throws Exception {
        assertGolden("v1-info", get("/v1"));
        assertGolden("v1-health", get("/v1/health"));
        assertGolden("v2-info", get("/v2/info"));
        assertGolden("v2-health", get("/v2/health"));
    }

    @Test
    void attributeValidationAndCallbackErrors() throws Exception {
        assertGolden("v1-validate", post("/v1/discoveryProvider/IP-Hostname/attributes/validate", v1Attributes()));
        assertGolden("v1-validate-invalid", post("/v1/discoveryProvider/IP-Hostname/attributes/validate", """
                [{"uuid":"1b6c48ad-c1c7-4c82-91ef-3b61bc9f52ac","name":"ip","contentType":"string",
                  "content":[{"data":"not a host"}],"version":"v2"}]"""));
        assertGolden("v2-callback-unknown",
                post("/v2/attributes/callback", callback("00000000-0000-4000-8000-000000000000")));
        assertGolden("v2-callback-unsupported",
                post("/v2/attributes/callback", callback("2cc7b1ee-7656-4844-a651-aed2300b750b")));
    }

    @Test
    void v1Discovery() throws Exception {
        HttpResponse<String> started = post("/v1/discoveryProvider/discover", """
                {"name":"wire","kind":"IP-Hostname","attributes":%s}""".formatted(v1Attributes()));
        assertGolden("v1-discover", started);

        String uuid = JSON.readTree(started.body()).get("uuid").asText();
        String page = """
                {"name":"wire","kind":"IP-Hostname","pageNumber":0,"itemsPerPage":10}""";
        await()
                .atMost(Duration.ofSeconds(30))
                .until(() -> !post("/v1/discoveryProvider/discover/" + uuid, page).body().contains(TERMINAL_V1));
        assertGolden("v1-discovery", post("/v1/discoveryProvider/discover/" + uuid, page));
    }

    @Test
    void v2RunLifecycle() throws Exception {
        String scope = """
                "runId":"%s","resources":["certificates"],"attributes":[
                  {"uuid":"2cc7b1ee-7656-4844-a651-aed2300b750b","name":"data_hosts","contentType":"string",
                   "content":[{"data":"127.0.0.1","contentType":"string"}],"version":"v3"},
                  {"uuid":"acc48fc4-803e-45b1-951f-02764abcbbe8","name":"data_ports","contentType":"string",
                   "content":[{"data":"%d","contentType":"string"}],"version":"v3"}]""".formatted(RUN_ID, tlsPort);
        String run = "{" + scope + "}";
        HttpResponse<String> initiated = post("/v2/discoveryProvider/discoveries/initiate", run);
        assertGolden("v2-initiate", initiated);
        String checkpoint = JSON.readTree(initiated.body()).get("checkpoint").toString();

        await()
                .atMost(Duration.ofSeconds(30))
                .until(() -> post("/v2/discoveryProvider/discoveries/status", run).body(),
                        status -> status.contains("\"completed\""));
        assertGolden("v2-status", post("/v2/discoveryProvider/discoveries/status", run));
        assertGolden("v2-status-with-checkpoint",
                post("/v2/discoveryProvider/discoveries/status", "{" + scope + ",\"checkpoint\":" + checkpoint + "}"));
        assertGolden("v2-results",
                post("/v2/discoveryProvider/discoveries/results", "{" + scope + ",\"afterSequence\":0}"));
        assertGolden("v2-cancel", post("/v2/discoveryProvider/discoveries/cancel", run));
    }

    private static String callback(String attributeUuid) {
        return """
                {"connectorInterface":"discovery","interfaceVersion":"v2","attributeUuid":"%s",
                 "attributeName":"data_hosts","contextAttributes":[],"currentAttributes":[
                   {"uuid":"2cc7b1ee-7656-4844-a651-aed2300b750b","name":"data_hosts","contentType":"string",
                    "content":[{"data":"127.0.0.1","contentType":"string"}],"version":"v3"}]}"""
                .formatted(attributeUuid);
    }

    private String v1Attributes() {
        return """
                [{"uuid":"1b6c48ad-c1c7-4c82-91ef-3b61bc9f52ac","name":"ip","contentType":"string",
                  "content":[{"data":"127.0.0.1"}],"version":"v2"},
                 {"uuid":"a9091e0d-f9b9-4514-b275-1dd52aa870ec","name":"port","contentType":"string",
                  "content":[{"data":"%d"}],"version":"v2"},
                 {"uuid":"3c70d728-e8c3-40f9-b9b2-5d7256f89ef0","name":"allPorts","contentType":"boolean",
                  "content":[{"data":false}],"version":"v2"},
                 {"uuid":"1517c7a5-34cb-4f94-a0aa-1e9fe5b5b277","name":"data_parallel_executions",
                  "contentType":"integer","content":[{"data":1}],"version":"v2"}]""".formatted(tlsPort);
    }

    private HttpResponse<String> get(String path) throws IOException, InterruptedException {
        return http.send(HttpRequest.newBuilder(uri(path)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String body) throws IOException, InterruptedException {
        return http
                .send(HttpRequest
                        .newBuilder(uri(path))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(), HttpResponse.BodyHandlers.ofString());
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + port + path);
    }

    private static Set<String> uuidsIn(String text) {
        Set<String> uuids = new HashSet<>();
        Matcher matcher = UUID_PATTERN.matcher(text);
        while (matcher.find()) {
            uuids.add(matcher.group());
        }
        return uuids;
    }

    /**
     * Masks what differs between runs and hosts: the TLS port and digests over it, the time and zone, generated UUIDs.
     */
    private String normalized(String body) {
        String masked = body.replaceAll("(?<![0-9])" + tlsPort + "(?![0-9])", "<port>");
        masked = DIGEST.matcher(masked).replaceAll("<digest>");
        masked = TIMESTAMP
                .matcher(masked)
                .replaceAll(match -> match
                        .group()
                        .replaceAll("(Z|[+-]\\d{2}:?\\d{2})$", "<zone>")
                        .replaceAll("[0-9]", "9")
                        .replaceAll("\\.9+", ".9"));
        return UUID_PATTERN
                .matcher(masked)
                .replaceAll(match -> stableUuids.contains(match.group()) ? match.group() : "<uuid>");
    }

    /**
     * Sorts every array and object, since neither order is part of the contract: Jackson 3 writes properties
     * alphabetically, and v1 info lists its endpoints in hash order.
     */
    private static JsonNode inAnyOrder(JsonNode node) {
        if (node.isArray()) {
            List<JsonNode> elements = new ArrayList<>();
            node.forEach(element -> elements.add(inAnyOrder(element)));
            elements.sort(Comparator.comparing(JsonNode::toString));
            return JSON.createArrayNode().addAll(elements);
        }
        if (node.isObject()) {
            ObjectNode sorted = JSON.createObjectNode();
            node
                    .properties()
                    .stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(field -> sorted.set(field.getKey(), inAnyOrder(field.getValue())));
            return sorted;
        }
        return node;
    }

    private void assertGolden(String name, HttpResponse<String> response) throws IOException {
        ObjectNode actual = JSON.createObjectNode();
        actual.put("status", response.statusCode());
        actual.put("contentType", response.headers().firstValue("Content-Type").map(t -> t.split(";")[0]).orElse(""));
        String body = normalized(response.body());
        actual.set("body", body.isEmpty() ? null : inAnyOrder(JSON.readTree(body)));

        Path golden = GOLDENS.resolve(name + ".json");
        if (Boolean.getBoolean("wire.golden.write")) {
            Files.writeString(golden, JSON.writerWithDefaultPrettyPrinter().writeValueAsString(actual) + "\n");
        }
        JsonNode expected = JSON.readTree(Files.readString(golden));
        assertEquals(expected, actual, "Wire output drifted from " + golden + ": " + actual);
    }
}
