package com.otilm.discovery.ip.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.connector.discovery.DiscoveryDataRequestDto;
import com.otilm.api.model.connector.discovery.DiscoveryProviderDto;
import com.otilm.api.model.connector.discovery.DiscoveryRequestDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.discovery.ip.dao.Certificate;
import com.otilm.discovery.ip.dao.DiscoveryHistory;
import com.otilm.discovery.ip.repository.CertificateRepository;
import com.otilm.discovery.ip.service.impl.AttributeServiceImpl;
import com.otilm.discovery.ip.service.impl.ConnectionServiceImpl;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.awaitility.Awaitility.await;

/**
 * Drives a full discovery against a TLS endpoint served from this JVM, so the scan path - URL
 * expansion, connection, certificate extraction, persistence and metadata - is exercised end to
 * end without reaching the network.
 *
 * <p>Not {@code @Transactional}: the scan runs on its own thread and commits through its own
 * transaction manager, so the discovery row has to be visible outside the test's transaction.
 */
@SpringBootTest
class DiscoveryScanIntegrationTest {

    private static final char[] PASSWORD = "changeit".toCharArray();

    private static HttpsServer server;
    private static int port;
    private static ServerSocket refusingEndpoint;
    private static int refusingPort;
    private static X509Certificate servedCertificate;

    @Autowired
    private DiscoveryService discoveryService;

    @Autowired
    private DiscoveryHistoryService discoveryHistoryService;

    @Autowired
    private CertificateRepository certificateRepository;

    @BeforeAll
    static void startTlsEndpoint() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        X500Principal subject = new X500Principal("CN=discovery-scan-test");
        Instant now = Instant.now();
        servedCertificate = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(
                        subject,
                        BigInteger.ONE,
                        Date.from(now.minus(1, ChronoUnit.DAYS)),
                        Date.from(now.plus(1, ChronoUnit.DAYS)),
                        subject,
                        keyPair.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())));

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("scan-test", keyPair.getPrivate(), PASSWORD,
                new java.security.cert.Certificate[] {servedCertificate});

        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keyStore, PASSWORD);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers.getKeyManagers(), null, null);

        server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext));
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.setExecutor(null);
        server.start();
        port = server.getAddress().getPort();

        // A second endpoint that accepts and immediately closes, so the TLS handshake cannot
        // complete and the URL is counted as failed. Held open for the class lifetime: releasing
        // a port and hoping it stays free leaves a window for another process to bind it.
        refusingEndpoint = new ServerSocket(0, 0, InetAddress.getByName("127.0.0.1"));
        refusingPort = refusingEndpoint.getLocalPort();
        Thread accepter = new Thread(() -> {
            while (!refusingEndpoint.isClosed()) {
                try (Socket ignored = refusingEndpoint.accept()) {
                    // closing the accepted socket is the point
                } catch (IOException e) {
                    return;
                }
            }
        }, "refusing-endpoint");
        accepter.setDaemon(true);
        accepter.start();
    }

    @AfterAll
    static void stopTlsEndpoint() throws IOException {
        if (server != null) {
            server.stop(0);
        }
        if (refusingEndpoint != null) {
            refusingEndpoint.close();
        }
    }

    /**
     * The watchdog and the probe race for the same connection whenever a deadline lands near the handshake
     * completing, and cancel() does not stop a callback that has already begun. Whichever wins, the outcome must be
     * one of exactly two things: a probe that succeeded, or a timeout that says it was the deadline. An unrelated
     * socket error means the watchdog disconnected a connection the probe had already claimed.
     */
    @Test
    void aDeadlineRacingACompletedHandshakeNeverProducesAnUnrelatedError() {
        String url = "https://localhost:" + port;

        // Swept rather than fixed: the window is the instant between connect() returning and the probe claiming
        // the connection, so a deadline has to land near the handshake's own duration to fall inside it. One
        // fixed value almost always fires early and never exercises the race at all.
        for (int attempt = 0; attempt < 200; attempt++) {
            ConnectionService racing =
                    new ConnectionServiceImpl(300, 2000, 1 + attempt % 40);
            try {
                Assertions.assertNotNull(racing.getCertificates(url).getCertificates());
            } catch (Exception thrown) {
                Assertions
                        .assertInstanceOf(SocketTimeoutException.class, thrown,
                                "attempt " + attempt + " failed with neither success nor a deadline timeout");
                Assertions
                        .assertTrue(thrown.getMessage().contains("deadline"),
                                "attempt " + attempt + " timed out without naming the deadline: "
                                        + thrown.getMessage());
            }
        }
    }

    private static RequestAttributeV2 attribute(String uuid, String name, AttributeContentType type,
            BaseAttributeContentV2<?> content) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setUuid(UUID.fromString(uuid));
        attribute.setName(name);
        attribute.setContentType(type);
        attribute.setContent(List.of(content));
        return attribute;
    }

    private DiscoveryRequestDto scanRequest(String name, int parallelExecutions) {
        DiscoveryRequestDto request = new DiscoveryRequestDto();
        request.setName(name);
        request.setKind("IP-Hostname");
        request.setAttributes(List.<RequestAttribute>of(
                attribute("1b6c48ad-c1c7-4c82-91ef-3b61bc9f52ac", AttributeServiceImpl.DATA_ATTRIBUTE_DISCOVERY_IP_NAME,
                        AttributeContentType.STRING, new StringAttributeContentV2("127.0.0.1")),
                attribute("a9091e0d-f9b9-4514-b275-1dd52aa870ec", AttributeServiceImpl.DATA_ATTRIBUTE_PORT_NAME,
                        AttributeContentType.STRING, new StringAttributeContentV2(String.valueOf(port))),
                attribute("3c70d728-e8c3-40f9-b9b2-5d7256f89ef0", AttributeServiceImpl.DATA_ATTRIBUTE_ALL_PORTS_NAME,
                        AttributeContentType.BOOLEAN, new BooleanAttributeContentV2(false)),
                attribute("1517c7a5-34cb-4f94-a0aa-1e9fe5b5b277",
                        AttributeServiceImpl.DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_NAME,
                        AttributeContentType.INTEGER, new IntegerAttributeContentV2(parallelExecutions))));
        return request;
    }

    private DiscoveryHistory runScanToCompletion(String name, int parallelExecutions) throws Exception {
        DiscoveryRequestDto request = scanRequest(name, parallelExecutions);
        return runScanToCompletion(request);
    }

    private DiscoveryHistory runScanToCompletion(DiscoveryRequestDto request) throws Exception {
        DiscoveryHistory history = discoveryHistoryService.addHistory(request);

        discoveryService.discoverCertificate(request, history);

        return awaitPersistedTerminalStatus(history.getUuid());
    }

    /**
     * The scan runs on a virtual thread and flips the in-memory status two statements before it
     * commits, so waiting on the passed entity can return while the closing transaction is still
     * open. Reloading the row instead means both the wait and the assertions observe committed
     * state, and avoids reading a non-volatile field across threads.
     */
    private DiscoveryHistory awaitPersistedTerminalStatus(String uuid) throws NotFoundException {
        await().atMost(Duration.ofSeconds(30))
                .until(() -> discoveryHistoryService.getHistoryByUuid(uuid).getStatus() != DiscoveryStatus.IN_PROGRESS);
        return discoveryHistoryService.getHistoryByUuid(uuid);
    }

    @Test
    void storesTheCertificateServedByTheEndpoint() throws Exception {
        DiscoveryHistory history = runScanToCompletion("scan-" + UUID.randomUUID(), 1);

        Assertions.assertEquals(DiscoveryStatus.COMPLETED, history.getStatus());

        List<Certificate> stored = certificateRepository.findByDiscoveryId(history.getId());
        Assertions.assertEquals(1, stored.size());
        Assertions.assertEquals(Base64.getEncoder().encodeToString(servedCertificate.getEncoded()),
                stored.get(0).getBase64Content());
    }

    @Test
    void recordsTheUrlCountsAsDiscoveryMetadata() throws Exception {
        DiscoveryHistory history = runScanToCompletion("meta-" + UUID.randomUUID(), 1);

        Assertions.assertEquals(DiscoveryStatus.COMPLETED, history.getStatus());
        String meta = history.getMeta();
        Assertions.assertNotNull(meta);
        Assertions.assertTrue(meta.contains("totalUrls"), meta);
        Assertions.assertTrue(meta.contains("successUrls"), meta);
        Assertions.assertTrue(meta.contains("failedUrls"), meta);
    }

    @Test
    void tagsEachCertificateWithTheSourceItCameFrom() throws Exception {
        DiscoveryHistory history = runScanToCompletion("source-" + UUID.randomUUID(), 1);

        Certificate stored = certificateRepository.findByDiscoveryId(history.getId()).get(0);
        Assertions.assertNotNull(stored.getMeta());
        Assertions.assertTrue(stored.getMeta().contains("discoverySource"), stored.getMeta());
        Assertions.assertTrue(stored.getMeta().contains("https://127.0.0.1:" + port), stored.getMeta());
    }

    @Test
    void reportsTheResultThroughTheProviderDto() throws Exception {
        DiscoveryHistory history = runScanToCompletion("dto-" + UUID.randomUUID(), 1);

        DiscoveryDataRequestDto dataRequest = new DiscoveryDataRequestDto();
        dataRequest.setName(history.getName());
        dataRequest.setPageNumber(1);
        dataRequest.setItemsPerPage(10);

        DiscoveryProviderDto dto = discoveryService.getProviderDtoData(dataRequest, history);

        Assertions.assertEquals(DiscoveryStatus.COMPLETED, dto.getStatus());
        Assertions.assertEquals(1, dto.getTotalCertificatesDiscovered());
        Assertions.assertEquals(1, dto.getCertificateData().size());
        Assertions.assertNotNull(dto.getMeta());
    }

    @Test
    void batchesCommitsWhenSeveralUrlsAreScannedInParallel() throws Exception {
        // A two-port scan with maxThreads=2 drives the batch-commit branch.
        DiscoveryRequestDto request = scanRequest("batch-" + UUID.randomUUID(), 2);
        request.getAttributes().stream()
                .filter(a -> AttributeServiceImpl.DATA_ATTRIBUTE_PORT_NAME.equals(a.getName()))
                .findFirst()
                .ifPresent(a -> ((RequestAttributeV2) a)
                        .setContent(List.<BaseAttributeContentV2<?>>of(
                                new StringAttributeContentV2(port + "," + refusingPort))));

        DiscoveryHistory history = runScanToCompletion(request);

        // One port serves TLS, the other refuses the handshake. A scan finishes COMPLETED even
        // when some URLs failed; the failures surface only in the discovery metadata.
        Assertions.assertEquals(DiscoveryStatus.COMPLETED, history.getStatus());
        Assertions.assertEquals(1, certificateRepository.findByDiscoveryId(history.getId()).size());
    }

    @Test
    void recordsTheReasonWhenDiscoveryFails() throws Exception {
        // No IP attribute, so URL expansion fails and the failure path records why.
        DiscoveryRequestDto request = new DiscoveryRequestDto();
        request.setName("failure-" + UUID.randomUUID());
        request.setKind("IP-Hostname");
        request.setAttributes(List.<RequestAttribute>of(
                attribute("a9091e0d-f9b9-4514-b275-1dd52aa870ec", AttributeServiceImpl.DATA_ATTRIBUTE_PORT_NAME,
                        AttributeContentType.STRING, new StringAttributeContentV2("443"))));

        DiscoveryHistory history = runScanToCompletion(request);

        Assertions.assertEquals(DiscoveryStatus.FAILED, history.getStatus());
        Assertions.assertNotNull(history.getMeta());
        Assertions.assertTrue(history.getMeta().contains("reason"), history.getMeta());
    }
}
