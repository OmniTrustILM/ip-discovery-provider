package com.otilm.discovery.ip.service;

import com.otilm.discovery.ip.dto.ConnectionResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

@SpringBootTest
public class ConnectionServiceTest{

    @Autowired
    private ConnectionService connectionService;

    @Test
    public void testConnection() throws IOException, NoSuchAlgorithmException, KeyManagementException {
        ConnectionResponse certificates = connectionService.getCertificates("https://google.com");
        Assertions.assertNotNull(certificates);
    }

    @Test
    public void testConnection_Fail() {
        Assertions.assertThrows(SocketTimeoutException.class, ()-> connectionService.getCertificates("https://localhost:124"));
    }

    /**
     * A target that completes the TCP handshake and then says nothing must be abandoned, not waited on forever.
     * Only the connect timeout was ever set, so the TLS handshake and the certificate read ran with the default
     * read timeout of 0 -- infinite -- and one such host held a scanner thread for the life of the process.
     */
    @Test
    void abandonsATargetThatAcceptsAndThenStalls() throws IOException {
        try (ServerSocket stalling = new ServerSocket(0, 0, InetAddress.getByName("127.0.0.1"))) {
            Thread accepter = new Thread(() -> {
                try (Socket held = stalling.accept()) {
                    // Accept, then never speak: the shape of a tarpit, and of a firewall that swallows the handshake.
                    Thread.sleep(Duration.ofMinutes(1));
                } catch (Exception e) {
                    Thread.currentThread().interrupt();
                }
            }, "stalling-endpoint");
            accepter.setDaemon(true);
            accepter.start();

            String url = "https://127.0.0.1:" + stalling.getLocalPort();
            Assertions
                    .assertTimeoutPreemptively(Duration.ofSeconds(10),
                            () -> Assertions
                                    .assertThrows(SocketTimeoutException.class,
                                            () -> connectionService.getCertificates(url)),
                            "the probe did not give up on a stalling target");
        }
    }
}