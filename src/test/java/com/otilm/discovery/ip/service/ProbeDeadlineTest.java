package com.otilm.discovery.ip.service;

import com.otilm.discovery.ip.service.impl.ConnectionServiceImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;

/**
 * A read timeout bounds inactivity between reads, not the probe. A peer that sends a byte just inside that window
 * keeps the handshake alive indefinitely, and because the scan waits for every future in its batch, one such target
 * stops the whole scan rather than just its own probe.
 */
class ProbeDeadlineTest {

    private static final int CONNECT_TIMEOUT_MS = 300;
    private static final int READ_TIMEOUT_MS = 2000;
    private static final int TOTAL_TIMEOUT_MS = 1500;
    private static final int DRIP_INTERVAL_MS = 400;

    @Test
    void abandonsATargetThatTricklesBytesUnderTheReadTimeout() throws IOException {
        try (ServerSocket tarpit = new ServerSocket(0, 0, InetAddress.getByName("127.0.0.1"))) {
            startTarpit(tarpit);
            ConnectionService service =
                    new ConnectionServiceImpl(CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS, TOTAL_TIMEOUT_MS);
            String url = "https://127.0.0.1:" + tarpit.getLocalPort();

            long startedAt = System.nanoTime();
            SocketTimeoutException thrown = Assertions
                    .assertTimeoutPreemptively(Duration.ofSeconds(20),
                            () -> Assertions
                                    .assertThrows(SocketTimeoutException.class, () -> service.getCertificates(url)),
                            "the probe never gave up on a trickling target");
            long elapsedMs = (System.nanoTime() - startedAt) / 1_000_000;

            Assertions
                    .assertTrue(thrown.getMessage().contains("deadline"),
                            "a deadline abandonment must say so rather than read as an inactivity timeout, so it stays "
                                    + "distinguishable from a refused or silent target: " + thrown.getMessage());
            Assertions
                    .assertTrue(elapsedMs < READ_TIMEOUT_MS * 4L,
                            "gave up after " + elapsedMs + " ms, far past the " + TOTAL_TIMEOUT_MS + " ms deadline");
        }
    }

    /**
     * Java reads a timeout of zero as "wait forever", so a deployment that sets one to zero silently restores the
     * unbounded probe these bounds exist to remove. A negative value is rejected per-probe at runtime rather than at
     * startup. Neither should be reachable.
     */
    @Test
    void refusesToStartWithATimeoutThatDisablesTheBound() {
        Assertions
                .assertThrows(IllegalArgumentException.class,
                        () -> new ConnectionServiceImpl(0, READ_TIMEOUT_MS, TOTAL_TIMEOUT_MS));
        Assertions
                .assertThrows(IllegalArgumentException.class,
                        () -> new ConnectionServiceImpl(CONNECT_TIMEOUT_MS, 0, TOTAL_TIMEOUT_MS));
        Assertions
                .assertThrows(IllegalArgumentException.class,
                        () -> new ConnectionServiceImpl(CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS, 0));
        Assertions
                .assertThrows(IllegalArgumentException.class,
                        () -> new ConnectionServiceImpl(-1, READ_TIMEOUT_MS, TOTAL_TIMEOUT_MS));
    }

    /**
     * Sends a valid TLS record header claiming a large handshake fragment, then drips a byte at a time. Every read the
     * client makes succeeds, so the read timeout never fires while the record never completes.
     */
    private static void startTarpit(ServerSocket tarpit) {
        Thread accepter = new Thread(() -> {
            try (Socket held = tarpit.accept(); OutputStream out = held.getOutputStream()) {
                out.write(new byte[] {0x16, 0x03, 0x03, 0x40, 0x00});
                out.flush();
                while (!Thread.currentThread().isInterrupted()) {
                    out.write(0);
                    out.flush();
                    Thread.sleep(DRIP_INTERVAL_MS);
                }
            } catch (Exception e) {
                Thread.currentThread().interrupt();
            }
        }, "tarpit");
        accepter.setDaemon(true);
        accepter.start();
    }
}
