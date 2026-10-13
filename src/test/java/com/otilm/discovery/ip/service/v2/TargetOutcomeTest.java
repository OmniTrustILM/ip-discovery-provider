package com.otilm.discovery.ip.service.v2;

import com.otilm.discovery.ip.service.ConnectionService;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * What a probe that yielded nothing means, read from what the JDK actually throws: the classification leans on the TLS
 * stack's exception types and messages, so it is pinned against real sockets rather than exceptions built by hand.
 */
@SpringBootTest
class TargetOutcomeTest {

    /**
     * A fatal handshake_failure alert, the answer of a TLS host that will not complete a handshake with this client.
     */
    private static final byte[] HANDSHAKE_FAILURE_ALERT = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};

    @Autowired
    private ConnectionService connectionService;

    @Test
    void aPortWithNothingListeningIsEmpty() throws Exception {
        int closedPort;
        try (ServerSocket closed = new ServerSocket(0, 0, InetAddress.getByName("127.0.0.1"))) {
            closedPort = closed.getLocalPort();
        }

        Assertions.assertEquals(TargetOutcome.EMPTY, outcomeOfProbing(closedPort));
    }

    @Test
    void aServiceThatAnswersWithoutTlsIsEmpty() throws Exception {
        try (ServerSocket plaintext = serve(socket -> answer(socket,
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.US_ASCII)))) {
            Assertions.assertEquals(TargetOutcome.EMPTY, outcomeOfProbing(plaintext.getLocalPort()));
        }
    }

    @Test
    void aConnectionClosedBeforeAnyTlsAnswerIsEmpty() throws Exception {
        // Reads the client's hello, then hangs up in an orderly way: the peer that takes the connection and has
        // nothing to say. Closing without reading arrives as a reset instead, which is the refused case again.
        try (ServerSocket closing = serve(socket -> answer(socket, new byte[0]))) {
            Assertions.assertEquals(TargetOutcome.EMPTY, outcomeOfProbing(closing.getLocalPort()));
        }
    }

    @Test
    void aConnectionResetBeforeAnyTlsAnswerIsEmpty() throws Exception {
        try (ServerSocket resetting = serve(socket -> {
        })) {
            Assertions.assertEquals(TargetOutcome.EMPTY, outcomeOfProbing(resetting.getLocalPort()));
        }
    }

    @Test
    void aTlsHostThatRefusesTheHandshakeHasFailed() throws Exception {
        try (ServerSocket refusing = serve(socket -> answer(socket, HANDSHAKE_FAILURE_ALERT))) {
            Assertions.assertEquals(TargetOutcome.FAILED, outcomeOfProbing(refusing.getLocalPort()));
        }
    }

    @Test
    void aTargetThatNeverAnsweredIsEmpty() {
        Assertions
                .assertEquals(TargetOutcome.EMPTY,
                        TargetOutcome.ofProbeFailure(new SocketTimeoutException("Read timed out")));
    }

    @Test
    void aNameThatDoesNotResolveHasFailed() {
        Assertions
                .assertEquals(TargetOutcome.FAILED,
                        TargetOutcome.ofProbeFailure(new UnknownHostException("intranet.example")),
                        "the target was named on purpose, so a name that leads nowhere is something to fix");
    }

    @Test
    void aFailureNothingHereRecognisesHasFailed() {
        Assertions.assertEquals(TargetOutcome.FAILED, TargetOutcome.ofProbeFailure(new IOException("unexpected")));
    }

    private TargetOutcome outcomeOfProbing(int port) {
        try {
            connectionService.getCertificates("https://127.0.0.1:" + port);
        } catch (Exception e) {
            return TargetOutcome.ofProbeFailure(e);
        }
        return Assertions.fail("the probe of port " + port + " was expected to fail");
    }

    /** Accepts one connection on a loopback port and hands it to the given behaviour, closing it afterwards. */
    private static ServerSocket serve(Consumer<Socket> behaviour) throws IOException {
        ServerSocket server = new ServerSocket(0, 0, InetAddress.getByName("127.0.0.1"));
        Thread accepter = new Thread(() -> {
            try (Socket socket = server.accept()) {
                behaviour.accept(socket);
            } catch (IOException e) {
                // The test closed the server first; nothing is waiting on this connection any more.
            }
        }, "target-outcome-endpoint");
        accepter.setDaemon(true);
        accepter.start();
        return server;
    }

    /** Waits for the client's opening bytes, so the reply cannot be read as an early close, then answers with these. */
    private static void answer(Socket socket, byte[] reply) {
        try {
            InputStream in = socket.getInputStream();
            if (in.read(new byte[16_384]) < 0) {
                return;
            }
            OutputStream out = socket.getOutputStream();
            out.write(reply);
            out.flush();
            socket.shutdownOutput();
            // Holds the socket until the client has read the reply and hung up.
            while (in.read(new byte[1_024]) >= 0) {
                // drain
            }
        } catch (IOException e) {
            // The client gave up first, which is as good as reading the reply.
        }
    }
}
