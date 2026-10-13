package com.otilm.discovery.ip.service.v2;

import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.service.impl.ConnectionServiceImpl;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.util.function.Consumer;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * What a probe that yielded nothing means, read from what the JDK actually throws: the classification leans on the TLS
 * stack's exception types and messages, so it is pinned against real sockets rather than exceptions built by hand.
 */
class TargetOutcomeTest {

    /**
     * A fatal handshake_failure alert, the answer of a TLS host that will not complete a handshake with this client.
     */
    private static final byte[] HANDSHAKE_FAILURE_ALERT = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};

    private final ConnectionService connectionService = new ConnectionServiceImpl(500, 2_000, 10_000);

    @Test
    void aPortWithNothingListeningIsEmpty() throws Exception {
        int closedPort;
        try (ServerSocket closed = new ServerSocket(0, 0, InetAddress.getByName("127.0.0.1"))) {
            closedPort = closed.getLocalPort();
        }

        Assertions.assertEquals(TargetOutcome.EMPTY, TargetOutcome.ofProbeFailure(probeFailure(closedPort)));
    }

    @Test
    void aServiceThatAnswersWithoutTlsIsEmpty() throws Exception {
        try (ServerSocket plaintext = serve(socket -> answer(socket,
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.US_ASCII)))) {
            Assertions
                    .assertEquals(TargetOutcome.EMPTY,
                            TargetOutcome.ofProbeFailure(probeFailure(plaintext.getLocalPort())));
        }
    }

    @Test
    void aConnectionClosedBeforeAnyTlsAnswerIsEmpty() throws Exception {
        // Reads the client's hello, then hangs up in an orderly way: the peer that takes the connection and has
        // nothing to say.
        try (ServerSocket closing = serve(socket -> answer(socket, new byte[0]))) {
            Assertions
                    .assertEquals(TargetOutcome.EMPTY,
                            TargetOutcome.ofProbeFailure(probeFailure(closing.getLocalPort())));
        }
    }

    @Test
    void aConnectionResetBeforeAnyTlsAnswerIsEmpty() throws Exception {
        // A zero linger makes the close a reset rather than an orderly hang-up, whatever the timing.
        try (ServerSocket resetting = serve(TargetOutcomeTest::lingerZero)) {
            Assertions
                    .assertEquals(TargetOutcome.EMPTY,
                            TargetOutcome.ofProbeFailure(probeFailure(resetting.getLocalPort())));
        }
    }

    @Test
    void aTlsHostThatRefusesTheHandshakeHasFailedAndSaysWhy() throws Exception {
        try (ServerSocket refusing = serve(socket -> answer(socket, HANDSHAKE_FAILURE_ALERT))) {
            Exception failure = probeFailure(refusing.getLocalPort());

            Assertions.assertEquals(TargetOutcome.FAILED, TargetOutcome.ofProbeFailure(failure));
            Assertions.assertEquals("TLS alert handshake_failure", TargetOutcome.reasonOf(failure));
        }
    }

    @Test
    void aTargetThatNeverAnsweredIsEmpty() {
        Assertions
                .assertEquals(TargetOutcome.EMPTY,
                        TargetOutcome.ofProbeFailure(new SocketTimeoutException("Read timed out")));
        Assertions
                .assertEquals(TargetOutcome.EMPTY,
                        TargetOutcome.ofProbeFailure(new SocketException("Network is unreachable (connect failed)")));
    }

    @Test
    void aScannerThatRunsOutOfLocalResourcesHasFailed() {
        Assertions
                .assertEquals(TargetOutcome.FAILED,
                        TargetOutcome.ofProbeFailure(new BindException("Address already in use: connect")),
                        "no local port to connect from is this scanner failing, not a target with nothing on it");
        Assertions
                .assertEquals(TargetOutcome.FAILED,
                        TargetOutcome.ofProbeFailure(new SocketException("Too many open files")));
    }

    @Test
    void aNameThatDoesNotResolveHasFailedAndSaysWhy() {
        UnknownHostException failure = new UnknownHostException("intranet.example");

        Assertions
                .assertEquals(TargetOutcome.FAILED, TargetOutcome.ofProbeFailure(failure),
                        "the target was named on purpose, so a name that leads nowhere is something to fix");
        Assertions.assertEquals("Host name did not resolve", TargetOutcome.reasonOf(failure));
    }

    @Test
    void aFailureNothingHereRecognisesHasFailedUnderItsOwnName() {
        IOException failure = new IOException("unexpected");

        Assertions.assertEquals(TargetOutcome.FAILED, TargetOutcome.ofProbeFailure(failure));
        Assertions.assertEquals("IOException", TargetOutcome.reasonOf(failure));
    }

    @Test
    void aHandshakeFailureWithoutAnAlertSaysSo() {
        Assertions
                .assertEquals("TLS handshake failed",
                        TargetOutcome.reasonOf(new SSLHandshakeException("No appropriate protocol")));
    }

    @Test
    void aCertificateThisConnectorCannotUseIsNamedAsItsOwnFault() {
        Assertions
                .assertEquals("Certificate this connector could not use (CertificateEncodingException)",
                        TargetOutcome.unusableCertificate(new CertificateEncodingException("no encoding")));
    }

    private Exception probeFailure(int port) {
        try {
            connectionService.getCertificates("https://127.0.0.1:" + port);
        } catch (Exception e) {
            return e;
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

    private static void lingerZero(Socket socket) {
        try {
            socket.setSoLinger(true, 0);
        } catch (SocketException e) {
            throw new IllegalStateException(e);
        }
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
