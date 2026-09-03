package com.otilm.discovery.ip.service.impl;

import com.otilm.discovery.ip.dto.ConnectionResponse;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.util.InsecureSSL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

// Deliberately not @Transactional: this service performs no persistence, it opens an outbound TLS
// connection. A transaction here took a pooled database connection for every scanned URL.
@Service
public class ConnectionServiceImpl implements ConnectionService {

    private static final Logger logger = LoggerFactory.getLogger(ConnectionServiceImpl.class);

    /**
     * Closes a probe that has outlived its deadline. One shared daemon thread: it only ever holds the probes in
     * flight, which the scan bounds by its parallelism, and cancelled entries are dropped rather than left to expire.
     */
    private static final ScheduledExecutorService DEADLINES = deadlineScheduler();

    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final int totalTimeoutMs;

    public ConnectionServiceImpl(@Value("${discovery.probe.connect-timeout-ms:300}") int connectTimeoutMs,
            @Value("${discovery.probe.read-timeout-ms:2000}") int readTimeoutMs,
            @Value("${discovery.probe.total-timeout-ms:10000}") int totalTimeoutMs) {
        // Java reads a timeout of zero as "wait forever", so a zero here would silently restore the unbounded
        // probe these bounds exist to remove, and a negative one would fail every probe at runtime rather than at
        // startup. Neither is a configuration worth honouring.
        requirePositive("discovery.probe.connect-timeout-ms", connectTimeoutMs);
        requirePositive("discovery.probe.read-timeout-ms", readTimeoutMs);
        requirePositive("discovery.probe.total-timeout-ms", totalTimeoutMs);
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
        this.totalTimeoutMs = totalTimeoutMs;
    }

    private static void requirePositive(String property, int value) {
        if (value <= 0) {
            throw new IllegalArgumentException(property + " must be positive, but was " + value
                    + "; zero means an unbounded wait");
        }
    }

    private static ScheduledExecutorService deadlineScheduler() {
        // Constructed directly rather than through Executors: the factory returns a wrapper that hides
        // setRemoveOnCancelPolicy, and without that a cancelled entry sits in the queue until its delay elapses.
        ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(1, runnable -> {
            Thread thread = new Thread(runnable, "probe-deadline");
            thread.setDaemon(true);
            return thread;
        });
        scheduler.setRemoveOnCancelPolicy(true);
        return scheduler;
    }

    @Override
    public ConnectionResponse getCertificates(String url) throws IOException, NoSuchAlgorithmException, KeyManagementException {

        logger.info("Requesting the certificate from URL {}", url);
        URL destination = new URL(url);
        // No catch normalising the failure: a refused connection and an unanswered one are different findings,
        // and both are IOException, which this method already declares.
        HttpsURLConnection conn = InsecureSSL.openInsecureConnection(destination);
        logger.debug("Connection object framed for the URL {}", url);
        conn.setConnectTimeout(connectTimeoutMs);
        // Both bounds are needed. A target that completes the TCP handshake and then stalls is not a connect
        // failure, so without a read timeout it holds a scanner thread forever. A sweep of mostly-empty address
        // space should give up early; both values are configurable where it should not.
        conn.setReadTimeout(readTimeoutMs);

        // The read timeout bounds inactivity between reads, not the probe. A peer that sends a byte just inside
        // that window keeps the handshake alive forever, and the scan waits on every future in its batch, so one
        // such target stops the whole scan rather than its own probe. The deadline covers connect() alone because
        // that is where the handshake happens; everything after it reads the completed session.
        AtomicBoolean deadlineExpired = new AtomicBoolean();
        ScheduledFuture<?> deadline = DEADLINES.schedule(() -> {
            deadlineExpired.set(true);
            conn.disconnect();
        }, totalTimeoutMs, TimeUnit.MILLISECONDS);
        try {
            conn.connect();
        } catch (IOException e) {
            // Closing the socket surfaces as an arbitrary socket error, which would blur a deliberate abandonment
            // with a genuine one. Reported as a timeout, since that is what it is.
            if (deadlineExpired.get()) {
                throw new SocketTimeoutException(
                        "Probe of " + url + " exceeded its total deadline of " + totalTimeoutMs + " ms");
            }
            throw e;
        } finally {
            deadline.cancel(false);
        }
        logger.debug("Connected to {}", url);
        X509Certificate[] certs = (X509Certificate[]) conn.getServerCertificates();
        String cipher = conn.getCipherSuite().toString();
        conn.disconnect();
        logger.debug("Connection to {} terminated", url);
        return new ConnectionResponse(cipher, certs);
    }


}
