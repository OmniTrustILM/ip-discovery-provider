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
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

// Deliberately not @Transactional: this service performs no persistence, it opens an outbound TLS
// connection. A transaction here took a pooled database connection for every scanned URL.
@Service
public class ConnectionServiceImpl implements ConnectionService {

    private static final Logger logger = LoggerFactory.getLogger(ConnectionServiceImpl.class);

    private final int connectTimeoutMs;
    private final int readTimeoutMs;

    public ConnectionServiceImpl(@Value("${discovery.probe.connect-timeout-ms:300}") int connectTimeoutMs,
            @Value("${discovery.probe.read-timeout-ms:2000}") int readTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
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
        conn.connect();
        logger.debug("Connected to {}", url);
        X509Certificate[] certs = (X509Certificate[]) conn.getServerCertificates();
        String cipher = conn.getCipherSuite().toString();
        conn.disconnect();
        logger.debug("Connection to {} terminated", url);
        return new ConnectionResponse(cipher, certs);
    }


}
