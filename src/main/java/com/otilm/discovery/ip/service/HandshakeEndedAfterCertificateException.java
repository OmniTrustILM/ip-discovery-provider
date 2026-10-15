package com.otilm.discovery.ip.service;

import java.io.IOException;

/**
 * A TLS handshake that broke off after the server had presented its certificate. The host answered as TLS, whatever the
 * cause says: the JDK reports a hang-up at this point exactly as it reports a peer that never answered.
 */
public class HandshakeEndedAfterCertificateException extends IOException {

    public HandshakeEndedAfterCertificateException(String url, IOException cause) {
        super("TLS handshake with " + url + " ended after the server presented its certificate: " + cause.getMessage(),
                cause);
    }
}
