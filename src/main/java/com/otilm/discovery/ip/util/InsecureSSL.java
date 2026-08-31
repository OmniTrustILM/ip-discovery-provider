package com.otilm.discovery.ip.util;

import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class InsecureSSL
{
    // Default trust manager that does NOT validate certificate chains
    private static TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager()
            {
                public X509Certificate[] getAcceptedIssuers()
                {
                    return null;
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType)
                {
                }

                public void checkServerTrusted(X509Certificate[] certs, String authType)
                {
                }
            }
    };

    /**
     * Accepts every hostname, deliberately.
     *
     * <p>This connector scans bare IP addresses and hostnames to collect whatever certificate the
     * endpoint presents. The names will frequently not match by design -- scanning 10.0.0.7 and
     * receiving a certificate for an unrelated CN is the normal case, and is exactly the finding
     * the scan exists to report. Enforcing verification here would reject those endpoints and stop
     * the connector doing its job.
     *
     * <p>The certificate is never trusted for anything: it is read, encoded and handed to Core.
     * No request carries credentials over these connections, and this class is used only by
     * ConnectionServiceImpl for outbound scanning -- never for an authenticated or inbound channel.
     *
     * <p>CodeQL raises java/unsafe-hostname-verification here. It is a true positive as a pattern
     * and is dismissed as won't-fix on that basis, not because the finding is wrong. Do not
     * "repair" this by adding verification.
     */
    private static final HostnameVerifier allHostsValid = (hostname, session) -> true;

    public static HttpsURLConnection openInsecureConnection(URL url) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(InsecureSSL.getInstance().getSocketFactory()); // allow connection when certificate chain not in default truststore
        conn.setHostnameVerifier(InsecureSSL.allHostsValid); // allow connection when the actual hostname and one on certificate differ

        return conn;
    }

    private static SSLContext getInstance() throws KeyManagementException, NoSuchAlgorithmException
    {
        return getInstance("TLS");
    }

    // Get insecure SSLContext with no trust store (all certificates are valid)
    private static SSLContext getInstance(String protocol) throws KeyManagementException, NoSuchAlgorithmException
    {
        SSLContext sc = SSLContext.getInstance(protocol);
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        return sc;
    }
}