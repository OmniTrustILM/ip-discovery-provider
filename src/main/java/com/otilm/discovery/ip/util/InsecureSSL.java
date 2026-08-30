package com.otilm.discovery.ip.util;

import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
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

    // Hostname verifier for which ALL hosts valid
    private static HostnameVerifier allHostsValid = new HostnameVerifier()
    {
        public boolean verify(String hostname, SSLSession session)
        {
            return true;
        }
    };

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