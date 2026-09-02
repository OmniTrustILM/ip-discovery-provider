package com.otilm.discovery.ip.service;

import com.otilm.discovery.ip.dto.ConnectionResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.net.SocketTimeoutException;
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
}