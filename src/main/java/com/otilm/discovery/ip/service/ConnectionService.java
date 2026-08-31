package com.otilm.discovery.ip.service;

import com.otilm.discovery.ip.dto.ConnectionResponse;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public interface ConnectionService {
	public ConnectionResponse getCertificates(String url) throws IOException, NoSuchAlgorithmException, KeyManagementException;
}

