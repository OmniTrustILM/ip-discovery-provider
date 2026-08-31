package com.otilm.discovery.ip.dto;

import java.security.cert.X509Certificate;

public class ConnectionResponse {
	private String cipher;
	private X509Certificate[] certificates;
	
	public String getCipher() {
		return cipher;
	}
	public void setCipher(String cipher) {
		this.cipher = cipher;
	}
	public X509Certificate[] getCertificates() {
		return certificates;
	}
	public void setCertificates(X509Certificate[] certificates) {
		this.certificates = certificates;
	}
	public ConnectionResponse(String cipher, X509Certificate[] certificates) {
		super();
		this.cipher = cipher;
		this.certificates = certificates;
	}
}
