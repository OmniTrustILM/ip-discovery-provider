package com.otilm.discovery.ip.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.connector.discovery.DiscoveryDataRequestDto;
import com.otilm.api.model.connector.discovery.DiscoveryProviderDto;
import com.otilm.api.model.connector.discovery.DiscoveryRequestDto;
import com.otilm.discovery.ip.dao.DiscoveryHistory;

import java.io.IOException;

public interface DiscoveryService {
	public void discoverCertificate(DiscoveryRequestDto request, DiscoveryHistory history) throws IOException, NotFoundException;

	public DiscoveryProviderDto getProviderDtoData(DiscoveryDataRequestDto request, DiscoveryHistory history);

    void deleteDiscovery(String uuid) throws NotFoundException;
}
