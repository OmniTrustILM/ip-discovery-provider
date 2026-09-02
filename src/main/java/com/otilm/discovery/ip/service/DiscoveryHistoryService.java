package com.otilm.discovery.ip.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.connector.discovery.DiscoveryRequestDto;
import com.otilm.discovery.ip.dao.DiscoveryHistory;

public interface DiscoveryHistoryService {
	public DiscoveryHistory addHistory(DiscoveryRequestDto request);
	public DiscoveryHistory getHistoryById(Long id) throws NotFoundException;
	public DiscoveryHistory getHistoryByUuid(String uuid) throws NotFoundException;
	public void setHistory(DiscoveryHistory history);
	void deleteHistory(DiscoveryHistory history);
}
