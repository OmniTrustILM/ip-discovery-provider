package com.otilm.discovery.ip.api;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.connector.DiscoveryController;
import com.otilm.api.model.connector.discovery.DiscoveryDataRequestDto;
import com.otilm.api.model.connector.discovery.DiscoveryProviderDto;
import com.otilm.api.model.connector.discovery.DiscoveryRequestDto;
import com.otilm.discovery.ip.dao.DiscoveryHistory;
import com.otilm.discovery.ip.service.DiscoveryHistoryService;
import com.otilm.discovery.ip.service.DiscoveryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/**
 * Controller class for all certificate discovery operations.
 * The certificate discovery including all the methods
 */
@RestController
public class DiscoveryControllerImpl implements DiscoveryController {
	
	private static final Logger logger = LoggerFactory.getLogger(DiscoveryControllerImpl.class);

	@Autowired
	public void setDiscoveryService(DiscoveryService discoveryService) {
		this.discoveryService = discoveryService;
	}
	@Autowired
	public void setDiscoveryHistoryService(DiscoveryHistoryService discoveryHistoryService) {
		this.discoveryHistoryService = discoveryHistoryService;
	}

	private DiscoveryService discoveryService;
	private DiscoveryHistoryService discoveryHistoryService;

	@Override
	public DiscoveryProviderDto discoverCertificate(@RequestBody DiscoveryRequestDto request) throws IOException, NotFoundException {
		logger.info("Initiating certificate discovery for the given inputs");
		DiscoveryHistory history;
		history = discoveryHistoryService.addHistory(request);
		discoveryService.discoverCertificate(request, history);
		DiscoveryDataRequestDto dto = new DiscoveryDataRequestDto();
		dto.setName(request.getName());
		dto.setPageNumber(0);
		dto.setItemsPerPage(10);
		return discoveryService.getProviderDtoData(dto, history);
		
	}

	@Override
	public DiscoveryProviderDto getDiscovery(String uuid, DiscoveryDataRequestDto request) throws NotFoundException {
		DiscoveryHistory history = discoveryHistoryService.getHistoryByUuid(uuid);
		return discoveryService.getProviderDtoData(request, history);
	}

	@Override
	public void deleteDiscovery(String uuid) throws IOException, NotFoundException {
		discoveryService.deleteDiscovery(uuid);
	}
}
