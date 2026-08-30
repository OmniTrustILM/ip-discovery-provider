package com.otilm.discovery.ip.api;

import com.otilm.api.interfaces.connector.InfoController;
import com.otilm.api.model.client.connector.InfoResponse;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.discovery.ip.EndpointsListener;
import com.otilm.discovery.ip.enums.DiscoveryKind;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
public class InfoControllerImpl implements InfoController {
    private static final Logger logger = LoggerFactory.getLogger(InfoControllerImpl.class);

    @Autowired
    public void setEndpointsListener(EndpointsListener endpointsListener) {
        this.endpointsListener = endpointsListener;
    }

    private EndpointsListener endpointsListener;

    @Override
    public List<InfoResponse> listSupportedFunctions() {
    	logger.info("Listing the end points for IP Discovery");
    	List<String> kinds = DiscoveryKind.getKinds();
    	List<InfoResponse> functions = new ArrayList<>(); 
        functions.add(new InfoResponse(kinds, FunctionGroupCode.DISCOVERY_PROVIDER, endpointsListener.getEndpoints()));
        logger.debug("Functions of the connector is obtained. Value is {}", functions);
        return functions;
    }
}