package com.otilm.discovery.ip.config;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.discovery.ip.dao.DiscoveryHistory;
import com.otilm.discovery.ip.service.DiscoveryHistoryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.AsyncConfigurer;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

@Configuration
public class CustomAsyncConfigurer implements AsyncConfigurer {

    private static final Logger logger = LoggerFactory.getLogger(CustomAsyncConfigurer.class);

    private DiscoveryHistoryService discoveryHistoryService;

    @Autowired
    public void setDiscoveryHistoryService(DiscoveryHistoryService discoveryHistoryService) {
        this.discoveryHistoryService = discoveryHistoryService;
    }

    @Override
    public Executor getAsyncExecutor() {
        // Use virtual threads for the executor
        return Executors.newVirtualThreadPerTaskExecutor();
    }

    @Override
    public AsyncUncaughtExceptionHandler getAsyncUncaughtExceptionHandler() {
        return (ex, method, params) -> {
            if (method.getName().equals("discoverCertificate")) {
                DiscoveryHistory history = (DiscoveryHistory) params[1];
                logger.error("Error occurred while discovering certificates, name {}: {}", history.getName(), ex.getMessage(), ex);
                history.setStatus(DiscoveryStatus.FAILED);
                history.setMeta(AttributeDefinitionUtils.serialize(getReasonMeta(ex.getMessage())));
                discoveryHistoryService.setHistory(history);
            }
        };
    }

    private List<MetadataAttributeV2> getReasonMeta(String exception) {
        List<MetadataAttributeV2> attributes = new ArrayList<>();

        // Exception Reason
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setName("reason");
        attribute.setUuid("abc0412a-60f6-11ed-9b6a-0242ac120002");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setType(AttributeType.META);
        attribute.setDescription("Reason for failure");

        MetadataAttributeProperties attributeProperties = new MetadataAttributeProperties();
        attributeProperties.setLabel("Reason");
        attributeProperties.setVisible(true);

        attribute.setProperties(attributeProperties);
        attribute.setContent(List.of(new StringAttributeContentV2(exception)));
        attributes.add(attribute);

        return attributes;
    }
}
