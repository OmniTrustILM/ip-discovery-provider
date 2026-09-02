package com.otilm.discovery.ip.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@Configuration
@EnableJpaAuditing
@PropertySource(value = ApplicationConfig.EXTERNAL_PROPERTY_SOURCE, ignoreResourceNotFound = true)
public class ApplicationConfig {

	public static final String EXTERNAL_PROPERTY_SOURCE = "file:${ip-discovery-provider.config.dir:/etc/ip-discovery-provider}/ip-discovery-provider.properties";

}