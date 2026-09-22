package com.otilm.discovery.ip.config;

import com.otilm.api.config.converter.IPlatformEnumConverterFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Binds an {@code IPlatformEnum}-typed path variable by its wire code — {@code certificates} rather than
 * {@code CERTIFICATE} — which Spring's default enum binding, matching on constant name, cannot do.
 */
@Configuration
public class PlatformEnumBindingConfiguration implements WebMvcConfigurer {

    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverterFactory(new IPlatformEnumConverterFactory());
    }
}
