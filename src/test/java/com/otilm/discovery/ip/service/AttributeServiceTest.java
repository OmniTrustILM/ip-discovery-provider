package com.otilm.discovery.ip.service;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

@SpringBootTest
public class AttributeServiceTest {
    @Autowired
    private AttributeService attributeService;

    @Test
    public void testAttributeResponse() {
        List<BaseAttribute> attributes = attributeService.getAttributes("IP-Hostname");
        Assertions.assertNotNull(attributes);
    }
}
