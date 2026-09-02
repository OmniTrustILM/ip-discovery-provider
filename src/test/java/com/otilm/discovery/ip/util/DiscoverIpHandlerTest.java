package com.otilm.discovery.ip.util;

import com.otilm.api.exception.ValidationException;
import com.otilm.discovery.ip.service.impl.AttributeServiceImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Set;
import java.util.regex.Pattern;

@SpringBootTest
public class DiscoverIpHandlerTest {

    @Test
    public void testIpRange_ok() {
        String startIp = "10.1.1.30";
        String endIp = "10.1.1.100";

        Set<String> ips =  DiscoverIpHandler.getIpRange(startIp, endIp);

        Assertions.assertNotNull(ips);
        Assertions.assertEquals(ips.size(), 71);
    }

    @Test
    public void testIpsHostname_ok() {
        String ipsHostnames = "www.example.com,192.168.1.1,10.1.1.20-10.1.1.50,172.16.1.0/24,172.16.1.0/24";

        Set<String> ips = DiscoverIpHandler.getIpHostnameUrls(ipsHostnames);

        Assertions.assertNotNull(ips);
        Assertions.assertEquals(ips.size(), 287);
    }

    @Test
    public void testIpsHostname_notok() {
        String ipsHostnames = "www.example.com,192.33.168.1.1";

        Assertions.assertThrows(ValidationException.class, () -> DiscoverIpHandler.getIpHostnameUrls(ipsHostnames));
    }

    @Test
    public void testCombinedRegexValidation_ok() {
        String ipsHostnames = "www.example.com,192.168.1.1,10.1.1.20-10.1.1.50,172.16.1.0/24,172.16.1.0/24";
        boolean match =Pattern.compile(AttributeServiceImpl.COMBINED_IP_HOSTNAME_VALIDATION_REGEX).matcher(ipsHostnames).matches();
        Assertions.assertTrue(match);

        ipsHostnames = "www.example.com";
        match =Pattern.compile(AttributeServiceImpl.COMBINED_IP_HOSTNAME_VALIDATION_REGEX).matcher(ipsHostnames).matches();
        Assertions.assertTrue(match);

        ipsHostnames = "192.168.1.1";
        match =Pattern.compile(AttributeServiceImpl.COMBINED_IP_HOSTNAME_VALIDATION_REGEX).matcher(ipsHostnames).matches();
        Assertions.assertTrue(match);

        ipsHostnames = "10.1.1.20-10.1.1.50";
        match =Pattern.compile(AttributeServiceImpl.COMBINED_IP_HOSTNAME_VALIDATION_REGEX).matcher(ipsHostnames).matches();
        Assertions.assertTrue(match);

        ipsHostnames = "172.16.1.0/24";
        match =Pattern.compile(AttributeServiceImpl.COMBINED_IP_HOSTNAME_VALIDATION_REGEX).matcher(ipsHostnames).matches();
        Assertions.assertTrue(match);
    }

    @Test
    public void testPortMatch_ok() {
        String ports = "443";
        boolean match = Pattern.compile(AttributeServiceImpl.PORT_VALIDATION_REGEX).matcher(ports).matches();
        Assertions.assertTrue(match);

        ports = "9000-10000";
        match = Pattern.compile(AttributeServiceImpl.PORT_RANGE_VALIDATION_REGEX).matcher(ports).matches();
        Assertions.assertTrue(match);
    }

    @Test
    public void testPortMatch_notok() {
        String ports = "443-445";
        boolean match = Pattern.compile(AttributeServiceImpl.PORT_VALIDATION_REGEX).matcher(ports).matches();
        Assertions.assertFalse(match);

        ports = "9000";
        match = Pattern.compile(AttributeServiceImpl.PORT_RANGE_VALIDATION_REGEX).matcher(ports).matches();
        Assertions.assertFalse(match);
    }

    @Test
    public void testCombinedPortRegexValidation_ok() {
        String ports = "443,80,8080,22,21,25,110,143,9000-10000";
        boolean match = Pattern.compile(AttributeServiceImpl.COMBINED_PORT_VALIDATION_REGEX).matcher(ports).matches();
        Assertions.assertTrue(match);
    }

    @Test
    public void testCombinedPortRegexValidation_notok() {
        String ports = "443,80,8080,22,21,25,110,143,9000-10000,";
        boolean match = Pattern.compile(AttributeServiceImpl.COMBINED_PORT_VALIDATION_REGEX).matcher(ports).matches();
        Assertions.assertFalse(match);

        ports = ",443,80,8080,22,21,25,110,143,9000-10000";
        match = Pattern.compile(AttributeServiceImpl.COMBINED_PORT_VALIDATION_REGEX).matcher(ports).matches();
        Assertions.assertFalse(match);

        ports = "443,80,8080,22,21,25,110,143,9000-100000";
        match = Pattern.compile(AttributeServiceImpl.COMBINED_PORT_VALIDATION_REGEX).matcher(ports).matches();
        Assertions.assertFalse(match);
    }
}
