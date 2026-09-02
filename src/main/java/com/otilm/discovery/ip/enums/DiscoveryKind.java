package com.otilm.discovery.ip.enums;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;

import java.util.Arrays;
import java.util.List;

public enum DiscoveryKind {
    IP_Hostname("IP-Hostname");

    private static final DiscoveryKind[] VALUES;

    static {
        VALUES = values();
    }

    private final String code;

    DiscoveryKind(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public static DiscoveryKind findByCode(String code) {
        return Arrays.stream(VALUES)
                .filter(k -> k.code.equals(code))
                .findFirst()
                .orElseThrow(() ->
                        new ValidationException(ValidationError.create("Unknown kind code {}", code)));
    }

    public static List<String> getKinds() {
        return Arrays.stream(VALUES)
                .map(DiscoveryKind::getCode)
                .toList();
    }
}
