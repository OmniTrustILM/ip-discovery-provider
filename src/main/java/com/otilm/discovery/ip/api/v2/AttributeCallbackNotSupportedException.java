package com.otilm.discovery.ip.api.v2;

/**
 * A callback was requested for an attribute that declares none. No attribute this connector defines does: every value
 * is typed by the operator rather than chosen from a set the connector computes.
 */
public class AttributeCallbackNotSupportedException extends RuntimeException {

    public AttributeCallbackNotSupportedException(String attributeName) {
        super(attributeName == null
                ? "This connector defines no attribute with a callback"
                : "Attribute " + attributeName + " declares no callback");
    }
}
