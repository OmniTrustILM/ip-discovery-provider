package com.otilm.discovery.ip.api.v2;

/**
 * This node cannot take the call right now. Answered as 503, which Core retries shortly without counting a failure, so
 * the call reaches this node again or another one once there is room.
 */
public class ConnectorBusyException extends RuntimeException {

    public ConnectorBusyException(String message) {
        super(message);
    }
}
