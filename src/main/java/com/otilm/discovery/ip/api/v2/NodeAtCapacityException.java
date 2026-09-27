package com.otilm.discovery.ip.api.v2;

/**
 * This node already holds as many runs as its buffer budget allows. Answered as 503, which is retryable: another node
 * may have room, and this one will once a run finishes.
 */
public class NodeAtCapacityException extends RuntimeException {

    public NodeAtCapacityException(String message) {
        super(message);
    }
}
