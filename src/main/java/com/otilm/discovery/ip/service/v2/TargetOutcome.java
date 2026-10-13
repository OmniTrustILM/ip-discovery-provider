package com.otilm.discovery.ip.service.v2;

import java.io.EOFException;
import java.net.SocketException;
import java.net.SocketTimeoutException;

/**
 * What a probe that ended in an exception came to. A sweep of address space consists mostly of targets with nothing on
 * them, so those are empty rather than failed: nothing listening, nothing answering, an answer that is not TLS, or a
 * connection dropped before any TLS answer. A target fails when it answered as a TLS host and still could not be read,
 * when it was named and the name leads nowhere, or for any reason not recognised here.
 */
enum TargetOutcome {

    EMPTY,
    FAILED;

    /**
     * How the JDK says the peer answered with something other than TLS, in its current wording and in the older
     * "Unrecognized SSL message, plaintext connection?". The TLS stack has no exception type for it.
     */
    private static final String NOT_TLS = "nrecognized SSL message";

    /** Deep enough for any wrapping the TLS stack does, and a bound on a cause chain that loops. */
    private static final int MAX_CAUSE_DEPTH = 8;

    static TargetOutcome ofProbeFailure(Throwable failure) {
        Throwable cause = failure;
        for (int depth = 0; cause != null && depth < MAX_CAUSE_DEPTH; depth++, cause = cause.getCause()) {
            // SocketException covers a refused, unroutable or reset connection; EOFException is a peer that hung up
            // before saying anything a TLS client could read.
            if (cause instanceof SocketException || cause instanceof SocketTimeoutException
                    || cause instanceof EOFException) {
                return EMPTY;
            }
            if (cause.getMessage() != null && cause.getMessage().contains(NOT_TLS)) {
                return EMPTY;
            }
        }
        return FAILED;
    }
}
