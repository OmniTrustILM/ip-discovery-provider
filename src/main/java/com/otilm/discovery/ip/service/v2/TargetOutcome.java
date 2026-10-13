package com.otilm.discovery.ip.service.v2;

import java.io.EOFException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.PortUnreachableException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLHandshakeException;

/**
 * What a probe that ended in an exception came to, and why. A sweep of address space consists mostly of targets with
 * nothing on them, so those are empty rather than failed: nothing listening, nothing answering, an answer that is not
 * TLS, or a connection dropped before any TLS answer. A target fails when it answered as a TLS host and still could not
 * be read, when it was named and the name leads nowhere, or for any reason not recognised here.
 */
enum TargetOutcome {

    EMPTY,
    FAILED;

    /**
     * How the JDK says the peer answered with something other than TLS, in its current wording and in the older
     * "Unrecognized SSL message, plaintext connection?". The TLS stack has no exception type for it.
     */
    private static final String NOT_TLS = "nrecognized SSL message";

    /**
     * The plain {@link SocketException} messages that come from the peer's side. Any other one, like "Too many open
     * files", is this scanner failing.
     */
    private static final List<String> PEER_SOCKET_ERRORS = List
            .of("Connection reset", "Broken pipe", "Network is unreachable");

    private static final Pattern TLS_ALERT = Pattern.compile("Received fatal alert: (\\w+)");

    /** Deep enough for any wrapping the TLS stack does, and a bound on a cause chain that loops. */
    private static final int MAX_CAUSE_DEPTH = 8;

    static TargetOutcome ofProbeFailure(Throwable failure) {
        Throwable cause = failure;
        for (int depth = 0; cause != null && depth < MAX_CAUSE_DEPTH; depth++, cause = cause.getCause()) {
            if (nothingAnswered(cause) || (cause.getMessage() != null && cause.getMessage().contains(NOT_TLS))) {
                return EMPTY;
            }
        }
        return FAILED;
    }

    /**
     * Why a failed probe failed, as an operator reads it: the TLS alert a host answered with, a name that does not
     * resolve, or the exception's own name for anything else.
     */
    static String reasonOf(Throwable failure) {
        Throwable cause = failure;
        for (int depth = 0; cause != null && depth < MAX_CAUSE_DEPTH; depth++, cause = cause.getCause()) {
            if (cause instanceof UnknownHostException) {
                return "Host name did not resolve";
            }
            Matcher alert = cause.getMessage() == null ? null : TLS_ALERT.matcher(cause.getMessage());
            if (alert != null && alert.find()) {
                return "TLS alert " + alert.group(1);
            }
        }
        return failure instanceof SSLHandshakeException ? "TLS handshake failed" : failure.getClass().getSimpleName();
    }

    /** The reason for a target whose certificate this connector could not turn into an item: its own fault. */
    static String unusableCertificate(Throwable failure) {
        return "Certificate this connector could not use (" + failure.getClass().getSimpleName() + ")";
    }

    /**
     * The peer refused, was unreachable, never answered or hung up. Listed one by one, because a {@code BindException}
     * or another local socket error is a {@code SocketException} too, and must not pass for an empty target.
     */
    private static boolean nothingAnswered(Throwable cause) {
        if (cause instanceof ConnectException || cause instanceof NoRouteToHostException
                || cause instanceof PortUnreachableException || cause instanceof SocketTimeoutException
                || cause instanceof EOFException) {
            return true;
        }
        return cause.getClass() == SocketException.class && cause.getMessage() != null
                && PEER_SOCKET_ERRORS.stream().anyMatch(cause.getMessage()::startsWith);
    }
}
