package com.otilm.discovery.ip;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.core.auth.Resource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

class ProblemDetailsHandlingAdviceTest {

    private final ProblemDetailsHandlingAdvice advice = new ProblemDetailsHandlingAdvice();

    /**
     * The two error models must not bleed while both surfaces serve: v1 answers with {@code ErrorMessageDto} and v2
     * with problem+json. This advice is scoped by annotation rather than by package or globally, and this is what
     * fails if someone widens it.
     */
    @Test
    void appliesOnlyToControllersMarkedAsV2() {
        RestControllerAdvice scope =
                AnnotationUtils.findAnnotation(ProblemDetailsHandlingAdvice.class, RestControllerAdvice.class);

        Assertions.assertNotNull(scope);
        Assertions
                .assertArrayEquals(new Class<?>[] {ConnectorV2Api.class}, scope.annotations(),
                        "the v2 advice must bind to ConnectorV2Api alone, or it will answer v1 callers in a shape "
                                + "they cannot read");
    }

    @Test
    void reportsAValidationFailureAs422() {
        ProblemDetail problem = advice.handleValidation(new ValidationException("bad spec"));

        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY.value(), problem.getStatus());
        Assertions.assertEquals("bad spec", problem.getDetail());
    }

    /**
     * Without its own mapping an {@link IllegalArgumentException} would reach the catch-all and become a 500, when it
     * is a rejected request. The connector's own validators never arrive here -- they wrap into a
     * {@link ValidationException} first -- so whatever does is a library's, and its message stays in the log.
     */
    @Test
    void reportsAMalformedArgumentAsAValidationFailureRatherThanAFault() {
        ProblemDetail problem = advice
                .handleIllegalArgument(new IllegalArgumentException(
                        "Cannot invoke \"com.otilm.discovery.ip.util.TargetEnumeration.size()\" because it is null"));

        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY.value(), problem.getStatus());
        Assertions
                .assertFalse(problem.getDetail().contains("com.otilm"),
                        "a library's message names internals and must not reach the wire: " + problem.getDetail());
    }

    /**
     * The converter's own message names the target type in full, so echoing it publishes the platform's package
     * layout to anyone who sends a bad resource code. The caller's value and the parameter name say everything a
     * caller can act on.
     */
    @Test
    void namesTheRejectedValueWithoutTheTargetTypeItFailedToConvertTo() {
        ProblemDetail problem = advice.handleUnconvertibleArgument(mismatch("resource", "wibble"));

        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY.value(), problem.getStatus());
        Assertions.assertTrue(problem.getDetail().contains("wibble"), problem.getDetail());
        Assertions.assertTrue(problem.getDetail().contains("resource"), problem.getDetail());
        Assertions
                .assertFalse(problem.getDetail().contains("com.otilm"),
                        "the converter's type name must stay in the log: " + problem.getDetail());
    }

    /** The value goes back out in a response, and a path variable is as long as the caller made it. */
    @Test
    void boundsTheRejectedValueItEchoes() {
        ProblemDetail problem = advice.handleUnconvertibleArgument(mismatch("resource", "x".repeat(4096)));

        Assertions.assertTrue(problem.getDetail().length() < 200, "echoed value must be bounded");
        Assertions.assertTrue(problem.getDetail().contains("..."), problem.getDetail());
    }

    /** The error code carries the meaning; the exception's text is a library's to begin with. */
    @Test
    void withholdsAnUnsupportedOperationsOwnMessage() {
        ProblemDetail problem = advice
                .handleUnsupported(new UnsupportedOperationException("java.util.ImmutableCollections$ListN.add"));

        Assertions.assertFalse(problem.getDetail().contains("ImmutableCollections"), problem.getDetail());
    }

    private static MethodArgumentTypeMismatchException mismatch(String name, String value) {
        return new MethodArgumentTypeMismatchException(value, Resource.class, name, (MethodParameter) null,
                new IllegalArgumentException("No enum constant com.otilm.api.model.core.auth.Resource." + value));
    }

    @Test
    void reportsAMissingResourceAs404() {
        ProblemDetail problem = advice.handleNotFound(new NotFoundException("run", "abc"));

        Assertions.assertEquals(HttpStatus.NOT_FOUND.value(), problem.getStatus());
    }

    /**
     * The catch-all is the ungated handler, so anything without a specific mapping arrives here — SQL text, host
     * resolution failures, constraint violations. The v1 advice was changed for exactly this reason and the v2 one
     * must not reintroduce the leak.
     */
    @Test
    void doesNotPutAnUnmappedFailuresMessageOnTheWire() {
        ProblemDetail problem = advice
                .handleEverythingElse(new IllegalStateException(
                        "ERROR: duplicate key value violates unique constraint \"ip_discovery_certificate_pkey\""));

        Assertions.assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), problem.getStatus());
        Assertions
                .assertFalse(problem.getDetail().contains("constraint"),
                        "the exception's own text must stay in the log: " + problem.getDetail());
        Assertions
                .assertEquals(ErrorCode.INTERNAL_SERVER_ERROR.getStatus().value(), problem.getStatus(),
                        "the error code is what a caller can act on, and it must survive the message being withheld");
    }
}
