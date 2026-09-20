package com.otilm.discovery.ip;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.error.ErrorCode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.RestControllerAdvice;

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
     * The scan-spec parser raises {@link IllegalArgumentException} for a malformed port. Without its own mapping it
     * would reach the catch-all and become a 500, when it is a rejected request.
     */
    @Test
    void reportsAMalformedArgumentAsAValidationFailureRatherThanAFault() {
        ProblemDetail problem = advice.handleIllegalArgument(new IllegalArgumentException("Invalid port: http"));

        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY.value(), problem.getStatus());
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
