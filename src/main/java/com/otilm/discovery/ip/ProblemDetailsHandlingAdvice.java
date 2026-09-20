package com.otilm.discovery.ip;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.discovery.ip.api.v2.AttributeCallbackNotSupportedException;
import com.otilm.discovery.ip.api.v2.AttributeDefinitionNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.stream.Collectors;

/**
 * Renders v2 failures as RFC 9457 problem+json.
 *
 * <p>
 * Bound to {@link ConnectorV2Api} rather than to everything: v1 keeps answering with {@code ErrorMessageDto} through
 * {@code ExceptionHandlingAdvice} for as long as both surfaces serve, and a v2 shape reaching a v1 caller would break
 * a Core that has not migrated. {@code HIGHEST_PRECEDENCE} is what makes this win over the v1 advice for the
 * controllers it covers.
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(annotations = ConnectorV2Api.class)
public class ProblemDetailsHandlingAdvice extends ResponseEntityExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ProblemDetailsHandlingAdvice.class);

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        String message = ex
                .getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> error.getField() + " " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));
        LOG.error("Validation error occurred: {}", message, ex);
        return new ResponseEntity<>(
                ProblemDetailExtended.fromErrorCode(ErrorCode.VALIDATION_FAILED, message, null, null), headers,
                HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @ExceptionHandler(ValidationException.class)
    public ProblemDetail handleValidation(ValidationException ex) {
        LOG.error("Validation error occurred: {}", ex.getMessage(), ex);
        return ProblemDetailExtended.fromErrorCode(ErrorCode.VALIDATION_FAILED, ex.getMessage(), null, null);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArgument(IllegalArgumentException ex) {
        // The scan-spec parser raises this for a malformed port; on the v2 surface it is a rejected request rather
        // than a fault, so it must not fall through to the catch-all and become a 500.
        LOG.error("Invalid argument: {}", ex.getMessage(), ex);
        return ProblemDetailExtended.fromErrorCode(ErrorCode.VALIDATION_FAILED, ex.getMessage(), null, null);
    }

    /**
     * A path variable that will not convert — a resource code naming no resource. Spring resolves this one itself,
     * into a 400 carrying its own default body, so without a handler here a v2 caller gets a third error shape from
     * a surface that promises problem+json. It answers 422 like every other rejected argument: the request reached
     * the right route and named something that does not exist, which is the same failure as asking for a resource
     * this connector does not discover.
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ProblemDetail handleUnconvertibleArgument(MethodArgumentTypeMismatchException ex) {
        LOG.error("Invalid path variable {}: {}", ex.getName(), ex.getMessage(), ex);
        // The cause carries the converter's own message, which names the value and the enum it failed to match.
        String detail = ex.getMostSpecificCause().getMessage();
        return ProblemDetailExtended.fromErrorCode(ErrorCode.VALIDATION_FAILED, detail, null, null);
    }

    @ExceptionHandler(AttributeDefinitionNotFoundException.class)
    public ProblemDetail handleAttributeDefinitionNotFound(AttributeDefinitionNotFoundException ex) {
        LOG.error("Attribute definition not found: {}", ex.getMessage(), ex);
        return ProblemDetailExtended
                .fromErrorCode(ErrorCode.ATTRIBUTE_DEFINITION_NOT_FOUND, ex.getMessage(), null, null);
    }

    @ExceptionHandler(AttributeCallbackNotSupportedException.class)
    public ProblemDetail handleAttributeCallbackNotSupported(AttributeCallbackNotSupportedException ex) {
        LOG.error("Attribute callback not supported: {}", ex.getMessage(), ex);
        return ProblemDetailExtended.fromErrorCode(ErrorCode.VALIDATION_FAILED, ex.getMessage(), null, null);
    }

    @ExceptionHandler(NotFoundException.class)
    public ProblemDetail handleNotFound(NotFoundException ex) {
        LOG.error("Resource not found: {}", ex.getMessage(), ex);
        return ProblemDetailExtended.fromErrorCode(ErrorCode.RESOURCE_NOT_FOUND, ex.getMessage(), null, null);
    }

    @ExceptionHandler(UnsupportedOperationException.class)
    public ProblemDetail handleUnsupported(UnsupportedOperationException ex) {
        LOG.error("Operation not supported: {}", ex.getMessage(), ex);
        return ProblemDetailExtended.fromErrorCode(ErrorCode.OPERATION_NOT_SUPPORTED, ex.getMessage(), null, null);
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleEverythingElse(Exception ex) {
        // The message is logged, not returned. This is the ungated handler, so anything without a more specific
        // mapping lands here -- SQL, host resolution and constraint text included -- and the v1 advice was changed
        // for the same reason. The error code alone is what a caller can act on.
        LOG.error("General error occurred: {}", ex.getMessage(), ex);
        return ProblemDetailExtended
                .fromErrorCode(ErrorCode.INTERNAL_SERVER_ERROR, "Internal server error.", null, null);
    }
}
