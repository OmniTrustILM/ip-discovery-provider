package com.otilm.discovery.ip;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a controller as part of the connector's v2 surface.
 *
 * <p>
 * Its only job is to scope {@link ProblemDetailsHandlingAdvice}. v1 and v2 answer errors in different shapes —
 * {@code ErrorMessageDto} and RFC 9457 problem+json — and the two must not bleed into each other while both surfaces
 * serve, so the advice binds to this annotation rather than to a package or to everything.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface ConnectorV2Api {
}
