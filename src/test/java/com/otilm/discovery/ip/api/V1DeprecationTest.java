package com.otilm.discovery.ip.api;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springdoc.core.converters.SchemaPropertyDeprecatingConverter;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * v1 stays deprecated but fully working while both surfaces serve, so the marking is the whole deliverable and it has
 * to be the marking OpenAPI actually reads. springdoc treats an operation as deprecated when either the handler
 * method or its declaring class carries the annotation, which is why the classes are annotated and the methods are
 * not; this asserts that predicate directly, since no springdoc web starter is on the classpath to serve a document
 * to inspect instead.
 */
class V1DeprecationTest {

    private static List<Method> handlerMethods(Class<?> controller) {
        List<Method> methods = new ArrayList<>();
        for (Class<?> api : controller.getInterfaces()) {
            for (Method declared : api.getDeclaredMethods()) {
                try {
                    methods.add(controller.getMethod(declared.getName(), declared.getParameterTypes()));
                } catch (NoSuchMethodException e) {
                    throw new AssertionError(controller.getSimpleName() + " does not implement " + declared, e);
                }
            }
        }
        Assertions.assertFalse(methods.isEmpty(), controller.getSimpleName() + " exposes no operations");
        return methods;
    }

    @Test
    void marksEveryV1OperationDeprecated() {
        List<Class<?>> v1 = List
                .of(AttributesControllerImpl.class, DiscoveryControllerImpl.class, HealthControllerImpl.class,
                        InfoControllerImpl.class);

        for (Class<?> controller : v1) {
            for (Method operation : handlerMethods(controller)) {
                Assertions
                        .assertTrue(SchemaPropertyDeprecatingConverter.isDeprecated(operation),
                                controller.getSimpleName() + "." + operation.getName()
                                        + " is on the superseded surface and must be published as deprecated");
            }
        }
    }

    /** The replacement must not inherit the marking, or the migration target reads as superseded too. */
    @Test
    void leavesTheV2OperationsUndeprecated() {
        List<Class<?>> v2 = List
                .of(com.otilm.discovery.ip.api.v2.InfoControllerImpl.class,
                        com.otilm.discovery.ip.api.v2.HealthControllerImpl.class,
                        com.otilm.discovery.ip.api.v2.DiscoveryMetadataControllerImpl.class);

        for (Class<?> controller : v2) {
            for (Method operation : handlerMethods(controller)) {
                Assertions
                        .assertFalse(SchemaPropertyDeprecatingConverter.isDeprecated(operation),
                                controller.getName() + "." + operation.getName() + " must not be marked deprecated");
            }
        }
    }
}
