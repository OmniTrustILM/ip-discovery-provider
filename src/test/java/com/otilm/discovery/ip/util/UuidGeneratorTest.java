package com.otilm.discovery.ip.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.UUID;

class UuidGeneratorTest {

    @Test
    void producesAParsableUuid() {
        String uuid = UuidGenerator.uuid();

        Assertions.assertEquals(uuid, UUID.fromString(uuid).toString());
    }

    @Test
    void producesADistinctValueEachCall() {
        Assertions.assertNotEquals(UuidGenerator.uuid(), UuidGenerator.uuid());
    }

    @Test
    void cannotBeInstantiated() throws NoSuchMethodException {
        Constructor<UuidGenerator> constructor = UuidGenerator.class.getDeclaredConstructor();
        constructor.setAccessible(true);

        InvocationTargetException thrown =
                Assertions.assertThrows(InvocationTargetException.class, constructor::newInstance);
        Assertions.assertInstanceOf(IllegalAccessError.class, thrown.getCause());
    }
}
