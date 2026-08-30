package com.otilm.discovery.ip;

import com.otilm.core.util.DatabaseMigrationUtils;
import com.otilm.discovery.ip.enums.JavaMigrationChecksums;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Simple tests for calculating checksums and validating the migration scripts integrity.
 */
class DatabaseMigrationTest {

    @Test
    void testJavaMigrationsChecksums() {
        for (JavaMigrationChecksums migrationChecksum : JavaMigrationChecksums.values()) {
            if (migrationChecksum.isAltered()) {
                continue;
            }
            int checksum = DatabaseMigrationUtils.calculateChecksum("src/main/java/db/migration/" + migrationChecksum.name() + ".java");
            Assertions.assertEquals(migrationChecksum.getChecksum(), checksum,
                    "Error in checking checksum of Java migration: " + migrationChecksum.name());
        }
    }
}
