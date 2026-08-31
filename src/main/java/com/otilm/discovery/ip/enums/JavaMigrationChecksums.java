package com.otilm.discovery.ip.enums;

/**
 * Stores the checksum of a Java-based migration.
 */
@SuppressWarnings("java:S115")
public enum JavaMigrationChecksums {
    /**
     * Checksum frozen at its pre-rebrand value. The CZERTAINLY to ILM rebrand rewrote the migration's import
     * statements, which changes the checksum computed from the source file, but the migration itself still applies
     * exactly the same schema change. Deployed databases recorded the original checksum, so recomputing it here would
     * fail Flyway validation on every existing installation. {@code isAltered} exempts the entry from the
     * source-integrity assertion in {@code DatabaseMigrationTest} — never recompute it.
     */
    V202211111930__MetadataToInfoAttributeMigration(578577573, true);

    private final int checksum;
    private final boolean isAltered;

    JavaMigrationChecksums(int checksum, boolean isAltered) {
        this.checksum = checksum;
        this.isAltered = isAltered;
    }

    public int getChecksum() {
        return checksum;
    }

    public boolean isAltered() {
        return isAltered;
    }
}
