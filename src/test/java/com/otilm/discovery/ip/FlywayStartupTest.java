package com.otilm.discovery.ip;

import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The shipped schema exists only through Flyway, so the migrations have to run when the application starts. The suite's
 * database switches Flyway off, which this test undoes on a database of its own.
 */
@SpringBootTest(properties = {
        "spring.flyway.enabled=true",
        "spring.jpa.hibernate.ddl-auto=none",
        "spring.datasource.url=jdbc:h2:mem:flyway;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1;"
                + "INIT=CREATE SCHEMA IF NOT EXISTS network"})
class FlywayStartupTest {

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void appliesEveryMigrationAtStartup() {
        List<String> applied = jdbc
                .queryForList("select version from network.network_schema_history"
                        + " where success = true and version is not null order by version", String.class);

        Assertions.assertEquals(List.of("202201041039", "202211111930"), applied);
    }
}
