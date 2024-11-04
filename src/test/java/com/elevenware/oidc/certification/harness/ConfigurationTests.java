package com.elevenware.oidc.certification.harness;

import com.elevenware.oidc4j.lib.commons.SecretUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ConfigurationTests {

    @TempDir
    private static Path configDir;

    @Test
    void canLoadFromFile() {

        String filename = configDir.resolve("config.json").toString();
        Configuration configuration = Configuration.fromFile(filename);

        assertNotNull(configuration);

        assertEquals("https://auth.conformance.elevenware.com", configuration.getDefaultIssuer());
        assertEquals("https://auth.admin.conformance.elevenware.com", configuration.getAdminIssuer());
        assertEquals("conformance_suite", configuration.getDefaultClientId());
        assertTrue(SecretUtils.verify("abcde12345", configuration.getDefaultClientSecret()));
        assertEquals("conformance_suite_admin", configuration.getAdminClientId());
        assertTrue(SecretUtils.verify("abcde12345", configuration.getAdminClientSecret()));
        assertEquals("George McIntosh", configuration.getUserName());
        assertEquals("george@elevenware.com", configuration.getEmail());

        assertTrue(configuration.verify());

    }

    @BeforeAll
    static void setup() throws IOException {
        Path path = Paths.get("src/test/resources/config.json");
        Path configFile = configDir.resolve("config.json");
        Files.copy(path, configFile);
    }

}
