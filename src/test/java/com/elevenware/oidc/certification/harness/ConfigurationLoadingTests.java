package com.elevenware.oidc.certification.harness;

import com.elevenware.oidc4j.lib.commons.SecretUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ConfigurationLoadingTests {

    @TempDir
    private static Path configDir;

    @Test
    void canLoadFromFile() {

        String filename = configDir.resolve("config.json").toString();
        Configuration configuration = Configuration.fromFile(filename);

        assertNotNull(configuration);

        assertEquals("https://auth.conformance.elevenware.com", configuration.getDefaultProvider().getIssuer());
        assertEquals("conformance_suite", configuration.getDefaultProvider().getClientId());
        assertTrue(SecretUtils.verify("abcde12345", configuration.getDefaultProvider().getClientSecret()));
        assertEquals("George McIntosh", configuration.getDefaultProvider().getUserName());
        assertEquals("george@elevenware.com", configuration.getDefaultProvider().getEmail());

        assertEquals("https://auth.admin.conformance.elevenware.com", configuration.getAdminProvider().getIssuer());
        assertEquals("conformance_suite_admin", configuration.getAdminProvider().getClientId());
        assertTrue(SecretUtils.verify("abcde12345", configuration.getAdminProvider().getClientSecret()));
        assertEquals("George McIntosh", configuration.getAdminProvider().getUserName());
        assertEquals("george.admin@elevenware.com", configuration.getAdminProvider().getEmail());

        assertTrue(configuration.verify());

    }

    @Test
    void canLoadKeys() {

        String filename = configDir.resolve("config_pem_keys.json").toString();
        Configuration configuration = Configuration.fromFile(filename);

        assertNotNull(configuration);
        Configuration.Provider defaultProvider = configuration.getDefaultProvider();
        assertNotNull(defaultProvider.getKeyPair());

        Configuration.Provider adminProvider = configuration.getAdminProvider();
        assertNull(adminProvider.getKeyPair());

    }

    @BeforeAll
    static void setup() throws IOException {
        Path path = Paths.get("src/test/resources/config.json");
        Path configFile = configDir.resolve("config.json");
        Files.copy(path, configFile);

        path = Paths.get("src/test/resources/config_pem_keys.json");
        configFile = configDir.resolve("config_pem_keys.json");
        Files.copy(path, configFile);

    }

}
