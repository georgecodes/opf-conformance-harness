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
import java.security.PrivateKey;
import java.security.PublicKey;

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

    @Test
    void canLoadKeys() {

        String filename = configDir.resolve("config_pem_keys.json").toString();
        Configuration configuration = Configuration.fromFile(filename);

        assertNotNull(configuration);

        String defaultPublicKey = configuration.getDefaultPublicKey();
        String defaultPrivateKey = configuration.getDefaultPrivateKey();

        assertNotNull(defaultPublicKey);
        PublicKey publicKey = KeyUtils.publicKeyFromPem(defaultPublicKey);

        assertNotNull(defaultPrivateKey);
        PrivateKey privateKey = KeyUtils.privateKeyFromPem(defaultPrivateKey);


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
