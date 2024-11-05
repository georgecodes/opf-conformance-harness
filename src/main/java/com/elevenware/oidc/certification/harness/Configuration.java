package com.elevenware.oidc.certification.harness;

import com.elevenware.oidc4j.lib.commons.SecretUtils;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

@JsonDeserialize(using = ConfigurationDeserializer.class)
public class Configuration {

    private Provider defaultProvider;
    private Provider adminProvider;

    public Provider getDefaultProvider() {
        return defaultProvider;
    }

    public void setDefaultProvider(Provider defaultProvider) {
        this.defaultProvider = defaultProvider;
    }

    public Provider getAdminProvider() {
        return adminProvider;
    }

    public void setAdminProvider(Provider adminProvider) {
        this.adminProvider = adminProvider;
    }

    public boolean verify() {
       return true;
    }

    public static Configuration fromEnv() {
        Configuration config = new Configuration();
        Configuration.Provider defaultProvider = new Configuration.Provider();
        defaultProvider.issuer = System.getenv("DEFAULT_ISSUER");
        defaultProvider.clientId = System.getenv("DEFAULT_CLIENT_ID");
        defaultProvider.clientSecret = System.getenv("DEFAULT_CLIENT_SECRET");
        defaultProvider.clientSecret = SecretUtils.bcrypt(defaultProvider.clientSecret);
        defaultProvider.userName = System.getenv("DEFAULT_USER_NAME");
        defaultProvider.email = System.getenv("DEFAULT_EMAIL");
        Configuration.Provider adminProvider = new Configuration.Provider();
        adminProvider.issuer = System.getenv("ADMIN_ISSUER");
        adminProvider.clientId = System.getenv("ADMIN_CLIENT_ID");
        adminProvider.clientSecret = System.getenv("ADMIN_CLIENT_SECRET");
        adminProvider.clientSecret = SecretUtils.bcrypt(adminProvider.clientSecret);
        adminProvider.userName = System.getenv("ADMIN_USER_NAME");
        adminProvider.email = System.getenv("ADMIN_EMAIL");
        adminProvider.group = System.getenv("ADMIN_GROUP");
        config.defaultProvider = defaultProvider;
        config.adminProvider = adminProvider;
        String defaultPublicKey = System.getenv("DEFAULT_PUBLIC_KEY");
        String defaultPrivateKey = System.getenv("DEFAULT_PRIVATE_KEY");
        if(defaultPublicKey != null && defaultPrivateKey != null) {
            PublicKey publicKey = KeyUtils.publicKeyFromFile(defaultPublicKey);
            PrivateKey privateKey = KeyUtils.privateKeyFromFile(defaultPrivateKey);
            KeyPair keyPair = new KeyPair(publicKey, privateKey);
            defaultProvider.keyPair = keyPair;
        }
        String adminPublicKey = System.getenv("ADMIN_PUBLIC_KEY");
        String adminPrivateKey = System.getenv("ADMIN_PRIVATE_KEY");
        if(defaultPublicKey != null && defaultPrivateKey != null) {
            PublicKey publicKey = KeyUtils.publicKeyFromFile(adminPublicKey);
            PrivateKey privateKey = KeyUtils.privateKeyFromFile(adminPrivateKey);
            KeyPair keyPair = new KeyPair(publicKey, privateKey);
            adminProvider.keyPair = keyPair;
        }
        boolean useEnv = config.verify();
        return config.verify() ? config : null;
    }

    private static String loadPem(String file) {
        try {
            String s = Files.readString(Path.of(file), StandardCharsets.UTF_8);
            return s;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Configuration defaultConfiguration() {
        Configuration config = new Configuration();
        config.defaultProvider = new Provider();
        config.adminProvider = new Provider();
        config.defaultProvider.issuer = "https://auth.conformance.elevenware.com";
        config.defaultProvider.clientId = "conformance_suite";
        config.defaultProvider.clientSecret = SecretUtils.bcrypt("abcde12345");
        config.adminProvider.issuer = "https://auth.admin.conformance.elevenware.com";
        config.adminProvider.clientId = "conformance_suite_admin";
        config.adminProvider.clientSecret = SecretUtils.bcrypt("abcde12345");
        config.adminProvider.group = "conformance-admins";
        config.defaultProvider.userName = "George McIntosh";
        config.defaultProvider.email = "george@elevenware.com";
        config.adminProvider.userName = "George McIntosh";
        config.adminProvider.email = "george.admin@elevenware.com";
        return config;
    }

    public static Configuration fromFile(String path) {
        Configuration configuration;
        ObjectMapper mapper = new ObjectMapper();
        try {
            configuration = mapper.readValue(new File(path), Configuration.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return configuration;
    }

    public static class Provider {
        private String issuer;
        private String clientId;
        private String clientSecret;
        private String group;
        private String userName;
        private String email;
        private KeyPair keyPair;

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getGroup() {
            return group;
        }

        public void setGroup(String group) {
            this.group = group;
        }

        public String getUserName() {
            return userName;
        }

        public void setUserName(String userName) {
            this.userName = userName;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public KeyPair getKeyPair() {
            return keyPair;
        }

        public void setKeyPair(KeyPair keyPair) {
            this.keyPair = keyPair;
        }
    }

}
