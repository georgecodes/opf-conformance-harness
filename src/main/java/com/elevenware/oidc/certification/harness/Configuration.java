package com.elevenware.oidc.certification.harness;

import com.elevenware.oidc4j.lib.commons.SecretUtils;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import java.io.File;
import java.io.IOException;
import java.util.Map;

@JsonDeserialize(using = ConfigurationDeserializer.class)
public class Configuration {

    private String defaultIssuer;
    private String adminIssuer;
    private String adminGroup;
    private String defaultClientId;
    private String defaultClientSecret;
    private String adminClientId;
    private String adminClientSecret;
    private String userName;
    private String email;

    public String getDefaultIssuer() {
        return defaultIssuer;
    }

    public void setDefaultIssuer(String defaultIssuer) {
        this.defaultIssuer = defaultIssuer;
    }

    public String getAdminIssuer() {
        return adminIssuer;
    }

    public void setAdminIssuer(String adminIssuer) {
        this.adminIssuer = adminIssuer;
    }

    public String getDefaultClientId() {
        return defaultClientId;
    }

    public void setDefaultClientId(String defaultClientId) {
        this.defaultClientId = defaultClientId;
    }

    public String getDefaultClientSecret() {
        return defaultClientSecret;
    }

    public void setDefaultClientSecret(String defaultClientSecret) {
        this.defaultClientSecret = defaultClientSecret;
    }

    public String getAdminClientId() {
        return adminClientId;
    }

    public void setAdminClientId(String adminClientId) {
        this.adminClientId = adminClientId;
    }

    public String getAdminClientSecret() {
        return adminClientSecret;
    }

    public void setAdminClientSecret(String adminClientSecret) {
        this.adminClientSecret = adminClientSecret;
    }

    public String getAdminGroup() {
        return adminGroup;
    }

    public void setAdminGroup(String adminGroup) {
        this.adminGroup = adminGroup;
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

    public boolean verify() {
        if(defaultIssuer != null && adminIssuer != null
                && adminGroup != null && defaultClientId != null
                && defaultClientSecret != null && adminClientId != null
                && adminClientSecret != null && userName != null && email != null) {
            return true;
        }
        return false;
    }

    public static Configuration fromEnv() {
        Configuration config = new Configuration();
        config.defaultIssuer = System.getenv("DEFAULT_ISSUER");
        config.adminIssuer = System.getenv("ADMIN_ISSUER");
        config.defaultClientId = System.getenv("DEFAULT_CLIENT_ID");
        config.defaultClientSecret = System.getenv("DEFAULT_CLIENT_SECRET");
        config.defaultClientSecret = SecretUtils.bcrypt(config.defaultClientSecret);
        config.adminClientId = System.getenv("ADMIN_CLIENT_ID");
        config.adminClientSecret = System.getenv("ADMIN_CLIENT_SECRET");
        config.adminClientSecret = SecretUtils.bcrypt(config.adminClientSecret);
        config.adminGroup = System.getenv("ADMIN_GROUP");
        config.userName = System.getenv("USER_NAME");
        config.email = System.getenv("EMAIL");
        boolean useEnv = config.verify();
        System.out.printf("Using environment variables: %s\n", useEnv);
        return config.verify() ? config : null;
    }

    public static Configuration defaultConfiguration() {
        Configuration config = new Configuration();
        config.defaultIssuer = "https://auth.conformance.elevenware.com";
        config.adminIssuer = "https://auth.admin.conformance.elevenware.com";
        config.defaultClientId = "conformance_suite";
        config.defaultClientSecret = SecretUtils.bcrypt("abcde12345");
        config.adminClientId = "conformance_suite_admin";
        config.adminClientSecret = SecretUtils.bcrypt("abcde12345");
        config.adminGroup = "conformance-admins";
        config.userName = "George McIntosh";
        config.email = "george@elevenware.com";
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


}
