package com.elevenware.oidc.certification.harness;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.IntNode;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ConfigurationDeserializer extends StdDeserializer<Configuration> {

    public ConfigurationDeserializer() {
        super(Configuration.class);
    }

    @Override
    public Configuration deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
        JsonNode node = jsonParser.getCodec().readTree(jsonParser);
        Configuration configuration = new Configuration();
        Configuration.Provider defaultProvider = generateProvider(node.get("defaultProvider"));
        configuration.setDefaultProvider(defaultProvider);
        Configuration.Provider adminProvider = generateProvider(node.get("adminProvider"));
        configuration.setAdminProvider(adminProvider);
        return configuration;
    }

    private Configuration.Provider generateProvider(JsonNode node) {
        Configuration.Provider provider = new Configuration.Provider();
        String issuer = node.get("issuer").asText();
        String clientId = node.get("clientId").asText();
        String clientSecret = node.get("clientSecret").asText();
        JsonNode user = node.get("user");
        String userName = user.get("name").asText();
        String email = user.get("email").asText();
        JsonNode group = node.get("group");
        if(group != null) {
            provider.setGroup(group.asText());
        }
        provider.setIssuer(issuer);
        provider.setClientId(clientId);
        provider.setClientSecret(clientSecret);
        provider.setUserName(userName);
        provider.setEmail(email);
        processKeys(node, provider);
        return provider;
    }

    private void processKeys(JsonNode node, Configuration.Provider configuration) {
        if(node.has("keys")) {
            JsonNode keys = node.get("keys");
            PublicKey publicKey = KeyUtils.publicKeyFromPem(keys.get("public").asText());
            PrivateKey privateKey = KeyUtils.privateKeyFromPem(keys.get("private").asText());
            KeyPair keyPair = new KeyPair(publicKey, privateKey);
            configuration.setKeyPair(keyPair);
        }
    }
}
