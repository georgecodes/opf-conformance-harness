package com.elevenware.oidc.certification.harness;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.IntNode;

import java.io.IOException;

public class ConfigurationDeserializer extends StdDeserializer<Configuration> {

    public ConfigurationDeserializer() {
        super(Configuration.class);
    }

    @Override
    public Configuration deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
        JsonNode node = jsonParser.getCodec().readTree(jsonParser);
        JsonNode defaultProvider = node.get("providers").get("default");
        JsonNode adminProvider = node.get("providers").get("admin");
        JsonNode user = node.get("user");
        Configuration configuration = new Configuration();
        configuration.setDefaultIssuer(defaultProvider.get("issuer").asText());
        configuration.setAdminIssuer(adminProvider.get("issuer").asText());
        configuration.setAdminGroup(adminProvider.get("group").asText());
        configuration.setDefaultClientId(defaultProvider.get("clientId").asText());
        configuration.setDefaultClientSecret(defaultProvider.get("clientSecret").asText());
        configuration.setAdminClientId(adminProvider.get("clientId").asText());
        configuration.setAdminClientSecret(adminProvider.get("clientSecret").asText());
        configuration.setUserName(user.get("name").asText());
        configuration.setEmail(user.get("email").asText());

        return configuration;
    }
}
