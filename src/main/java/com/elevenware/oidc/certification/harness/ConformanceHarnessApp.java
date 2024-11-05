package com.elevenware.oidc.certification.harness;

import com.elevenware.oidc4j.lib.grants.GrantTypes;
import com.elevenware.oidc4j.lib.provider.OIDCProvider;
import com.elevenware.oidc4j.lib.provider.ProviderConfig;
import com.elevenware.oidc4j.lib.provider.model.BasicUser;
import com.elevenware.oidc4j.lib.provider.model.OAuthClient;
import com.elevenware.oidc4j.lib.provider.repository.AuthorizationRepository;
import com.elevenware.oidc4j.lib.provider.repository.GrantRepository;
import com.elevenware.oidc4j.lib.provider.repository.UserRepository;
import com.elevenware.oidc4j.lib.provider.repository.mem.InMemoryAuthorizationRepository;
import com.elevenware.oidc4j.lib.provider.repository.mem.InMemoryClientRepository;
import com.elevenware.oidc4j.lib.provider.repository.mem.InMemoryGrantRepository;
import com.elevenware.oidc4j.lib.provider.repository.mem.InMemoryUserRepository;
import com.elevenware.oidc4j.lib.provider.validators.ClientAuthenticationValidator;
import com.elevenware.oidc4j.lib.provider.validators.GrantTypeAcceptableValidator;
import com.elevenware.oidc4j.lib.provider.validators.GrantTypePresentValidator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.nimbusds.jwt.JWTClaimsSet;
import io.javalin.Javalin;
import io.javalin.json.JavalinJackson;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Optional;
import java.util.Set;


public class ConformanceHarnessApp {

    public static void main(String[] args) throws NoSuchAlgorithmException {

        Configuration configuration = null;
        if(System.getProperty("oidc.config") != null) {
            configuration = Configuration.fromFile(System.getProperty("oidc.config"));
        }

        if(System.getenv("OIDC_CONFIG_FILE") != null) {
            configuration = Configuration.fromFile(System.getenv("OIDC_CONFIG"));
        }

        if(configuration == null) {
            configuration = Configuration.fromEnv();
        }
        if(configuration == null) {
            configuration = Configuration.defaultConfiguration();
        }

        int port = 9090;
        JavalinJackson jsonMapper = new JavalinJackson();
        jsonMapper.getMapper()
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);
        Javalin javalin = Javalin.create(conf -> {
            conf.jsonMapper(jsonMapper);
        });

        BasicUser defaultUser = new BasicUser(configuration.getDefaultProvider().getEmail(), configuration.getDefaultProvider().getUserName());
        BasicUser adminUser = new BasicUser(configuration.getAdminProvider().getEmail(), configuration.getAdminProvider().getUserName());

        OAuthClient defaultClient = OAuthClient.builder()
                .clientId(configuration.getDefaultProvider().getClientId())
                .clientSecret(configuration.getDefaultProvider().getClientSecret())
                .grantTypes(Set.of(GrantTypes.AUTHORIZATION_CODE))
                .build();

        OAuthClient adminClient = OAuthClient.builder()
                .clientId(configuration.getAdminProvider().getClientId())
                .clientSecret(configuration.getAdminProvider().getClientSecret())
                .grantTypes(Set.of(GrantTypes.AUTHORIZATION_CODE))
                .build();

        OIDCProvider defaultProvider = createProvider( configuration.getDefaultProvider(),
                defaultClient, defaultUser);
        OIDCProvider adminProvider = createProvider(configuration.getAdminProvider(), adminClient, adminUser);

        ConformanceHarness harness = new ConformanceHarness(javalin, defaultProvider, adminProvider, defaultUser, adminUser);
        javalin.start(port);

    }

    private static OIDCProvider createProvider(Configuration.Provider providerConfig, OAuthClient client, BasicUser user) throws NoSuchAlgorithmException {

        KeyPair keyPair = Optional.ofNullable(providerConfig.getKeyPair()).orElseGet(() -> {
            try {
                return createKeyPair();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        });


        ProviderConfig config = ProviderConfig.builder()
                .baseUrl(providerConfig.getIssuer())
                .keyPair(keyPair)
                .build();
        OIDCProvider provider = new OIDCProvider(config);
        InMemoryClientRepository clientRepository = new InMemoryClientRepository();
        AuthorizationRepository authorizationRepository = new InMemoryAuthorizationRepository();
        UserRepository userRepository = new InMemoryUserRepository();
        userRepository.saveUser(user);
        GrantRepository grantRepository = new InMemoryGrantRepository();
        clientRepository.addClient(client);
        provider.setClientRepository(clientRepository);
        provider.setAuthorizationRepository(authorizationRepository);
        provider.setGrantRepository(grantRepository);
        provider.setUserRepository(userRepository);
        provider.addClaimsProvider((JWTClaimsSet.Builder claimsBuilder) -> {
            if(providerConfig.getGroup() != null) {
                claimsBuilder.claim("groups", List.of(providerConfig.getGroup()));
            }

        });

        provider.setTokenRequestValidators(List.of(
                new ClientAuthenticationValidator(clientRepository),
                new GrantTypeAcceptableValidator(clientRepository),
                new GrantTypePresentValidator()
        ));
        return provider;
    }

    private static KeyPair createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        return keyPairGenerator.generateKeyPair();
    }

}
