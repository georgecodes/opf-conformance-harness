package com.elevenware.oidc.certification.harness;

import com.elevenware.oidc4j.lib.commons.SecretUtils;
import com.elevenware.oidc4j.lib.grants.GrantTypes;
import com.elevenware.oidc4j.lib.provider.ClaimsProvider;
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
import java.util.Set;


public class ConformanceHarnessApp {

    public static void main(String[] args) throws NoSuchAlgorithmException {

        int port = 9090;
        JavalinJackson jsonMapper = new JavalinJackson();
        jsonMapper.getMapper()
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);
        Javalin javalin = Javalin.create(conf -> {
            conf.jsonMapper(jsonMapper);
        });

        BasicUser user = new BasicUser("George McIntosh", "george.mcintosh@raidiam.com");

        OAuthClient defaultClient = OAuthClient.builder()
                .clientId("conformance_suite")
                .clientSecret(SecretUtils.bcrypt("abcde12345"))
                .grantTypes(Set.of(GrantTypes.AUTHORIZATION_CODE))
                .build();

        OAuthClient adminClient = OAuthClient.builder()
                .clientId("conformance_suite_admin")
                .clientSecret(SecretUtils.bcrypt("abcde12345"))
                .grantTypes(Set.of(GrantTypes.AUTHORIZATION_CODE))
                .build();

        OIDCProvider defaultProvider = createProvider( "https://auth.conformance.elevenware.com", defaultClient, user, (JWTClaimsSet.Builder claimsBuilder) -> {
        });
        OIDCProvider adminProvider = createProvider("https://auth.admin.conformance.elevenware.com", adminClient, user, (JWTClaimsSet.Builder claimsBuilder) -> {
            claimsBuilder.claim("groups", List.of("conformance-admins"));
        });

        ConformanceHarness harness = new ConformanceHarness(javalin, defaultProvider, adminProvider, user);
        javalin.start(port);

    }

    private static OIDCProvider createProvider(String issuer, OAuthClient client, BasicUser user, ClaimsProvider claimsProvider) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        ProviderConfig config = ProviderConfig.builder()
                .baseUrl(issuer)
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
        provider.addClaimsProvider(claimsProvider);

        provider.setTokenRequestValidators(List.of(
                new ClientAuthenticationValidator(clientRepository),
                new GrantTypeAcceptableValidator(clientRepository),
                new GrantTypePresentValidator()
        ));
        return provider;
    }

}
