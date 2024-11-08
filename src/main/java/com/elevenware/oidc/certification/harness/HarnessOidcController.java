package com.elevenware.oidc.certification.harness;

import com.elevenware.oidc4j.lib.grants.GrantType;
import com.elevenware.oidc4j.lib.grants.GrantTypes;
import com.elevenware.oidc4j.lib.provider.OAuthException;
import com.elevenware.oidc4j.lib.provider.OIDCProvider;
import com.elevenware.oidc4j.lib.provider.model.AuthorizationInitiationRequest;
import com.elevenware.oidc4j.lib.provider.model.AuthorizationRequest;
import com.elevenware.oidc4j.lib.provider.model.ClientSecretPost;
import com.elevenware.oidc4j.lib.provider.model.OauthUser;
import com.elevenware.oidc4j.lib.provider.model.TokenRequest;
import com.elevenware.oidc4j.lib.provider.model.TokenResponse;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import io.javalin.http.Context;
import io.javalin.http.HttpStatus;
import org.apache.commons.lang3.RandomStringUtils;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class HarnessOidcController {

    private final OIDCProvider defaultProvider;
    private final OIDCProvider adminProvider;

    public HarnessOidcController(OIDCProvider defaultProvider, OIDCProvider adminProvider) {
        this.defaultProvider = defaultProvider;
        this.adminProvider = adminProvider;
    }

    public void discovery(Context context) {
        OIDCProvider provider = context.attribute("PROVIDER");
        context.json(provider.getDiscoveryDocument());
    }

    public void jwks(Context context) {
        OIDCProvider provider = context.attribute("PROVIDER");
        KeyPair keyPair = provider.getConfig().getKeyPair();
        JWK jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
        JWKSet jwkSet = new JWKSet(jwk);
        context.json(jwkSet.toPublicJWKSet().toJSONObject());
    }

    public void userinfo(Context context) {
        OauthUser user = context.attribute("USER");
        context.json(Map.of(
                "name", user.getName(),
                "email", user.getEmail()
        ));
    }

    public void token(Context context) {
        OIDCProvider provider = context.attribute("PROVIDER");
        ClientSecretPost clientAuth = getClientSecretPost(context);
        String grantTypeId = context.formParam("grant_type");
        Map<String, List<String>> params = context.formParamMap();
        GrantType grantType = GrantTypes.byName(grantTypeId);
        TokenRequest.Builder tokenRequestBuilder = TokenRequest.builder()
                .grantType(grantType)
                .clientAuthentication(clientAuth);
        if(grantType == GrantTypes.CLIENT_CREDENTIALS) {

        }
        if(grantType == GrantTypes.AUTHORIZATION_CODE) {
            String redirectUri = params.get("redirect_uri").get(0);
            String code = params.get("code").get(0);
            tokenRequestBuilder.redirectUri(redirectUri).code(code);

        }
        TokenRequest tokenRequest = tokenRequestBuilder.build();
        try {
            TokenResponse tokenResponse = provider.requestToken(tokenRequest);
            context.json(tokenResponse);
        } catch (OAuthException e) {
            context.status(HttpStatus.BAD_REQUEST);
        }
    }

    public void frontChannelAuthorize(Context context) {
        OIDCProvider provider = context.attribute("PROVIDER");
        OauthUser user = context.attribute("USER");
        Map<String, List<String>> params = context.queryParamMap();
        String authCode = RandomStringUtils.randomAlphanumeric(16);
        AuthorizationInitiationRequest authorizationRequest = AuthorizationInitiationRequest.builder()
                .clientId(params.get("client_id").get(0))
                .redirectUri(params.get("redirect_uri").get(0))
                .responseType(params.get("response_type").get(0))
                .scope(scopesFrom(params.get("scope").get(0)))
                .state(params.get("state").get(0))
                .nonce(params.get("nonce").get(0))
                .code(authCode)
                .user(user)
                .build();
        provider.registerAuthorizationRequest(authorizationRequest);
        StringBuilder redirect = new StringBuilder().append(authorizationRequest.getRedirectUri())
                .append("?code=").append(authCode)
                .append("&state=").append(authorizationRequest.getState());
        context.redirect(redirect.toString());
    }

    private Set<String> scopesFrom(String scope) {
        String[] scopes = scope.split(" ");
        return Set.of(scopes);
    }

    private ClientSecretPost getClientSecretPost(Context context) {
        OIDCProvider provider = context.attribute("PROVIDER");
        String clientAuth = context.header("Authorization");
        String clientId = context.formParam("client_id");
        String clientSecret = context.formParam("client_secret");
        if(clientAuth != null) {
            // client secret basic
            String[] parts = clientAuth.split("Basic ");
            if(parts.length != 2) {
                context.status(HttpStatus.BAD_REQUEST);
                return null;
            }
            String[] creds = new String(Base64.getDecoder().decode(parts[1])).split(":");
            clientId = creds[0];
            clientSecret = creds[1];
        }
        return new ClientSecretPost(clientId, clientSecret);
    }


}
