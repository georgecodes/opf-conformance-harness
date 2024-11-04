package com.elevenware.oidc.certification.harness;

import com.elevenware.oidc4j.lib.commons.Lifecycle;
import com.elevenware.oidc4j.lib.provider.OIDCProvider;
import com.elevenware.oidc4j.lib.provider.model.OauthUser;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import io.javalin.Javalin;
import io.javalin.json.JavalinJackson;

import java.net.URI;

public class ConformanceHarness {

    private final OIDCProvider provider;
    private final int port;
    private final String sub;
    private Javalin javalin;

    public ConformanceHarness(Javalin javalin, OIDCProvider provider, String sub, OauthUser user) {
        this.provider = provider;
        this.sub = sub;
        String baseUrl = provider.getConfig().getBaseUrl();
        URI base = URI.create(baseUrl);
        this.port = base.getPort();
        this.javalin = javalin;

        mount(javalin, new HarnessOidcController(provider, user));

    }

    public void mount(Javalin javalin, HarnessOidcController controller) {
        javalin.get(sub("/.well-known/openid-configuration"), controller::discovery);
        javalin.post(sub("/token"), controller::token);
        javalin.get(sub("/authorize"), controller::frontChannelAuthorize);
        javalin.get(sub("/jwks"), controller::jwks);
        javalin.get(sub("/userinfo"), controller::userinfo);
    }

    private String sub(String path) {
        return sub + path;
    }

}