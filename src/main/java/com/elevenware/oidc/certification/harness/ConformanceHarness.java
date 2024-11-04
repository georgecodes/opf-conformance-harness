package com.elevenware.oidc.certification.harness;

import com.elevenware.oidc4j.lib.commons.Lifecycle;
import com.elevenware.oidc4j.lib.provider.OIDCProvider;
import com.elevenware.oidc4j.lib.provider.model.OauthUser;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.json.JavalinJackson;
import io.javalin.router.Endpoint;

import java.net.URI;

public class ConformanceHarness {

    private final OIDCProvider defaultProvider;
    private final OIDCProvider adminProvider;

    public ConformanceHarness(Javalin javalin, OIDCProvider defaultProvider, OIDCProvider adminProvider, OauthUser user) {
        this.defaultProvider = defaultProvider;
        this.adminProvider = adminProvider;
        mount(javalin, new HarnessOidcController(defaultProvider, adminProvider, user));
    }

    public void mount(Javalin javalin, HarnessOidcController controller) {
        javalin.before("/*", ctx -> {
            ctx.attribute("PROVIDER", providerFor(ctx));
        });
        javalin.get("/.well-known/openid-configuration", controller::discovery);
        javalin.post("/token", controller::token);
        javalin.get("/authorize", controller::frontChannelAuthorize);
        javalin.get("/jwks", controller::jwks);
        javalin.get("/userinfo", controller::userinfo);
    }

    private OIDCProvider providerFor(Context context) {
        String header = context.header("X-Admin");
        if(header == null) {
            return defaultProvider;
        }
        if (header.equals("true")) {
            return adminProvider;
        }
        return defaultProvider;
    }

}