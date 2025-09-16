package com.nnipa.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.Scopes;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;

/**
 * OpenAPI/Swagger configuration for the Authentication Service.
 */
@Configuration
public class OpenApiConfig {

    @Value("${server.servlet.context-path:}")
    private String contextPath;

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(apiInfo())
                .servers(servers())
                .components(components())
                .security(Arrays.asList(
                        new SecurityRequirement().addList("bearerAuth"),
                        new SecurityRequirement().addList("basicAuth"),
                        new SecurityRequirement().addList("oauth2")
                ));
    }

    private Info apiInfo() {
        return new Info()
                .title("Authentication Service API")
                .description("NNIPA Platform Authentication Service - Handles OAuth 2.0, SAML, " +
                        "OpenID Connect, JWT token generation, MFA, and password policies.")
                .version("1.0.0")
                .contact(new Contact()
                        .name("NNIPA Platform Team")
                        .email("auth-support@nnipa.cloud")
                        .url("https://nnipa.cloud"))
                .license(new License()
                        .name("Proprietary")
                        .url("https://nnipa.cloud/license"));
    }

    private List<Server> servers() {
        String basePath = StringUtils.hasText(contextPath) ? contextPath : "";

        Server localServer = new Server()
                .url("http://localhost:4002" + basePath)
                .description("Local Development Server");

        Server devServer = new Server()
                .url("https://dev.nnipa.cloud" + basePath)
                .description("Development Server");

        Server stagingServer = new Server()
                .url("https://staging.nnipa.cloud" + basePath)
                .description("Staging Server");

        Server prodServer = new Server()
                .url("https://api.nnipa.cloud" + basePath)
                .description("Production Server");

        return Arrays.asList(localServer, devServer, stagingServer, prodServer);
    }

    private Components components() {
        String basePath = StringUtils.hasText(contextPath) ? contextPath : "";

        return new Components()
                .addSecuritySchemes("bearerAuth",
                        new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("JWT Bearer Token Authentication"))
                .addSecuritySchemes("basicAuth",
                        new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("basic")
                                .description("Basic Authentication"))
                .addSecuritySchemes("oauth2",
                        new SecurityScheme()
                                .type(SecurityScheme.Type.OAUTH2)
                                .description("OAuth 2.0 Authentication")
                                .flows(new OAuthFlows()
                                        .authorizationCode(new OAuthFlow()
                                                .authorizationUrl("http://localhost:4002" + basePath + "/oauth/authorize")
                                                .tokenUrl("http://localhost:4002" + basePath + "/oauth/token")
                                                .scopes(new Scopes()
                                                        .addString("read", "Read access")
                                                        .addString("write", "Write access")))));
    }
}