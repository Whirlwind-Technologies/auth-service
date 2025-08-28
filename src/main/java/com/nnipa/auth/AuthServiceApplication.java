package com.nnipa.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.client.RestTemplate;

/**
 * Main application class for the Authentication Service.
 *
 * This service handles:
 * - User authentication (OAuth 2.0, SAML, OpenID Connect)
 * - Session management and JWT token generation
 * - Multi-factor authentication (MFA)
 * - Password policies and security
 *
 * Integration points:
 * - Tenant Management Service: For tenant context and validation
 * - Authorization Service: Provides roles/permissions after authentication
 * - Notification Service: For MFA codes, password reset emails
 * - API Gateway: Entry point for all authentication requests
 */
@Slf4j
@SpringBootApplication
@EnableCaching
@EnableJpaAuditing
@EnableAsync
@EnableScheduling
@EnableTransactionManagement
@EnableRedisHttpSession
@ConfigurationPropertiesScan("com.nnipa.auth.config")
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
        log.info("===========================================");
        log.info("NNIPA Authentication Service Started");
        log.info("===========================================");
        log.info("Authentication Methods Supported:");
        log.info("- OAuth 2.0 (Google, GitHub, Microsoft)");
        log.info("- SAML 2.0");
        log.info("- OpenID Connect");
        log.info("- JWT Token Authentication");
        log.info("- Basic Username/Password");
        log.info("===========================================");
        log.info("Security Features:");
        log.info("- Multi-Factor Authentication (TOTP, SMS)");
        log.info("- Password Policies & Strength Validation");
        log.info("- Session Management with Redis");
        log.info("- Rate Limiting for Login Attempts");
        log.info("- Token Refresh Mechanism");
        log.info("===========================================");
        log.info("Integration Points:");
        log.info("- Tenant Service: Tenant validation");
        log.info("- Authorization Service: Role/permission assignment");
        log.info("- Notification Service: MFA & password reset");
        log.info("- API Gateway: Request routing & rate limiting");
        log.info("===========================================");
    }

    /**
     * Password encoder bean using BCrypt algorithm.
     * Provides strong password hashing for security.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * RestTemplate for inter-service communication.
     * Used to communicate with tenant, authorization, and notification services.
     */
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}