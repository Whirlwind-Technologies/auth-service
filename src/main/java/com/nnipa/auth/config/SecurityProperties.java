package com.nnipa.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Security configuration properties for the Authentication Service.
 */
@Data
@Component
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    private Jwt jwt = new Jwt();
    private Password password = new Password();
    private Mfa mfa = new Mfa();
    private Session session = new Session();

    @Data
    public static class Jwt {
        private String secret;
        private Long accessTokenExpiration = 900000L; // 15 minutes
        private Long refreshTokenExpiration = 604800000L; // 7 days
        private String issuer = "https://nnipa.cloud";
    }

    @Data
    public static class Password {
        private Policy policy = new Policy();

        @Data
        public static class Policy {
            private Integer minLength = 12;
            private Boolean requireUppercase = true;
            private Boolean requireLowercase = true;
            private Boolean requireDigit = true;
            private Boolean requireSpecial = true;
            private Integer maxAgeDays = 90;
            private Integer historyCount = 5;
        }
    }

    @Data
    public static class Mfa {
        private Boolean enabled = true;
        private String issuer = "NNIPA Platform";
        private Totp totp = new Totp();
        private Sms sms = new Sms();

        @Data
        public static class Totp {
            private Integer timeStep = 30;
            private Integer window = 3;
            private Integer digits = 6;
        }

        @Data
        public static class Sms {
            private String provider = "twilio";
            private Twilio twilio = new Twilio();

            @Data
            public static class Twilio {
                private String accountSid;
                private String authToken;
                private String fromNumber;
            }
        }
    }

    @Data
    public static class Session {
        private Integer timeout = 1800; // 30 minutes
        private Integer maxConcurrent = 3;
        private Boolean rememberMeEnabled = true;
        private Integer rememberMeDuration = 1209600; // 14 days
    }
}