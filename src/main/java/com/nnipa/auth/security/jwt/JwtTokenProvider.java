package com.nnipa.auth.security.jwt;

import com.nnipa.auth.config.SecurityProperties;
import com.nnipa.auth.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * JWT token provider - fixed version with correlation ID support
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final SecurityProperties securityProperties;

    /**
     * Generate access token with correlation ID.
     */
    public String generateAccessToken(User user, String correlationId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + securityProperties.getJwt().getAccessTokenExpiration());

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId().toString());
        claims.put("tenantId", user.getTenantId().toString());
        claims.put("email", user.getEmail());
        claims.put("username", user.getUsername());
        claims.put("emailVerified", user.getEmailVerified());
        claims.put("mfaEnabled", user.getMfaEnabled());
        claims.put("authProvider", user.getPrimaryAuthProvider().toString());
        claims.put("type", "access");
        claims.put("correlationId", correlationId);

        return Jwts.builder()
                .claims(claims)
                .subject(user.getId().toString())
                .issuer(securityProperties.getJwt().getIssuer())
                .issuedAt(now)
                .expiration(expiryDate)
                .id(UUID.randomUUID().toString())
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();
    }

    /**
     * Generate access token without correlation ID (backward compatibility).
     */
    public String generateAccessToken(User user) {
        return generateAccessToken(user, UUID.randomUUID().toString());
    }

    /**
     * Generate MFA token with correlation ID.
     */
    public String generateMfaToken(User user, String correlationId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + 300000); // 5 minutes

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId().toString());
        claims.put("tenantId", user.getTenantId().toString());
        claims.put("type", "mfa");
        claims.put("purpose", "mfa_verification");
        claims.put("correlationId", correlationId);

        return Jwts.builder()
                .claims(claims)
                .subject(user.getId().toString())
                .issuer(securityProperties.getJwt().getIssuer())
                .issuedAt(now)
                .expiration(expiryDate)
                .id(UUID.randomUUID().toString())
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();
    }

    /**
     * Generate refresh token for authenticated user.
     */
    public String generateRefreshToken(User user) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + securityProperties.getJwt().getRefreshTokenExpiration());

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId().toString());
        claims.put("tenantId", user.getTenantId().toString());
        claims.put("type", "refresh");

        return Jwts.builder()
                .claims(claims)
                .subject(user.getId().toString())
                .issuer(securityProperties.getJwt().getIssuer())
                .issuedAt(now)
                .expiration(expiryDate)
                .id(UUID.randomUUID().toString())
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();
    }

    // ... rest of the methods remain the same ...

    public UUID getUserIdFromToken(String token) {
        Claims claims = getClaims(token);
        return UUID.fromString(claims.get("userId", String.class));
    }

    public UUID getTenantIdFromToken(String token) {
        Claims claims = getClaims(token);
        return UUID.fromString(claims.get("tenantId", String.class));
    }

    public String getUsernameFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get("username", String.class);
    }

    public String getJtiFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.getId();
    }

    public String getTokenType(String token) {
        Claims claims = getClaims(token);
        return claims.get("type", String.class);
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (SecurityException ex) {
            log.error("Invalid JWT signature: {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token: {}", ex.getMessage());
        } catch (ExpiredJwtException ex) {
            log.debug("JWT token is expired: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            log.error("JWT token is unsupported: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty: {}", ex.getMessage());
        }
        return false;
    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = getClaims(token);
            return claims.getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        } catch (Exception e) {
            log.error("Error checking token expiration: {}", e.getMessage());
            return true;
        }
    }

    public Date getExpirationDateFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.getExpiration();
    }

    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = securityProperties.getJwt().getSecret().getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public long getAccessTokenExpirationInSeconds() {
        return securityProperties.getJwt().getAccessTokenExpiration() / 1000;
    }

    public long getRefreshTokenExpirationInSeconds() {
        return securityProperties.getJwt().getRefreshTokenExpiration() / 1000;
    }
}