package com.nnipa.auth.service;

import com.nnipa.auth.dto.request.LoginRequest;
import com.nnipa.auth.dto.request.RefreshTokenRequest;
import com.nnipa.auth.dto.request.RegisterRequest;
import com.nnipa.auth.dto.response.AuthResponse;
import com.nnipa.auth.dto.response.TokenResponse;
import com.nnipa.auth.dto.response.UserInfoResponse;
import com.nnipa.auth.entity.*;
import com.nnipa.auth.enums.*;
import com.nnipa.auth.exception.AuthenticationException;
import com.nnipa.auth.exception.InvalidTokenException;
import com.nnipa.auth.integration.NotificationServiceClient;
import com.nnipa.auth.repository.*;
import com.nnipa.auth.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Core authentication service handling login, registration, and token management.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final UserCredentialRepository credentialRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final LoginAttemptRepository loginAttemptRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final SessionService sessionService;
    private final RateLimitingService rateLimitingService;
    private final AuditService auditService;
    private final NotificationServiceClient notificationService;
    private final MfaService mfaService;

    /**
     * Authenticate user with username/password.
     */
    @Transactional
    public AuthResponse authenticate(LoginRequest request, String ipAddress, String userAgent) {
        log.debug("Authenticating user: {}", request.getUsername());

        // Check rate limiting
        if (rateLimitingService.isLoginBlocked(request.getUsername(), ipAddress)) {
            auditService.logAuthenticationEvent(
                    null, null, AuditEventType.LOGIN_FAILURE, false,
                    ipAddress, userAgent, Map.of("reason", "rate_limited")
            );
            throw new AuthenticationException("Too many failed login attempts. Please try again later.");
        }

        // Find user
        User user = userRepository.findByUsernameOrEmail(request.getUsername(), request.getUsername())
                .orElseThrow(() -> {
                    recordFailedLogin(null, request.getUsername(), ipAddress, userAgent, "User not found");
                    return new AuthenticationException("Invalid credentials");
                });

        // Check for suspicious activity
        detectSuspiciousActivity(user, ipAddress, userAgent);

        // Validate user status
        validateUserStatus(user);

        // Verify password
        UserCredential credential = user.getCredential();
        if (credential == null || !passwordEncoder.matches(request.getPassword(), credential.getPasswordHash())) {
            handleFailedLogin(user, credential, ipAddress, userAgent);
            auditService.logAuthenticationEvent(
                    user.getId(), user.getTenantId(), AuditEventType.LOGIN_FAILURE,
                    false, ipAddress, userAgent, Map.of("reason", "invalid_password")
            );
            throw new AuthenticationException("Invalid credentials");
        }

        // Check password expiration
        if (credential.isPasswordExpired() || credential.getMustChangePassword()) {
            auditService.logAuthenticationEvent(
                    user.getId(), user.getTenantId(), AuditEventType.LOGIN_FAILURE,
                    false, ipAddress, userAgent, Map.of("reason", "password_expired")
            );
            throw new AuthenticationException("Password has expired. Please reset your password.");
        }

        // Check for new device
        boolean isNewDevice = checkNewDevice(user, userAgent, ipAddress);

        // Check if MFA is required
        if (user.getMfaEnabled() || isNewDevice) {
            log.debug("MFA required for user: {}", user.getId());
            String mfaToken = jwtTokenProvider.generateMfaToken(user);

            // Send MFA code if SMS/Email
            if (mfaService.getUserMfaDevices(user.getId()).stream()
                    .anyMatch(d -> d.getType() == MfaType.SMS && d.getEnabled())) {
                mfaService.sendSmsCode(user.getId());
            }

            return AuthResponse.builder()
                    .mfaRequired(true)
                    .mfaToken(mfaToken)
                    .build();
        }

        // Generate tokens
        String accessToken = jwtTokenProvider.generateAccessToken(user);
        String refreshToken = createRefreshToken(user, request.getDeviceInfo(), ipAddress, userAgent);

        // Update login info
        updateLoginInfo(user, credential, ipAddress);

        // Log successful login
        auditService.logAuthenticationEvent(
                user.getId(), user.getTenantId(), AuditEventType.LOGIN_SUCCESS,
                true, ipAddress, userAgent, Map.of("method", "password")
        );

        // Send new device notification if needed
        if (isNewDevice) {
            notificationService.sendNewDeviceLoginNotification(user, userAgent, ipAddress);
        }

        // Create session
        createUserSession(user, refreshToken, ipAddress, userAgent, request.getDeviceInfo());

        return buildAuthResponse(user, accessToken, refreshToken);
    }

    /**
     * Register new user.
     */
    @Transactional
    public AuthResponse register(RegisterRequest request, String ipAddress) {
        log.info("Registering new user: {}", request.getEmail());

        // Validate passwords match
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new AuthenticationException("Passwords do not match");
        }

        // Check if user already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AuthenticationException("Email already registered");
        }

        if (request.getUsername() != null && userRepository.existsByUsername(request.getUsername())) {
            throw new AuthenticationException("Username already taken");
        }

        // Get tenant ID (would integrate with tenant-service here)
        UUID tenantId = getTenantIdFromCode(request.getTenantCode());

        // Create user
        User user = User.builder()
                .tenantId(tenantId)
                .username(request.getUsername())
                .email(request.getEmail())
                .emailVerified(false)
                .phoneNumber(request.getPhoneNumber())
                .phoneVerified(false)
                .status(UserStatus.PENDING_ACTIVATION)
                .primaryAuthProvider(AuthProvider.LOCAL)
                .mfaEnabled(request.getEnableMfa())
                .build();

        user = userRepository.save(user);

        // Create credentials
        UserCredential credential = UserCredential.builder()
                .user(user)
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .passwordExpiresAt(LocalDateTime.now().plusDays(90))
                .mustChangePassword(false)
                .failedAttempts(0)
                .build();

        credentialRepository.save(credential);

        // Generate activation token (would send via notification-service)
        String activationToken = UUID.randomUUID().toString();
        user.setActivationToken(activationToken);
        user.setActivationTokenExpiresAt(LocalDateTime.now().plusDays(7));
        userRepository.save(user);

        // Generate tokens for immediate login (optional)
        String accessToken = jwtTokenProvider.generateAccessToken(user);
        String refreshToken = createRefreshToken(user, null, ipAddress, null);

        return buildAuthResponse(user, accessToken, refreshToken);
    }

    /**
     * Complete MFA authentication.
     */
    @Transactional
    public AuthResponse completeMfaAuthentication(String mfaToken, String code, MfaType type) {
        log.debug("Completing MFA authentication");

        // Validate MFA token
        if (!jwtTokenProvider.validateToken(mfaToken)) {
            throw new InvalidTokenException("Invalid MFA token");
        }

        UUID userId = jwtTokenProvider.getUserIdFromToken(mfaToken);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthenticationException("User not found"));

        // Verify MFA code
        boolean valid = mfaService.verifyMfaCode(userId, code, type);

        if (!valid) {
            auditService.logAuthenticationEvent(
                    userId, user.getTenantId(), AuditEventType.LOGIN_FAILURE,
                    false, null, null, Map.of("reason", "invalid_mfa_code")
            );
            throw new AuthenticationException("Invalid MFA code");
        }

        // Generate tokens
        String accessToken = jwtTokenProvider.generateAccessToken(user);
        String refreshToken = createRefreshToken(user, null, null, null);

        // Log successful MFA authentication
        auditService.logAuthenticationEvent(
                userId, user.getTenantId(), AuditEventType.LOGIN_SUCCESS,
                true, null, null, Map.of("method", "mfa", "mfa_type", type.toString())
        );

        return buildAuthResponse(user, accessToken, refreshToken);
    }


    /**
     * Get user info.
     */
    public UserInfoResponse getUserInfo(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthenticationException("User not found"));

        return UserInfoResponse.builder()
                .id(user.getId())
                .tenantId(user.getTenantId())
                .externalUserId(user.getExternalUserId())
                .username(user.getUsername())
                .email(user.getEmail())
                .emailVerified(user.getEmailVerified())
                .phoneNumber(user.getPhoneNumber())
                .phoneVerified(user.getPhoneVerified())
                .status(user.getStatus())
                .primaryAuthProvider(user.getPrimaryAuthProvider())
                .mfaEnabled(user.getMfaEnabled())
                .lastLoginAt(user.getLastLoginAt())
                .linkedProviders(user.getOauth2Accounts().stream()
                        .map(account -> account.getProvider().toString())
                        .collect(Collectors.toSet()))
                .createdAt(user.getCreatedAt())
                .build();
    }

    /**
     * Activate user account with activation token.
     */
    @Transactional
    public void activateAccount(String activationToken) {
        log.info("Activating account with token");

        User user = userRepository.findByActivationToken(activationToken)
                .orElseThrow(() -> new AuthenticationException("Invalid activation token"));

        // Check token expiration
        if (user.getActivationTokenExpiresAt() != null &&
                user.getActivationTokenExpiresAt().isBefore(LocalDateTime.now())) {
            throw new AuthenticationException("Activation token has expired");
        }

        // Activate user
        user.setStatus(UserStatus.ACTIVE);
        user.setEmailVerified(true);
        user.setActivationToken(null);
        user.setActivationTokenExpiresAt(null);
        userRepository.save(user);

        // Log activation
        auditService.logAuthenticationEvent(
                user.getId(), user.getTenantId(), AuditEventType.ACCOUNT_ACTIVATED,
                true, null, null, null
        );

        log.info("Account activated for user: {}", user.getId());
    }

    /**
     * Refresh access token using refresh token.
     */
    @Transactional
    public TokenResponse refreshToken(RefreshTokenRequest request) {
        log.debug("Refreshing token");

        // Validate refresh token format
        if (!jwtTokenProvider.validateToken(request.getRefreshToken())) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        // Check token type
        if (!"refresh".equals(jwtTokenProvider.getTokenType(request.getRefreshToken()))) {
            throw new InvalidTokenException("Token is not a refresh token");
        }

        // Find refresh token in database
        RefreshToken refreshToken = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        // Validate refresh token
        if (!refreshToken.isValid()) {
            throw new InvalidTokenException("Refresh token is invalid or expired");
        }

        User user = refreshToken.getUser();
        validateUserStatus(user);

        // Generate new access token
        String newAccessToken = jwtTokenProvider.generateAccessToken(user);

        // Optionally rotate refresh token
        String newRefreshToken = rotateRefreshToken(refreshToken);

        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken != null ? newRefreshToken : request.getRefreshToken())
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getAccessTokenExpirationInSeconds())
                .refreshExpiresIn(jwtTokenProvider.getRefreshTokenExpirationInSeconds())
                .build();
    }

    /**
     * Logout user and invalidate tokens.
     */
    @Transactional
    @CacheEvict(value = {"userAuth", "sessions"}, key = "#userId")
    public void logout(UUID userId, String refreshToken, boolean logoutFromAllDevices) {
        log.info("Logging out user: {}", userId);

        if (logoutFromAllDevices) {
            // Revoke all refresh tokens
            refreshTokenRepository.revokeAllUserTokens(userId, "User logged out from all devices");
            sessionService.invalidateAllUserSessions(userId);
        } else if (refreshToken != null) {
            // Revoke specific refresh token
            refreshTokenRepository.findByToken(refreshToken)
                    .ifPresent(token -> {
                        token.revoke("User logged out");
                        refreshTokenRepository.save(token);
                    });
        }

        // Add current access token to blacklist (handled by JWT filter)
    }

    /**
     * Validate token.
     */
    @Cacheable(value = "tokenValidation", key = "#token")
    public boolean validateToken(String token) {
        return jwtTokenProvider.validateToken(token) && !sessionService.isTokenBlacklisted(token);
    }

    // Private helper methods

    private void validateUserStatus(User user) {
        if (user.getStatus() == UserStatus.DELETED) {
            throw new AuthenticationException("Account has been deleted");
        }
        if (user.getStatus() == UserStatus.SUSPENDED) {
            throw new AuthenticationException("Account is suspended");
        }
        if (user.getStatus() == UserStatus.EXPIRED) {
            throw new AuthenticationException("Account has expired");
        }
        if (user.isAccountLocked()) {
            throw new AuthenticationException("Account is temporarily locked until " + user.getLockedUntil());
        }
        if (user.getStatus() == UserStatus.PENDING_ACTIVATION) {
            throw new AuthenticationException("Account is not activated. Please check your email.");
        }
    }

    private void handleFailedLogin(User user, UserCredential credential, String ipAddress, String userAgent) {
        credential.incrementFailedAttempts();
        credentialRepository.save(credential);

        // Lock account after 5 failed attempts
        if (credential.getFailedAttempts() >= 5) {
            user.setLockedUntil(LocalDateTime.now().plusMinutes(15));
            user.setLockReason("Too many failed login attempts");
            userRepository.save(user);
        }

        recordFailedLogin(user, user.getUsername(), ipAddress, userAgent, "Invalid password");
        rateLimitingService.recordFailedAttempt(user.getUsername(), ipAddress);
    }

    private void updateLoginInfo(User user, UserCredential credential, String ipAddress) {
        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginIp(ipAddress);
        userRepository.save(user);

        credential.resetFailedAttempts();
        credentialRepository.save(credential);

        rateLimitingService.resetFailedAttempts(user.getUsername());
    }

    private String createRefreshToken(User user, String deviceInfo, String ipAddress, String userAgent) {
        String tokenValue = jwtTokenProvider.generateRefreshToken(user);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(tokenValue)
                .deviceInfo(deviceInfo)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .expiresAt(LocalDateTime.now().plusDays(7))
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshToken);
        return tokenValue;
    }

    private String rotateRefreshToken(RefreshToken oldToken) {
        // Mark old token as replaced
        oldToken.setRevoked(true);
        oldToken.setRevokedAt(LocalDateTime.now());
        oldToken.setRevokedReason("Token rotated");

        // Create new refresh token
        String newTokenValue = jwtTokenProvider.generateRefreshToken(oldToken.getUser());
        oldToken.setReplacedByToken(newTokenValue);
        refreshTokenRepository.save(oldToken);

        RefreshToken newToken = RefreshToken.builder()
                .user(oldToken.getUser())
                .token(newTokenValue)
                .deviceInfo(oldToken.getDeviceInfo())
                .ipAddress(oldToken.getIpAddress())
                .userAgent(oldToken.getUserAgent())
                .expiresAt(LocalDateTime.now().plusDays(7))
                .revoked(false)
                .build();

        refreshTokenRepository.save(newToken);
        return newTokenValue;
    }

    private void recordSuccessfulLogin(User user, String ipAddress, String userAgent) {
        LoginAttempt attempt = LoginAttempt.builder()
                .user(user)
                .username(user.getUsername())
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .success(true)
                .authProvider(user.getPrimaryAuthProvider())
                .build();

        loginAttemptRepository.save(attempt);
    }

    private void recordFailedLogin(User user, String username, String ipAddress, String userAgent, String reason) {
        LoginAttempt attempt = LoginAttempt.builder()
                .user(user)
                .username(username)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .success(false)
                .failureReason(reason)
                .authProvider(AuthProvider.LOCAL)
                .build();

        loginAttemptRepository.save(attempt);
    }

    private AuthResponse buildAuthResponse(User user, String accessToken, String refreshToken) {
        UserInfoResponse userInfo = UserInfoResponse.builder()
                .id(user.getId())
                .tenantId(user.getTenantId())
                .externalUserId(user.getExternalUserId())
                .username(user.getUsername())
                .email(user.getEmail())
                .emailVerified(user.getEmailVerified())
                .phoneNumber(user.getPhoneNumber())
                .phoneVerified(user.getPhoneVerified())
                .status(user.getStatus())
                .primaryAuthProvider(user.getPrimaryAuthProvider())
                .mfaEnabled(user.getMfaEnabled())
                .lastLoginAt(user.getLastLoginAt())
                .linkedProviders(user.getOauth2Accounts().stream()
                        .map(account -> account.getProvider().toString())
                        .collect(Collectors.toSet()))
                .createdAt(user.getCreatedAt())
                .build();

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getAccessTokenExpirationInSeconds())
                .refreshExpiresIn(jwtTokenProvider.getRefreshTokenExpirationInSeconds())
                .user(userInfo)
                .mfaRequired(false)
                .authenticatedAt(LocalDateTime.now())
                .build();
    }

    private UUID getTenantIdFromCode(String tenantCode) {
        // TODO: Integrate with tenant-management-service to get tenant ID
        // For now, return a placeholder UUID
        return UUID.randomUUID();
    }

    /**
     * Check if username exists.
     */
    public boolean isUsernameExists(String username) {
        return userRepository.existsByUsername(username);
    }

    /**
     * Check if email exists.
     */
    public boolean isEmailExists(String email) {
        return userRepository.existsByEmail(email);
    }

    // Private helper methods

    private void detectSuspiciousActivity(User user, String ipAddress, String userAgent) {
        // Check for unusual login patterns
        long recentFailures = loginAttemptRepository.countRecentFailedAttempts(
                user.getUsername(), LocalDateTime.now().minusHours(1)
        );

        if (recentFailures > 10) {
            auditService.logSecurityEvent(
                    user.getId(), SecurityEventType.BRUTE_FORCE_ATTACK,
                    "Multiple failed login attempts detected", ipAddress,
                    Map.of("failures", recentFailures)
            );
        }

        // Check for geo-location anomaly (simplified)
        if (user.getLastLoginIp() != null && !user.getLastLoginIp().equals(ipAddress)) {
            // In production, would check actual geo-location distance
            log.warn("Login from different IP for user: {}", user.getId());
        }
    }

    private boolean checkNewDevice(User user, String userAgent, String ipAddress) {
        // Simplified device check - in production would use device fingerprinting
        return user.getLastLoginAt() != null &&
                (user.getLastLoginIp() == null || !user.getLastLoginIp().equals(ipAddress));
    }

    private void createUserSession(User user, String refreshToken, String ipAddress,
                                   String userAgent, String deviceInfo) {
        // Create session tracking (simplified)
        sessionService.createSession(
                user.getId(),
                refreshToken,
                Map.of(
                        "ipAddress", ipAddress != null ? ipAddress : "",
                        "userAgent", userAgent != null ? userAgent : "",
                        "deviceInfo", deviceInfo != null ? deviceInfo : "",
                        "createdAt", LocalDateTime.now()
                ),
                Duration.ofDays(7)
        );
    }
}