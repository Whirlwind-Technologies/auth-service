package com.nnipa.auth.service;

import com.nnipa.auth.client.TenantGrpcClient;
import com.nnipa.auth.dto.request.LoginRequest;
import com.nnipa.auth.dto.request.RefreshTokenRequest;
import com.nnipa.auth.dto.request.RegisterRequest;
import com.nnipa.auth.dto.response.AuthResponse;
import com.nnipa.auth.dto.response.TokenResponse;
import com.nnipa.auth.dto.response.UserInfoResponse;
import com.nnipa.auth.entity.*;
import com.nnipa.auth.enums.*;
import com.nnipa.auth.event.AuthEventPublisher;
import com.nnipa.auth.exception.AuthenticationException;
import com.nnipa.auth.exception.InvalidTokenException;
import com.nnipa.auth.repository.*;
import com.nnipa.auth.security.jwt.JwtTokenProvider;
import com.nnipa.auth.util.CorrelationIdUtil;
import com.nnipa.proto.auth.AuthenticationEvent;
import com.nnipa.proto.tenant.CreateTenantCommand;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Production-ready authentication service with enhanced security features.
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
    private final MfaService mfaService;
    private final AuthEventPublisher authEventPublisher;
    private final TenantGrpcClient tenantGrpcClient;
    private final KafkaTemplate<String, byte[]> kafkaTemplate;
    private final SecurityEventService securityEventService;
    private final TokenBlacklistService tokenBlacklistService;
    private final PasswordPolicyService passwordPolicyService;
    private final AccountLockoutService accountLockoutService;
    private final CorrelationIdUtil correlationIdUtil;
    private final TemporaryTenantTracker temporaryTenantTracker;

    /**
     * Authenticate user with production security features.
     */
    @Transactional
    public AuthResponse authenticate(LoginRequest request, String ipAddress, String userAgent) {
        String correlationId = getCorrelationId();
        log.debug("Authenticating user: {} with correlation ID: {}", request.getUsername(), correlationId);

        // Check account lockout status
        if (accountLockoutService.isAccountLocked(request.getUsername())) {
            logSecurityEvent(SecurityEventType.ACCOUNT_LOCKED, request.getUsername(), ipAddress, correlationId);
            throw new AuthenticationException("Account is locked. Please contact support.");
        }

        // Check rate limiting (moved to API Gateway but kept as backup)
        if (rateLimitingService.isLoginBlocked(request.getUsername(), ipAddress)) {
            auditService.logAuthenticationEvent(
                    null, null, AuditEventType.LOGIN_FAILURE, false,
                    ipAddress, userAgent, Map.of(
                            "reason", "rate_limited",
                            "correlation_id", correlationId
                    )
            );
            publishAuthenticationEvent(null, null, "LOGIN_RATE_LIMITED", correlationId);
            throw new AuthenticationException("Too many failed login attempts. Please try again later.");
        }

        // Find user
        User user = userRepository.findByUsernameOrEmail(request.getUsername(), request.getUsername())
                .orElseThrow(() -> {
                    rateLimitingService.recordFailedAttempt(request.getUsername(), ipAddress);
                    accountLockoutService.recordFailedAttempt(request.getUsername());
                    logSecurityEvent(SecurityEventType.INVALID_CREDENTIALS, request.getUsername(), ipAddress, correlationId);
                    return new AuthenticationException("Invalid credentials");
                });

        // Check user status
        validateUserStatus(user, correlationId);

        // Verify password
        UserCredential credential = credentialRepository.findByUserIdAndType(user.getId(), CredentialType.PASSWORD)
                .orElseThrow(() -> new AuthenticationException("No password configured"));

        if (!passwordEncoder.matches(request.getPassword(), credential.getCredentialValue())) {
            handleFailedAuthentication(user, request.getUsername(), ipAddress, correlationId);
            throw new AuthenticationException("Invalid credentials");
        }

        // Check password expiry
        checkPasswordExpiry(credential, user, correlationId);

        // Reset failed attempts on successful authentication
        rateLimitingService.resetFailedAttempts(request.getUsername());
        accountLockoutService.resetFailedAttempts(request.getUsername());

        // Check for suspicious activity
        if (securityEventService.detectSuspiciousActivity(user.getId(), ipAddress, userAgent)) {
            log.warn("Suspicious activity detected for user: {} from IP: {}", user.getUsername(), ipAddress);
            // Trigger additional verification
            return handleSuspiciousLogin(user, ipAddress, userAgent, correlationId);
        }

        // Check MFA requirement
        if (user.getMfaEnabled()) {
            return handleMfaAuthentication(user, ipAddress, userAgent, correlationId);
        }

        // Generate tokens
        String accessToken = jwtTokenProvider.generateAccessToken(user, correlationId);
        String refreshToken = createRefreshToken(user, request.getDeviceId(), ipAddress, userAgent);

        // Create session
        sessionService.createSession(user, accessToken, refreshToken, ipAddress, userAgent, correlationId);

        // Update last login
        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginIp(ipAddress);
        userRepository.save(user);

        // Log successful authentication
        auditService.logAuthenticationEvent(
                user.getId(), user.getTenantId(), AuditEventType.LOGIN_SUCCESS,
                true, ipAddress, userAgent, Map.of(
                        "method", "password",
                        "correlation_id", correlationId
                )
        );

        // Publish authentication event
        publishAuthenticationEvent(user.getId(), user.getTenantId(), "USER_AUTHENTICATED", correlationId);

        return buildAuthResponse(user, accessToken, refreshToken);
    }

    /**
     * Register new user with tenant integration.
     */
    @Transactional
    public AuthResponse register(RegisterRequest request, String ipAddress) {
        String correlationId = getCorrelationId();
        log.info("Processing registration for email: {} with correlation ID: {}", request.getEmail(), correlationId);

        // Validate email and username uniqueness
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AuthenticationException("Email already registered");
        }

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new AuthenticationException("Username already taken");
        }

        // Validate password against policy
        passwordPolicyService.validatePassword(request.getPassword(), request.getUsername(), request.getEmail());

        // Determine registration type
        RegistrationType registrationType = determineRegistrationType(request);

        if (registrationType == RegistrationType.SELF_SIGNUP) {
            return processSelfSignup(request, ipAddress, correlationId);
        } else {
            return processAdminCreatedUser(request, ipAddress, correlationId);
        }
    }

    /**
     * Process self-signup (new organization).
     */
    private AuthResponse processSelfSignup(RegisterRequest request, String ipAddress, String correlationId) {
        log.info("Processing self-signup for organization: {} with correlation ID: {}",
                request.getOrganizationName(), correlationId);

        // Step 1: Create user identity first to get the actual user ID
        User user = User.builder()
                .tenantId(UUID.randomUUID()) // Temporary tenant ID - will be updated
                .username(request.getUsername())
                .email(request.getEmail())
                .emailVerified(false)
                .phoneNumber(request.getPhoneNumber())
                .phoneVerified(false)
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .status(UserStatus.PENDING_ACTIVATION)
                .primaryAuthProvider(AuthProvider.LOCAL)
                .mfaEnabled(request.getEnableMfa())
                .build();

        // Save to get the actual generated ID
        user = userRepository.save(user);
        final UUID actualUserId = user.getId();

        // Step 2: Create credentials immediately
        UserCredential credential = UserCredential.builder()
                .userId(actualUserId)
                .type(CredentialType.PASSWORD)
                .credentialValue(passwordEncoder.encode(request.getPassword()))
                .expiresAt(LocalDateTime.now().plusDays(90))
                .build();
        credentialRepository.save(credential);

        // Step 3: Now create tenant with the actual user ID
        UUID tenantId = createTenantForOrganizationWithUserCallback(request, correlationId, actualUserId);

        // Step 4: Update user with the actual tenant ID
        if (!tenantId.equals(user.getTenantId())) {
            user.setTenantId(tenantId);
            user = userRepository.save(user);
        }

        // Step 5: Continue with the rest of the flow
        publishUserEvent(actualUserId, tenantId, "USER-REGISTERED", correlationId, Map.of(
                "email", user.getEmail(),
                "activation_required", true
        ));

        auditService.logAuthenticationEvent(
                actualUserId, tenantId, AuditEventType.USER_REGISTERED,
                true, ipAddress, null, Map.of(
                        "type", "self_signup",
                        "organization", request.getOrganizationName(),
                        "correlation_id", correlationId
                )
        );

        String accessToken = jwtTokenProvider.generateAccessToken(user, correlationId);
        String refreshToken = createRefreshToken(user, null, ipAddress, null);

        return buildAuthResponse(user, accessToken, refreshToken);
    }

    /**
     * Create tenant for organization with user callback approach.
     */
    private UUID createTenantForOrganizationWithUserCallback(RegisterRequest request, String correlationId, UUID userId) {
        try {
            log.info("Creating tenant via gRPC for organization: {} with correlation ID: {} and user ID: {}",
                    request.getOrganizationName(), correlationId, userId);

            CompletableFuture<UUID> tenantFuture = tenantGrpcClient.createTenant(
                    request.getOrganizationName(),
                    request.getOrganizationEmail(),
                    correlationId
            );

            UUID tenantId = tenantFuture.get(5, TimeUnit.SECONDS);

            log.info("Successfully created tenant via gRPC with ID: {} for organization: {}",
                    tenantId, request.getOrganizationName());

            return tenantId;

        } catch (TimeoutException e) {
            log.error("Timeout creating tenant via gRPC for organization: {}, correlation ID: {}, user ID: {}",
                    request.getOrganizationName(), correlationId, userId, e);

            return handleAsyncTenantCreationWithUser(request, correlationId, userId);

        } catch (Exception e) {
            log.error("Error creating tenant via gRPC for organization: {}, correlation ID: {}, user ID: {}",
                    request.getOrganizationName(), correlationId, userId, e);

            return handleAsyncTenantCreationWithUser(request, correlationId, userId);
        }
    }

    /**
     * Handle async tenant creation with actual user ID.
     */
    private UUID handleAsyncTenantCreationWithUser(RegisterRequest request, String correlationId, UUID userId) {
        // Generate temporary tenant ID
        UUID temporaryTenantId = UUID.randomUUID();

        // Track the temporary tenant mapping with the actual user ID
        temporaryTenantTracker.registerTemporaryTenant(userId, temporaryTenantId, correlationId);

        // Publish tenant creation command to Kafka with actual user ID
        publishTenantCreationCommand(request, correlationId, userId);

        log.warn("Using temporary tenant ID: {} for organization: {}, will be updated async via Kafka for user: {}",
                temporaryTenantId, request.getOrganizationName(), userId);

        return temporaryTenantId;
    }

    /**
     * Process admin-created user (existing tenant).
     */
    private AuthResponse processAdminCreatedUser(RegisterRequest request, String ipAddress, String correlationId) {
        log.info("Processing admin-created user for tenant: {} with correlation ID: {}",
                request.getTenantId(), correlationId);

        // Validate tenant ID for admin-created users
        if (request.getTenantId() == null || request.getTenantId().trim().isEmpty()) {
            throw new AuthenticationException("Tenant ID is required for admin-created users");
        }

        UUID tenantId = UUID.fromString(request.getTenantId());

        // Verify tenant exists using gRPC client
        if (!tenantGrpcClient.tenantExists(tenantId)) {
            throw new AuthenticationException("Invalid tenant ID");
        }

        // Step 1: Create user identity with tenant association
        User user = User.builder()
                .tenantId(tenantId)
                .username(request.getUsername())
                .email(request.getEmail())
                .emailVerified(false)
                .phoneNumber(request.getPhoneNumber())
                .phoneVerified(false)
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .status(UserStatus.PENDING_ACTIVATION)
                .primaryAuthProvider(AuthProvider.LOCAL)
                .mfaEnabled(request.getEnableMfa())
                .build();

        user = userRepository.save(user);

        // Create credentials
        UserCredential credential = UserCredential.builder()
                .userId(user.getId())
                .type(CredentialType.PASSWORD)
                .credentialValue(passwordEncoder.encode(request.getPassword()))
                .expiresAt(LocalDateTime.now().plusDays(90)) // Password expires in 90 days
                .build();

        credentialRepository.save(credential);

        // Generate activation token
        String activationToken = UUID.randomUUID().toString();
        user.setActivationToken(activationToken);
        user.setActivationTokenExpiresAt(LocalDateTime.now().plusDays(7));
        userRepository.save(user);

        // Step 2: Publish admin-created user event
        authEventPublisher.publishAdminCreatedUserEvent(user, activationToken, user.getUsername());

        // Step 3: Send commands to other services
        // Create user profile
        authEventPublisher.sendCreateUserProfileCommand(
                user.getId(),
                tenantId,
                user.getEmail(),
                request.getFirstName(),
                request.getLastName()
        );

        // Assign role
        String role = request.getInitialRole() != null ?
                request.getInitialRole() : "MEMBER";
        authEventPublisher.sendAssignRoleCommand(user.getId(), tenantId, role);

        // Log successful registration
        auditService.logAuthenticationEvent(
                user.getId(), tenantId, AuditEventType.USER_REGISTERED,
                true, ipAddress, null, Map.of(
                        "type", "admin_created",
                        "created_by", user.getUsername(),
                        "initial_role", role,
                        "correlation_id", correlationId
                )
        );

        // For admin-created users, don't generate tokens immediately
        // They need to activate their account first
        return AuthResponse.builder()
                .user(UserInfoResponse.builder()
                        .id(user.getId())
                        .email(user.getEmail())
                        .username(user.getUsername())
                        .build())
                .authenticatedAt(LocalDateTime.now())
                .build();
    }


    /**
     * Create tenant for organization using gRPC.
     */
    private UUID createTenantForOrganization(RegisterRequest request, String correlationId) {
        try {
            log.info("Creating tenant via gRPC for organization: {} with correlation ID: {}",
                    request.getOrganizationName(), correlationId);

            // Call tenant service via gRPC to create new tenant
            CompletableFuture<UUID> tenantFuture = tenantGrpcClient.createTenant(
                    request.getOrganizationName(),
                    request.getOrganizationEmail(),
                    correlationId
            );

            // Wait with timeout (5 seconds)
            UUID tenantId = tenantFuture.get(5, TimeUnit.SECONDS);

            log.info("Successfully created tenant via gRPC with ID: {} for organization: {}",
                    tenantId, request.getOrganizationName());

            return tenantId;

        } catch (TimeoutException e) {
            log.error("Timeout creating tenant via gRPC for organization: {}, correlation ID: {}",
                    request.getOrganizationName(), correlationId, e);

            return handleAsyncTenantCreation(request, correlationId);

        } catch (Exception e) {
            log.error("Error creating tenant via gRPC for organization: {}, correlation ID: {}",
                    request.getOrganizationName(), correlationId, e);

            return handleAsyncTenantCreation(request, correlationId);
        }
    }

    /**
     * Handle async tenant creation when synchronous call fails.
     * Creates a temporary tenant ID and publishes command to Kafka.
     */
    private UUID handleAsyncTenantCreation(RegisterRequest request, String correlationId) {
        // Generate temporary tenant ID
        UUID temporaryTenantId = UUID.randomUUID();

        // Get the user ID that's being created (you might need to pass this from the calling method)
        // For now, we'll use a placeholder - in practice, you'd pass the user ID
        UUID userId = UUID.randomUUID(); // This should be the actual user ID being created

        // Track the temporary tenant ID in Redis
        temporaryTenantTracker.registerTemporaryTenant(userId, temporaryTenantId, correlationId);

        // Publish tenant creation command to Kafka for async processing
        publishTenantCreationCommand(request, correlationId, userId);

        log.warn("Using temporary tenant ID: {} for organization: {}, will be updated async via Kafka",
                temporaryTenantId, request.getOrganizationName());

        return temporaryTenantId;
    }

    private void validateUserStatus(User user, String correlationId) {
        switch (user.getStatus()) {
            case SUSPENDED:
                logSecurityEvent(SecurityEventType.SUSPENDED_ACCOUNT_ACCESS, user.getUsername(), null, correlationId);
                throw new AuthenticationException("Account is suspended");
            case INACTIVE:
                throw new AuthenticationException("Account is inactive");
            case PENDING_ACTIVATION:
                throw new AuthenticationException("Please activate your account first");
            case ACTIVE:
                // Continue with authentication
                break;
            default:
                throw new AuthenticationException("Invalid account status");
        }
    }

    private void checkPasswordExpiry(UserCredential credential, User user, String correlationId) {
        if (credential.getExpiresAt() != null && credential.getExpiresAt().isBefore(LocalDateTime.now())) {
            logSecurityEvent(SecurityEventType.PASSWORD_EXPIRED, user.getUsername(), null, correlationId);
            throw new AuthenticationException("Password has expired. Please reset your password.");
        }

        // Warn if password expires soon (within 7 days)
        if (credential.getExpiresAt() != null) {
            long daysUntilExpiry = Duration.between(LocalDateTime.now(), credential.getExpiresAt()).toDays();
            if (daysUntilExpiry <= 7) {
                log.warn("Password for user {} expires in {} days", user.getUsername(), daysUntilExpiry);
            }
        }
    }

    private void handleFailedAuthentication(User user, String username, String ipAddress, String correlationId) {
        rateLimitingService.recordFailedAttempt(username, ipAddress);
        accountLockoutService.recordFailedAttempt(username);

        auditService.logAuthenticationEvent(
                user.getId(), user.getTenantId(), AuditEventType.LOGIN_FAILURE,
                false, ipAddress, null, Map.of(
                        "reason", "invalid_password",
                        "correlation_id", correlationId
                )
        );

        logSecurityEvent(SecurityEventType.INVALID_CREDENTIALS, username, ipAddress, correlationId);
    }

    private AuthResponse handleSuspiciousLogin(User user, String ipAddress, String userAgent, String correlationId) {
        // Force MFA for suspicious login
        String mfaToken = jwtTokenProvider.generateMfaToken(user, correlationId);

        // Send MFA code
        mfaService.sendMfaCode(user.getId(), MfaType.EMAIL);

        logSecurityEvent(SecurityEventType.SUSPICIOUS_LOGIN, user.getUsername(), ipAddress, correlationId);

        return AuthResponse.builder()
                .mfaRequired(true)
                .mfaToken(mfaToken)
                .mfaTypes(Set.of(MfaType.EMAIL, MfaType.TOTP))
                .authenticatedAt(LocalDateTime.now())
                .build();
    }

    private AuthResponse handleMfaAuthentication(User user, String ipAddress, String userAgent, String correlationId) {
        String mfaToken = jwtTokenProvider.generateMfaToken(user, correlationId);

        // Send MFA code if using SMS/EMAIL
        if (user.getMfaType() == MfaType.SMS || user.getMfaType() == MfaType.EMAIL) {
            mfaService.sendMfaCode(user.getId(), user.getMfaType());
        }

        auditService.logAuthenticationEvent(
                user.getId(), user.getTenantId(), AuditEventType.MFA_REQUIRED,
                true, ipAddress, userAgent, Map.of(
                        "mfa_type", user.getMfaType().toString(),
                        "correlation_id", correlationId
                )
        );

        return AuthResponse.builder()
                .mfaRequired(true)
                .mfaToken(mfaToken)
                .mfaTypes(Set.of(user.getMfaType()))
                .authenticatedAt(LocalDateTime.now())
                .build();
    }

    private void publishAuthenticationEvent(UUID userId, UUID tenantId, String eventType, String correlationId) {
        try {
           AuthenticationEvent event = AuthenticationEvent.newBuilder()
                    .setEventId(UUID.randomUUID().toString())
                    .setEventType(eventType)
                    .setUserId(userId != null ? userId.toString() : "")
                    .setTenantId(tenantId != null ? tenantId.toString() : "")
                    .setCorrelationId(correlationId)
                    .setTimestamp(System.currentTimeMillis())
                    .build();

            kafkaTemplate.send("nnipa.events.auth." + eventType.toLowerCase(),
                    correlationId, event.toByteArray());
        } catch (Exception e) {
            log.error("Failed to publish authentication event: {}", eventType, e);
        }
    }

    private void publishUserEvent(UUID userId, UUID tenantId, String eventType, String correlationId, Map<String, Object> metadata) {
        // Similar to publishAuthenticationEvent but with additional metadata
        publishAuthenticationEvent(userId, tenantId, eventType, correlationId);
    }

    /**
     * Publish tenant creation command to Kafka as fallback.
     * This is used when gRPC synchronous call fails or times out.
     */
    private void publishTenantCreationCommand(RegisterRequest request, String correlationId, UUID userId) {
        try {
            log.debug("Publishing tenant creation command for organization: {} with correlation ID: {} and user ID: {}",
                    request.getOrganizationName(), correlationId, userId);

            // Build CommandMetadata
            com.nnipa.proto.common.CommandMetadata metadata =
                    com.nnipa.proto.common.CommandMetadata.newBuilder()
                            .setCommandId(UUID.randomUUID().toString())
                            .setCorrelationId(correlationId)
                            .setTimestamp(com.google.protobuf.Timestamp.newBuilder()
                                    .setSeconds(System.currentTimeMillis() / 1000)
                                    .setNanos((int) ((System.currentTimeMillis() % 1000) * 1000000))
                                    .build())
                            .setSource("auth-service")
                            .build();

            // Build TenantDetails
            CreateTenantCommand.TenantDetails.Builder detailsBuilder =
                    CreateTenantCommand.TenantDetails.newBuilder()
                            .setCode(generateTenantCode(request.getOrganizationName()))
                            .setName(request.getOrganizationName())
                            .setOrganizationType("SELF_SIGNUP") // Since this is from self-signup
                            .setSubscriptionPlan("FREE") // Default plan for self-signup
                            .setIsolationStrategy("SHARED") // Default isolation strategy
                            .setAdminEmail(request.getEmail())
                            .setBillingEmail(request.getOrganizationEmail() != null ?
                                    request.getOrganizationEmail() : request.getEmail());

            // Add metadata including user ID for response routing
            detailsBuilder.putMetadata("created_by", "self_signup");
            detailsBuilder.putMetadata("user_id", userId.toString());  // Important: Include user ID
            detailsBuilder.putMetadata("user_email", request.getEmail());
            detailsBuilder.putMetadata("username", request.getUsername());
            if (request.getOrganizationEmail() != null) {
                detailsBuilder.putMetadata("organization_email", request.getOrganizationEmail());
            }

            // Add default settings
            detailsBuilder.putSettings("max_users", "10"); // Default limit for free plan
            detailsBuilder.putSettings("storage_limit_gb", "5"); // Default storage limit
            detailsBuilder.putSettings("auto_provisioning", "true");

            // Build the complete command
            CreateTenantCommand command = CreateTenantCommand.newBuilder()
                    .setMetadata(metadata)
                    .setDetails(detailsBuilder.build())
                    .build();

            // Send to Kafka
            String topicName = "nnipa.commands.tenant.create";
            kafkaTemplate.send(topicName, correlationId, command.toByteArray())
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            log.error("Failed to publish tenant creation command for correlation ID: {} and user ID: {}. Error: {}",
                                    correlationId, userId, ex.getMessage(), ex);

                            // Could implement retry logic here or store for later processing
                            // For now, just log the failure - the system should handle eventual consistency

                        } else {
                            log.info("Successfully published tenant creation command for correlation ID: {} and user ID: {} to topic: {}",
                                    correlationId, userId, topicName);
                        }
                    });

            log.info("Tenant creation command published successfully for organization: {} with correlation ID: {} and user ID: {}",
                    request.getOrganizationName(), correlationId, userId);

        } catch (Exception e) {
            log.error("Error publishing tenant creation command for organization: {} with correlation ID: {} and user ID: {}",
                    request.getOrganizationName(), correlationId, userId, e);
            // Don't throw exception here as this is an async operation
            // The tenant creation will be handled eventually or through retry mechanisms
        }
    }


    /**
     * Generate a unique tenant code from organization name
     */
    private String generateTenantCode(String organizationName) {
        // Create a code from organization name: lowercase, replace spaces with hyphens,
        // remove special characters, and add random suffix to ensure uniqueness
        String baseCode = organizationName.toLowerCase()
                .replaceAll("[^a-z0-9\\s]", "") // Remove special characters
                .replaceAll("\\s+", "-") // Replace spaces with hyphens
                .replaceAll("-+", "-") // Replace multiple hyphens with single
                .replaceAll("^-|-$", ""); // Remove leading/trailing hyphens

        // Limit length and add random suffix
        if (baseCode.length() > 20) {
            baseCode = baseCode.substring(0, 20);
        }

        // Add random suffix to ensure uniqueness
        String randomSuffix = UUID.randomUUID().toString().substring(0, 8);

        return baseCode + "-" + randomSuffix;
    }

    private void logSecurityEvent(SecurityEventType eventType, String username, String ipAddress, String correlationId) {
        securityEventService.logEvent(eventType, username, ipAddress, correlationId);
    }

    private String getCorrelationId() {
        return correlationIdUtil.getCorrelationId();
    }

    private RegistrationType determineRegistrationType(RegisterRequest request) {
        return request.getTenantCode() != null ?
                RegistrationType.ADMIN_CREATED : RegistrationType.SELF_SIGNUP;
    }

    private AuthResponse buildAuthResponse(User user, String accessToken, String refreshToken) {
        Set<String> linkedProviders = user.getOauth2Accounts() != null ?
                user.getOauth2Accounts().stream()
                        .map(account -> account.getProvider().toString())
                        .collect(Collectors.toSet()) : new HashSet<>();

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
                .linkedProviders(linkedProviders)
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

    private String createRefreshToken(User user, String deviceInfo, String ipAddress, String userAgent) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .deviceInfo(deviceInfo)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .expiresAt(LocalDateTime.now().plusDays(30))
                .build();

        refreshTokenRepository.save(refreshToken);
        return refreshToken.getToken();
    }

    /**
     * Logout user and invalidate tokens.
     */
    @Transactional
    public void logout(String token, String correlationId) {
        UUID userId = jwtTokenProvider.getUserIdFromToken(token);

        // Add token to blacklist
        tokenBlacklistService.blacklistToken(token);

        // Invalidate refresh tokens
        refreshTokenRepository.deleteByUserId(userId);

        // Clear session
        sessionService.invalidateSession(userId);

        // Log logout event
        auditService.logAuthenticationEvent(
                userId, null, AuditEventType.LOGOUT,
                true, null, null, Map.of("correlation_id", correlationId)
        );
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
        validateUserStatus(user, getCorrelationId());

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

    /**
     * Validate token.
     */
    @Cacheable(value = "tokenValidation", key = "#token")
    public boolean validateToken(String token) {
        return jwtTokenProvider.validateToken(token) && !sessionService.isTokenBlacklisted(token);
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
}