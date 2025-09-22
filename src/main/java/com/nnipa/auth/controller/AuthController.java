package com.nnipa.auth.controller;

import com.nnipa.auth.dto.request.*;
import com.nnipa.auth.dto.response.*;
import com.nnipa.auth.security.jwt.JwtTokenProvider;
import com.nnipa.auth.service.AuthenticationService;
import io.jsonwebtoken.Claims;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * REST controller for authentication endpoints.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication and token management APIs")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping("/login")
    @Operation(summary = "Authenticate user", description = "Login with username/email and password")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Successfully authenticated",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Invalid credentials"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "423",
                    description = "Account locked"
            )
    })
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        log.info("Login attempt for user: {}", request.getUsername());

        String ipAddress = getClientIpAddress(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        AuthResponse authResponse = authenticationService.authenticate(request, ipAddress, userAgent);

        if (authResponse.getMfaRequired()) {
            return ResponseEntity.ok(ApiResponse.success(authResponse, "MFA verification required"));
        }

        return ResponseEntity.ok(ApiResponse.success(authResponse, "Login successful"));
    }

    @PostMapping("/register")
    @Operation(summary = "Register new user", description = "Create a new user account")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "201",
                    description = "User registered successfully",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid registration data"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "409",
                    description = "User already exists"
            )
    })
    public ResponseEntity<ApiResponse<AuthResponse>> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {

        log.info("Registration attempt for email: {}", request.getEmail());

        String ipAddress = getClientIpAddress(httpRequest);
        AuthResponse authResponse = authenticationService.register(request, ipAddress);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(authResponse, "Registration successful. Please check your email to activate your account."));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token", description = "Get new access token using refresh token")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Token refreshed successfully",
                    content = @Content(schema = @Schema(implementation = TokenResponse.class))
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Invalid or expired refresh token"
            )
    })
    public ResponseEntity<ApiResponse<TokenResponse>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {

        log.debug("Token refresh request");

        TokenResponse tokenResponse = authenticationService.refreshToken(request);

        return ResponseEntity.ok(ApiResponse.success(tokenResponse, "Token refreshed successfully"));
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout user", description = "Invalidate user session and tokens")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Logged out successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized"
            )
    })
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<Void>> logout(
            @RequestHeader("Authorization") String authHeader) {

        // Extract token from header
        String token = authHeader.replace("Bearer ", "");

        // Generate correlation ID for tracking
        String correlationId = UUID.randomUUID().toString();

        log.info("Logout request with correlation ID: {}", correlationId);

        authenticationService.logout(token, correlationId);

        return ResponseEntity.ok(ApiResponse.success(null, "Logged out successfully"));
    }

    @PostMapping("/validate")
    @Operation(summary = "Validate token", description = "Check if a token is valid")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Token validation result",
                    content = @Content(schema = @Schema(implementation = TokenValidationResponse.class))
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Authorization header missing or invalid"
            )
    })
    @Parameter(
            name = "Authorization",
            description = "Bearer token for validation",
            required = true,
            in = ParameterIn.HEADER,
            example = "Bearer eyJhbGciOiJIUzUxMiJ9...",
            schema = @Schema(type = "string")
    )
    public ResponseEntity<ApiResponse<TokenValidationResponse>> validateToken(
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestBody(required = false) ValidateTokenRequest request) {

        log.debug("Token validation request");

        // Extract token from Authorization header
        String token = extractTokenFromHeader(authorizationHeader);

        // Optional: Get token type from request body, default to "access"
        String tokenType = (request != null && request.getTokenType() != null)
                ? request.getTokenType()
                : "access";

        TokenValidationResponse response;
        try {
            boolean isValid = authenticationService.validateToken(token);
            if (isValid) {
                Claims claims = jwtTokenProvider.getClaims(token);
                response = TokenValidationResponse.builder()
                        .valid(true)
                        .userId(UUID.fromString(claims.get("userId", String.class)))
                        .tenantId(UUID.fromString(claims.get("tenantId", String.class)))
                        .username(claims.get("username", String.class))
                        .expiresAt(claims.getExpiration().getTime())
                        .issuedAt(claims.getIssuedAt().getTime())
                        .jti(claims.getId())
                        .claims(claims)
                        .build();
            } else {
                response = TokenValidationResponse.builder()
                        .valid(false)
                        .errorMessage("Token is invalid or expired")
                        .build();
            }
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error( "Invalid Authorization header format", "AUTH_HEADER_INVALID"));
        } catch (Exception e) {
            response = TokenValidationResponse.builder()
                    .valid(false)
                    .errorMessage(e.getMessage())
                    .build();
        }

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/me")
    @Operation(summary = "Get current user info", description = "Get authenticated user information")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "User information retrieved",
                    content = @Content(schema = @Schema(implementation = UserInfoResponse.class))
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized"
            )
    })
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<UserInfoResponse>> getCurrentUser(
            @AuthenticationPrincipal UUID userId) {

        log.debug("Get current user info for: {}", userId);

        UserInfoResponse userInfo = authenticationService.getUserInfo(userId);

        return ResponseEntity.ok(ApiResponse.success(userInfo, "User information retrieved"));
    }

    @PostMapping("/activate")
    @Operation(summary = "Activate user account", description = "Activate user account with activation token")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Account activated successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid or expired activation token"
            )
    })
    public ResponseEntity<ApiResponse<Void>> activateAccount(
            @RequestParam String token) {

        log.info("Account activation request with token: {}", token);

        authenticationService.activateAccount(token);

        return ResponseEntity.ok(ApiResponse.success(null, "Account activated successfully"));
    }

    @GetMapping("/check-availability")
    @Operation(summary = "Check username/email availability", description = "Check if username or email is available")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Availability check result"
            )
    })
    public ResponseEntity<ApiResponse<Boolean>> checkAvailability(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String email) {

        if (username != null) {
            boolean available = !authenticationService.isUsernameExists(username);
            return ResponseEntity.ok(ApiResponse.success(available,
                    available ? "Username is available" : "Username is already taken"));
        }

        if (email != null) {
            boolean available = !authenticationService.isEmailExists(email);
            return ResponseEntity.ok(ApiResponse.success(available,
                    available ? "Email is available" : "Email is already registered"));
        }

        return ResponseEntity.badRequest()
                .body(ApiResponse.error("Please provide username or email to check", "MISSING_PARAMETER"));
    }

    // Helper method to get client IP address
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    /**
     * Extract JWT token from Authorization header.
     * Expected format: "Bearer <token>"
     */
    private String extractTokenFromHeader(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Authorization header must start with 'Bearer '");
        }

        String token = authorizationHeader.substring(7); // Remove "Bearer " prefix

        if (token.trim().isEmpty()) {
            throw new IllegalArgumentException("Token cannot be empty");
        }

        return token;
    }

}