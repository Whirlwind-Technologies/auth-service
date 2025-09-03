package com.nnipa.auth.service;

import com.nnipa.auth.config.SecurityProperties;
import com.nnipa.auth.entity.PasswordHistory;
import com.nnipa.auth.entity.PasswordResetToken;
import com.nnipa.auth.entity.User;
import com.nnipa.auth.entity.UserCredential;
import com.nnipa.auth.enums.UserStatus;
import com.nnipa.auth.exception.AuthenticationException;
import com.nnipa.auth.repository.PasswordHistoryRepository;
import com.nnipa.auth.repository.PasswordResetTokenRepository;
import com.nnipa.auth.repository.UserCredentialRepository;
import com.nnipa.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.passay.*;
import org.passay.dictionary.ArrayWordList;
import org.passay.dictionary.WordListDictionary;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Service for password management and policy enforcement.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordService {

    private final UserRepository userRepository;
    private final UserCredentialRepository credentialRepository;
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecurityProperties securityProperties;

    /**
     * Validate password against configured policies.
     */
    public PasswordValidationResult validatePassword(String password, String username, String email) {
        SecurityProperties.Password.Policy policy = securityProperties.getPassword().getPolicy();

        List<Rule> rules = new ArrayList<>();

        // Length rule
        rules.add(new LengthRule(policy.getMinLength(), 128));

        // Character rules
        List<CharacterRule> characterRules = new ArrayList<>();

        if (policy.getRequireUppercase()) {
            characterRules.add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
        }
        if (policy.getRequireLowercase()) {
            characterRules.add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
        }
        if (policy.getRequireDigit()) {
            characterRules.add(new CharacterRule(EnglishCharacterData.Digit, 1));
        }
        if (policy.getRequireSpecial()) {
            characterRules.add(new CharacterRule(EnglishCharacterData.Special, 1));
        }

        if (!characterRules.isEmpty()) {
            rules.add(new CharacterCharacteristicsRule(characterRules.size(), characterRules));
        }

        // Username rule - password shouldn't contain username
        if (username != null) {
            rules.add(new UsernameRule(true, true));
        }

        // No whitespace
        rules.add(new WhitespaceRule());

        // No common passwords
        WordListDictionary dictionary = new WordListDictionary(
                new ArrayWordList(new String[]{
                        "password", "123456", "password123", "admin", "letmein",
                        "welcome", "monkey", "dragon", "master", "qwerty"
                })
        );
        rules.add(new DictionaryRule(dictionary));

        // No sequences
        rules.add(new IllegalSequenceRule(EnglishSequenceData.Alphabetical, 3, false));
        rules.add(new IllegalSequenceRule(EnglishSequenceData.Numerical, 3, false));
        rules.add(new IllegalSequenceRule(EnglishSequenceData.USQwerty, 3, false));

        // No repeated characters
        rules.add(new RepeatCharactersRule(3));

        // Create password data with username context
        PasswordData passwordData = new PasswordData(password);
        if (username != null) {
            passwordData.setUsername(username);
        }

        // Validate
        PasswordValidator validator = new PasswordValidator(rules);
        RuleResult result = validator.validate(passwordData);

        if (result.isValid()) {
            // Calculate password strength
            int strength = calculatePasswordStrength(password);
            return PasswordValidationResult.builder()
                    .valid(true)
                    .strength(strength)
                    .message("Password meets all requirements")
                    .build();
        } else {
            List<String> messages = validator.getMessages(result);
            return PasswordValidationResult.builder()
                    .valid(false)
                    .errors(messages)
                    .message(String.join("; ", messages))
                    .build();
        }
    }

    /**
     * Change user password.
     */
    @Transactional
    @CacheEvict(value = {"userAuth", "sessions"}, key = "#userId")
    public void changePassword(UUID userId, String currentPassword, String newPassword) {
        log.info("Password change requested for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthenticationException("User not found"));

        UserCredential credential = credentialRepository.findByUserId(userId)
                .orElseThrow(() -> new AuthenticationException("Credentials not found"));

        // Verify current password
        if (!passwordEncoder.matches(currentPassword, credential.getPasswordHash())) {
            throw new AuthenticationException("Current password is incorrect");
        }

        // Validate new password
        PasswordValidationResult validation = validatePassword(
                newPassword,
                user.getUsername(),
                user.getEmail()
        );

        if (!validation.isValid()) {
            throw new AuthenticationException("New password does not meet requirements: " + validation.getMessage());
        }

        // Check password history
        if (!isPasswordUnique(userId, newPassword)) {
            throw new AuthenticationException(
                    "Password has been used recently. Please choose a different password."
            );
        }

        // Save old password to history
        savePasswordToHistory(credential);

        // Update password
        credential.setPasswordHash(passwordEncoder.encode(newPassword));
        credential.setPasswordExpiresAt(LocalDateTime.now().plusDays(
                securityProperties.getPassword().getPolicy().getMaxAgeDays()
        ));
        credential.setMustChangePassword(false);
        credential.resetFailedAttempts();
        credentialRepository.save(credential);

        // Update user
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        // Send notification (would integrate with notification-service)
//        notificationService.sendPasswordChangeNotification(user);

        log.info("Password changed successfully for user: {}", userId);
    }

    /**
     * Initiate password reset process.
     */
    @Transactional
    public void initiatePasswordReset(String email, String ipAddress) {
        log.info("Password reset requested for email: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("User not found"));

        // Generate reset token
        String resetToken = generateResetToken();

        // Save reset token
        PasswordResetToken token = PasswordResetToken.builder()
                .user(user)
                .token(resetToken)
                .expiresAt(LocalDateTime.now().plusHours(1))
                .ipAddress(ipAddress)
                .build();

        passwordResetTokenRepository.save(token);

        // Send reset email (would integrate with notification-service)
//        notificationService.sendPasswordResetEmail(user, resetToken);

        log.info("Password reset email sent to: {}", email);
    }

    /**
     * Reset password using token.
     */
    @Transactional
    @CacheEvict(value = {"userAuth", "sessions"}, key = "#result.user.id")
    public User resetPassword(String token, String newPassword) {
        log.info("Password reset with token");

        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token)
                .orElseThrow(() -> new AuthenticationException("Invalid or expired reset token"));

        // Check if token is expired
        if (resetToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new AuthenticationException("Reset token has expired");
        }

        // Check if token is already used
        if (resetToken.getUsed()) {
            throw new AuthenticationException("Reset token has already been used");
        }

        User user = resetToken.getUser();

        // Validate new password
        PasswordValidationResult validation = validatePassword(
                newPassword,
                user.getUsername(),
                user.getEmail()
        );

        if (!validation.isValid()) {
            throw new AuthenticationException("Password does not meet requirements: " + validation.getMessage());
        }

        // Check password history
        if (!isPasswordUnique(user.getId(), newPassword)) {
            throw new AuthenticationException(
                    "Password has been used recently. Please choose a different password."
            );
        }

        // Get or create credential
        UserCredential credential = credentialRepository.findByUserId(user.getId())
                .orElse(UserCredential.builder()
                        .user(user)
                        .build());

        // Save old password to history if exists
        if (credential.getPasswordHash() != null) {
            savePasswordToHistory(credential);
        }

        // Update password
        credential.setPasswordHash(passwordEncoder.encode(newPassword));
        credential.setPasswordExpiresAt(LocalDateTime.now().plusDays(
                securityProperties.getPassword().getPolicy().getMaxAgeDays()
        ));
        credential.setMustChangePassword(false);
        credential.resetFailedAttempts();
        credentialRepository.save(credential);

        // Update user
        user.setPasswordChangedAt(LocalDateTime.now());
        user.setStatus(UserStatus.ACTIVE); // Activate if was pending
        userRepository.save(user);

        // Mark token as used
        resetToken.setUsed(true);
        resetToken.setUsedAt(LocalDateTime.now());
        passwordResetTokenRepository.save(resetToken);

        // Send confirmation email
//        notificationService.sendPasswordResetConfirmation(user);

        log.info("Password reset successfully for user: {}", user.getId());

        return user;
    }

    /**
     * Force password reset for user.
     */
    @Transactional
    public void forcePasswordReset(UUID userId) {
        log.info("Forcing password reset for user: {}", userId);

        UserCredential credential = credentialRepository.findByUserId(userId)
                .orElseThrow(() -> new AuthenticationException("User credentials not found"));

        credential.setMustChangePassword(true);
        credential.setPasswordExpiresAt(LocalDateTime.now());
        credentialRepository.save(credential);
    }

    /**
     * Check if password is due for change.
     */
    public boolean isPasswordExpired(UUID userId) {
        UserCredential credential = credentialRepository.findByUserId(userId)
                .orElse(null);

        if (credential == null) {
            return false;
        }

        return credential.isPasswordExpired() || credential.getMustChangePassword();
    }

    /**
     * Generate secure password.
     */
    public String generateSecurePassword() {
        PasswordGenerator generator = new PasswordGenerator();

        List<CharacterRule> rules = Arrays.asList(
                new CharacterRule(EnglishCharacterData.UpperCase, 2),
                new CharacterRule(EnglishCharacterData.LowerCase, 2),
                new CharacterRule(EnglishCharacterData.Digit, 2),
                new CharacterRule(EnglishCharacterData.Special, 2)
        );

        String password = generator.generatePassword(16, rules);
        return password;
    }

    // Private helper methods

    private boolean isPasswordUnique(UUID userId, String newPassword) {
        UserCredential credential = credentialRepository.findByUserId(userId)
                .orElse(null);

        if (credential == null) {
            return true;
        }

        // Check current password
        if (passwordEncoder.matches(newPassword, credential.getPasswordHash())) {
            return false;
        }

        // Check password history
        Integer historyCount = securityProperties.getPassword().getPolicy().getHistoryCount();
        List<PasswordHistory> history = passwordHistoryRepository
                .findRecentByCredentialId(credential.getId(), historyCount);

        for (PasswordHistory oldPassword : history) {
            if (passwordEncoder.matches(newPassword, oldPassword.getPasswordHash())) {
                return false;
            }
        }

        return true;
    }

    private void savePasswordToHistory(UserCredential credential) {
        PasswordHistory history = PasswordHistory.builder()
                .credential(credential)
                .passwordHash(credential.getPasswordHash())
                .salt(credential.getSalt())
                .build();

        passwordHistoryRepository.save(history);

        // Clean up old history entries
        Integer historyCount = securityProperties.getPassword().getPolicy().getHistoryCount();
        passwordHistoryRepository.deleteOldEntries(credential.getId(), historyCount);
    }

    private String generateResetToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private int calculatePasswordStrength(String password) {
        int strength = 0;

        // Length scoring
        if (password.length() >= 8) strength += 10;
        if (password.length() >= 12) strength += 10;
        if (password.length() >= 16) strength += 10;

        // Character diversity
        if (password.matches(".*[a-z].*")) strength += 10;
        if (password.matches(".*[A-Z].*")) strength += 10;
        if (password.matches(".*[0-9].*")) strength += 10;
        if (password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) strength += 20;

        // No common patterns
        if (!password.toLowerCase().contains("password")) strength += 10;
        if (!password.matches(".*(.)(\\1{2,}).*")) strength += 10; // No repeated characters

        return Math.min(strength, 100);
    }

    /**
     * Result of password validation.
     */
    @lombok.Data
    @lombok.Builder
    public static class PasswordValidationResult {
        private boolean valid;
        private Integer strength;
        private String message;
        private List<String> errors;
    }
}