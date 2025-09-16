package com.nnipa.auth.service;

import com.nnipa.auth.enums.SecurityEventType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Service for managing password policies
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordPolicyService {

    private static final int MIN_PASSWORD_LENGTH = 12;
    private static final int MAX_PASSWORD_LENGTH = 128;
    private static final Pattern UPPERCASE_PATTERN = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile("[a-z]");
    private static final Pattern DIGIT_PATTERN = Pattern.compile("[0-9]");
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]");
    private static final List<String> COMMON_PASSWORDS = Arrays.asList(
            "password123", "12345678", "qwerty123", "admin123", "letmein123"
    );

    private final RedisTemplate<String, Object> redisTemplate;

    public void validatePassword(String password, String username, String email) {
        List<String> violations = new ArrayList<>();

        // Check length
        if (password.length() < MIN_PASSWORD_LENGTH) {
            violations.add("Password must be at least " + MIN_PASSWORD_LENGTH + " characters long");
        }

        if (password.length() > MAX_PASSWORD_LENGTH) {
            violations.add("Password must not exceed " + MAX_PASSWORD_LENGTH + " characters");
        }

        // Check complexity
        if (!UPPERCASE_PATTERN.matcher(password).find()) {
            violations.add("Password must contain at least one uppercase letter");
        }

        if (!LOWERCASE_PATTERN.matcher(password).find()) {
            violations.add("Password must contain at least one lowercase letter");
        }

        if (!DIGIT_PATTERN.matcher(password).find()) {
            violations.add("Password must contain at least one digit");
        }

        if (!SPECIAL_CHAR_PATTERN.matcher(password).find()) {
            violations.add("Password must contain at least one special character");
        }

        // Check for common passwords
        if (COMMON_PASSWORDS.stream().anyMatch(password.toLowerCase()::contains)) {
            violations.add("Password is too common");
        }

        // Check for username/email in password
        if (username != null && password.toLowerCase().contains(username.toLowerCase())) {
            violations.add("Password must not contain your username");
        }

        if (email != null) {
            String emailPrefix = email.split("@")[0];
            if (password.toLowerCase().contains(emailPrefix.toLowerCase())) {
                violations.add("Password must not contain parts of your email");
            }
        }

        // Check for sequences
        if (hasSequence(password)) {
            violations.add("Password must not contain sequential characters");
        }

        // Check for repeated characters
        if (hasRepeatedCharacters(password)) {
            violations.add("Password must not contain more than 3 repeated characters");
        }

        if (!violations.isEmpty()) {
            throw new IllegalArgumentException("Password policy violations: " + String.join(", ", violations));
        }

        // Check password history (if user exists)
        checkPasswordHistory(password, username);
    }

    private boolean hasSequence(String password) {
        String sequences = "abcdefghijklmnopqrstuvwxyz0123456789";
        String reverseSequences = new StringBuilder(sequences).reverse().toString();

        for (int i = 0; i < password.length() - 2; i++) {
            String substr = password.substring(i, i + 3).toLowerCase();
            if (sequences.contains(substr) || reverseSequences.contains(substr)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasRepeatedCharacters(String password) {
        for (int i = 0; i < password.length() - 3; i++) {
            char c = password.charAt(i);
            if (password.charAt(i + 1) == c &&
                    password.charAt(i + 2) == c &&
                    password.charAt(i + 3) == c) {
                return true;
            }
        }
        return false;
    }

    private void checkPasswordHistory(String password, String username) {
        // Check last 5 passwords
        String key = "password-history:" + username;
        List<Object> history = redisTemplate.opsForList().range(key, 0, 4);

        if (history != null && !history.isEmpty()) {
            // This would compare hashed passwords in production
            log.debug("Checking password history for user: {}", username);
        }
    }

    public void recordPasswordChange(String username, String hashedPassword) {
        String key = "password-history:" + username;
        redisTemplate.opsForList().leftPush(key, hashedPassword);
        redisTemplate.opsForList().trim(key, 0, 4); // Keep only last 5
        redisTemplate.expire(key, 365, TimeUnit.DAYS);
    }
}

