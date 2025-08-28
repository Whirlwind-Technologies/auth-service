package com.nnipa.auth.service;

import com.nnipa.auth.config.SecurityProperties;
import com.nnipa.auth.entity.MfaDevice;
import com.nnipa.auth.entity.User;
import com.nnipa.auth.enums.MfaType;
import com.nnipa.auth.exception.AuthenticationException;
import com.nnipa.auth.repository.MfaDeviceRepository;
import com.nnipa.auth.repository.UserRepository;
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.PostConstruct;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for Multi-Factor Authentication (MFA) management.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MfaService {

    private final MfaDeviceRepository mfaDeviceRepository;
    private final UserRepository userRepository;
    private final SecurityProperties securityProperties;
    private final RedisTemplate<String, Object> redisTemplate;

    private GoogleAuthenticator googleAuthenticator;
    private static final String MFA_CODE_PREFIX = "mfa-code:";
    private static final String MFA_ATTEMPT_PREFIX = "mfa-attempt:";
    private static final int MAX_MFA_ATTEMPTS = 3;
    private static final Duration MFA_CODE_TTL = Duration.ofMinutes(5);
    private static final int BACKUP_CODES_COUNT = 10;

    @PostConstruct
    public void init() {
        // Initialize Google Authenticator
        googleAuthenticator = new GoogleAuthenticator();

        // Initialize Twilio if SMS MFA is enabled
        if (securityProperties.getMfa().getSms().getTwilio().getAccountSid() != null) {
            Twilio.init(
                    securityProperties.getMfa().getSms().getTwilio().getAccountSid(),
                    securityProperties.getMfa().getSms().getTwilio().getAuthToken()
            );
        }
    }

    /**
     * Setup TOTP (Time-based One-Time Password) MFA for user.
     */
    @Transactional
    public Map<String, String> setupTotp(UUID userId, String deviceName) {
        log.info("Setting up TOTP MFA for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthenticationException("User not found"));

        // Check if TOTP is already set up
        if (mfaDeviceRepository.existsByUserIdAndType(userId, MfaType.TOTP)) {
            throw new AuthenticationException("TOTP already configured for this account");
        }

        // Generate secret key
        GoogleAuthenticatorKey key = googleAuthenticator.createCredentials();
        String secret = key.getKey();

        // Create MFA device
        MfaDevice device = MfaDevice.builder()
                .user(user)
                .type(MfaType.TOTP)
                .deviceName(deviceName != null ? deviceName : "Default TOTP Device")
                .secret(secret)
                .verified(false)
                .enabled(false)
                .build();

        mfaDeviceRepository.save(device);

        // Generate QR code URL
        String issuer = securityProperties.getMfa().getIssuer();
        String qrCodeUrl = GoogleAuthenticatorQRGenerator.getOtpAuthURL(
                issuer,
                user.getEmail(),
                key
        );

        Map<String, String> response = new HashMap<>();
        response.put("secret", secret);
        response.put("qrCode", qrCodeUrl);
        response.put("deviceId", device.getId().toString());

        return response;
    }

    /**
     * Verify and enable TOTP device.
     */
    @Transactional
    @CacheEvict(value = "userMfaDevices", key = "#deviceId")
    public boolean verifyAndEnableTotp(UUID deviceId, String code) {
        log.debug("Verifying TOTP code for device: {}", deviceId);

        MfaDevice device = mfaDeviceRepository.findById(deviceId)
                .orElseThrow(() -> new AuthenticationException("MFA device not found"));

        if (device.getType() != MfaType.TOTP) {
            throw new AuthenticationException("Device is not a TOTP device");
        }

        // Verify the code
        boolean isValid = googleAuthenticator.authorize(device.getSecret(), Integer.parseInt(code));

        if (isValid) {
            device.setVerified(true);
            device.setVerifiedAt(LocalDateTime.now());
            device.setEnabled(true);
            device.setLastUsedAt(LocalDateTime.now());
            mfaDeviceRepository.save(device);

            // Enable MFA for user
            User user = device.getUser();
            user.setMfaEnabled(true);
            user.setMfaSecret(device.getSecret());
            userRepository.save(user);

            log.info("TOTP MFA enabled for user: {}", user.getId());
            return true;
        }

        return false;
    }

    /**
     * Setup SMS MFA for user.
     */
    @Transactional
    public Map<String, String> setupSms(UUID userId, String phoneNumber) {
        log.info("Setting up SMS MFA for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthenticationException("User not found"));

        // Validate phone number format
        if (!isValidPhoneNumber(phoneNumber)) {
            throw new AuthenticationException("Invalid phone number format");
        }

        // Check if SMS MFA is already set up for this number
        Optional<MfaDevice> existingDevice = mfaDeviceRepository
                .findByUserIdAndTypeAndEnabled(userId, MfaType.SMS, true);

        if (existingDevice.isPresent() && existingDevice.get().getPhoneNumber().equals(phoneNumber)) {
            throw new AuthenticationException("SMS MFA already configured for this phone number");
        }

        // Create MFA device
        MfaDevice device = MfaDevice.builder()
                .user(user)
                .type(MfaType.SMS)
                .deviceName("SMS to " + maskPhoneNumber(phoneNumber))
                .phoneNumber(phoneNumber)
                .verified(false)
                .enabled(false)
                .build();

        mfaDeviceRepository.save(device);

        // Send verification code
        String verificationCode = generateVerificationCode();
        sendSmsCode(phoneNumber, verificationCode);

        // Store verification code in Redis
        String codeKey = MFA_CODE_PREFIX + "sms:" + device.getId();
        redisTemplate.opsForValue().set(codeKey, verificationCode, MFA_CODE_TTL);

        Map<String, String> response = new HashMap<>();
        response.put("deviceId", device.getId().toString());
        response.put("maskedPhoneNumber", maskPhoneNumber(phoneNumber));
        response.put("message", "Verification code sent to your phone");

        return response;
    }

    /**
     * Verify MFA code (TOTP or SMS).
     */
    @Transactional
    public boolean verifyMfaCode(UUID userId, String code, MfaType type) {
        log.debug("Verifying {} MFA code for user: {}", type, userId);

        // Check rate limiting
        if (isMfaBlocked(userId)) {
            throw new AuthenticationException("Too many failed MFA attempts. Please try again later.");
        }

        Optional<MfaDevice> deviceOpt = mfaDeviceRepository
                .findByUserIdAndTypeAndEnabled(userId, type, true);

        if (deviceOpt.isEmpty()) {
            recordFailedMfaAttempt(userId);
            throw new AuthenticationException("MFA device not found or not enabled");
        }

        MfaDevice device = deviceOpt.get();
        boolean isValid = false;

        switch (type) {
            case TOTP:
                isValid = googleAuthenticator.authorize(device.getSecret(), Integer.parseInt(code));
                break;

            case SMS:
            case EMAIL:
                String storedCode = (String) redisTemplate.opsForValue()
                        .get(MFA_CODE_PREFIX + type.toString().toLowerCase() + ":" + userId);
                isValid = code.equals(storedCode);
                if (isValid) {
                    // Delete used code
                    redisTemplate.delete(MFA_CODE_PREFIX + type.toString().toLowerCase() + ":" + userId);
                }
                break;

            case BACKUP_CODES:
                isValid = verifyBackupCode(device, code);
                break;

            default:
                throw new AuthenticationException("Unsupported MFA type: " + type);
        }

        if (isValid) {
            device.setLastUsedAt(LocalDateTime.now());
            mfaDeviceRepository.save(device);
            resetMfaAttempts(userId);
            log.info("MFA verification successful for user: {}", userId);
        } else {
            recordFailedMfaAttempt(userId);
            log.warn("MFA verification failed for user: {}", userId);
        }

        return isValid;
    }

    /**
     * Generate backup codes for user.
     */
    @Transactional
    public List<String> generateBackupCodes(UUID userId) {
        log.info("Generating backup codes for user: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthenticationException("User not found"));

        // Generate backup codes
        List<String> codes = new ArrayList<>();
        SecureRandom random = new SecureRandom();

        for (int i = 0; i < BACKUP_CODES_COUNT; i++) {
            String code = String.format("%08d", random.nextInt(100000000));
            codes.add(code);
        }

        // Store hashed backup codes
        String hashedCodes = hashBackupCodes(codes);

        // Check if backup codes device exists
        Optional<MfaDevice> existingDevice = mfaDeviceRepository
                .findByUserIdAndTypeAndEnabled(userId, MfaType.BACKUP_CODES, true);

        MfaDevice device;
        if (existingDevice.isPresent()) {
            device = existingDevice.get();
            device.setBackupCodes(hashedCodes);
        } else {
            device = MfaDevice.builder()
                    .user(user)
                    .type(MfaType.BACKUP_CODES)
                    .deviceName("Backup Codes")
                    .backupCodes(hashedCodes)
                    .verified(true)
                    .verifiedAt(LocalDateTime.now())
                    .enabled(true)
                    .build();
        }

        mfaDeviceRepository.save(device);

        return codes;
    }

    /**
     * Send MFA code via SMS.
     */
    public void sendSmsCode(UUID userId) {
        log.debug("Sending SMS MFA code to user: {}", userId);

        MfaDevice device = mfaDeviceRepository
                .findByUserIdAndTypeAndEnabled(userId, MfaType.SMS, true)
                .orElseThrow(() -> new AuthenticationException("SMS MFA not configured"));

        String code = generateVerificationCode();
        sendSmsCode(device.getPhoneNumber(), code);

        // Store code in Redis
        String codeKey = MFA_CODE_PREFIX + "sms:" + userId;
        redisTemplate.opsForValue().set(codeKey, code, MFA_CODE_TTL);
    }

    /**
     * Get user's MFA devices.
     */
    @Cacheable(value = "userMfaDevices", key = "#userId")
    public List<MfaDeviceInfo> getUserMfaDevices(UUID userId) {
        List<MfaDevice> devices = mfaDeviceRepository.findByUserId(userId);

        return devices.stream()
                .map(this::toMfaDeviceInfo)
                .collect(Collectors.toList());
    }

    /**
     * Disable MFA device.
     */
    @Transactional
    @CacheEvict(value = "userMfaDevices", key = "#userId")
    public void disableMfaDevice(UUID userId, UUID deviceId) {
        log.info("Disabling MFA device {} for user: {}", deviceId, userId);

        MfaDevice device = mfaDeviceRepository.findById(deviceId)
                .orElseThrow(() -> new AuthenticationException("MFA device not found"));

        if (!device.getUser().getId().equals(userId)) {
            throw new AuthenticationException("Device does not belong to user");
        }

        device.setEnabled(false);
        mfaDeviceRepository.save(device);

        // Check if user has any other enabled MFA devices
        List<MfaDevice> enabledDevices = mfaDeviceRepository
                .findByUserIdAndEnabled(userId, true);

        if (enabledDevices.isEmpty()) {
            // Disable MFA for user if no devices left
            User user = device.getUser();
            user.setMfaEnabled(false);
            user.setMfaSecret(null);
            userRepository.save(user);
        }
    }

    // Private helper methods

    private void sendSmsCode(String phoneNumber, String code) {
        try {
            String messageBody = String.format(
                    "%s: Your verification code is %s. It will expire in 5 minutes.",
                    securityProperties.getMfa().getIssuer(),
                    code
            );

            Message.creator(
                    new com.twilio.type.PhoneNumber(phoneNumber),
                    new com.twilio.type.PhoneNumber(
                            securityProperties.getMfa().getSms().getTwilio().getFromNumber()),
                    messageBody
            ).create();

            log.debug("SMS code sent to: {}", maskPhoneNumber(phoneNumber));
        } catch (Exception e) {
            log.error("Failed to send SMS: {}", e.getMessage());
            throw new AuthenticationException("Failed to send SMS verification code");
        }
    }

    private String generateVerificationCode() {
        SecureRandom random = new SecureRandom();
        return String.format("%06d", random.nextInt(1000000));
    }

    private boolean verifyBackupCode(MfaDevice device, String code) {
        // Implement backup code verification logic
        // This would check against hashed backup codes and mark them as used
        return false; // Placeholder
    }

    private String hashBackupCodes(List<String> codes) {
        // Hash and store backup codes securely
        // In production, use proper hashing for each code
        return String.join(",", codes); // Placeholder - should be hashed
    }

    private boolean isValidPhoneNumber(String phoneNumber) {
        // E.164 format validation
        return phoneNumber != null && phoneNumber.matches("^\\+[1-9]\\d{1,14}$");
    }

    private String maskPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.length() < 4) {
            return "****";
        }
        return phoneNumber.substring(0, 3) + "****" + phoneNumber.substring(phoneNumber.length() - 2);
    }

    private void recordFailedMfaAttempt(UUID userId) {
        String attemptKey = MFA_ATTEMPT_PREFIX + userId;
        Long attempts = redisTemplate.opsForValue().increment(attemptKey);
        redisTemplate.expire(attemptKey, Duration.ofMinutes(15));

        if (attempts != null && attempts >= MAX_MFA_ATTEMPTS) {
            String blockKey = "mfa-block:" + userId;
            redisTemplate.opsForValue().set(blockKey, true, Duration.ofMinutes(15));
        }
    }

    private boolean isMfaBlocked(UUID userId) {
        String blockKey = "mfa-block:" + userId;
        return Boolean.TRUE.equals(redisTemplate.hasKey(blockKey));
    }

    private void resetMfaAttempts(UUID userId) {
        String attemptKey = MFA_ATTEMPT_PREFIX + userId;
        redisTemplate.delete(attemptKey);
    }

    private MfaDeviceInfo toMfaDeviceInfo(MfaDevice device) {
        return MfaDeviceInfo.builder()
                .id(device.getId())
                .type(device.getType())
                .deviceName(device.getDeviceName())
                .verified(device.getVerified())
                .enabled(device.getEnabled())
                .isPrimary(device.getIsPrimary())
                .lastUsedAt(device.getLastUsedAt())
                .createdAt(device.getCreatedAt())
                .build();
    }

    /**
     * DTO for MFA device information.
     */
    @lombok.Data
    @lombok.Builder
    public static class MfaDeviceInfo {
        private UUID id;
        private MfaType type;
        private String deviceName;
        private Boolean verified;
        private Boolean enabled;
        private Boolean isPrimary;
        private LocalDateTime lastUsedAt;
        private LocalDateTime createdAt;
    }
}