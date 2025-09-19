package com.nnipa.auth.event.consumer;

import com.nnipa.auth.service.TemporaryTenantTracker;
import com.google.protobuf.InvalidProtocolBufferException;
import com.nnipa.auth.entity.User;
import com.nnipa.auth.repository.UserRepository;
import com.nnipa.proto.tenant.TenantCreationResponseEvent;
import com.nnipa.proto.tenant.UpdateUserTenantAssociationCommand;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;
import java.util.Optional;

/**
 * Kafka consumer in auth-service to handle tenant creation responses.
 * Updates user records with actual tenant IDs after async tenant creation.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TenantResponseConsumer {

    private final UserRepository userRepository;
    private final KafkaTemplate<String, byte[]> kafkaTemplate;
    private final TemporaryTenantTracker temporaryTenantTracker;


    /**
     * Handle tenant creation response from tenant-management-service.
     * Updates the user's tenant association from temporary to actual tenant ID.
     */
    @KafkaListener(
            topics = "${kafka.topics.tenant-creation-response:nnipa.events.tenant.creation-response}",
            groupId = "${spring.kafka.consumer.group-id}",
            containerFactory = "kafkaListenerContainerFactory"
    )
    @Transactional
    public void handleTenantCreationResponse(
            @Payload byte[] message,
            @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
            @Header(KafkaHeaders.RECEIVED_KEY) String key,
            @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
            @Header(KafkaHeaders.OFFSET) long offset,
            Acknowledgment acknowledgment) {

        log.info("Received TenantCreationResponse from topic: {}, partition: {}, offset: {}, key: {}",
                topic, partition, offset, key);

        try {
            // Parse the protobuf message
            TenantCreationResponseEvent response = TenantCreationResponseEvent.parseFrom(message);
            String correlationId = response.getMetadata().getCorrelationId();

            log.info("Processing TenantCreationResponse for user: {} with tenant: {} [correlationId: {}]",
                    response.getUserId(), response.getTenantId(), correlationId);

            if ("SUCCESS".equals(response.getStatus())) {
                updateUserTenantAssociation(response);
            } else if ("FAILED".equals(response.getStatus())) {
                handleTenantCreationFailure(response);
            } else if ("DUPLICATE".equals(response.getStatus())) {
                handleDuplicateTenant(response);
            }

            // Acknowledge message after successful processing
            acknowledgment.acknowledge();

        } catch (InvalidProtocolBufferException e) {
            log.error("Failed to parse TenantCreationResponseEvent from offset: {}", offset, e);
            // Acknowledge to avoid stuck messages
            acknowledgment.acknowledge();
        } catch (Exception e) {
            log.error("Failed to process TenantCreationResponseEvent from offset: {}", offset, e);
            // Don't acknowledge - let it retry
        }
    }

    /**
     * Update user's tenant association with the actual tenant ID.
     */
    private void updateUserTenantAssociation(TenantCreationResponseEvent response) {
        try {
            // Find user by ID or email
            Optional<User> userOpt = findUser(response.getUserId(), response.getUserEmail());

            if (userOpt.isPresent()) {
                User user = userOpt.get();
                UUID oldTenantId = user.getTenantId();
                UUID newTenantId = UUID.fromString(response.getTenantId());

                // Check if it's a temporary tenant ID using the tracker
                if (temporaryTenantTracker.isTemporary(oldTenantId)) {
                    // Update user's tenant ID
                    user.setTenantId(newTenantId);
                    userRepository.save(user);

                    log.info("Updated user {} tenant association from temporary {} to actual {}",
                            user.getId(), oldTenantId, newTenantId);

                    // Remove temporary tenant from tracker
                    temporaryTenantTracker.removeTemporaryTenant(oldTenantId);

                    // Publish event for audit and other services
                    publishUserTenantUpdatedEvent(user, oldTenantId, newTenantId, response);

                } else if (oldTenantId.equals(newTenantId)) {
                    log.debug("User {} already has the correct tenant ID: {}",
                            user.getId(), newTenantId);
                } else {
                    log.warn("User {} has tenant ID {} which is not temporary, expected update to {}",
                            user.getId(), oldTenantId, newTenantId);
                }
            } else {
                log.error("User not found for tenant creation response: userId={}, email={}",
                        response.getUserId(), response.getUserEmail());

                // You might want to retry or send to DLQ
            }

        } catch (Exception e) {
            log.error("Failed to update user tenant association", e);
            throw e; // Rethrow to trigger retry
        }
    }

    /**
     * Handle tenant creation failure.
     */
    private void handleTenantCreationFailure(TenantCreationResponseEvent response) {
        log.error("Tenant creation failed for user: {} with error: {}",
                response.getUserId(), response.getErrorMessage());

        // Find user and update status
        Optional<User> userOpt = findUser(response.getUserId(), response.getUserEmail());

        if (userOpt.isPresent()) {
            User user = userOpt.get();

            // You might want to:
            // 1. Set a flag indicating tenant creation failed
            // 2. Send notification to user
            // 3. Allow retry through UI

            user.getMetadata().put("tenant_creation_failed", "true");
            user.getMetadata().put("tenant_creation_error", response.getErrorMessage());
            userRepository.save(user);

            // Send notification
            publishTenantCreationFailedNotification(user, response);
        }
    }

    /**
     * Handle duplicate tenant scenario.
     */
    private void handleDuplicateTenant(TenantCreationResponseEvent response) {
        log.info("Duplicate tenant detected for user: {}, using existing tenant: {}",
                response.getUserId(), response.getTenantId());

        // Still update the user's tenant association
        updateUserTenantAssociation(response);
    }

    /**
     * Find user by ID or email.
     */
    private Optional<User> findUser(String userId, String userEmail) {
        try {
            // Try by ID first
            if (userId != null && !userId.isEmpty()) {
                try {
                    UUID id = UUID.fromString(userId);
                    Optional<User> user = userRepository.findById(id);
                    if (user.isPresent()) {
                        return user;
                    }
                } catch (IllegalArgumentException e) {
                    log.debug("Invalid UUID format for userId: {}", userId);
                }
            }

            // Try by email as fallback
            if (userEmail != null && !userEmail.isEmpty()) {
                return userRepository.findByEmail(userEmail);
            }

            return Optional.empty();

        } catch (Exception e) {
            log.error("Error finding user", e);
            return Optional.empty();
        }
    }

    /**
     * Check if tenant ID is temporary (generated when sync call failed).
     */
    private boolean isTemporaryTenantId(UUID tenantId) {
        return temporaryTenantTracker.isTemporary(tenantId);
    }

    /**
     * Publish event when user's tenant association is updated.
     */
    private void publishUserTenantUpdatedEvent(User user, UUID oldTenantId, UUID newTenantId,
                                               TenantCreationResponseEvent response) {
        try {
            UpdateUserTenantAssociationCommand command = UpdateUserTenantAssociationCommand.newBuilder()
                    .setMetadata(com.nnipa.proto.common.EventMetadata.newBuilder()
                            .setEventId(UUID.randomUUID().toString())
                            .setCorrelationId(response.getMetadata().getCorrelationId())
                            .setSourceService("auth-service")
                            .setEventType("UserTenantAssociationUpdated")
                            .setTimestamp(com.google.protobuf.Timestamp.newBuilder()
                                    .setSeconds(System.currentTimeMillis() / 1000)
                                    .build())
                            .build())
                    .setUserId(user.getId().toString())
                    .setOldTenantId(oldTenantId.toString())
                    .setNewTenantId(newTenantId.toString())
                    .setTenantCode(response.getTenantCode())
                    .setUpdatedAt(com.google.protobuf.Timestamp.newBuilder()
                            .setSeconds(System.currentTimeMillis() / 1000)
                            .build())
                    .build();

            kafkaTemplate.send(
                    "nnipa.events.user.tenant.updated",
                    user.getId().toString(),
                    command.toByteArray()
            );

            log.info("Published UserTenantAssociationUpdated event for user: {}", user.getId());

        } catch (Exception e) {
            log.error("Failed to publish UserTenantAssociationUpdated event", e);
        }
    }

    /**
     * Send notification about tenant creation failure.
     */
    private void publishTenantCreationFailedNotification(User user, TenantCreationResponseEvent response) {
        // Publish to notification service
        // Implementation depends on your notification service structure
        log.info("Publishing tenant creation failure notification for user: {}", user.getId());
    }
}