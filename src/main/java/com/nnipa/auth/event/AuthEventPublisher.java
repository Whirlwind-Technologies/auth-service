package com.nnipa.auth.event;

import com.google.protobuf.Timestamp;
import com.nnipa.auth.entity.User;
import com.nnipa.proto.auth.*;
import com.nnipa.proto.command.*;
import com.nnipa.proto.common.EventMetadata;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Service to publish authentication events to Kafka using Protobuf.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthEventPublisher {

    private final KafkaTemplate<String, byte[]> kafkaTemplate;

    @Value("${spring.application.name:auth-service}")
    private String applicationName;

    /**
     * Publish user registration event for self-signup (new tenant).
     */
    public void publishSelfSignupEvent(User user, String activationToken,
                                       String organizationName, String organizationType) {
        try {
            log.info("Publishing self-signup event for user: {} with new tenant", user.getId());

            // Build self-signup event
            SelfSignupEvent event = SelfSignupEvent.newBuilder()
                    .setMetadata(createEventMetadata())
                    .setUserId(user.getId().toString())
                    .setEmail(user.getEmail())
                    .setUsername(user.getUsername() != null ? user.getUsername() : "")
                    .setFirstName(user.getFirstName() != null ? user.getFirstName() : "")
                    .setLastName(user.getLastName() != null ? user.getLastName() : "")
                    .setActivationToken(activationToken)
                    .setOrganizationName(organizationName)
                    .setOrganizationType(organizationType != null ? organizationType : "STANDARD")
                    .setTimestamp(toProtobufTimestamp(Instant.now()))
                    .build();

            // Send to self-signup topic
            String key = user.getId().toString();
            byte[] value = event.toByteArray();

            kafkaTemplate.send("nnipa.events.auth.self-signup", key, value)
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            log.error("Failed to publish self-signup event", ex);
                        } else {
                            log.info("Self-signup event published successfully for user: {}", user.getId());
                        }
                    });

        } catch (Exception e) {
            log.error("Error publishing self-signup event", e);
        }
    }

    /**
     * Publish admin-created user event (existing tenant).
     */
    public void publishAdminCreatedUserEvent(User user, String activationToken, String createdBy) {
        try {
            log.info("Publishing admin-created user event for user: {} in tenant: {}",
                    user.getId(), user.getTenantId());

            // Build admin-created user event
            AdminCreatedUserEvent event = AdminCreatedUserEvent.newBuilder()
                    .setMetadata(createEventMetadata())
                    .setUserId(user.getId().toString())
                    .setTenantId(user.getTenantId().toString())
                    .setEmail(user.getEmail())
                    .setUsername(user.getUsername() != null ? user.getUsername() : "")
                    .setFirstName(user.getFirstName() != null ? user.getFirstName() : "")
                    .setLastName(user.getLastName() != null ? user.getLastName() : "")
                    .setActivationToken(activationToken)
                    .setCreatedBy(createdBy)
                    .setTimestamp(toProtobufTimestamp(Instant.now()))
                    .build();

            // Send to admin-created topic
            String key = user.getTenantId().toString(); // Partition by tenant
            byte[] value = event.toByteArray();

            kafkaTemplate.send("nnipa.events.auth.admin-created-user", key, value)
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            log.error("Failed to publish admin-created user event", ex);
                        } else {
                            log.info("Admin-created user event published successfully");
                        }
                    });

        } catch (Exception e) {
            log.error("Error publishing admin-created user event", e);
        }
    }

    /**
     * Send command to create tenant (for self-signup).
     */
    public CompletableFuture<SendResult<String, byte[]>> sendCreateTenantCommand(
            UUID userId, String organizationName, String organizationType, String email) {

        CreateTenantCommand command = CreateTenantCommand.newBuilder()
                .setMetadata(createEventMetadata())
                .setUserId(userId.toString())
                .setOrganizationName(organizationName)
                .setOrganizationType(organizationType != null ? organizationType : "STANDARD")
                .setOrganizationEmail(email)
                .setOwnerUserId(userId.toString())
                .build();

        String key = userId.toString();
        byte[] value = command.toByteArray();

        return kafkaTemplate.send("nnipa.commands.tenant.create", key, value);
    }

    /**
     * Send command to create user profile.
     */
    public CompletableFuture<SendResult<String, byte[]>> sendCreateUserProfileCommand(
            UUID userId, UUID tenantId, String email, String firstName, String lastName) {

        CreateUserProfileCommand command = CreateUserProfileCommand.newBuilder()
                .setMetadata(createEventMetadata())
                .setUserId(userId.toString())
                .setTenantId(tenantId.toString())
                .setEmail(email)
                .setFirstName(firstName != null ? firstName : "")
                .setLastName(lastName != null ? lastName : "")
                .build();

        String key = userId.toString();
        byte[] value = command.toByteArray();

        return kafkaTemplate.send("nnipa.commands.user.create-profile", key, value);
    }

    /**
     * Send command to assign role.
     */
    public CompletableFuture<SendResult<String, byte[]>> sendAssignRoleCommand(
            UUID userId, UUID tenantId, String role) {

        AssignRoleCommand command = AssignRoleCommand.newBuilder()
                .setMetadata(createEventMetadata())
                .setUserId(userId.toString())
                .setTenantId(tenantId.toString())
                .setRole(role)
                .build();

        String key = userId.toString();
        byte[] value = command.toByteArray();

        return kafkaTemplate.send("nnipa.commands.authz.assign-role", key, value);
    }

    private EventMetadata createEventMetadata() {
        return EventMetadata.newBuilder()
                .setEventId(UUID.randomUUID().toString())
                .setSourceService(applicationName)
                .setVersion("1.0")
                .setTimestamp(toProtobufTimestamp(Instant.now()))
                .setCorrelationId(UUID.randomUUID().toString())
                .build();
    }

    private Timestamp toProtobufTimestamp(Instant instant) {
        return Timestamp.newBuilder()
                .setSeconds(instant.getEpochSecond())
                .setNanos(instant.getNano())
                .build();
    }
}