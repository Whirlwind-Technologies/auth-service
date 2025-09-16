package com.nnipa.auth.repository;

import com.nnipa.auth.entity.UserCredential;
import com.nnipa.auth.enums.CredentialType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for UserCredential entity - fixed version
 */
@Repository
public interface UserCredentialRepository extends JpaRepository<UserCredential, UUID> {

    Optional<UserCredential> findByUserId(UUID userId);

    // This method was missing - needed by AuthenticationService
    Optional<UserCredential> findByUserIdAndType(UUID userId, CredentialType type);

    List<UserCredential> findByUserIdAndTypeIn(UUID userId, List<CredentialType> types);

    @Modifying
    @Query("UPDATE UserCredential c SET c.failedAttempts = 0, c.lastFailedAttempt = null WHERE c.userId = :userId")
    void resetFailedAttempts(@Param("userId") UUID userId);

    @Modifying
    @Query("DELETE FROM UserCredential c WHERE c.userId = :userId AND c.type = :type")
    void deleteByUserIdAndType(@Param("userId") UUID userId, @Param("type") CredentialType type);

    boolean existsByUserIdAndType(UUID userId, CredentialType type);
}