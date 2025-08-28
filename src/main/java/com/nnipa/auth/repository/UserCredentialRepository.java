package com.nnipa.auth.repository;

import com.nnipa.auth.entity.UserCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Repository for UserCredential entity.
 */
@Repository
public interface UserCredentialRepository extends JpaRepository<UserCredential, UUID> {

    Optional<UserCredential> findByUserId(UUID userId);

    @Modifying
    @Query("UPDATE UserCredential c SET c.failedAttempts = 0, c.lastFailedAttempt = null WHERE c.user.id = :userId")
    void resetFailedAttempts(@Param("userId") UUID userId);
}