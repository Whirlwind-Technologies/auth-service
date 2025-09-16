package com.nnipa.auth.repository;

import com.nnipa.auth.entity.RefreshToken;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for RefreshToken entity.
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findByUserId(UUID userId);

    @Modifying
    @Query("UPDATE RefreshToken r SET r.revoked = true, r.revokedAt = :now, r.revokedReason = :reason " +
            "WHERE r.user.id = :userId AND r.revoked = false")
    void revokeAllUserTokens(@Param("userId") UUID userId, @Param("reason") String reason, @Param("now") LocalDateTime now);

    default void revokeAllUserTokens(UUID userId, String reason) {
        revokeAllUserTokens(userId, reason, LocalDateTime.now());
    }

    @Query("SELECT r FROM RefreshToken r WHERE r.expiresAt < :now AND r.revoked = false")
    List<RefreshToken> findExpiredTokens(@Param("now") LocalDateTime now);

    @Modifying
    @Query("DELETE FROM RefreshToken r WHERE r.expiresAt < :cutoff OR (r.revoked = true AND r.revokedAt < :cutoff)")
    void deleteExpiredTokens(@Param("cutoff") LocalDateTime cutoff);

    @Modifying
    @Transactional
    void deleteByUserId(UUID userId);
}