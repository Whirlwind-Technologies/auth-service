package com.nnipa.auth.repository;

import com.nnipa.auth.entity.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Repository for LoginAttempt entity.
 */
@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, UUID> {

    List<LoginAttempt> findByUserId(UUID userId);

    List<LoginAttempt> findByUsername(String username);

    List<LoginAttempt> findByIpAddress(String ipAddress);

    @Query("SELECT l FROM LoginAttempt l WHERE l.username = :username AND l.attemptTime > :since AND l.success = false")
    List<LoginAttempt> findRecentFailedAttempts(@Param("username") String username, @Param("since") LocalDateTime since);

    @Query("SELECT l FROM LoginAttempt l WHERE l.ipAddress = :ipAddress AND l.attemptTime > :since AND l.success = false")
    List<LoginAttempt> findRecentFailedAttemptsByIp(@Param("ipAddress") String ipAddress, @Param("since") LocalDateTime since);

    @Query("SELECT COUNT(l) FROM LoginAttempt l WHERE l.username = :username AND l.attemptTime > :since AND l.success = false")
    long countRecentFailedAttempts(@Param("username") String username, @Param("since") LocalDateTime since);

    @Modifying
    @Query("DELETE FROM LoginAttempt l WHERE l.attemptTime < :cutoff")
    void deleteOldAttempts(@Param("cutoff") LocalDateTime cutoff);
}