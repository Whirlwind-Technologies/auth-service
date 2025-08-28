package com.nnipa.auth.repository;

import com.nnipa.auth.entity.SecurityEvent;
import com.nnipa.auth.enums.SecurityEventType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, UUID> {

    List<SecurityEvent> findByUserId(UUID userId);

    List<SecurityEvent> findByUserIdAndResolved(UUID userId, Boolean resolved);

    List<SecurityEvent> findByEventType(SecurityEventType eventType);

    @Query("SELECT s FROM SecurityEvent s WHERE s.resolved = false " +
            "AND s.eventTime < :cutoff")
    List<SecurityEvent> findUnresolvedOlderThan(@Param("cutoff") LocalDateTime cutoff);

    @Query("SELECT COUNT(s) FROM SecurityEvent s WHERE s.userId = :userId " +
            "AND s.eventType = :eventType AND s.eventTime > :since")
    long countRecentEvents(@Param("userId") UUID userId,
                           @Param("eventType") SecurityEventType eventType,
                           @Param("since") LocalDateTime since);
}