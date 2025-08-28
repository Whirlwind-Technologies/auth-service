package com.nnipa.auth.repository;

import com.nnipa.auth.entity.AuditLog;
import com.nnipa.auth.enums.AuditEventType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    @Query("SELECT a FROM AuditLog a WHERE a.userId = :userId ORDER BY a.eventTime DESC")
    List<AuditLog> findRecentByUserId(@Param("userId") UUID userId, Pageable pageable);

    default List<AuditLog> findRecentByUserId(UUID userId, int limit) {
        return findRecentByUserId(userId, Pageable.ofSize(limit));
    }

    Page<AuditLog> findByTenantId(UUID tenantId, Pageable pageable);

    List<AuditLog> findByUserIdAndEventType(UUID userId, AuditEventType eventType);

    @Query("SELECT a FROM AuditLog a WHERE a.eventTime BETWEEN :start AND :end")
    List<AuditLog> findByEventTimeBetween(@Param("start") LocalDateTime start,
                                          @Param("end") LocalDateTime end);

    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.userId = :userId " +
            "AND a.eventType = :eventType AND a.success = false " +
            "AND a.eventTime > :since")
    long countFailedEvents(@Param("userId") UUID userId,
                           @Param("eventType") AuditEventType eventType,
                           @Param("since") LocalDateTime since);

    @Modifying
    @Query("DELETE FROM AuditLog a WHERE a.eventTime < :cutoff")
    int deleteOldLogs(@Param("cutoff") LocalDateTime cutoff);
}