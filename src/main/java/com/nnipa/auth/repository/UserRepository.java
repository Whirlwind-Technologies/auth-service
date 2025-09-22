package com.nnipa.auth.repository;
import com.nnipa.auth.entity.User;
import com.nnipa.auth.enums.UserStatus;
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
 * Repository for User entity.
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByEmail(String email);
    Optional<User> findByUsername(String username);
    Optional<User> findByUsernameOrEmail(String username, String email);
    boolean existsByEmail(String email);
    boolean existsByUsername(String username);
    Optional<User> findByActivationToken(String token);
    Optional<User> findByIdAndTenantId(UUID id, UUID tenantId);

    List<User> findByTenantId(UUID tenantId);

    @Query("SELECT u FROM User u WHERE u.tenantId = :tenantId AND u.status = :status")
    List<User> findByTenantIdAndStatus(@Param("tenantId") UUID tenantId, @Param("status") UserStatus status);

    @Modifying
    @Query("UPDATE User u SET u.status = :status WHERE u.id = :userId")
    void updateUserStatus(@Param("userId") UUID userId, @Param("status") UserStatus status);

    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = null, u.lockReason = null WHERE u.id = :userId")
    void unlockUser(@Param("userId") UUID userId);

    @Query("SELECT u FROM User u WHERE u.lockedUntil < :now AND u.lockedUntil IS NOT NULL")
    List<User> findUsersToUnlock(@Param("now") LocalDateTime now);

    @Query("SELECT u FROM User u LEFT JOIN FETCH u.metadata WHERE u.tenantId = :tenantId AND u.status != 'DELETED'")
    List<User> findByTenantIdWithMetadata(@Param("tenantId") UUID tenantId);
}