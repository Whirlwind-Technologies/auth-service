package com.nnipa.auth.repository;

import com.nnipa.auth.entity.MfaDevice;
import com.nnipa.auth.enums.MfaType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for MfaDevice entity.
 */
@Repository
public interface MfaDeviceRepository extends JpaRepository<MfaDevice, UUID> {

    List<MfaDevice> findByUserId(UUID userId);

    List<MfaDevice> findByUserIdAndEnabled(UUID userId, Boolean enabled);

    Optional<MfaDevice> findByUserIdAndTypeAndEnabled(UUID userId, MfaType type, Boolean enabled);

    @Query("SELECT m FROM MfaDevice m WHERE m.user.id = :userId AND m.isPrimary = true")
    Optional<MfaDevice> findPrimaryDevice(@Param("userId") UUID userId);

    boolean existsByUserIdAndType(UUID userId, MfaType type);
}