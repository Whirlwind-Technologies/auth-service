package com.nnipa.auth.repository;

import com.nnipa.auth.entity.PasswordHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, UUID> {

    @Query(value = "SELECT * FROM password_history WHERE credential_id = :credentialId " +
            "ORDER BY created_at DESC LIMIT :limit", nativeQuery = true)
    List<PasswordHistory> findRecentByCredentialId(@Param("credentialId") UUID credentialId,
                                                   @Param("limit") Integer limit);

    @Modifying
    @Query(value = "DELETE FROM password_history WHERE credential_id = :credentialId " +
            "AND id NOT IN (SELECT id FROM password_history " +
            "WHERE credential_id = :credentialId ORDER BY created_at DESC LIMIT :keep)",
            nativeQuery = true)
    void deleteOldEntries(@Param("credentialId") UUID credentialId, @Param("keep") Integer keep);
}