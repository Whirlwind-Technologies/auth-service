package com.nnipa.auth.repository;

import com.nnipa.auth.entity.OAuth2Account;
import com.nnipa.auth.enums.AuthProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for OAuth2Account entity.
 */
@Repository
public interface OAuth2AccountRepository extends JpaRepository<OAuth2Account, UUID> {

    Optional<OAuth2Account> findByProviderAndProviderUserId(AuthProvider provider, String providerUserId);

    List<OAuth2Account> findByUserId(UUID userId);

    boolean existsByUserIdAndProvider(UUID userId, AuthProvider provider);

    void deleteByUserIdAndProvider(UUID userId, AuthProvider provider);
}