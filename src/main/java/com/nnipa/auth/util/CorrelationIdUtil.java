package com.nnipa.auth.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;

/**
 * Utility component for handling correlation IDs across the application.
 */
@Slf4j
@Component
public class CorrelationIdUtil {

    private static final String CORRELATION_ID_HEADER = "X-Correlation-Id";
    private static final String CORRELATION_ID_ATTRIBUTE = "correlation-id";

    /**
     * Get correlation ID from various sources in order of preference:
     * 1. HTTP header (from API Gateway)
     * 2. Request attributes (for internal usage)
     * 3. Generate new UUID as fallback
     */
    public String getCorrelationId() {
        // Try HTTP headers first (API Gateway)
        String correlationId = getFromHttpHeaders();
        if (correlationId != null) {
            return correlationId;
        }

        // Try request attributes (internal calls)
        correlationId = getFromRequestAttributes();
        if (correlationId != null) {
            return correlationId;
        }

        // Generate new correlation ID as fallback
        correlationId = UUID.randomUUID().toString();
        log.debug("Generated new correlation ID: {}", correlationId);

        // Store it in request attributes for subsequent calls in the same request
        storeInRequestAttributes(correlationId);

        return correlationId;
    }

    /**
     * Set correlation ID in request attributes for the current request scope.
     */
    public void setCorrelationId(String correlationId) {
        storeInRequestAttributes(correlationId);
    }

    private String getFromHttpHeaders() {
        try {
            RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
            if (attributes instanceof ServletRequestAttributes) {
                HttpServletRequest request = ((ServletRequestAttributes) attributes).getRequest();
                String correlationId = request.getHeader(CORRELATION_ID_HEADER);
                if (correlationId != null && !correlationId.trim().isEmpty()) {
                    log.debug("Found correlation ID in HTTP header: {}", correlationId);
                    return correlationId.trim();
                }
            }
        } catch (Exception e) {
            log.debug("Could not retrieve correlation ID from HTTP headers: {}", e.getMessage());
        }
        return null;
    }

    private String getFromRequestAttributes() {
        try {
            RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
            if (attributes != null) {
                Object correlationId = attributes.getAttribute(CORRELATION_ID_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
                if (correlationId != null) {
                    log.debug("Found correlation ID in request attributes: {}", correlationId);
                    return correlationId.toString();
                }
            }
        } catch (Exception e) {
            log.debug("Could not retrieve correlation ID from request attributes: {}", e.getMessage());
        }
        return null;
    }

    private void storeInRequestAttributes(String correlationId) {
        try {
            RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
            if (attributes != null) {
                attributes.setAttribute(CORRELATION_ID_ATTRIBUTE, correlationId, RequestAttributes.SCOPE_REQUEST);
            }
        } catch (Exception e) {
            log.debug("Could not store correlation ID in request attributes: {}", e.getMessage());
        }
    }
}