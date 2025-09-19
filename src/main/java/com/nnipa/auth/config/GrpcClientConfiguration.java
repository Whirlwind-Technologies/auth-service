package com.nnipa.auth.config;

import io.grpc.ClientInterceptor;
import io.grpc.Metadata;
import io.grpc.stub.MetadataUtils;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.client.interceptor.GrpcGlobalClientInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Bean;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall.SimpleForwardingClientCall;
import io.grpc.ForwardingClientCallListener.SimpleForwardingClientCallListener;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import java.util.concurrent.TimeUnit;

/**
 * gRPC Client Configuration for Authentication Service
 */
@Slf4j
@Configuration
public class GrpcClientConfiguration {

    /**
     * Global client interceptor for adding correlation ID to all calls
     */
    @GrpcGlobalClientInterceptor
    public ClientInterceptor correlationIdInterceptor() {
        return new ClientInterceptor() {
            @Override
            public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(
                    MethodDescriptor<ReqT, RespT> method,
                    CallOptions callOptions,
                    Channel next) {

                // Set default deadline if not already set
                if (callOptions.getDeadline() == null) {
                    callOptions = callOptions.withDeadlineAfter(5, TimeUnit.SECONDS);
                }

                return new SimpleForwardingClientCall<ReqT, RespT>(next.newCall(method, callOptions)) {
                    @Override
                    public void start(Listener<RespT> responseListener, Metadata headers) {
                        // Add correlation ID to headers
                        String correlationId = getCurrentCorrelationId();
                        if (correlationId != null) {
                            Metadata.Key<String> correlationKey =
                                    Metadata.Key.of("correlation-id", Metadata.ASCII_STRING_MARSHALLER);
                            headers.put(correlationKey, correlationId);
                        }

                        // Add authentication token if available
                        String authToken = getAuthToken();
                        if (authToken != null) {
                            Metadata.Key<String> authKey =
                                    Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
                            headers.put(authKey, "Bearer " + authToken);
                        }

                        super.start(responseListener, headers);
                    }
                };
            }

            private String getCurrentCorrelationId() {
                // Get from MDC or request context
                return org.slf4j.MDC.get("correlationId");
            }

            private String getAuthToken() {
                // Get from security context if service-to-service auth is needed
                try {
                    var authentication = org.springframework.security.core.context
                            .SecurityContextHolder.getContext().getAuthentication();
                    if (authentication != null && authentication.getCredentials() != null) {
                        return authentication.getCredentials().toString();
                    }
                } catch (Exception e) {
                    log.debug("No auth token available for gRPC call");
                }
                return null;
            }
        };
    }

    /**
     * Logging interceptor for client calls
     */
    @GrpcGlobalClientInterceptor
    public ClientInterceptor loggingInterceptor() {
        return new ClientInterceptor() {
            @Override
            public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(
                    MethodDescriptor<ReqT, RespT> method,
                    CallOptions callOptions,
                    Channel next) {

                final long startTime = System.currentTimeMillis();
                final String methodName = method.getFullMethodName();

                log.debug("gRPC client call started: {}", methodName);

                return new SimpleForwardingClientCall<ReqT, RespT>(next.newCall(method, callOptions)) {
                    @Override
                    public void start(Listener<RespT> responseListener, Metadata headers) {
                        super.start(new SimpleForwardingClientCallListener<RespT>(responseListener) {
                            @Override
                            public void onClose(Status status, Metadata trailers) {
                                long duration = System.currentTimeMillis() - startTime;

                                if (status.isOk()) {
                                    log.debug("gRPC client call completed: {} [{}ms]",
                                            methodName, duration);
                                } else {
                                    log.warn("gRPC client call failed: {} [{}ms] - {} {}",
                                            methodName, duration, status.getCode(), status.getDescription());
                                }

                                super.onClose(status, trailers);
                            }
                        }, headers);
                    }
                };
            }
        };
    }

    /**
     * Retry interceptor for handling transient failures
     */
    @GrpcGlobalClientInterceptor
    public ClientInterceptor retryInterceptor() {
        return new ClientInterceptor() {
            @Override
            public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(
                    MethodDescriptor<ReqT, RespT> method,
                    CallOptions callOptions,
                    Channel next) {

                // Configure retry policy based on method
                if (shouldRetry(method)) {
                    // Add retry configuration to call options
                    // This is simplified - in production, use a proper retry library
                    return new RetryingClientCall<>(next.newCall(method, callOptions), 3, 1000);
                }

                return next.newCall(method, callOptions);
            }

            private boolean shouldRetry(MethodDescriptor<?, ?> method) {
                // Only retry idempotent operations
                String methodName = method.getFullMethodName();
                return methodName.contains("Get") ||
                        methodName.contains("TenantExists") ||
                        methodName.contains("Status");
            }
        };
    }

    /**
     * Simple retry wrapper for client calls
     */
    private static class RetryingClientCall<ReqT, RespT> extends SimpleForwardingClientCall<ReqT, RespT> {
        private final int maxRetries;
        private final long retryDelayMs;
        private int attemptCount = 0;

        protected RetryingClientCall(ClientCall<ReqT, RespT> delegate, int maxRetries, long retryDelayMs) {
            super(delegate);
            this.maxRetries = maxRetries;
            this.retryDelayMs = retryDelayMs;
        }

        @Override
        public void start(Listener<RespT> responseListener, Metadata headers) {
            super.start(new SimpleForwardingClientCallListener<RespT>(responseListener) {
                @Override
                public void onClose(Status status, Metadata trailers) {
                    if (!status.isOk() && isRetriable(status) && attemptCount < maxRetries) {
                        attemptCount++;
                        log.debug("Retrying gRPC call, attempt {}/{}", attemptCount, maxRetries);

                        try {
                            Thread.sleep(retryDelayMs * attemptCount); // Exponential backoff
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }

                        // Retry the call
                        RetryingClientCall.this.start(responseListener, headers);
                    } else {
                        super.onClose(status, trailers);
                    }
                }

                private boolean isRetriable(Status status) {
                    return status.getCode() == Status.Code.UNAVAILABLE ||
                            status.getCode() == Status.Code.DEADLINE_EXCEEDED ||
                            status.getCode() == Status.Code.RESOURCE_EXHAUSTED;
                }
            }, headers);
        }
    }
}