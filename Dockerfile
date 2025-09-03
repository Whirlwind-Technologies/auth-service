FROM maven:3.9.9-eclipse-temurin-21 AS builder

WORKDIR /app

# Copy and install the local nnipa-protos dependency first
COPY nnipa-protos-1.0.0.jar /tmp/
RUN mvn install:install-file \
    -Dfile=/tmp/nnipa-protos-1.0.0.jar \
    -DgroupId=com.nnipa \
    -DartifactId=nnipa-protos \
    -Dversion=1.0.0 \
    -Dpackaging=jar \
    -DgeneratePom=true

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application
RUN mvn clean package -DskipTests

# Runtime stage - use JRE instead of JDK for smaller image
FROM eclipse-temurin:21-jre-alpine AS runner

# Install curl for health checks and glibc compatibility for Snappy
RUN apk add --no-cache curl libc6-compat

WORKDIR /app

# Copy the JAR file
COPY --from=builder /app/target/*.jar app.jar

# Create non-root user for security
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup && \
    chown -R appuser:appgroup /app

USER appuser

# Expose the correct port
EXPOSE 4002

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:4002/auth-service/actuator/health || exit 1

# JVM options for container environment
ENTRYPOINT ["java", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-XX:InitialRAMPercentage=50.0", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", \
    "app.jar"]