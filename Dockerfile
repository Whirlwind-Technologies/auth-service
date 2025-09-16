# Build stage
FROM maven:3.9-eclipse-temurin-21 AS builder

# Build arguments for GitHub authentication
ARG GITHUB_ACTOR
ARG GITHUB_TOKEN

WORKDIR /app

# Copy pom.xml and download dependencies
COPY pom.xml .

# Create Maven settings.xml with GitHub authentication
RUN mkdir -p /root/.m2 && \
    printf '<?xml version="1.0" encoding="UTF-8"?>\n<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"\n          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0\n          http://maven.apache.org/xsd/settings-1.0.0.xsd">\n    <servers>\n        <server>\n            <id>github</id>\n            <username>%s</username>\n            <password>%s</password>\n        </server>\n    </servers>\n</settings>\n' "$GITHUB_ACTOR" "$GITHUB_TOKEN" > /root/.m2/settings.xml

# Download dependencies first (for better layer caching)
RUN mvn dependency:go-offline -B || true

# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:21-jre-alpine

# Install curl for health checks
RUN apk add --no-cache curl

# Create non-root user
RUN addgroup -g 1001 -S appuser && \
    adduser -u 1001 -S appuser -G appuser

# Create directories
RUN mkdir -p /app/logs && \
    chown -R appuser:appuser /app

WORKDIR /app

# Copy JAR from builder
COPY --from=builder --chown=appuser:appuser /app/target/*.jar app.jar

# Switch to non-root user
USER appuser

# JVM options for container environment
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75.0 \
    -XX:+UseG1GC \
    -XX:+UseStringDeduplication \
    -Djava.security.egd=file:/dev/./urandom"

# Expose port
EXPOSE 4002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:4002/auth-service/actuator/health || exit 1

# Run the application
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]