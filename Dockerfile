FROM maven:3.9.9-eclipse-temurin-21 AS builder

WORKDIR /app

COPY pom.xml .

RUN mvn dependency:go-offline -B

COPY src ./src

RUN mvn clean package -DskipTests -Pproduction


FROM openjdk:21-jdk AS runner

WORKDIR /app

COPY --from=builder ./app/target/*.jar ./app.jar

EXPOSE 4002

# Health check
#HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
#    CMD curl -f http://localhost:4002/api/v1/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]