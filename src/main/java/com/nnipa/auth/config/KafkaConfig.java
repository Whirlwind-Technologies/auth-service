package com.nnipa.auth.config;

import io.confluent.kafka.serializers.protobuf.KafkaProtobufSerializer;
import io.confluent.kafka.serializers.protobuf.KafkaProtobufSerializerConfig;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaAdmin;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Kafka configuration for publishing events using Protobuf serialization.
 * Integrates with Confluent Schema Registry for schema management.
 */
@Configuration
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers:localhost:9092}")
    private String bootstrapServers;

    @Value("${schema.registry.url:http://localhost:8081}")
    private String schemaRegistryUrl;

    @Value("${spring.application.name:auth-service}")
    private String applicationName;

    /**
     * Kafka Admin configuration for topic management.
     */
    @Bean
    public KafkaAdmin kafkaAdmin() {
        Map<String, Object> configs = new HashMap<>();
        configs.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        return new KafkaAdmin(configs);
    }

    /**
     * Create topics for auth events.
     */
    @Bean
    public NewTopic userRegisteredTopic() {
        return TopicBuilder.name("nnipa.events.auth.user-registered")
                .partitions(3)
                .replicas(1)
                .config("retention.ms", "604800000") // 7 days
                .config("compression.type", "snappy")
                .build();
    }

    @Bean
    public NewTopic passwordChangedTopic() {
        return TopicBuilder.name("nnipa.events.auth.password-changed")
                .partitions(3)
                .replicas(1)
                .config("retention.ms", "604800000")
                .build();
    }

    @Bean
    public NewTopic loginEventTopic() {
        return TopicBuilder.name("nnipa.events.auth.login")
                .partitions(6)
                .replicas(1)
                .config("retention.ms", "259200000") // 3 days
                .build();
    }

    @Bean
    public NewTopic mfaEventTopic() {
        return TopicBuilder.name("nnipa.events.auth.mfa")
                .partitions(3)
                .replicas(1)
                .config("retention.ms", "259200000")
                .build();
    }

    @Bean
    public NewTopic securityAlertTopic() {
        return TopicBuilder.name("nnipa.events.auth.security-alert")
                .partitions(3)
                .replicas(1)
                .config("retention.ms", "2592000000") // 30 days
                .config("min.insync.replicas", "2")
                .build();
    }

    /**
     * Producer factory for Protobuf messages.
     */
    @Bean
    public ProducerFactory<String, Object> producerFactory() {
        Map<String, Object> props = new HashMap<>();

        // Kafka connection
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);

        // Serialization
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class);

        // Schema Registry
        props.put(KafkaProtobufSerializerConfig.SCHEMA_REGISTRY_URL_CONFIG, schemaRegistryUrl);
        props.put(KafkaProtobufSerializerConfig.AUTO_REGISTER_SCHEMAS, true);
        props.put(KafkaProtobufSerializerConfig.USE_LATEST_VERSION, true);

        // Producer performance and reliability
        props.put(ProducerConfig.ACKS_CONFIG, "all"); // Wait for all replicas
        props.put(ProducerConfig.RETRIES_CONFIG, 3);
        props.put(ProducerConfig.BATCH_SIZE_CONFIG, 16384);
        props.put(ProducerConfig.LINGER_MS_CONFIG, 10);
        props.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 33554432);
        props.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, "snappy");
        props.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true); // Exactly-once semantics

        // Client identification
        props.put(ProducerConfig.CLIENT_ID_CONFIG, applicationName + "-producer");

        return new DefaultKafkaProducerFactory<>(props);
    }

    /**
     * KafkaTemplate for sending Protobuf messages.
     */
    @Bean
    public KafkaTemplate<String, Object> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }
}