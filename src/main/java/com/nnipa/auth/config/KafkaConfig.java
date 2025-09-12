package com.nnipa.auth.config;

import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.*;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

/**
 * Kafka configuration for auth-service with Protobuf serialization.
 */
@Slf4j
@Configuration
@EnableKafka
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers:localhost:9092}")
    private String bootstrapServers;

    @Value("${spring.kafka.schema-registry.url:http://localhost:8081}")
    private String schemaRegistryUrl;

    /**
     * Producer factory for byte[] messages (Protobuf serialized).
     */
    @Bean
    public ProducerFactory<String, byte[]> producerFactory() {
        Map<String, Object> configProps = new HashMap<>();
        configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class);
        configProps.put(ProducerConfig.ACKS_CONFIG, "all");
        configProps.put(ProducerConfig.RETRIES_CONFIG, 3);
        configProps.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);
        configProps.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, "snappy");

        return new DefaultKafkaProducerFactory<>(configProps);
    }

    /**
     * Kafka template for sending byte[] messages.
     */
    @Bean
    public KafkaTemplate<String, byte[]> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }

    // Topic definitions for auth events
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
    public NewTopic createTenantCommandTopic() {
        return TopicBuilder.name("nnipa.commands.tenant.create")
                .partitions(3)
                .replicas(1)
                .build();
    }

    @Bean
    public NewTopic createUserProfileCommandTopic() {
        return TopicBuilder.name("nnipa.commands.user.create-profile")
                .partitions(3)
                .replicas(1)
                .build();
    }

    @Bean
    public NewTopic assignRoleCommandTopic() {
        return TopicBuilder.name("nnipa.commands.authz.assign-role")
                .partitions(3)
                .replicas(1)
                .build();
    }
}