package com.zyhit.config;

import java.time.Duration;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;

// 只保留你自定义的 Converter/Provider
import com.zyhit.config.PasswordAuthenticationConverter;
import com.zyhit.config.PasswordAuthenticationProvider;

@Configuration
public class AuthorizationServerConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("coin-api")
                .clientSecret(passwordEncoder.encode("coin-secret"))
                .scope("all")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD) // 密码模式
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(48)) // 48小时
                        .refreshTokenTimeToLive(Duration.ofDays(7)) // 7天
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    // RedisTemplate 配置
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        return template;
    }

    // Redis 版 OAuth2AuthorizationService
    @Bean
    public org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizationService(RedisTemplate<String, Object> redisTemplate) {
        return new RedisOAuth2AuthorizationService(redisTemplate);
    }

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            AuthenticationManager authenticationManager,
            AuthorizationServerSettings authorizationServerSettings,
            RegisteredClientRepository registeredClientRepository,
            org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizationService
    ) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http.apply(authorizationServerConfigurer);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationServerSettings(authorizationServerSettings)
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .accessTokenRequestConverter(new PasswordAuthenticationConverter())
                        .authenticationProvider(new PasswordAuthenticationProvider(
                                authenticationManager,
                                registeredClientRepository,
                                authorizationService,
                                null
                        ))
                );
        http.csrf(csrf -> csrf.disable());
        return http.build();
    }
}