package com.zyhit.config;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import java.util.concurrent.TimeUnit;

public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {
    private static final String PREFIX = "oauth2:authorization:";
    private final RedisTemplate<String, Object> redisTemplate;

    public RedisOAuth2AuthorizationService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        String key = PREFIX + authorization.getId();
        redisTemplate.opsForValue().set(key, authorization, 2, TimeUnit.DAYS);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        String key = PREFIX + authorization.getId();
        redisTemplate.delete(key);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        String key = PREFIX + id;
        Object obj = redisTemplate.opsForValue().get(key);
        return obj instanceof OAuth2Authorization ? (OAuth2Authorization) obj : null;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        String type = tokenType == null ? null : tokenType.getValue();
        for (String key : redisTemplate.keys(PREFIX + "*")) {
            Object obj = redisTemplate.opsForValue().get(key);
            if (obj instanceof OAuth2Authorization) {
                OAuth2Authorization auth = (OAuth2Authorization) obj;
                if (type == null || "access_token".equals(type)) {
                    if (auth.getAccessToken() != null && auth.getAccessToken().getToken().getTokenValue().equals(token)) {
                        return auth;
                    }
                }
                if (type == null || "refresh_token".equals(type)) {
                    if (auth.getRefreshToken() != null && auth.getRefreshToken().getToken().getTokenValue().equals(token)) {
                        return auth;
                    }
                }
            }
        }
        return null;
    }
} 