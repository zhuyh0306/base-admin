package com.zyhit.filter;

import com.alibaba.fastjson.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Objects;
import java.util.Set;

@Component
public class TokenCheckFilter implements GlobalFilter, Ordered {

    private static final Logger logger = LoggerFactory.getLogger(TokenCheckFilter.class);

    @Value("${no.token.access.urls:/admin/login,/admin/validate/code}")
    private Set<String> noTokenAccessUrls;

    private final JwtDecoder jwtDecoder;
    private final RedisTemplate<String, Object> redisTemplate;

    public TokenCheckFilter(JwtDecoder jwtDecoder, RedisTemplate<String, Object> redisTemplate) {
        this.jwtDecoder = jwtDecoder;
        this.redisTemplate = redisTemplate;
        logger.error("=== TokenCheckFilter CONSTRUCTOR CALLED ===");
        logger.info("TokenCheckFilter initialized with noTokenAccessUrls: {}", noTokenAccessUrls);
    }

    @Override
    public int getOrder() {
        // 设置为最高优先级，确保在路由之前执行
        return -100;
    }

    /**
     * 实现判断用户是否携带token ，或token 错误的功能
     *
     * @param exchange
     * @param chain
     * @return
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        logger.error("=== TokenCheckFilter FILTER METHOD CALLED ===");
        String path = exchange.getRequest().getURI().getPath();
        logger.info("TokenCheckFilter processing request: {}", path);
        
        // 不需要token 就能访问
        if (allowNoTokenAccess(exchange)) {
            logger.info("Path {} is allowed without token", path);
            return chain.filter(exchange);
        }
        
        // 获取用户的token
        String token = getToken(exchange);
        logger.info("Token extracted: {}", token != null ? token.substring(0, Math.min(50, token.length())) + "..." : "null");

        if (!StringUtils.hasText(token)) { // token 为 Empty
            logger.warn("No token provided for path: {}", path);
            return buildUnauthorizedResult(exchange, "Token is required");
        }

        // 验证 JWT token
        try {
            logger.info("Decoding JWT token...");
            Jwt jwt = jwtDecoder.decode(token);
            logger.info("JWT decoded successfully, subject: {}", jwt.getSubject());
            
            // 检查 token 是否在 Redis 中存在（可选，用于支持 token 撤销）
            // 暂时跳过 Redis 检查，直接允许 JWT 验证通过的 token
            // if (!isTokenValidInRedis(token)) {
            //     logger.warn("Token not found in Redis for path: {}", path);
            //     return buildUnauthorizedResult(exchange, "Token has been revoked");
            // }
            
            // 将用户信息添加到请求头中，供下游服务使用
            ServerHttpRequest request = exchange.getRequest().mutate()
                    .header("X-User-Id", jwt.getSubject())
                    .header("X-User-Name", jwt.getSubject())
                    .header("X-Client-Id", jwt.getClaimAsString("client_id"))
                    .build();
            
            logger.info("Request forwarded with user headers for path: {}", path);
            return chain.filter(exchange.mutate().request(request).build());
            
        } catch (JwtException e) {
            logger.error("JWT validation failed for path {}: {}", path, e.getMessage());
            return buildUnauthorizedResult(exchange, "Invalid token: " + e.getMessage());
        }
    }

    private boolean allowNoTokenAccess(ServerWebExchange exchange) {
        String path = exchange.getRequest().getURI().getPath();
        boolean allowed = noTokenAccessUrls.contains(path);
        logger.debug("Path {} allowed without token: {}", path, allowed);
        return allowed;
    }

    /**
     * 从头里面获取
     *
     * @param exchange
     * @return
     */
    private String getToken(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        HttpHeaders headers = request.getHeaders();
        String authorization = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (Objects.isNull(authorization) || authorization.trim().isEmpty()) {
            return null;
        }
        return authorization.replace("Bearer ", "");
    }

    /**
     * 检查 token 是否在 Redis 中有效
     */
    private boolean isTokenValidInRedis(String token) {
        try {
            // 这里可以根据你的 Redis 存储策略来检查
            // 例如：检查 token 是否在黑名单中，或者检查授权信息是否存在
            String key = "oauth2:authorization:token:" + token;
            Object value = redisTemplate.opsForValue().get(key);
            boolean valid = value != null; // 如果存在则认为有效
            logger.debug("Token Redis check result: {}", valid);
            return valid;
        } catch (Exception e) {
            // Redis 连接失败时，默认允许通过（可以根据需要调整策略）
            logger.warn("Redis check failed, defaulting to allow: {}", e.getMessage());
            return true;
        }
    }

    private Mono<Void> buildUnauthorizedResult(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().set("Content-Type", "application/json;charset=UTF-8");
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("error", "unauthorized");
        jsonObject.put("error_description", message);
        jsonObject.put("timestamp", System.currentTimeMillis());
        DataBuffer dataBuffer = response.bufferFactory().wrap(jsonObject.toJSONString().getBytes());
        return response.writeWith(Flux.just(dataBuffer));
    }
} 