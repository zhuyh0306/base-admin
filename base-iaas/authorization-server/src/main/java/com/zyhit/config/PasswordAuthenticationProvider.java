package com.zyhit.config;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import java.security.Principal;
import java.time.Instant;
import java.time.Duration;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

public class PasswordAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationManager authenticationManager;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;

    public PasswordAuthenticationProvider(AuthenticationManager authenticationManager,
                                          RegisteredClientRepository registeredClientRepository,
                                          OAuth2AuthorizationService authorizationService,
                                          Object ignored) {
        this.authenticationManager = authenticationManager;
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PasswordAuthenticationToken passwordAuthenticationToken = (PasswordAuthenticationToken) authentication;
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(
                        passwordAuthenticationToken.getPrincipal(),
                        passwordAuthenticationToken.getCredentials());
        Authentication userAuth = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        if (!userAuth.isAuthenticated()) {
            throw new RuntimeException("用户认证失败");
        }

        // 获取 RegisteredClient
        String clientId = (String) passwordAuthenticationToken.getAdditionalParameters().getOrDefault("client_id", "coin-api");
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new RuntimeException("客户端不存在");
        }

        // 手动生成 AccessToken
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(Duration.ofHours(48));
        Set<String> scopes = Collections.singleton("all");
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                UUID.randomUUID().toString(),
                issuedAt,
                expiresAt,
                scopes
        );

        // 手动生成 RefreshToken（可选）
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            refreshToken = new OAuth2RefreshToken(
                    UUID.randomUUID().toString(),
                    issuedAt,
                    issuedAt.plus(Duration.ofDays(7))
            );
        }

        // 保存授权信息
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(userAuth.getName())
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .attribute(Principal.class.getName(), userAuth)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
        authorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                userAuth,
                accessToken,
                refreshToken,
                Collections.emptyMap()
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}