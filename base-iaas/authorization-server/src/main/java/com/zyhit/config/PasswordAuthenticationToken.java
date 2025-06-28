package com.zyhit.config;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import java.util.Map;

public class PasswordAuthenticationToken extends AbstractAuthenticationToken {
    private final String username;
    private final String password;
    private final Map<String, Object> additionalParameters;

    public PasswordAuthenticationToken(String username, String password, Map<String, Object> additionalParameters) {
        super(null);
        this.username = username;
        this.password = password;
        this.additionalParameters = additionalParameters;
        setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return password;
    }

    @Override
    public Object getPrincipal() {
        return username;
    }

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }
}