package com.zyhit.config;

import org.springframework.security.web.authentication.AuthenticationConverter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import java.util.HashMap;
import java.util.Map;
import org.springframework.util.StringUtils;

public class PasswordAuthenticationConverter implements AuthenticationConverter {
    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter("grant_type");
        if (!"password".equals(grantType)) {
            return null;
        }
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String scope = request.getParameter("scope");

        Map<String, Object> additionalParameters = new HashMap<>();
        if (StringUtils.hasText(scope)) {
            additionalParameters.put("scope", scope);
        }
        return new PasswordAuthenticationToken(username, password, additionalParameters);
    }
}