package com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.server.auth.filters;

import com.sysnormal.commons.core.DefaultDataSwap;
import com.sysnormal.commons.core.utils_core.TextUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    public CustomAccessDeniedHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        String message = accessDeniedException != null ? accessDeniedException.getMessage() : "not authorized";
        if (!TextUtils.hasText(message)) {
            message = "not authorized";
        }
        //String responseBody = "{\"succes\": false, \"message\": \"" +  message + "\", \"data\": null,\"httpStatusCode\": 401, \"exception\": null}";
        DefaultDataSwap body = new DefaultDataSwap();
        body.success = false;
        body.message = message;
        body.exception = accessDeniedException;
        //response.getWriter().write(responseBody); //not use like this
        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
