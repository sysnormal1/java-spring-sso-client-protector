package com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.server.auth.filters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;

public class JwtAuthenticationException extends AuthenticationException {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationException.class);
    public JwtAuthenticationException(String msg){
        super(msg);
        logger.debug("INIT {}.{}", this.getClass().getSimpleName(), "JwtAuthenticationException");
        logger.debug("END {}.{}", this.getClass().getSimpleName(), "JwtAuthenticationException");
    }
    public JwtAuthenticationException(String msg, Throwable cause) {
        super(msg, cause);
        logger.debug("INIT {}.{}", this.getClass().getSimpleName(), "JwtAuthenticationException");
        logger.debug("END {}.{}", this.getClass().getSimpleName(), "JwtAuthenticationException");
    }
}
