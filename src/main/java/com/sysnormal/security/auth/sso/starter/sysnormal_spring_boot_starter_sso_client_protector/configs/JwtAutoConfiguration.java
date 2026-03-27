package com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.configs;

import com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.properties.jwt.JwtSsoClientProtectorProperties;
import com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.properties.security.SecurityProperties;
import com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.server.auth.filters.JwtAuthenticationFilter;
import com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.services.jwt.JwtSsoClientProtectorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * SecurityAutoConfiguration
 *
 * @author aalencarvz1
 * @version 1.0.0
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(JwtSsoClientProtectorProperties.class)
public class JwtAutoConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(JwtAutoConfiguration.class);
    @Bean
    //@ConditionalOnMissingBean(JwtSsoClientProtectorService.class)
    public JwtSsoClientProtectorService jwtSsoClientProtectorService(JwtSsoClientProtectorProperties jwtSsoClientProtectorProperties) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        logger.debug("INIT {}.{}", this.getClass().getSimpleName(), "jwtSsoClientProtectorService");
        logger.debug("END {}.{}", this.getClass().getSimpleName(), "jwtSsoClientProtectorService");
        return new JwtSsoClientProtectorService(jwtSsoClientProtectorProperties);
    }

    @Bean
    @ConditionalOnMissingBean(name = "jwtAuthenticationFilter")
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtSsoClientProtectorService jwtSsoClientProtectorService, SecurityProperties securityProperties) {
        logger.debug("INIT {}.{}", this.getClass().getSimpleName(), "jwtAuthenticationFilter");
        logger.debug("END {}.{}", this.getClass().getSimpleName(), "jwtAuthenticationFilter");
        return new JwtAuthenticationFilter(jwtSsoClientProtectorService,  securityProperties);
    }
}
