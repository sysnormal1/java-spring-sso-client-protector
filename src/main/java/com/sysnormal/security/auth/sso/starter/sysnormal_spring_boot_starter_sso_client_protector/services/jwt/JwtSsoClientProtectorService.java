package com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.services.jwt;

import com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.properties.jwt.JwtSsoClientProtectorProperties;
import com.sysnormal.security.core.security_core.services.jwt.JwtCoreService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * jwt service
 *
 * @author aalencarvz1
 * @version 1.0.0
 */
//@Service //dont use this in starters
@EnableConfigurationProperties(JwtSsoClientProtectorProperties.class)
public class JwtSsoClientProtectorService extends JwtCoreService {

    private static final Logger logger = LoggerFactory.getLogger(JwtSsoClientProtectorService.class);

    private final JwtSsoClientProtectorProperties jwtSsoClientProtectorProperties;

    public JwtSsoClientProtectorService(JwtSsoClientProtectorProperties jwtSsoClientProtectorProperties) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        super();
        logger.debug("INIT {}.{} {}", this.getClass().getSimpleName(), "JwtSsoClientProtectorService", jwtSsoClientProtectorProperties.getPublicKeyPath());
        this.jwtSsoClientProtectorProperties = jwtSsoClientProtectorProperties;
        this.setPublicPemFilePath(this.jwtSsoClientProtectorProperties.getPublicKeyPath());
        logger.debug("END {}.{}", this.getClass().getSimpleName(), "JwtSsoClientProtectorService");
    }

    public String getAuthenticatedToken() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            return (String) auth.getCredentials();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}
