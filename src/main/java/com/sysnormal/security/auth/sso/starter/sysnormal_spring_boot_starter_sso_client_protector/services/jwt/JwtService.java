package com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.services.jwt;

import com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.properties.jwt.JwtProperties;
import com.sysnormal.security.core.security_core.services.jwt.JwtCoreService;
import com.sysnormal.security.core.security_core.utils.KeyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * jwt service
 *
 * @author aalencarvz1
 * @version 1.0.0
 */
//@Service //dont use this in starters
@EnableConfigurationProperties(JwtProperties.class)
public class JwtService extends JwtCoreService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    private final JwtProperties jwtProperties;

    public JwtService(JwtProperties jwtProperties) {
        super();
        this.jwtProperties = jwtProperties;

        try {
            this.setPublicPem(Files.readString(Path.of(jwtProperties.getPublicKeyPath())));
            this.setPublicKey(KeyUtils.parseRsaPublicKey(this.getPublicPem()));
            buildJwtParser(this.getPublicKey());
        } catch (Exception e) {
            throw new IllegalStateException("Error", e);
        }
    }

}
