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

        String publicKeyPath = jwtProperties.getPublicKeyPath();

        logger.info("Initializing JwtService with public key path from spring.jwt.public-key-path property: '{}'", publicKeyPath);

        try {
            Path path = Path.of(publicKeyPath);

            logger.debug("Resolved public key path to absolute path: '{}'", path.toAbsolutePath());

            if (!Files.exists(path)) {
                logger.error("Public key file does not exist at path: '{}'", path.toAbsolutePath());
                throw new IllegalStateException("Public key file not found: " + path.toAbsolutePath());
            }

            if (!Files.isReadable(path)) {
                logger.error("Public key file is not readable at path: '{}'", path.toAbsolutePath());
                throw new IllegalStateException("Public key file is not readable: " + path.toAbsolutePath());
            }

            logger.info("Public key file found. Attempting to read file...");

            String pem = Files.readString(path);
            this.setPublicPem(pem);

            logger.info("Successfully read public key file ({} bytes).", pem.length());

            this.setPublicKey(KeyUtils.parseRsaPublicKey(pem));

            logger.info("Successfully parsed RSA public key.");

            buildJwtParser(this.getPublicKey());

            logger.info("JWT parser successfully initialized.");

        } catch (Exception e) {
            logger.error("Failed to initialize JwtService with public key path '{}'. Error: {}",
                    publicKeyPath, e.getMessage(), e);

            throw new IllegalStateException("Failed to initialize JwtService", e);
        }
    }

}
