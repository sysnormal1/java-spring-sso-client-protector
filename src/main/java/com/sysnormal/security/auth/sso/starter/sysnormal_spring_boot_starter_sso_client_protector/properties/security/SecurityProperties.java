package com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.properties.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * security properties
 *
 * @author aalencarvz1
 * @version 1.0.0
 */
@ConfigurationProperties(prefix = "spring.security")
@Getter
@Setter
public class SecurityProperties {
    private boolean enabled = true;

    public List<String> publicEndPoints = List.of();

}
