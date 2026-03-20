package com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.configs;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * SsoAutoConfiguration
 *
 * @author aalencarvz1
 * @version 1.0.0
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(name = "org.springframework.boot.SpringApplication")
@Import({
        JwtAutoConfiguration.class,
        SecurityAutoConfiguration.class
})
public class ClientProtectorAutoConfiguration {
}
