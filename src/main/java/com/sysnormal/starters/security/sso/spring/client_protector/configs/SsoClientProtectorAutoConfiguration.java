package com.sysnormal.starters.security.sso.spring.client_protector.configs;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;

/**
 * Auto configuration class load this starter (aponted on metainf)
 * @author Alencar
 */
@AutoConfiguration
//@ConditionalOnClass(name = "org.springframework.boot.SpringApplication")
@Import({
        WebSecurityAutoConfiguration.class
})
public class SsoClientProtectorAutoConfiguration {}

