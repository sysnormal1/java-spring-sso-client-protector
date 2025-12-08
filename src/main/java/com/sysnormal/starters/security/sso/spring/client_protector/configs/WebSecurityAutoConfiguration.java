package com.sysnormal.starters.security.sso.spring.client_protector.configs;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sysnormal.starters.security.sso.spring.client_protector.services.SsoClientProtectorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * auto configuration web security
 * @author Alencar
 * @version 1.0.0
 */
@AutoConfiguration
@EnableWebSecurity
@ConditionalOnProperty(prefix = "sso.client.protection", name = "enabled", havingValue = "true", matchIfMissing = true)
public class WebSecurityAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(WebSecurityAutoConfiguration.class);

    @Value("${app.security.public-endpoints}")
    private List<String> publicEndpoints;

    @Bean
    @ConditionalOnMissingBean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean
    @ConditionalOnMissingBean
    public SsoClientProtectorService ssoClientProtectorService(
            @Value("${sso.base-endpoint}") String baseSsoEndpoint,
            @Value("${sso.check-token-endpoint}") String checkToken,
            @Value("${app.security.public-endpoints}") List<String> publicEndpoints,
            ObjectMapper mapper
    ) {
        return new SsoClientProtectorService(
                baseSsoEndpoint,
                checkToken,
                publicEndpoints,
                mapper
        );
    }



    /**
     * Configure cors
     *
     * @return the cors configuration
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("*"); // ou coloque a origem específica do seu front
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(false); // ou true, se usar cookies/sessão

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    /**
     * filter chain
     *
     * @param http the http security request
     * @param baseSsoAuthenticationFilterCheck the base client filter check
     * @return the security filter chain
     * @throws Exception throw exception if error on http build
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, SsoClientProtectorService baseSsoAuthenticationFilterCheck) throws Exception {
        logger.debug("public endpoints: {} {}", Arrays.toString(publicEndpoints.toArray(new String[0])),publicEndpoints);
        http.csrf(csrf -> csrf.disable()) // desabilita CSRF no novo padrão
                .cors(Customizer.withDefaults())             // habilita CORS (pode customizar aqui)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(publicEndpoints.toArray(new String[0]))
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                )
                .addFilterBefore(baseSsoAuthenticationFilterCheck, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        ;
        return http.build();
    }

}
