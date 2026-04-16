package com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.server.auth.filters;

import com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.properties.security.SecurityProperties;
import com.sysnormal.security.auth.sso.starter.sysnormal_spring_boot_starter_sso_client_protector.services.jwt.JwtSsoClientProtectorService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

//@Component
//@Order(Ordered.HIGHEST_PRECEDENCE + 10)
//@EnableConfigurationProperties(SecurityProperties.class)
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtSsoClientProtectorService jwtSsoClientProtectorService;

    private final SecurityProperties securityProperties;

    public JwtAuthenticationFilter(JwtSsoClientProtectorService jwtSsoClientProtectorService, SecurityProperties securityProperties) {
        logger.debug("INIT {}.{}", this.getClass().getSimpleName(), "JwtAuthenticationFilter");
        this.jwtSsoClientProtectorService = jwtSsoClientProtectorService;
        this.securityProperties = securityProperties;
        logger.debug("END {}.{}", this.getClass().getSimpleName(), "JwtAuthenticationFilter");
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        logger.debug("INIT {}.{}", this.getClass().getSimpleName(), "shouldNotFilter");
        logger.debug("END {}.{}", this.getClass().getSimpleName(), "shouldNotFilter");
        return securityProperties.getPublicEndPoints().contains(request.getRequestURI());
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain
    ) throws ServletException, IOException {
        logger.debug("INIT {}.{} {}",this.getClass().getSimpleName(), "doFilterInternal",request.getRequestURI());
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        String token = header.substring(7);
        try {
            Claims claims = jwtSsoClientProtectorService.getClaims(token);
            Long agentId = claims.get("agentId", Long.class);

            // Você pode criar uma implementação própria de UserDetails se quiser
            List<GrantedAuthority> authorities = List.of();
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            agentId,
                            token,
                            authorities
                    );
            authentication.setDetails(claims);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("xxxx 7 setted authentication {} {} {}",authentication.getPrincipal(), authentication.getDetails(), claims);
        } catch (ExpiredJwtException e) {
            throw new JwtAuthenticationException("expired token",e);
        } catch (JwtException e) {
            throw new JwtAuthenticationException("invalid token",e);
        }
        logger.debug("END {}.{} {}",this.getClass().getSimpleName(), "doFilterInternal",request.getRequestURI());
        filterChain.doFilter(request, response);
    }
}
