package com.securityExample;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;


@Slf4j
@Component
public class JwtRefreshAuthFilter extends OncePerRequestFilter {

    private final HandlerExceptionResolver handlerExceptionResolver;
    private final JwtTokenService tokenService;

    @Autowired
    public JwtRefreshAuthFilter(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver handlerExceptionResolver, JwtTokenService tokenService) {
        this.handlerExceptionResolver = handlerExceptionResolver;
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest httpRequest, @NonNull HttpServletResponse httpResponse, @NonNull FilterChain filterChain) {

        try {
            log.info("Jwt Refresh Auth Filter");
            String requestURI = httpRequest.getRequestURI();

            if (requestURI.startsWith("/login")) {
                filterChain.doFilter(httpRequest, httpResponse);
                return;
            }

            String authorizationHeader = httpRequest.getHeader("Authorization");
            String token = authorizationHeader.substring(7);
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            System.out.println(token);

            if (!requestURI.equals("/refresh")) {
                if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                    if (authentication != null && tokenService.isRefreshToken(token)) {
                        httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        httpResponse.getWriter().write("Refresh has no access.");
                        return;
                    }
                }
            }

            if (!tokenService.isRefreshToken(token)) {
                httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
                httpResponse.getWriter().write("Access has no access.");
                return;
            }

            filterChain.doFilter(httpRequest, httpResponse);
        } catch (Exception e) {
            log.error("Jwt Refresh Auth Filter Chain Exception:", e);
            handlerExceptionResolver.resolveException(httpRequest, httpResponse, null, e);
        }
    }
}
