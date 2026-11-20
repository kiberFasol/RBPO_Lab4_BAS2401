package com.university.dormitory.security;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Фильтр проверки JWT access-токена из заголовка Authorization.
 * Не проверяется на эндпоинтах входа, регистрации и обновления токенов.
 */
@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return "POST".equals(request.getMethod())
                && ("/api/auth/login".equals(path)
                    || "/api/auth/register".equals(path)
                    || "/api/auth/refresh".equals(path));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String token = resolveToken(request);
            if (token != null) {
                // Убедиться, что это access-токен, а не refresh
                String type = jwtTokenProvider.getTokenType(token);
                if (!"access".equals(type)) {
                    throw new BadCredentialsException("Ожидается access-токен");
                }
                var authentication = jwtTokenProvider.getAuthentication(token);
                var context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);
            }
        } catch (JwtException | IllegalArgumentException | AuthenticationException exception) {
            SecurityContextHolder.clearContext();
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (bearerToken == null) {
            return null;
        }
        if (!bearerToken.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw new BadCredentialsException("Ожидается Bearer-токен");
        }
        return bearerToken.substring(7).trim();
    }
}
