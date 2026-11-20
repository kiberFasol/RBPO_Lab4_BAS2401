package com.university.dormitory.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Провайдер JWT-токенов: генерация, валидация, извлечение данных.
 * Поддерживает access- и refresh-токены с различными сроками действия.
 */
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final UserDetailsService userDetailsService;

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.accessExpiration}")
    private long accessExpiration;

    @Value("${jwt.refreshExpiration}")
    private long refreshExpiration;

    // ==================== Ключ подписи ====================

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    // ==================== Создание токенов ====================

    /**
     * Создает access-токен.
     * claim "type" = "access" для отличия от refresh при валидации.
     */
    public String createAccessToken(String email, Collection<? extends GrantedAuthority> authorities) {
        Claims claims = Jwts.claims()
                .subject(email)
                .add("auth", authorities.stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .add("type", "access")
                .build();

        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + accessExpiration);

        return Jwts.builder()
                .claims(claims)
                .issuedAt(now)
                .expiration(expirationDate)
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Создает refresh-токен.
     * claim "type" = "refresh", claim "jti" = уникальный идентификатор сессии.
     * Возвращает массив [tokenString, jti] для сохранения jti в БД.
     */
    public String[] createRefreshToken(String email) {
        String jti = UUID.randomUUID().toString();

        Claims claims = Jwts.claims()
                .subject(email)
                .id(jti)
                .add("type", "refresh")
                .build();

        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + refreshExpiration);

        String token = Jwts.builder()
                .claims(claims)
                .issuedAt(now)
                .expiration(expirationDate)
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();

        return new String[]{token, jti};
    }

    // ==================== Валидация ====================

    /**
     * Проверяет подпись и срок действия токена.
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // ==================== Извлечение данных ====================

    public String getUsername(String token) {
        return parseClaims(token).getSubject();
    }

    public String getTokenType(String token) {
        return parseClaims(token).get("type", String.class);
    }

    public String getTokenId(String token) {
        return parseClaims(token).getId();
    }

    public Date getExpiration(String token) {
        return parseClaims(token).getExpiration();
    }

    public Set<GrantedAuthority> getAuthorities(String token) {
        return ((Collection<?>) parseClaims(token).get("auth", Collection.class))
                .stream()
                .map(authority -> new SimpleGrantedAuthority((String) authority))
                .collect(Collectors.toSet());
    }

    /**
     * Получает Authentication для Spring Security на основе access-токена.
     */
    public Authentication getAuthentication(String token) {
        String username = getUsername(token);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    public long getRefreshExpirationMs() {
        return refreshExpiration;
    }

    // ==================== Вспомогательное ====================

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
