package com.university.dormitory.config;

import com.university.dormitory.security.JwtTokenFilter;
import com.university.dormitory.security.JwtTokenProvider;
import com.university.dormitory.security.RestAccessDeniedHandler;
import com.university.dormitory.security.RestAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;
    private final RestAuthenticationEntryPoint authenticationEntryPoint;
    private final RestAccessDeniedHandler accessDeniedHandler;

    /**
     * Создаем JwtTokenFilter. Не объявлен как @Bean, чтобы Spring Boot
     * не зарегистрировал его дополнительно как обычный servlet-фильтр.
     */
    public JwtTokenFilter jwtTokenFilter() {
        return new JwtTokenFilter(jwtTokenProvider);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // JWT передается в заголовке, cookie не используются → CSRF отключен
            .csrf(AbstractHttpConfigurer::disable)
            // Stateless: Spring Security не хранит HTTP-сессию
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
            )
            .authorizeHttpRequests(auth -> auth
                // Публичные эндпоинты (вход, регистрация, обновление токена)
                .requestMatchers(HttpMethod.POST, "/api/auth/register").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/auth/refresh").permitAll()

                // Административные и служебные операции
                .requestMatchers("/api/operations/**").hasAnyRole("ADMIN", "STAFF")

                // Управление комнатами: просмотр — аутентифицированным, модификация — персоналу/админу
                .requestMatchers(HttpMethod.GET, "/api/rooms/**").authenticated()
                .requestMatchers("/api/rooms/**").hasAnyRole("ADMIN", "STAFF")

                // Все остальные запросы требуют аутентификации (детальные ограничения через @PreAuthorize)
                .anyRequest().authenticated()
            )
            // Добавляем JWT-фильтр перед стандартным фильтром аутентификации
            .addFilterBefore(jwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
