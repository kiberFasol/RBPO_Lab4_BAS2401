package com.university.dormitory.service;

import com.university.dormitory.dto.*;
import com.university.dormitory.entity.SessionStatus;
import com.university.dormitory.entity.User;
import com.university.dormitory.entity.UserSession;
import com.university.dormitory.exception.BusinessRuleException;
import com.university.dormitory.repository.UserRepository;
import com.university.dormitory.repository.UserSessionRepository;
import com.university.dormitory.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;

/**
 * Сервис аутентификации: регистрация, вход, обновление пары токенов.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final UserSessionRepository sessionRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;

    // ==================== Регистрация ====================

    @Transactional
    public AuthenticationResponse register(RegisterRequestDto dto) {
        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new BusinessRuleException(
                    "Пользователь с адресом электронной почты '" + dto.getEmail() + "' уже зарегистрирован",
                    HttpStatus.CONFLICT
            );
        }

        // Пользователю жестко задается базовая роль STUDENT (защита от эскалации привилегий)
        User user = User.builder()
                .fullName(dto.getFullName().trim())
                .email(dto.getEmail().trim().toLowerCase())
                .password(passwordEncoder.encode(dto.getPassword()))
                .role("STUDENT")
                .enabled(true)
                .accountNonLocked(true)
                .build();

        User saved = userRepository.save(user);

        // Сразу выдаём пару токенов, чтобы пользователь мог обращаться к API без отдельного логина
        return issueTokenPair(saved, null);
    }

    // ==================== Вход ====================

    @Transactional
    public AuthenticationResponse login(AuthenticationRequest request) {
        String email = request.getEmail().trim().toLowerCase();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Пользователь не найден"));

        // Spring Security проверит пароль, заблокирован ли аккаунт и т.д.
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, request.getPassword())
        );

        return issueTokenPair(user, request.getDeviceId());
    }

    // ==================== Обновление токенов ====================

    @Transactional
    public AuthenticationResponse refresh(RefreshRequest request) {
        String refreshToken = request.getRefreshToken();

        // 1. Проверяем подпись и срок действия refresh-токена
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new BusinessRuleException("Недействительный refresh-токен", HttpStatus.UNAUTHORIZED);
        }

        // 2. Убедиться, что это именно refresh-токен
        String type = jwtTokenProvider.getTokenType(refreshToken);
        if (!"refresh".equals(type)) {
            throw new BusinessRuleException("Ожидается refresh-токен", HttpStatus.UNAUTHORIZED);
        }

        // 3. Получаем jti из токена и находим сессию в БД
        String jti = jwtTokenProvider.getTokenId(refreshToken);
        UserSession session = sessionRepository.findByRefreshTokenId(jti)
                .orElseThrow(() -> new BusinessRuleException("Сессия не найдена", HttpStatus.UNAUTHORIZED));

        // 4. Проверяем статус сессии
        if (session.getStatus() == SessionStatus.REVOKED) {
            // Сессия уже отозвана — не реагируем (кто-то пытается использовать старый токен)
            throw new BusinessRuleException("Сессия отозвана", HttpStatus.UNAUTHORIZED);
        }

        if (session.getStatus() == SessionStatus.USED) {
            // *** ДЕТЕКТИРОВАНИЕ ПОВТОРНОГО ИСПОЛЬЗОВАНИЯ ***
            // Этот refresh уже был использован ранее, значит токен мог быть скомпрометирован.
            // Отзываем ВСЕ активные сессии пользователя для защиты.
            sessionRepository.revokeAllActiveSessionsByUserId(
                    session.getUser().getId(), SessionStatus.REVOKED);
            throw new BusinessRuleException(
                    "Обнаружено повторное использование refresh-токена. Все сессии отозваны.",
                    HttpStatus.UNAUTHORIZED
            );
        }

        // 5. Помечаем текущую сессию как использованную
        session.setStatus(SessionStatus.USED);
        sessionRepository.save(session);

        // 6. Проверяем, что пользователь из токена совпадает с пользователем сессии
        String email = jwtTokenProvider.getUsername(refreshToken);
        User user = session.getUser();
        if (!user.getEmail().equalsIgnoreCase(email)) {
            throw new BusinessRuleException("Несоответствие пользователя", HttpStatus.UNAUTHORIZED);
        }

        // 7. Выдаем новую пару
        return issueTokenPair(user, session.getDeviceId());
    }

    // ==================== Вспомогательные ====================

    /**
     * Формирует пару access/refresh, сохраняет сессию и возвращает DTO ответа.
     */
    private AuthenticationResponse issueTokenPair(User user, String deviceId) {
        Collection<? extends GrantedAuthority> authorities = getAuthorities(user);

        String accessToken = jwtTokenProvider.createAccessToken(user.getEmail(), authorities);
        String[] refreshResult = jwtTokenProvider.createRefreshToken(user.getEmail());
        String refreshToken = refreshResult[0];
        String jti = refreshResult[1];

        Instant now = Instant.now();
        UserSession session = UserSession.builder()
                .user(user)
                .refreshTokenId(jti)
                .status(SessionStatus.ACTIVE)
                .deviceId(deviceId)
                .createdAt(now)
                .expiresAt(now.plusMillis(jwtTokenProvider.getRefreshExpirationMs()))
                .build();

        sessionRepository.save(session);

        return new AuthenticationResponse(user.getEmail(), accessToken, refreshToken);
    }

    private Collection<? extends GrantedAuthority> getAuthorities(User user) {
        String roleName = user.getRole();
        if (!roleName.startsWith("ROLE_")) {
            roleName = "ROLE_" + roleName;
        }
        return Collections.singletonList(new SimpleGrantedAuthority(roleName));
    }
}
