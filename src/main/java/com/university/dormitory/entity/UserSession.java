package com.university.dormitory.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Сущность сессии пользователя.
 * Каждая запись соответствует выданному refresh-токену и позволяет:
 * - отслеживать состояние (ACTIVE / USED / REVOKED),
 * - обнаруживать повторное использование refresh-токена,
 * - отзывать все сессии пользователя.
 */
@Entity
@Table(name = "user_sessions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /** Уникальный идентификатор refresh-токена (claim jti). */
    @Column(name = "refresh_token_id", nullable = false, unique = true)
    private String refreshTokenId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private SessionStatus status = SessionStatus.ACTIVE;

    /** Метка устройства/клиента (передается клиентом при входе, необязательна). */
    @Column(name = "device_id")
    private String deviceId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    /** Время истечения refresh-токена. */
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
}
