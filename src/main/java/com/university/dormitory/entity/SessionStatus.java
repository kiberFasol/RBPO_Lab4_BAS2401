package com.university.dormitory.entity;

/**
 * Статус сессии пользователя (refresh-токена).
 * ACTIVE  — сессия действует, refresh-токен может быть использован.
 * USED    — refresh-токен уже был использован для получения новой пары.
 * REVOKED — сессия отозвана (например, при обнаружении повторного использования).
 */
public enum SessionStatus {
    ACTIVE,
    USED,
    REVOKED
}
