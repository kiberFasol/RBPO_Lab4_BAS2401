package com.university.dormitory.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * DTO ответа при успешной аутентификации.
 * Содержит пару access/refresh токенов.
 */
@Data
@AllArgsConstructor
public class AuthenticationResponse {
    private String email;
    private String accessToken;
    private String refreshToken;
}
