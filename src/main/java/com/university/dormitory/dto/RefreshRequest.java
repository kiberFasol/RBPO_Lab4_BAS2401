package com.university.dormitory.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO запроса на обновление пары токенов.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RefreshRequest {
    @NotBlank(message = "Refresh-токен обязателен")
    private String refreshToken;
}
