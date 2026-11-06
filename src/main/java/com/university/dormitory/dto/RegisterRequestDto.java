package com.university.dormitory.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequestDto {

    @NotBlank(message = "ФИО обязательно для заполнения")
    @Size(min = 2, max = 255, message = "ФИО должно содержать от 2 до 255 символов")
    private String fullName;

    @NotBlank(message = "Email обязателен для заполнения")
    @Email(message = "Некорректный формат email")
    private String email;

    @NotBlank(message = "Пароль обязателен для заполнения")
    @Size(min = 8, max = 64, message = "Длина пароля должна быть от 8 до 64 символов")
    @Pattern(
        regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!._\\-]).*$",
        message = "Пароль должен содержать минимум одну цифру, одну строчную букву, одну заглавную букву и один специальный символ (@#$%^&+=!._-)"
    )
    private String password;
}

