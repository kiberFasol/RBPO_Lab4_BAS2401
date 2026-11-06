package com.university.dormitory.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.university.dormitory.dto.RegisterRequestDto;
import com.university.dormitory.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("CSRF эндпоинт доступен без аутентификации")
    void getCsrfToken_ReturnsToken() throws Exception {
        mockMvc.perform(get("/api/csrf"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isString())
                .andExpect(jsonPath("$.headerName").value("X-XSRF-TOKEN"));
    }

    @Test
    @DisplayName("Успешная регистрация нового пользователя (назначается роль STUDENT)")
    void register_Success() throws Exception {
        String uniqueEmail = "new_student_" + System.currentTimeMillis() + "@university.ru";
        RegisterRequestDto dto = RegisterRequestDto.builder()
                .fullName("Тестовый Студент")
                .email(uniqueEmail)
                .password("SecurePass123!")
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.email").value(uniqueEmail))
                .andExpect(jsonPath("$.role").value("STUDENT"));
    }

    @Test
    @DisplayName("Регистрация: слабый пароль вызывает ошибку 400 Bad Request")
    void register_WeakPassword_ReturnsBadRequest() throws Exception {
        RegisterRequestDto dto = RegisterRequestDto.builder()
                .fullName("Тестовый Студент")
                .email("weak_pass@university.ru")
                .password("12345") // Слишком короткий и без спецсимволов/букв
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Validation Error"));
    }

    @Test
    @DisplayName("Регистрация: дубликат email вызывает ошибку 409 Conflict")
    void register_DuplicateEmail_ReturnsConflict() throws Exception {
        String duplicateEmail = "ivanov@university.ru"; // Пользователь уже есть в тестовых данных
        RegisterRequestDto dto = RegisterRequestDto.builder()
                .fullName("Другой Иванов")
                .email(duplicateEmail)
                .password("SecurePass123!")
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409));
    }
}

