package com.university.dormitory.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.university.dormitory.dto.AuthenticationRequest;
import com.university.dormitory.dto.RefreshRequest;
import com.university.dormitory.dto.RegisterRequestDto;
import com.university.dormitory.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

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

    // ==================== Регистрация ====================

    @Test
    @DisplayName("Успешная регистрация: возвращает пару access/refresh и email")
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
                .andExpect(jsonPath("$.email").value(uniqueEmail))
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString());
    }

    @Test
    @DisplayName("Регистрация: слабый пароль → 400 Bad Request")
    void register_WeakPassword_ReturnsBadRequest() throws Exception {
        RegisterRequestDto dto = RegisterRequestDto.builder()
                .fullName("Тестовый Студент")
                .email("weak_pass@university.ru")
                .password("12345")
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Validation Error"));
    }

    @Test
    @DisplayName("Регистрация: дубликат email → 409 Conflict")
    void register_DuplicateEmail_ReturnsConflict() throws Exception {
        String duplicateEmail = "ivanov@university.ru";
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

    // ==================== Вход ====================

    @Test
    @DisplayName("Успешный вход: возвращает пару access/refresh")
    void login_Success() throws Exception {
        AuthenticationRequest request = new AuthenticationRequest(
                "ivanov@university.ru", "Password123!", "test-device"
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("ivanov@university.ru"))
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString());
    }

    @Test
    @DisplayName("Вход с неверным паролем → 401 Unauthorized")
    void login_WrongPassword_ReturnsUnauthorized() throws Exception {
        AuthenticationRequest request = new AuthenticationRequest(
                "ivanov@university.ru", "WrongPassword!", null
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    // ==================== Обновление токенов ====================

    @Test
    @DisplayName("Успешное обновление: старый refresh → новая пара")
    void refresh_Success() throws Exception {
        // Сначала логинимся, чтобы получить refresh
        AuthenticationRequest loginReq = new AuthenticationRequest(
                "petrov@university.ru", "Password123!", null
        );

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andReturn();

        String refreshToken = objectMapper.readTree(
                loginResult.getResponse().getContentAsString()
        ).get("refreshToken").asText();

        // Обновляем
        RefreshRequest refreshReq = new RefreshRequest(refreshToken);
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString());
    }

    @Test
    @DisplayName("Повторное использование refresh-токена → 401 (reuse detection)")
    void refresh_ReuseDetection() throws Exception {
        // Логинимся
        AuthenticationRequest loginReq = new AuthenticationRequest(
                "sidorova@university.ru", "Password123!", null
        );

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andReturn();

        String refreshToken = objectMapper.readTree(
                loginResult.getResponse().getContentAsString()
        ).get("refreshToken").asText();

        // Первое обновление — успешно
        RefreshRequest refreshReq = new RefreshRequest(refreshToken);
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshReq)))
                .andExpect(status().isOk());

        // Повторное использование того же refresh → должно вернуть ошибку
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshReq)))
                .andExpect(status().isUnauthorized());
    }

    // ==================== Доступ к защищенным ресурсам ====================

    @Test
    @DisplayName("Доступ без токена → 401")
    void protectedEndpoint_NoToken_ReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/rooms"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Доступ с валидным access-токеном → 200")
    void protectedEndpoint_WithAccessToken_ReturnsOk() throws Exception {
        // Логинимся
        AuthenticationRequest loginReq = new AuthenticationRequest(
                "ivanov@university.ru", "Password123!", null
        );

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andReturn();

        String accessToken = objectMapper.readTree(
                loginResult.getResponse().getContentAsString()
        ).get("accessToken").asText();

        // Запрос с токеном
        mockMvc.perform(get("/api/rooms")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk());
    }
}
