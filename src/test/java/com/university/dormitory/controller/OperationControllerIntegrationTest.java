package com.university.dormitory.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.university.dormitory.dto.operation.CheckInRequestDto;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDate;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class OperationControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Безопасность: неаутентифицированный запрос возвращает 401 Unauthorized")
    void unauthenticatedRequest_ReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    @Test
    @WithMockUser(username = "admin@university.ru", roles = {"ADMIN"})
    @DisplayName("CRUD проверка: получение списка пользователей администратором")
    void getUsers_WithAdminRole_ReturnsList() throws Exception {
        mockMvc.perform(get("/api/users"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    @WithMockUser(username = "student@university.ru", roles = {"STUDENT"})
    @DisplayName("Безопасность: студент не имеет доступа к просмотру всех пользователей (403 Forbidden)")
    void getUsers_WithStudentRole_ReturnsForbidden() throws Exception {
        mockMvc.perform(get("/api/users"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.error").value("Forbidden"));
    }

    @Test
    @WithMockUser(username = "student@university.ru", roles = {"STUDENT"})
    @DisplayName("CRUD проверка: получение списка комнат аутентифицированным пользователем")
    void getRooms_ReturnsList() throws Exception {
        mockMvc.perform(get("/api/rooms"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    @WithMockUser(username = "admin@university.ru", roles = {"ADMIN"})
    @DisplayName("Операция 4 (интеграция): вызов регламентного закрытия договоров администратором")
    void processExpirations_ReturnsSuccess() throws Exception {
        mockMvc.perform(post("/api/operations/contracts/process-expirations")
                        .with(csrf())
                        .param("asOfDate", LocalDate.now().toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.expiredContractsCount").isNumber())
                .andExpect(jsonPath("$.freedRoomsCount").isNumber());
    }

    @Test
    @WithMockUser(username = "admin@university.ru", roles = {"ADMIN"})
    @DisplayName("Операция 1 (интеграция): ошибка валидации дат заселения (выезд раньше заезда)")
    void checkIn_InvalidDates_ReturnsBadRequest() throws Exception {
        CheckInRequestDto dto = CheckInRequestDto.builder()
                .applicationId(3L)
                .roomId(1L)
                .checkInDate(LocalDate.now().plusMonths(2))
                .checkOutDate(LocalDate.now().plusMonths(1)) // раньше заезда!
                .build();

        mockMvc.perform(post("/api/operations/check-in")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Bad Request"));
    }

    @Test
    @WithMockUser(username = "admin@university.ru", roles = {"ADMIN"})
    @DisplayName("Безопасность: отказ без CSRF токена на POST запрос (403 Forbidden)")
    void checkIn_WithoutCsrf_ReturnsForbidden() throws Exception {
        CheckInRequestDto dto = CheckInRequestDto.builder()
                .applicationId(3L)
                .roomId(1L)
                .checkInDate(LocalDate.now().plusMonths(2))
                .checkOutDate(LocalDate.now().plusMonths(1))
                .build();

        mockMvc.perform(post("/api/operations/check-in")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.error").value("Forbidden"));
    }
}
