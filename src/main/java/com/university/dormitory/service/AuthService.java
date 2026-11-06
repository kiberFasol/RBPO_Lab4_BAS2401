package com.university.dormitory.service;

import com.university.dormitory.dto.RegisterRequestDto;
import com.university.dormitory.dto.UserResponseDto;
import com.university.dormitory.entity.User;
import com.university.dormitory.exception.BusinessRuleException;
import com.university.dormitory.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserResponseDto register(RegisterRequestDto dto) {
        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new BusinessRuleException(
                    "Пользователь с адресом электронной почты '" + dto.getEmail() + "' уже зарегистрирован",
                    HttpStatus.CONFLICT
            );
        }

        // Защита от эскалации привилегий: пользователю ВСЕГДА жестко задается базовая роль STUDENT
        User user = User.builder()
                .fullName(dto.getFullName().trim())
                .email(dto.getEmail().trim().toLowerCase())
                .password(passwordEncoder.encode(dto.getPassword()))
                .role("STUDENT")
                .enabled(true)
                .accountNonLocked(true)
                .build();

        User saved = userRepository.save(user);

        return new UserResponseDto(
                saved.getId(),
                saved.getFullName(),
                saved.getEmail(),
                saved.getRole()
        );
    }
}

