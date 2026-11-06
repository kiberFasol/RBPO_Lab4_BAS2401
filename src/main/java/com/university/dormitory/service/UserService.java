package com.university.dormitory.service;

import com.university.dormitory.dto.UserRequestDto;
import com.university.dormitory.dto.UserResponseDto;
import com.university.dormitory.entity.User;
import com.university.dormitory.exception.ResourceNotFoundException;
import com.university.dormitory.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public List<UserResponseDto> findAll() {
        return userRepository.findAll().stream()
                .map(this::toResponse)
                .toList();
    }

    public UserResponseDto findById(Long id) {
        return toResponse(getOrThrow(id));
    }

    @Transactional
    public UserResponseDto create(UserRequestDto dto) {
        User user = User.builder()
                .fullName(dto.getFullName())
                .email(dto.getEmail())
                .password(passwordEncoder.encode("Default@123"))
                .role(dto.getRole() != null ? dto.getRole() : "STUDENT")
                .enabled(true)
                .accountNonLocked(true)
                .build();
        return toResponse(userRepository.save(user));
    }

    @Transactional
    public UserResponseDto update(Long id, UserRequestDto dto) {
        User user = getOrThrow(id);
        if (dto.getFullName() != null) user.setFullName(dto.getFullName());
        if (dto.getEmail() != null) user.setEmail(dto.getEmail());
        if (dto.getRole() != null) user.setRole(dto.getRole());
        return toResponse(userRepository.save(user));
    }

    @Transactional
    public void delete(Long id) {
        userRepository.delete(getOrThrow(id));
    }

    public User getOrThrow(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User", id));
    }

    private UserResponseDto toResponse(User user) {
        return new UserResponseDto(
                user.getId(),
                user.getFullName(),
                user.getEmail(),
                user.getRole()
        );
    }
}
