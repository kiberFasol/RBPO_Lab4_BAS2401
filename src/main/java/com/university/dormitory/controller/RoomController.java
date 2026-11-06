package com.university.dormitory.controller;

import com.university.dormitory.dto.RoomRequestDto;
import com.university.dormitory.dto.RoomResponseDto;
import com.university.dormitory.service.RoomService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/rooms")
@RequiredArgsConstructor
public class RoomController {

    private final RoomService roomService;

    @GetMapping
    public ResponseEntity<List<RoomResponseDto>> getAll() {
        return ResponseEntity.ok(roomService.findAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<RoomResponseDto> getById(@PathVariable Long id) {
        return ResponseEntity.ok(roomService.findById(id));
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<RoomResponseDto> create(@RequestBody RoomRequestDto dto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(roomService.create(dto));
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'STAFF')")
    public ResponseEntity<RoomResponseDto> update(@PathVariable Long id,
                                                   @RequestBody RoomRequestDto dto) {
        return ResponseEntity.ok(roomService.update(id, dto));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasRole('ADMIN')")
    public void delete(@PathVariable Long id) {
        roomService.delete(id);
    }
}
