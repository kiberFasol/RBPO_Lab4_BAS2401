package com.university.dormitory.repository;

import com.university.dormitory.entity.SessionStatus;
import com.university.dormitory.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    Optional<UserSession> findByRefreshTokenId(String refreshTokenId);

    /**
     * Отзыв всех активных сессий пользователя (используется при обнаружении
     * повторного использования refresh-токена — reuse detection).
     */
    @Modifying
    @Query("UPDATE UserSession s SET s.status = :status WHERE s.user.id = :userId AND s.status = 'ACTIVE'")
    int revokeAllActiveSessionsByUserId(@Param("userId") Long userId,
                                        @Param("status") SessionStatus status);

    List<UserSession> findAllByUserIdAndStatus(Long userId, SessionStatus status);
}
