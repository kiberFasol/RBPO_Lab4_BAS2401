package com.university.dormitory.security;

import com.university.dormitory.entity.HousingApplication;
import com.university.dormitory.entity.ResidenceContract;
import com.university.dormitory.entity.RoomTransferRequest;
import com.university.dormitory.repository.HousingApplicationRepository;
import com.university.dormitory.repository.ResidenceContractRepository;
import com.university.dormitory.repository.RoomTransferRequestRepository;
import com.university.dormitory.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component("securityService")
@RequiredArgsConstructor
public class SecurityService {

    private final UserRepository userRepository;
    private final HousingApplicationRepository applicationRepository;
    private final ResidenceContractRepository contractRepository;
    private final RoomTransferRequestRepository transferRequestRepository;

    /**
     * Проверка, является ли аутентифицированный пользователь администратором/персоналом
     * или владельцем пользователя с userId.
     */
    public boolean isUserOwnerOrStaff(Long userId, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        if (hasElevatedPrivileges(authentication)) {
            return true;
        }
        String currentUserEmail = authentication.getName();
        return userRepository.findById(userId)
                .map(user -> user.getEmail().equalsIgnoreCase(currentUserEmail))
                .orElse(false);
    }

    /**
     * Проверка владения заявкой на проживание (HousingApplication).
     */
    public boolean isApplicationOwnerOrStaff(Long applicationId, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        if (hasElevatedPrivileges(authentication)) {
            return true;
        }
        String currentUserEmail = authentication.getName();
        return applicationRepository.findById(applicationId)
                .map(app -> app.getUser() != null && app.getUser().getEmail().equalsIgnoreCase(currentUserEmail))
                .orElse(false);
    }

    /**
     * Проверка владения договором (ResidenceContract).
     */
    public boolean isContractOwnerOrStaff(Long contractId, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        if (hasElevatedPrivileges(authentication)) {
            return true;
        }
        String currentUserEmail = authentication.getName();
        return contractRepository.findById(contractId)
                .map(contract -> contract.getApplication() != null
                        && contract.getApplication().getUser() != null
                        && contract.getApplication().getUser().getEmail().equalsIgnoreCase(currentUserEmail))
                .orElse(false);
    }

    /**
     * Проверка владения запросом на переселение (RoomTransferRequest).
     */
    public boolean isTransferOwnerOrStaff(Long transferId, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        if (hasElevatedPrivileges(authentication)) {
            return true;
        }
        String currentUserEmail = authentication.getName();
        return transferRequestRepository.findById(transferId)
                .map(req -> req.getContract() != null
                        && req.getContract().getApplication() != null
                        && req.getContract().getApplication().getUser() != null
                        && req.getContract().getApplication().getUser().getEmail().equalsIgnoreCase(currentUserEmail))
                .orElse(false);
    }

    public boolean hasElevatedPrivileges(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN") || a.getAuthority().equals("ROLE_STAFF"));
    }
}

