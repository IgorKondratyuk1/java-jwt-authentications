package com.securityExample.service;

import com.securityExample.entity.User;
import com.securityExample.repository.UserRepository;
import com.securityExample.util.UserEmailValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.NoSuchElementException;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final UserEmailValidator emailValidator;

    public User save(User user) throws IOException {
        String password = user.getPassword();
        String encodePassword = passwordEncoder.encode(password);
        user.setPassword(encodePassword);
        return repository.save(user);
    }

    public User update(User user) {
        var existingUser = findUserById(user.getId());
        processEmailChange(user,existingUser);
        updateSecurityInfo(user, existingUser);
        return repository.save(user);
    }

    public Optional<User> findUserByEmail(String email) {
        return repository.findByUserEmail(email);
    }

    public User findById(Long userId) {
        return repository.findById(userId).orElseThrow(
                () -> new NoSuchElementException("Can not find user by ID: " + userId)
        );
    }

    public boolean existsByEmail(String email) {
        return repository.findByUserEmail(email).isPresent();
    }

    private User findUserById(Long userId) {
        return repository.findById(userId)
                .orElseThrow(
                        () -> new NoSuchElementException("Can not find user by ID: " + userId)
                );
    }

    private void updateSecurityInfo(User user, User existingUser) {
        user.setPassword(existingUser.getPassword());
        user.setRole(existingUser.getRole());
    }

    private void processEmailChange(User user,User existingUser) {
        if (isEmailChanged(existingUser.getUserEmail(), user.getUserEmail())) {
            validateNewEmail(user.getUserEmail());
        }
    }

    private void checkDuplicateEmail(String email) {
        var userByEmail = findUserByEmail(email);
        if (userByEmail.isPresent()) {
            throw new RuntimeException("A user with this email already exists");
        }
    }

    private void validateNewEmail(String newEmail) {
        checkDuplicateEmail(newEmail);
        validateEmailFormat(newEmail);
    }

    private void validateEmailFormat(String email) {
        if (!emailValidator.isValid(email)) {
            throw new RuntimeException("Invalid email address");
        }
    }

    public boolean isEmailChanged(String oldEmail, String newEmail) {
        return newEmail != null && !oldEmail.equals(newEmail);
    }
}