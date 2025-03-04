package com.securityExample.service;

import com.securityExample.dto.AuthResponse;
import com.securityExample.entity.Role;
import com.securityExample.entity.Token;
import com.securityExample.entity.User;
import com.securityExample.util.PasswordValidator;
import com.securityExample.util.UserEmailValidator;
import com.securityExample.util.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthenticationService {
    private final PasswordValidator passwordValidator;
    private final UserEmailValidator emailValidator;
    private final UserService userService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final UserMapper userDtoMapper;


    public AuthResponse register(User user) throws IOException {
        var newUser = registerNewUser(user);
        String jwtToken = manageUserTokens(newUser);
        return createNewAuthResponse(jwtToken, newUser);
    }


    public AuthResponse login(User user) {
        var authenticatedUser = authenticateUser(user);
        String jwtToken = manageUserTokens(authenticatedUser);
        return createNewAuthResponse(jwtToken, authenticatedUser);
    }

    private User authenticateUser(User user) {
        Optional<User> userByEmail = userService.findUserByEmail(user.getUserEmail().toLowerCase());
        checkUserCredentials(user.getPassword(), userByEmail);
        return userByEmail.get();
    }

    private User registerNewUser(User user) throws IOException {
        validateUserRegistrationData(user);
        var newUser = userService.save(createNewUser(user));
        return newUser;
    }

    private String manageUserTokens(User user) {
        String jwtToken = jwtService.generateToken(user);
        var token = createNewToken(jwtToken, user);
        revokeAllUserTokens(user);
        tokenService.deleteInvalidTokensByUserId(user.getId());
        tokenService.save(token);
        return jwtToken;
    }

    private void validateUserRegistrationData(User user) {
        String lowercaseEmail = user.getUserEmail().toLowerCase();
        user.setUserEmail(lowercaseEmail);
        validateEmailAndPassword(user);
        var userByEmail = userService.findUserByEmail(user.getUserEmail());
        checkForDuplicateEmail(userByEmail);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenService.findAllValidTokensByUserId(user.getId());
        if (validUserTokens.isEmpty()) {
            return;
        }
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenService.saveAll(validUserTokens);
    }

    private void checkUserCredentials(String password, Optional<User> user) {
        if (user.isEmpty()
                || !passwordEncoder.matches(password, user.get().getPassword())) {
            throw new RuntimeException("Incorrect username or password!!!");
        }
    }

    private void checkForDuplicateEmail(Optional<User> user) {
        if (user.isPresent()) {
            throw new RuntimeException("A user with this email already exists");
        }
    }

    private void validateEmailAndPassword(User user) {
        if (!emailValidator.isValid(user.getUserEmail())) {
            throw new RuntimeException("Invalid email address");
        }
        if (!passwordValidator.isValid(user.getPassword())) {
            throw new RuntimeException("Passwords must be 8 to 16 characters long and contain "
                    + "at least one letter, one digit, and one special character.");
        }
    }

    private AuthResponse createNewAuthResponse(String jwtToken, User user) {
        var userDto = userDtoMapper.mapToDto(user);
        return AuthResponse.builder()
                .token(jwtToken)
                .userDto(userDto)
                .build();
    }

    private Token createNewToken(String jwtToken, User savedUser) {
        return Token.builder()
                .user(savedUser)
                .token(jwtToken)
                .expired(false)
                .revoked(false)
                .build();
    }

    private User createNewUser(User user) {
        return User.builder()
                .userName(user.getUserName())
                .userEmail(user.getUserEmail())
                .password(user.getPassword())
                .role(Role.USER)
                .build();
    }
}