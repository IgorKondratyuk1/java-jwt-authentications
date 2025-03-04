package com.securityExample;

import com.securityExample.dto.AuthResponse;
import com.securityExample.dto.UserDto;
import com.securityExample.service.AuthenticationService;
import com.securityExample.service.TokenService;
import com.securityExample.util.UserMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Marker;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.Principal;

@Slf4j
@RestController
@AllArgsConstructor
public class AuthController {

    private final AuthenticationService authService;
    private final UserMapper mapper;
    private final TokenService tokenService;


    @GetMapping
    public String home(Principal principal) {
        return "Hello, " + principal.getName();
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody UserDto dto) throws IOException {
        var user = mapper.mapToModel(dto);
        var authResponse = authService.register(user);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody UserDto dto) {
        var user = mapper.mapToModel(dto);
        var authResponse = authService.login(user);
        return ResponseEntity.ok(authResponse);
    }

    // Refresh Token endpoint
//    @PostMapping("/refresh")
//    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
//        String refreshToken = request.get("refreshToken");
//        String username = tokenService.extractUsername(refreshToken);
//        UserDetails user = User.withUsername(username).password("").roles("USER").build();
//
//        if (!tokenService.validateToken(refreshToken, user)) {
//            return ResponseEntity.badRequest().body("Invalid refresh token");
//        }
//
//        String accessToken = tokenService.generateAccessToken(user);
//        return ResponseEntity.ok(Map.of("accessToken", accessToken));
//    }
}
