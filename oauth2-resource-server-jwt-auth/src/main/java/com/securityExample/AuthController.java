package com.securityExample;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenService tokenService;

    public AuthController(AuthenticationManager authenticationManager, JwtTokenService tokenService) {
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
    }

    @GetMapping
    public String home(Principal principal) {
        return "Hello, " + principal.getName();
    }

    @PostMapping("/token")
    public String token(Authentication authentication) {
        System.out.println("token for " + authentication.getName());
        UserDetails user = (UserDetails) authentication.getPrincipal();
        return this.tokenService.generateAccessToken(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.get("username"), request.get("password"))
        );
        UserDetails user = (UserDetails) authentication.getPrincipal();
        String accessToken = tokenService.generateAccessToken(user);
        String refreshToken = tokenService.generateRefreshToken(user);
        return ResponseEntity.ok(Map.of("accessToken", accessToken, "refreshToken", refreshToken));
    }

    // Refresh Token endpoint
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        String username = tokenService.extractUsername(refreshToken);
        UserDetails user = User.withUsername(username).password("").roles("USER").build();

        if (!tokenService.validateToken(refreshToken, user)) {
            return ResponseEntity.badRequest().body("Invalid refresh token");
        }

        String accessToken = tokenService.generateAccessToken(user);
        return ResponseEntity.ok(Map.of("accessToken", accessToken));
    }
}
