package com.securityExample;

import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Service
@AllArgsConstructor
public class JwtTokenService {

    private final JwtDecoder jwtDecoder;
    private final JwtEncoder jwtEncoder;

    public String generateAccessToken(UserDetails userDetails) {
        return generateToken(userDetails, 1000 * 60 * 15, TokenType.ACCESS.toString()); // 15 minutes for access token
    }

    // Generate Refresh Token
    public String generateRefreshToken(UserDetails userDetails) {
        return generateToken(userDetails, 1000 * 60 * 60 * 24,  TokenType.REFRESH.toString()); // 24 hours for refresh token
    }

    private String generateToken(UserDetails userDetails, long expirationMillis, String tokenType) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", userDetails.getUsername());
        claims.put("roles", userDetails.getAuthorities());

        Instant now = Instant.now();
        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuedAt(now)
                .expiresAt(now.plusMillis(expirationMillis))
                .claim("sub", userDetails.getUsername())
                .claim("roles", userDetails.getAuthorities())
                .claim("token_type", tokenType)
                .build();

        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claimsSet));
        return jwt.getTokenValue();
    }

    // Extract Username from the Token
    public String extractUsername(String token) {
        Jwt jwt = jwtDecoder.decode(token);
        return jwt.getClaimAsString("sub");
    }

    // Validate Token
    public boolean validateToken(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    // Check if Token Expired
    private boolean isTokenExpired(String token) {
        Jwt jwt = jwtDecoder.decode(token);
        Instant expiration = jwt.getExpiresAt();
        return expiration != null && expiration.isBefore(Instant.now());
    }

    public boolean isRefreshToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            String tokenType = jwt.getClaimAsString("token_type");
            return TokenType.REFRESH.name().equals(tokenType);
        } catch (JwtException e) {
            e.printStackTrace();
            return false;
        }
    }
}
