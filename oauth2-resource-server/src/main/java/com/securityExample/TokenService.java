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
public class TokenService {

    private final JwtDecoder jwtDecoder;
    private final JwtEncoder jwtEncoder;

//    public String generateToken(Authentication authentication) {
//        Instant instant = Instant.now();
//        String scope = authentication.getAuthorities().stream()
//                .map(GrantedAuthority::getAuthority)
//                .collect(Collectors.joining(" "));
//
//        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
//                .issuer("self")
//                .issuedAt(instant)
//                .expiresAt(instant.plus(1, ChronoUnit.HOURS))
//                .subject(authentication.getName())
//                .claim("scope", scope)
//                .build();
//
//        return this.jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
//    }

    public String generateAccessToken(UserDetails userDetails) {
        return generateToken(userDetails, 1000 * 60 * 15); // 15 minutes for access token
    }

    // Generate Refresh Token
    public String generateRefreshToken(UserDetails userDetails) {
        return generateToken(userDetails, 1000 * 60 * 60 * 24); // 24 hours for refresh token
    }

    private String generateToken(UserDetails userDetails, long expirationMillis) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", userDetails.getUsername());
        claims.put("roles", userDetails.getAuthorities());

        Instant now = Instant.now();
        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuedAt(now)
                .expiresAt(now.plusMillis(expirationMillis))
                .claim("sub", userDetails.getUsername())
                .claim("roles", userDetails.getAuthorities())
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
}
