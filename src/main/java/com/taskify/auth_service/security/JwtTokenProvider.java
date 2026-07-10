package com.taskify.auth_service.security;

import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtTokenProvider {

    private final SecretKey jwtSecretKey = Jwts.SIG.HS256.key().build();

    public String generateAccessToken(String email, String role) {
        // 24 Hours
        long accessTokenExpirationMs = 86400000;
        return buildToken(email, accessTokenExpirationMs, role);
    }

    public String generateRefreshToken(String email, String role) {
        // 30 Days
        long refreshTokenExpirationMs = 2592000000L;
        return buildToken(email, refreshTokenExpirationMs, role);
    }

    private String buildToken(String email, long expirationMs, String role) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .subject(email)
                .claim("role", role)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(jwtSecretKey)
                .compact();
    }

    // Extract user identifier (Subject) from token
    public String getEmailFromToken(String token) {
        return Jwts.parser()
                .verifyWith(jwtSecretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    // Validate token cryptographic signature and expiration status
    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(jwtSecretKey).build().parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false; // Returns false if signature is broken, structural layout is invalid, or expired
        }
    }
}
