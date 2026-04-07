package com.ketki.smart_parking.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    // ─────────────────────────────────────────
    // Pulled from application.properties
    // ─────────────────────────────────────────
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expirationMs;

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    // ─────────────────────────────────────────
    // Generate a JWT token for a user
    // ─────────────────────────────────────────
    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // ─────────────────────────────────────────
    // Extract username from token
    // ─────────────────────────────────────────
    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    // ─────────────────────────────────────────
    // Extract role from token
    // ─────────────────────────────────────────
    public String extractRole(String token) {
        return getClaims(token).get("role", String.class);
    }

    // ─────────────────────────────────────────
    // Validate token — checks signature + expiry
    // ─────────────────────────────────────────
    public boolean validateToken(String token) {
        try {
            getClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            System.out.println("JWT expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.out.println("JWT unsupported: " + e.getMessage());
        } catch (MalformedJwtException e) {
            System.out.println("JWT malformed: " + e.getMessage());
        } catch (SignatureException e) {
            System.out.println("JWT signature invalid: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("JWT empty: " + e.getMessage());
        }
        return false;
    }

    // ─────────────────────────────────────────
    // Internal — parse and return all claims
    // ─────────────────────────────────────────
    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
