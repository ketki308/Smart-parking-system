package com.ketki.smart_parking.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // ─────────────────────────────────────────
        // Step 1 — Read Authorization header
        // Expected format: "Bearer <token>"
        // ─────────────────────────────────────────
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // No token — pass request along (Security config decides if route is public)
            filterChain.doFilter(request, response);
            return;
        }

        // ─────────────────────────────────────────
        // Step 2 — Extract token from header
        // ─────────────────────────────────────────
        String token = authHeader.substring(7); // Remove "Bearer " prefix

        // ─────────────────────────────────────────
        // Step 3 — Validate token
        // ─────────────────────────────────────────
        if (!jwtUtil.validateToken(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        // ─────────────────────────────────────────
        // Step 4 — Extract username and role
        // ─────────────────────────────────────────
        String username = jwtUtil.extractUsername(token);
        String role = jwtUtil.extractRole(token);

        // ─────────────────────────────────────────
        // Step 5 — Set authentication in context
        // Spring Security now knows who this user is
        // ─────────────────────────────────────────
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_" + role))
                );

        authentication.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // ─────────────────────────────────────────
        // Step 6 — Continue the request
        // ─────────────────────────────────────────
        filterChain.doFilter(request, response);
    }
}
