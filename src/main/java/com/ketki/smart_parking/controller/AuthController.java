package com.ketki.smart_parking.controller;

import com.ketki.smart_parking.dto.AuthRequest;
import com.ketki.smart_parking.dto.AuthResponse;
import com.ketki.smart_parking.dto.RegisterRequest;
import com.ketki.smart_parking.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // ─────────────────────────────────────────
    // POST /api/auth/register
    // Body: { "username": "", "email": "", "password": "" }
    // ─────────────────────────────────────────
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    // ─────────────────────────────────────────
    // POST /api/auth/login
    // Body: { "username": "", "password": "" }
    // ─────────────────────────────────────────
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody AuthRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
}