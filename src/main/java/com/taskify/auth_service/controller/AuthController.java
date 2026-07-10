package com.taskify.auth_service.controller;

import com.taskify.auth_service.dto.*;
import com.taskify.auth_service.service.AuthService;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final MessageSource messageSource;

    public AuthController(AuthService authService, MessageSource messageSource) {
        this.authService = authService;
        this.messageSource = messageSource;
    }

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<Void>> signup(@RequestBody SignupRequest request) {
        authService.registerUser(request);

        String successMsg = messageSource.getMessage("auth.signup.success", null, LocaleContextHolder.getLocale());

        ApiResponse<Void> response = ApiResponse.<Void>builder()
                .success(true)
                .message(successMsg)
                .timestamp(LocalDateTime.now().toString())
                .build();

        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponse<AuthResponse>> verifyOtp(@RequestBody OtpVerificationRequest request) {
        AuthResponse authPayload = authService.verifyOtp(request.getEmail(), request.getOtp());

        String successMsg = messageSource.getMessage("auth.verify.success", null, LocaleContextHolder.getLocale());

        ApiResponse<AuthResponse> response = ApiResponse.<AuthResponse>builder()
                .success(true)
                .message(successMsg)
                .data(authPayload)
                .timestamp(LocalDateTime.now().toString())
                .build();

        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@RequestBody LoginRequest request) {
        AuthResponse authPayload = authService.loginUser(request);

        String successMsg = messageSource.getMessage("auth.login.success", null, LocaleContextHolder.getLocale());

        ApiResponse<AuthResponse> response = ApiResponse.<AuthResponse>builder()
                .success(true)
                .message(successMsg)
                .data(authPayload)
                .timestamp(LocalDateTime.now().toString())
                .build();

        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(@RequestParam String refreshToken) {
        AuthResponse authPayload = authService.refreshAccessToken(refreshToken);

        String successMsg = messageSource.getMessage("auth.refresh.success", null, LocaleContextHolder.getLocale());

        ApiResponse<AuthResponse> response = ApiResponse.<AuthResponse>builder()
                .success(true)
                .message(successMsg)
                .data(authPayload)
                .timestamp(LocalDateTime.now().toString())
                .build();

        return ResponseEntity.ok(response);
    }
}
