package com.jwt.controller;

import com.jwt.annotation.Audited;
import com.jwt.dto.ApiResponse;
import com.jwt.dto.AuthResponse;
import com.jwt.dto.LoginRequest;
import com.jwt.dto.RefreshTokenRequest;
import com.jwt.dto.RegisterRequest;
import com.jwt.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    @Audited(
            index = 0,
            shouldStoreAll = false,
            fieldsToAudit = {"username", "email", "firstName", "lastName"},
            activity = "USER_REGISTRATION")
    public ResponseEntity<ApiResponse<AuthResponse>> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration request received for username: {}", request.getUsername());
        try {
            AuthResponse response = authService.register(request);
            log.info("User registered successfully: {}", request.getUsername());
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.success("User registered successfully", response));
        } catch (Exception e) {
            log.error("Registration failed for username: {} - Error: {}", request.getUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ApiResponse.error(e.getMessage()));
        }
    }

    @PostMapping("/login")
    @Audited(
            index = 0,
            shouldStoreAll = false,
            fieldsToAudit = {"username"},
            activity = "USER_LOGIN")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login attempt for username: {}", request.getUsername());
        try {
            AuthResponse response = authService.login(request);
            log.info("Login successful for username: {}", request.getUsername());
            return ResponseEntity.ok(ApiResponse.success("Login successful", response));
        } catch (Exception e) {
            log.warn("Login failed for username: {} - Invalid credentials", request.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Invalid username or password"));
        }
    }

    @GetMapping("/profile")
    @Audited(activity = "VIEW_PROFILE")
    public ResponseEntity<ApiResponse<String>> getProfile(Authentication authentication) {
        String username = authentication.getName();
        log.info("Profile viewed by user: {}", username);
        return ResponseEntity.ok(ApiResponse.success("Profile retrieved", "Welcome, " + username + "!"));
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    @Audited(activity = "ADMIN_DASHBOARD_ACCESS")
    public ResponseEntity<ApiResponse<String>> adminEndpoint() {
        log.info("Admin dashboard accessed");
        return ResponseEntity.ok(ApiResponse.success("Admin access granted", "This is an admin-only endpoint"));
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @Audited(activity = "USER_DASHBOARD_ACCESS")
    public ResponseEntity<ApiResponse<String>> userEndpoint() {
        log.info("User dashboard accessed");
        return ResponseEntity.ok(ApiResponse.success("User access granted", "This is a user endpoint"));
    }

    @PostMapping("/refresh")
    @Audited(
            index = 0,
            shouldStoreAll = false,
            fieldsToAudit = {},
            activity = "TOKEN_REFRESH")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Token refresh request received");
        try {
            AuthResponse response = authService.refreshToken(request);
            log.info("Token refreshed successfully");
            return ResponseEntity.ok(ApiResponse.success("Token refreshed successfully", response));
        } catch (Exception e) {
            log.warn("Token refresh failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ApiResponse.error(e.getMessage()));
        }
    }

    @PostMapping("/logout")
    @Audited(activity = "USER_LOGOUT")
    public ResponseEntity<ApiResponse<String>> logout(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Logout request received");
        try {
            authService.logout(request.getRefreshToken());
            log.info("User logged out successfully");
            return ResponseEntity.ok(ApiResponse.success("Logged out successfully", null));
        } catch (Exception e) {
            log.warn("Logout failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ApiResponse.error(e.getMessage()));
        }
    }
}
