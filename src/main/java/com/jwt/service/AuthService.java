package com.jwt.service;

import com.jwt.dto.AuthResponse;
import com.jwt.dto.LoginRequest;
import com.jwt.dto.RefreshTokenRequest;
import com.jwt.dto.RegisterRequest;
import com.jwt.model.RefreshToken;
import com.jwt.model.Role;
import com.jwt.model.User;
import com.jwt.repository.RoleRepository;
import com.jwt.repository.UserRepository;
import com.jwt.utils.JwtUtil;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        log.info("Registering new user: {}", request.getUsername());

        // Check if username exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists");
        }

        // Check if email exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        // Create new user
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setActive(true);

        // Assign roles
        Set<Role> roles = new HashSet<>();
        if (request.getRoles() != null && !request.getRoles().isEmpty()) {
            request.getRoles().forEach(roleName -> {
                Role role = roleRepository
                        .findByName(roleName)
                        .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));
                roles.add(role);
            });
        } else {
            // Default role: USER
            Role userRole = roleRepository.findByName("ROLE_USER").orElseGet(() -> {
                Role newRole = new Role("ROLE_USER");
                newRole.setDescription("Standard user role");
                return roleRepository.save(newRole);
            });
            roles.add(userRole);
        }
        user.setRoles(roles);

        // Save user
        userRepository.save(user);

        Set<String> roleNames = user.getRoles().stream().map(Role::getName).collect(Collectors.toSet());

        log.info("User registered successfully: {}", user.getUsername());
        return new AuthResponse(null, null, user.getUsername(), user.getEmail(), roleNames);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        log.info("User attempting to login: {}", request.getUsername());

        // Authenticate user
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        // Load user details
        User user = userRepository
                .findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Generate access token
        String token = jwtUtil.generateToken(user);

        // Generate refresh token
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        Set<String> roleNames = user.getRoles().stream().map(Role::getName).collect(Collectors.toSet());

        log.info("User logged in successfully: {}", user.getUsername());
        return new AuthResponse(token, refreshToken.getToken(), user.getUsername(), user.getEmail(), roleNames);
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        log.info("Refresh token request received");

        return refreshTokenService
                .findByToken(request.getRefreshToken())
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    // Generate new access token
                    String accessToken = jwtUtil.generateToken(user);

                    // Generate new refresh token (rotate refresh tokens for security)
                    RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

                    Set<String> roleNames =
                            user.getRoles().stream().map(Role::getName).collect(Collectors.toSet());

                    log.info("Token refreshed successfully for user: {}", user.getUsername());
                    return new AuthResponse(
                            accessToken, newRefreshToken.getToken(), user.getUsername(), user.getEmail(), roleNames);
                })
                .orElseThrow(() -> new RuntimeException("Refresh token not found or invalid"));
    }

    @Transactional
    public void logout(String refreshToken) {
        log.info("Logout request received");
        refreshTokenService.revokeToken(refreshToken);
        log.info("User logged out successfully");
    }
}
