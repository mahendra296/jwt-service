package com.jwt.dto;

import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String token;
    private String refreshToken;
    private String type = "Bearer";
    private String username;
    private String email;
    private Set<String> roles;

    public AuthResponse(String token, String refreshToken, String username, String email, Set<String> roles) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.username = username;
        this.email = email;
        this.roles = roles;
    }
}
