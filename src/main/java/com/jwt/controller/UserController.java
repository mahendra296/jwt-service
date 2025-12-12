package com.jwt.controller;

import com.jwt.annotation.Audited;
import com.jwt.annotation.Identifier;
import com.jwt.dto.ApiResponse;
import com.jwt.model.User;
import com.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Audited(activity = "VIEW_ALL_USERS")
    public ResponseEntity<ApiResponse<List<User>>> getAllUsers() {
        log.info("Fetching all users");
        List<User> users = userService.getAllUsers();
        log.info("Retrieved {} users", users.size());
        return ResponseEntity.ok(ApiResponse.success("Users retrieved successfully", users));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
    @Audited(
            index = 0,
            shouldStoreAll = true,
            activity = "VIEW_USER_DETAILS",
            identifier = Identifier.USER_ID,
            identifierKey = "id"
    )
    public ResponseEntity<ApiResponse<User>> getUserById(@PathVariable Long id) {
        log.info("Fetching user with id: {}", id);
        User user = userService.getUserById(id)
                .orElseThrow(() -> {
                    log.error("User not found with id: {}", id);
                    return new RuntimeException("User not found");
                });
        log.info("User retrieved successfully: {}", user.getUsername());
        return ResponseEntity.ok(ApiResponse.success("User retrieved successfully", user));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
    @Audited(
            index = 1,
            shouldStoreAll = false,
            fieldsToAudit = {"username", "email", "firstName", "lastName", "isActive"},
            activity = "UPDATE_USER_PROFILE",
            identifier = Identifier.USER_ID,
            identifierKey = "id"
    )
    public ResponseEntity<ApiResponse<User>> updateUser(
            @PathVariable Long id,
            @RequestBody User userDetails) {
        log.info("Updating user with id: {}", id);
        User updatedUser = userService.updateUser(id, userDetails);
        log.info("User updated successfully: {}", updatedUser.getUsername());
        return ResponseEntity.ok(ApiResponse.success("User updated successfully", updatedUser));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Audited(
            index = 0,
            shouldStoreAll = true,
            activity = "DELETE_USER",
            identifier = Identifier.USER_ID,
            identifierKey = "id"
    )
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable Long id) {
        log.info("Deleting user with id: {}", id);
        userService.deleteUser(id);
        log.info("User deleted successfully with id: {}", id);
        return ResponseEntity.ok(ApiResponse.success("User deleted successfully", null));
    }

    @PutMapping("/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    @Audited(
            index = 1,
            shouldStoreAll = true,
            activity = "ASSIGN_USER_ROLES",
            identifier = Identifier.USER_ID,
            identifierKey = "id"
    )
    public ResponseEntity<ApiResponse<User>> assignRoles(
            @PathVariable Long id,
            @RequestBody Set<String> roles) {
        log.info("Assigning roles {} to user with id: {}", roles, id);
        User user = userService.assignRoles(id, roles);
        log.info("Roles assigned successfully to user: {}", user.getUsername());
        return ResponseEntity.ok(ApiResponse.success("Roles assigned successfully", user));
    }

    @PutMapping("/{id}/activate")
    @PreAuthorize("hasRole('ADMIN')")
    @Audited(
            index = 0,
            shouldStoreAll = true,
            activity = "ACTIVATE_USER",
            identifier = Identifier.USER_ID,
            identifierKey = "id"
    )
    public ResponseEntity<ApiResponse<User>> activateUser(@PathVariable Long id) {
        log.info("Activating user with id: {}", id);
        User user = userService.activateUser(id);
        log.info("User activated successfully: {}", user.getUsername());
        return ResponseEntity.ok(ApiResponse.success("User activated successfully", user));
    }

    @PutMapping("/{id}/deactivate")
    @PreAuthorize("hasRole('ADMIN')")
    @Audited(
            index = 0,
            shouldStoreAll = true,
            activity = "DEACTIVATE_USER",
            identifier = Identifier.USER_ID,
            identifierKey = "id"
    )
    public ResponseEntity<ApiResponse<User>> deactivateUser(@PathVariable Long id) {
        log.info("Deactivating user with id: {}", id);
        User user = userService.deactivateUser(id);
        log.info("User deactivated successfully: {}", user.getUsername());
        return ResponseEntity.ok(ApiResponse.success("User deactivated successfully", user));
    }
}