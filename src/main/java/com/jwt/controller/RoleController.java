package com.jwt.controller;

import com.jwt.annotation.Audited;
import com.jwt.dto.ApiResponse;
import com.jwt.model.Role;
import com.jwt.service.RoleService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/roles")
@RequiredArgsConstructor
@Slf4j
public class RoleController {

    private final RoleService roleService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Audited(activity = "VIEW_ALL_ROLES")
    public ResponseEntity<ApiResponse<List<Role>>> getAllRoles() {
        log.info("Fetching all roles");
        List<Role> roles = roleService.getAllRoles();
        log.info("Retrieved {} roles", roles.size());
        return ResponseEntity.ok(ApiResponse.success("Roles retrieved successfully", roles));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Audited(
            index = 0,
            shouldStoreAll = true,
            activity = "VIEW_ROLE_DETAILS"
    )
    public ResponseEntity<ApiResponse<Role>> getRoleById(@PathVariable Long id) {
        log.info("Fetching role with id: {}", id);
        Role role = roleService.getRoleById(id)
                .orElseThrow(() -> {
                    log.error("Role not found with id: {}", id);
                    return new RuntimeException("Role not found");
                });
        log.info("Role retrieved successfully: {}", role.getName());
        return ResponseEntity.ok(ApiResponse.success("Role retrieved successfully", role));
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Audited(
            index = 0,
            shouldStoreAll = false,
            fieldsToAudit = {"name", "description"},
            activity = "CREATE_ROLE"
    )
    public ResponseEntity<ApiResponse<Role>> createRole(@RequestBody Role role) {
        log.info("Creating new role: {}", role.getName());
        Role createdRole = roleService.createRole(role);
        log.info("Role created successfully: {}", createdRole.getName());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Role created successfully", createdRole));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Audited(
            index = 1,
            shouldStoreAll = false,
            fieldsToAudit = {"name", "description"},
            activity = "UPDATE_ROLE"
    )
    public ResponseEntity<ApiResponse<Role>> updateRole(
            @PathVariable Long id,
            @RequestBody Role roleDetails) {
        log.info("Updating role with id: {}", id);
        Role updatedRole = roleService.updateRole(id, roleDetails);
        log.info("Role updated successfully: {}", updatedRole.getName());
        return ResponseEntity.ok(ApiResponse.success("Role updated successfully", updatedRole));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Audited(
            index = 0,
            shouldStoreAll = true,
            activity = "DELETE_ROLE"
    )
    public ResponseEntity<ApiResponse<Void>> deleteRole(@PathVariable Long id) {
        log.info("Deleting role with id: {}", id);
        roleService.deleteRole(id);
        log.info("Role deleted successfully with id: {}", id);
        return ResponseEntity.ok(ApiResponse.success("Role deleted successfully", null));
    }
}
