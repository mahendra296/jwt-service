package com.jwt.service;

import com.jwt.model.Role;
import com.jwt.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class RoleService {

    private final RoleRepository roleRepository;

    /**
     * Get all roles
     */
    @Transactional(readOnly = true)
    public List<Role> getAllRoles() {
        log.debug("Fetching all roles");
        return roleRepository.findAll();
    }

    /**
     * Get role by ID
     */
    @Transactional(readOnly = true)
    public Optional<Role> getRoleById(Long id) {
        log.debug("Fetching role with id: {}", id);
        return roleRepository.findById(id);
    }

    /**
     * Get role by name
     */
    @Transactional(readOnly = true)
    public Optional<Role> getRoleByName(String name) {
        log.debug("Fetching role with name: {}", name);
        return roleRepository.findByName(name);
    }

    /**
     * Create new role
     */
    @Transactional
    public Role createRole(Role role) {
        log.info("Creating new role: {}", role.getName());

        if (roleRepository.findByName(role.getName()).isPresent()) {
            throw new RuntimeException("Role already exists: " + role.getName());
        }

        Role savedRole = roleRepository.save(role);
        log.info("Role created successfully: {}", savedRole.getName());
        return savedRole;
    }

    /**
     * Update role
     */
    @Transactional
    public Role updateRole(Long id, Role roleDetails) {
        log.info("Updating role with id: {}", id);

        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Role not found with id: " + id));

        if (roleDetails.getDescription() != null) {
            role.setDescription(roleDetails.getDescription());
        }

        Role updatedRole = roleRepository.save(role);
        log.info("Role updated successfully: {}", updatedRole.getId());
        return updatedRole;
    }

    /**
     * Delete role
     */
    @Transactional
    public void deleteRole(Long id) {
        log.info("Deleting role with id: {}", id);

        if (!roleRepository.existsById(id)) {
            throw new RuntimeException("Role not found with id: " + id);
        }

        roleRepository.deleteById(id);
        log.info("Role deleted successfully: {}", id);
    }
}
