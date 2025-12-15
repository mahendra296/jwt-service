package com.jwt.repository;

import com.jwt.model.Role;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<com.jwt.model.Role, Long> {
    Optional<Role> findByName(String name);
}
