package com.jwt.repository;

import com.jwt.model.AuditLogEntity;
import java.time.ZonedDateTime;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLogEntity, Long> {

    List<AuditLogEntity> findByUsername(String username);

    List<AuditLogEntity> findByCustomerId(Long customerId);

    List<AuditLogEntity> findByActivity(String activity);

    List<AuditLogEntity> findByActiveTimeStampBetween(ZonedDateTime start, ZonedDateTime end);
}
