package com.jwt.service;

import com.jwt.dto.AuditLog;
import com.jwt.model.AuditLogEntity;
import com.jwt.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuditService {

    private final ObjectMapper objectMapper;
    private final AuditLogRepository auditLogRepository;

    @Async
    public void processAudit(AuditLog auditLog) {
        try {
            AuditLogEntity entity = AuditLogEntity.fromAuditLog(auditLog);
            auditLogRepository.save(entity);

            log.info(
                    "AUDIT saved: activity={}, username={}, endpoint={}",
                    auditLog.getActivity(),
                    auditLog.getUsername(),
                    auditLog.getRequestUrl());

        } catch (Exception e) {
            log.error("Failed to process audit asynchronously", e);
        }
    }
}
