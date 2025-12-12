package com.jwt.service;

import com.jwt.annotation.Identifier;
import com.jwt.dto.AuditLog;
import com.jwt.model.AuditLogEntity;
import com.jwt.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuditService {

    private final ObjectMapper objectMapper;
    private final AuditLogRepository auditLogRepository;

    @Async
    public void processAudit(AuditData auditData) {
        try {
            // Build other fields map for audited fields
            Map<String, Object> otherFieldsMap = new HashMap<>();

            if (auditData.getIdentifier() != Identifier.NONE && auditData.getIdentifierKey() != null && !auditData.getIdentifierKey().isEmpty()) {
                Object identifierValue = extractFieldValue(auditData.getTargetArg(), auditData.getIdentifierKey());
                otherFieldsMap.put("identifier", identifierValue);
                otherFieldsMap.put("identifierType", auditData.getIdentifier().name());
            }

            if (auditData.isShouldStoreAll()) {
                otherFieldsMap.put("requestData", auditData.getTargetArg());
            } else if (auditData.getFieldsToAudit() != null && auditData.getFieldsToAudit().length > 0) {
                Map<String, Object> auditedFields = new HashMap<>();
                for (String field : auditData.getFieldsToAudit()) {
                    Object value = extractFieldValue(auditData.getTargetArg(), field);
                    auditedFields.put(field, value);
                }
                otherFieldsMap.put("auditedFields", auditedFields);
            }

            String otherFieldsJson = otherFieldsMap.isEmpty() ? null : objectMapper.writeValueAsString(otherFieldsMap);
            String requestJson = auditData.getTargetArg() != null ? objectMapper.writeValueAsString(auditData.getTargetArg()) : null;

            // Extract customer info from target argument if available
            Long customerId = extractLongFieldValue(auditData.getTargetArg(), "customerId");
            String customerNumber = extractStringFieldValue(auditData.getTargetArg(), "customerNumber");
            String phoneNumber = extractStringFieldValue(auditData.getTargetArg(), "phoneNumber");

            AuditLog auditLog = AuditLog.builder()
                    .activity(auditData.getActivity())
                    .username(auditData.getUsername())
                    .requestUrl(auditData.getEndpoint())
                    .methodName(auditData.getHttpMethod())
                    .ipAddress(auditData.getIpAddress())
                    .device(auditData.getDevice())
                    .operatingSystem(auditData.getOperatingSystem())
                    .browser(auditData.getBrowser())
                    .channel(auditData.getChannel())
                    .timeZone(auditData.getTimeZone())
                    .traceId(auditData.getTraceId())
                    .customerId(customerId)
                    .customerNumber(customerNumber)
                    .phoneNumber(phoneNumber)
                    .request(requestJson)
                    .otherFields(otherFieldsJson)
                    .build();

            AuditLogEntity entity = AuditLogEntity.fromAuditLog(auditLog);
            auditLogRepository.save(entity);

            log.info("AUDIT saved: activity={}, username={}, endpoint={}",
                    auditData.getActivity(), auditData.getUsername(), auditData.getEndpoint());

        } catch (Exception e) {
            log.error("Failed to process audit asynchronously", e);
        }
    }

    private Object extractFieldValue(Object target, String fieldPath) {
        try {
            if (target == null) {
                return null;
            }

            JsonNode node = objectMapper.valueToTree(target);
            String[] parts = fieldPath.split("\\.");

            for (String part : parts) {
                if (node == null || node.isNull()) {
                    return null;
                }
                node = node.get(part);
            }

            if (node == null || node.isNull()) {
                return null;
            }

            if (node.isTextual()) {
                return node.asText();
            } else if (node.isNumber()) {
                return node.numberValue();
            } else if (node.isBoolean()) {
                return node.asBoolean();
            } else {
                return node.toString();
            }
        } catch (Exception e) {
            log.warn("Failed to extract field '{}' from object", fieldPath, e);
            return null;
        }
    }

    private String extractStringFieldValue(Object target, String fieldPath) {
        Object value = extractFieldValue(target, fieldPath);
        return value != null ? value.toString() : null;
    }

    private Long extractLongFieldValue(Object target, String fieldPath) {
        Object value = extractFieldValue(target, fieldPath);
        if (value == null) {
            return null;
        }
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        try {
            return Long.parseLong(value.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class AuditData {
        private String activity;
        private String endpoint;
        private String httpMethod;
        private String username;
        private Identifier identifier;
        private String identifierKey;
        private boolean shouldStoreAll;
        private String[] fieldsToAudit;
        private Object targetArg;
        private String ipAddress;
        private String device;
        private String operatingSystem;
        private String browser;
        private String channel;
        private String timeZone;
        private String traceId;
    }
}
