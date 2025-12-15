package com.jwt.model;

import com.jwt.dto.AuditLog;
import jakarta.persistence.*;
import java.time.ZonedDateTime;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "user_activity")
public class AuditLogEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "customer_id")
    private Long customerId;

    @Column(name = "active_timestamp")
    private ZonedDateTime activeTimeStamp;

    @Column(name = "timezone")
    private String timeZone;

    private String channel;

    @Column(name = "ip_address")
    private String ipAddress;

    private String device;

    @Column(name = "operating_system")
    private String operatingSystem;

    private String browser;

    private String activity;

    @Column(name = "method_name")
    private String methodName;

    @Column(name = "other_fields", columnDefinition = "TEXT")
    private String otherFields;

    @Column(name = "trace_id")
    private String traceId;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "customer_number")
    private String customerNumber;

    @Column(name = "username")
    private String username;

    @Column(name = "request_url")
    private String requestUrl;

    @Column(name = "request", columnDefinition = "TEXT")
    private String request;

    @Column(name = "response", columnDefinition = "TEXT")
    private String response;

    public static AuditLogEntity fromAuditLog(AuditLog auditLog) {
        AuditLogEntity auditLogEntity = new AuditLogEntity();
        if (auditLog != null) {
            auditLogEntity.setCustomerId(auditLog.getCustomerId());
            auditLogEntity.setTimeZone(auditLog.getTimeZone());
            auditLogEntity.setChannel(auditLog.getChannel());
            auditLogEntity.setIpAddress(auditLog.getIpAddress());
            auditLogEntity.setDevice(auditLog.getDevice());
            auditLogEntity.setOperatingSystem(auditLog.getOperatingSystem());
            auditLogEntity.setBrowser(auditLog.getBrowser());
            auditLogEntity.setActivity(auditLog.getActivity());
            auditLogEntity.setOtherFields(auditLog.getOtherFields());
            auditLogEntity.setTraceId(auditLog.getTraceId());
            auditLogEntity.setPhoneNumber(auditLog.getPhoneNumber());
            auditLogEntity.setUsername(auditLog.getUsername());
            auditLogEntity.setCustomerNumber(auditLog.getCustomerNumber());
            auditLogEntity.setRequest(auditLog.getRequest());
            auditLogEntity.setResponse(auditLog.getResponse());
            auditLogEntity.setMethodName(auditLog.getMethodName());
            auditLogEntity.setRequestUrl(auditLog.getRequestUrl());
            auditLogEntity.setActiveTimeStamp(ZonedDateTime.now());
        }
        return auditLogEntity;
    }
}
