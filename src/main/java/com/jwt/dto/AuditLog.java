package com.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuditLog {

    private Long customerId;
    private String timeZone;
    private String channel;
    private String ipAddress;
    private String device;
    private String operatingSystem;
    private String browser;
    private String activity;
    private String methodName;
    private String otherFields;
    private String traceId;
    private String phoneNumber;
    private String customerNumber;
    private String username;
    private String requestUrl;
    private String request;
    private String response;
}
