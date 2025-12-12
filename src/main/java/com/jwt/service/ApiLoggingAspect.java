package com.jwt.service;

import com.jwt.annotation.Audited;
import com.jwt.model.ApiLog;
import com.jwt.repository.ApiLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tools.jackson.databind.ObjectMapper;

@Aspect
@Component
@Slf4j
@RequiredArgsConstructor
public class ApiLoggingAspect {

    private final ApiLogRepository apiLogRepository;
    private final ObjectMapper objectMapper;
    private final AuditService auditService;

    @Pointcut("within(@org.springframework.web.bind.annotation.RestController *)")
    public void restControllerMethods() {}

    @Around("restControllerMethods()")
    public Object logApiCall(ProceedingJoinPoint joinPoint) throws Throwable {
        long startTime = System.currentTimeMillis();

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder
                .currentRequestAttributes()).getRequest();

        ApiLog apiLog = ApiLog.builder()
                .endpoint(request.getRequestURI())
                .httpMethod(request.getMethod())
                .ipAddress(getClientIpAddress(request))
                .build();

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getPrincipal())) {
            apiLog.setUsername(authentication.getName());
        }

        Object[] args = joinPoint.getArgs();
        if (args != null && args.length > 0) {
            try {
                String requestBody = objectMapper.writeValueAsString(args[0]);
                if (requestBody.contains("password")) {
                    requestBody = requestBody.replaceAll("\"password\"\\s*:\\s*\"[^\"]*\"",
                            "\"password\":\"***MASKED***\"");
                }
                apiLog.setRequestBody(requestBody);
            } catch (Exception e) {
                log.warn("Failed to serialize request body", e);
            }
        }

        Object result = null;
        try {
            result = joinPoint.proceed();

            if (result instanceof ResponseEntity) {
                ResponseEntity<?> responseEntity = (ResponseEntity<?>) result;
                apiLog.setStatusCode(responseEntity.getStatusCode().value());

                try {
                    String responseBody = objectMapper.writeValueAsString(responseEntity.getBody());
                    if (responseBody.contains("token")) {
                        responseBody = responseBody.replaceAll("\"token\"\\s*:\\s*\"[^\"]*\"",
                                "\"token\":\"***MASKED***\"");
                    }
                    apiLog.setResponseBody(responseBody);
                } catch (Exception e) {
                    log.warn("Failed to serialize response body", e);
                }
            }

        } catch (Exception e) {
            apiLog.setStatusCode(500);
            apiLog.setErrorMessage(e.getMessage());
            throw e;
        } finally {
            long executionTime = System.currentTimeMillis() - startTime;
            apiLog.setExecutionTimeMs(executionTime);

            saveApiLogAsync(apiLog);

            log.info("API Call: {} {} - Status: {} - Time: {}ms - User: {}",
                    apiLog.getHttpMethod(),
                    apiLog.getEndpoint(),
                    apiLog.getStatusCode(),
                    executionTime,
                    apiLog.getUsername());
        }

        return result;
    }

    private void saveApiLogAsync(ApiLog apiLog) {
        try {
            apiLogRepository.save(apiLog);
        } catch (Exception e) {
            log.error("Failed to save API log", e);
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0];
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    @After("@annotation(audited)")
    public void auditMethod(JoinPoint joinPoint, Audited audited) {
        try {
            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder
                    .currentRequestAttributes()).getRequest();

            Object[] args = joinPoint.getArgs();
            Object targetArg = null;
            if (args != null && args.length > 0 && audited.index() < args.length) {
                targetArg = args[audited.index()];
            }

            String username = null;
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated()
                    && !"anonymousUser".equals(authentication.getPrincipal())) {
                username = authentication.getName();
            }

            String userAgent = request.getHeader("User-Agent");
            UserAgentInfo userAgentInfo = parseUserAgent(userAgent);

            AuditService.AuditData auditData = AuditService.AuditData.builder()
                    .activity(audited.activity())
                    .endpoint(request.getRequestURI())
                    .httpMethod(request.getMethod())
                    .username(username)
                    .identifier(audited.identifier())
                    .identifierKey(audited.identifierKey())
                    .shouldStoreAll(audited.shouldStoreAll())
                    .fieldsToAudit(audited.fieldsToAudit())
                    .targetArg(targetArg)
                    .ipAddress(getClientIpAddress(request))
                    .device(userAgentInfo.device)
                    .operatingSystem(userAgentInfo.operatingSystem)
                    .browser(userAgentInfo.browser)
                    .channel(request.getHeader("X-Channel"))
                    .timeZone(request.getHeader("X-Timezone"))
                    .traceId(request.getHeader("X-Trace-Id"))
                    .build();

            auditService.processAudit(auditData);

        } catch (Exception e) {
            log.error("Failed to process audit annotation", e);
        }
    }

    private UserAgentInfo parseUserAgent(String userAgent) {
        UserAgentInfo info = new UserAgentInfo();
        if (userAgent == null || userAgent.isEmpty()) {
            return info;
        }

        // Parse browser
        if (userAgent.contains("Chrome") && !userAgent.contains("Edg")) {
            info.browser = "Chrome";
        } else if (userAgent.contains("Firefox")) {
            info.browser = "Firefox";
        } else if (userAgent.contains("Safari") && !userAgent.contains("Chrome")) {
            info.browser = "Safari";
        } else if (userAgent.contains("Edg")) {
            info.browser = "Edge";
        } else if (userAgent.contains("MSIE") || userAgent.contains("Trident")) {
            info.browser = "Internet Explorer";
        } else {
            info.browser = "Unknown";
        }

        // Parse operating system
        if (userAgent.contains("Windows")) {
            info.operatingSystem = "Windows";
        } else if (userAgent.contains("Mac OS X")) {
            info.operatingSystem = "macOS";
        } else if (userAgent.contains("Linux")) {
            info.operatingSystem = "Linux";
        } else if (userAgent.contains("Android")) {
            info.operatingSystem = "Android";
        } else if (userAgent.contains("iPhone") || userAgent.contains("iPad")) {
            info.operatingSystem = "iOS";
        } else {
            info.operatingSystem = "Unknown";
        }

        // Parse device type
        if (userAgent.contains("Mobile") || userAgent.contains("Android") || userAgent.contains("iPhone")) {
            info.device = "Mobile";
        } else if (userAgent.contains("Tablet") || userAgent.contains("iPad")) {
            info.device = "Tablet";
        } else {
            info.device = "Desktop";
        }

        return info;
    }

    private static class UserAgentInfo {
        String browser = "Unknown";
        String operatingSystem = "Unknown";
        String device = "Unknown";
    }
}
