package com.jwt.service;

import com.jwt.annotation.Audited;
import com.jwt.constant.AppConstant;
import com.jwt.dto.AuditLog;
import com.jwt.model.ApiLog;
import com.jwt.repository.ApiLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.antlr.v4.runtime.misc.Pair;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
@ConditionalOnProperty(name = "app.audit.enabled", havingValue = "true")
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

        HttpServletRequest request =
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

        ApiLog apiLog = ApiLog.builder()
                .endpoint(request.getRequestURI())
                .httpMethod(request.getMethod())
                .ipAddress(getClientIpAddress(request))
                .build();

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null
                && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getPrincipal())) {
            apiLog.setUsername(authentication.getName());
        }

        Object[] args = joinPoint.getArgs();
        if (args != null && args.length > 0) {
            try {
                String requestBody = objectMapper.writeValueAsString(args[0]);
                if (requestBody.contains("password")) {
                    requestBody =
                            requestBody.replaceAll("\"password\"\\s*:\\s*\"[^\"]*\"", "\"password\":\"***MASKED***\"");
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
                        responseBody =
                                responseBody.replaceAll("\"token\"\\s*:\\s*\"[^\"]*\"", "\"token\":\"***MASKED***\"");
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

            log.info(
                    "API Call: {} {} - Status: {} - Time: {}ms - User: {}",
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
            MethodSignature methodSignature = (MethodSignature) joinPoint.getSignature();
            HttpServletRequest httpRequest =
                    ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            AuditLog auditLog = new AuditLog();
            audit(audited, joinPoint, methodSignature, httpRequest, auditLog);

            auditService.processAudit(auditLog);

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

    private AuditLog audit(
            Audited audited,
            JoinPoint joinPoint,
            MethodSignature method,
            HttpServletRequest httpRequest,
            AuditLog auditLog) {
        auditLog.setTimeZone(httpRequest.getHeader(AppConstant.HEADER_ZONE_ID));
        auditLog.setChannel(httpRequest.getHeader(AppConstant.HEADER_USER_PLATFORM));
        auditLog.setIpAddress(httpRequest.getRemoteAddr());
        auditLog.setDevice(httpRequest.getHeader(AppConstant.HEADER_DEVICE_NAME));
        auditLog.setOperatingSystem(httpRequest.getHeader(AppConstant.HEADER_OPERATING_SYSTEM));
        auditLog.setBrowser(httpRequest.getHeader(AppConstant.HEADER_BROWSER));
        auditLog.setMethodName(method.getName());
        auditLog.setActivity(audited.activity());
        auditLog.setRequest(getRequestBody(joinPoint));
        auditLog.setRequestUrl(httpRequest.getRequestURI());

        String idToken = httpRequest.getHeader(AppConstant.HEADER_ID_TOKEN);
        try {
            Map<String, Object> argumentsMap = prepareArgumentsMap(joinPoint, audited.fieldsToAudit(), audited.index());

            prepareAudit(audited, httpRequest, argumentsMap, auditLog);

        } catch (Exception e) {
            log.warn(
                    "Wrong index {} provided for input params for method {}, exception : {}",
                    audited.index(),
                    method.getMethod(),
                    e.getMessage());
        }
        return auditLog;
    }

    private Map<String, Object> prepareArgumentsMap(JoinPoint joinPoint, String[] params, int auditIndex) {
        Map<String, Object> argumentMap = new HashMap<>();
        Object paramValue = null;

        try {
            paramValue = joinPoint.getArgs()[auditIndex];
        } catch (ArrayIndexOutOfBoundsException e) {
            log.error("Audit parameter not found for index: {}", auditIndex);
        }

        if (paramValue != null) {
            for (String param : params) {
                String[] splitValues = param.split("\\.");
                if (splitValues.length == 1) {
                    var pair = getFieldValue(paramValue, splitValues[0]);
                    argumentMap.put(pair.a, pair.b);
                } else if (splitValues.length > 1) {
                    Pair<String, Object> nestedPair = null;
                    for (String split : splitValues) {
                        if (nestedPair != null) {
                            nestedPair = getFieldValue(nestedPair.b, split);
                        } else nestedPair = getFieldValue(paramValue, split);
                    }
                    /*var pair = getFieldValue(paramValue, splitValues[0]);
                    Pair<String, Object> nestedPair = null;
                    if (pair.b != null) {
                        nestedPair = getFieldValue(pair.b, splitValues[1]);
                    }*/
                    argumentMap.put(nestedPair.a, nestedPair.b); // getSecond() should be implemented in Pair
                } else {
                    log.debug("Invalid audited parameter defined");
                }
            }
        }
        return argumentMap;
    }

    public static Pair<String, Object> getFieldValue(Object obj, String name) {
        String[] split = name.split("#");

        try {
            if (split.length == 1) {
                // Handle field access
                Field field = obj.getClass().getDeclaredField(name);
                field.setAccessible(true);
                return new Pair(name, field.get(obj));
            } else if (split.length == 2) {
                // Handle method invocation
                Method method = obj.getClass().getDeclaredMethod(split[1]);
                return new Pair(split[0], method.invoke(obj));
            } else {
                return new Pair(name, null);
            }
        } catch (NoSuchFieldException | NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            e.printStackTrace(); // Handle exceptions as needed
            return new Pair(name, null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public AuditLog prepareAudit(
            Audited audited,
            HttpServletRequest httpRequest,
            Map<String, Object> argumentsMap,
            AuditLog optionalAuditLog) {
        AuditLog auditLog = (optionalAuditLog != null) ? optionalAuditLog : new AuditLog();
        StringJoiner fields = new StringJoiner(
                System.lineSeparator(),
                auditLog.getOtherFields() != null ? auditLog.getOtherFields() : "",
                System.lineSeparator());

        for (String field : audited.fieldsToAudit()) {
            String[] parts = field.split("\\.");
            String key = parts[parts.length - 1];
            String objValue =
                    argumentsMap.containsKey(key) ? argumentsMap.get(key).toString() : null;

            switch (key) {
                case "customerId":
                    if (auditLog.getCustomerId() == null) {
                        assert objValue != null;
                        auditLog.setCustomerId(Long.valueOf(objValue));
                    }
                    break;
                case "phoneNumber":
                    String channel = httpRequest.getHeader(AppConstant.HEADER_REQUEST_CHANNEL);
                    if (AppConstant.MOMO_LOAN_CHANNEL.equals(channel) || AppConstant.WHATSAPP_CHANNEL.equals(channel)) {
                        auditLog.setPhoneNumber(objValue);
                    }
                    break;
                case "customerNumber":
                    auditLog.setCustomerNumber(objValue);
                    break;
                case "name":
                    auditLog.setUsername(objValue);
                    break;
                default:
                    fields.add(key + " : " + objValue);
                    break;
            }
        }

        auditLog.setOtherFields(audited.shouldStoreAll() ? fields.toString() : auditLog.getOtherFields());
        return auditLog;
    }

    private String getRequestBody(JoinPoint request) {
        try {
            StringBuilder json = new StringBuilder();
            Object[] args = request.getArgs();

            // Iterate through method arguments
            for (Object arg : args) {
                json.append(objectMapper.writeValueAsString(arg));
            }
            String requestBody = json.toString();

            // Mask sensitive fields
            if (requestBody.contains("password")) {
                requestBody = requestBody.replaceAll("\"password\"\\s*:\\s*\"[^\"]*\"", "\"password\":\"***MASKED***\"");
            }
            if (requestBody.contains("email")) {
                requestBody = requestBody.replaceAll("\"email\"\\s*:\\s*\"[^\"]*\"", "\"email\":\"***MASKED***\"");
            }

            return requestBody;
        } catch (Exception ex) {
            return null;
        }
    }
}
