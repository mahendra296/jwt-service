package com.jwt.service;

import com.jwt.model.ApiLog;
import com.jwt.repository.ApiLogRepository;
import java.time.LocalDateTime;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class ApiLogService {

    private final ApiLogRepository apiLogRepository;

    /**
     * Save API log
     */
    @Transactional
    public ApiLog saveLog(ApiLog apiLog) {
        return apiLogRepository.save(apiLog);
    }

    /**
     * Get all logs
     */
    @Transactional(readOnly = true)
    public List<ApiLog> getAllLogs() {
        return apiLogRepository.findAll();
    }

    /**
     * Get all logs with pagination
     */
    @Transactional(readOnly = true)
    public Page<ApiLog> getAllLogs(Pageable pageable) {
        return apiLogRepository.findAll(pageable);
    }

    /**
     * Clean up old logs (can be used with scheduled jobs)
     */
    @Transactional
    public void deleteOldLogs(LocalDateTime before) {
        log.info("Cleaning up logs before: {}", before);
        // Implementation for deleting old logs
        // You can add custom query in repository if needed
    }
}
