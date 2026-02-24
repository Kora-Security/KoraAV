// src/common/quarantine_manager.h
#ifndef KORAAV_QUARANTINE_MANAGER_H
#define KORAAV_QUARANTINE_MANAGER_H

#include <string>
#include <cstdint>
#include <vector>

namespace koraav {

/**
 * Centralized Quarantine Manager
 * Handles quarantine of malicious files for all threat types
 */
class QuarantineManager {
public:
    QuarantineManager(const std::string& quarantine_dir = "/opt/koraav/var/quarantine");
    
    /**
     * Quarantine a process executable
     * Returns: path to quarantined file, or empty string on failure
     */
    std::string QuarantineProcess(uint32_t pid, const std::string& threat_type);
    
    /**
     * Quarantine a specific file
     * Returns: path to quarantined file, or empty string on failure
     */
    std::string QuarantineFile(const std::string& file_path, const std::string& threat_type);
    
    /**
     * List all quarantined items
     */
    std::vector<std::string> ListQuarantine();
    
    /**
     * Restore a quarantined file (for false positives)
     * Returns: true on success
     */
    bool RestoreFile(const std::string& quarantine_path, const std::string& original_path);
    
    /**
     * Delete quarantined file permanently
     */
    bool DeleteQuarantined(const std::string& quarantine_path);

private:
    std::string quarantine_dir_;
    
    std::string GetProcessExecutablePath(uint32_t pid);
    std::string GenerateQuarantineName(const std::string& original_path, 
                                       const std::string& threat_type, 
                                       uint32_t pid = 0);
};

} // namespace koraav

#endif // KORAAV_QUARANTINE_MANAGER_H
