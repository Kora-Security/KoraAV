// src/realtime-protection/yara-realtime/realtime_yara_scanner.h
#ifndef KORAAV_REALTIME_YARA_SCANNER_H
#define KORAAV_REALTIME_YARA_SCANNER_H

#include "../../common/yara_manager.h"
#include <string>
#include <vector>
#include <mutex>
#include <unordered_set>

namespace koraav {
namespace realtime {

/**
 * Real-Time YARA Scanner
 * 
 * Now uses the centralized YaraManager instead of creating its own instance.
 * This ensures that CLI scans and realtime scans use the SAME rules.
 */
class RealtimeYaraScanner {
public:
    RealtimeYaraScanner();
    ~RealtimeYaraScanner() = default;
    
    /**
     * Initialize (loads rules via YaraManager)
     */
    bool Initialize(const std::string& rules_dir);
    
    /**
     * Scan a file in real-time
     */
    bool ScanFile(const std::string& path, std::vector<std::string>& matches);
    
    /**
     * Scan file data in memory
     */
    bool ScanData(const std::vector<char>& data, std::vector<std::string>& matches);
    
    /**
     * Quick scan (for ransomware detector - same as regular scan now)
     */
    bool QuickScan(const std::string& path, std::vector<std::string>& matches);
    
    /**
     * Check if file should be scanned
     */
    bool ShouldScan(const std::string& path, size_t file_size);
    
    /**
     * Whitelist extensions to skip
     */
    void WhitelistExtension(const std::string& ext);
    
    /**
     * Statistics
     */
    struct Statistics {
        uint64_t files_scanned;
        uint64_t malware_detected;
        uint64_t skipped_too_large;
        uint64_t skipped_whitelisted;
        double avg_scan_time_ms;
    };
    
    Statistics GetStatistics() const;

private:
    // Configuration
    size_t max_file_size_;
    std::unordered_set<std::string> whitelisted_extensions_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    Statistics stats_;
    
    // Helpers
    bool IsWhitelistedExtension(const std::string& path);
    void UpdateStatistics(double scan_time_ms, bool malware_found);
};

} // namespace realtime
} // namespace koraav

#endif // KORAAV_REALTIME_YARA_SCANNER_H
