// src/realtime-protection/yara-realtime/realtime_yara_scanner.h
#ifndef KORAAV_REALTIME_YARA_SCANNER_H
#define KORAAV_REALTIME_YARA_SCANNER_H

#include "../../scanner/signatures/yara_scanner.h"
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_set>

namespace koraav {
namespace realtime {

/**
 * Real-Time YARA Scanner
 * Scans files as they're created, downloaded, or executed
 * Integrates with existing eBPF file monitoring
 */
class RealtimeYaraScanner {
public:
    RealtimeYaraScanner();
    ~RealtimeYaraScanner();
    
    /**
     * Initialize with YARA rules
     */
    bool Initialize(const std::string& rules_dir);
    
    /**
     * Scan a file in real-time
     * Returns: true if file is clean, false if malicious
     */
    bool ScanFile(const std::string& path, std::vector<std::string>& matches);
    
    /**
     * Scan file data in memory (for downloads)
     */
    bool ScanData(const std::vector<char>& data, std::vector<std::string>& matches);
    
    /**
     * Quick scan (only critical rules for speed)
     */
    bool QuickScan(const std::string& path, std::vector<std::string>& matches);
    
    /**
     * Check if file should be scanned (size limits, whitelist)
     */
    bool ShouldScan(const std::string& path, size_t file_size);
    
    /**
     * don't waste time on images and safe files
     */
    void WhitelistExtension(const std::string& ext);
    
    /**
     * Get statistics
     */
    struct Statistics {
        uint64_t files_scanned;
        uint64_t malware_detected;
        uint64_t false_positives;
        uint64_t skipped_too_large;
        uint64_t skipped_whitelisted;
        double avg_scan_time_ms;
    };
    
    Statistics GetStatistics() const;

private:
    std::unique_ptr<scanner::YaraScanner> yara_scanner_;
    std::unique_ptr<scanner::YaraScanner> quick_scanner_;  // Subset of critical rules
    
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
