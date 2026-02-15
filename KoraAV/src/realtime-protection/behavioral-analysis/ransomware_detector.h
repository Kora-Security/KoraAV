// src/realtime-protection/behavioral-analysis/ransomware_detector.h
#ifndef KORAAV_RANSOMWARE_DETECTOR_H
#define KORAAV_RANSOMWARE_DETECTOR_H

#include "../yara-realtime/realtime_yara_scanner.h"
#include <string>
#include <vector>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <memory>
#include <fstream>
#include <mutex>
#include <chrono>

namespace koraav {
namespace realtime {

/**
 * Ransomware Detector (Pre-Encryption Interception + YARA)
 * Intercepts file writes BEFORE data hits the disk and checks for encryption
 * Uses Linux fanotify API for pre-write interception
 * Also using YARA for pattern-based malware detection
 * This tries to prevent files from being encrypted in the first place!
 * 
 * Tracks encryption attempts per process to confirm ransomware behavior before killing the process. This prevents false positives.
 * YARA scanning on file creation/execution for immediate detection
 */
class RansomwareDetector {
public:
    RansomwareDetector();
    ~RansomwareDetector();
    
    /**
     * Initialize detector
     * Sets up fanotify to monitor file writes
     */
    bool Initialize(const std::vector<std::string>& protected_paths);
    
    /**
     * Start intercepting file writes
     * Blocks until Stop() is called
     */
    void Run();
    
    /**
     * Stop detector
     */
    void Stop();
    
    /**
     * Add process to whitelist (won't be blocked)
     * NOTE: Only root can add to whitelist (prevents malware self-whitelisting)
     */
    void WhitelistProcess(uint32_t pid);
    
    /**
     * Remove from whitelist
     */
    void RemoveFromWhitelist(uint32_t pid);
    
    /**
     * Check if process is whitelisted
     */
    bool IsWhitelisted(uint32_t pid) const;
    
    /**
     * Add path pattern to whitelist
     * Example: "/home/user/dev/star" for development directories (use * for wildcard)
     */
    void WhitelistPath(const std::string& pattern);
    
    /**
     * Get statistics
     */
    struct Statistics {
        uint64_t files_checked;
        uint64_t encryption_attempts_blocked;
        uint64_t processes_killed;
        uint64_t whitelisted_operations;
        uint64_t false_positives_prevented;  // Caught before killing
    };
    
    Statistics GetStatistics() const;
    
    /**
     * Get per-process statistics
     */
    struct ProcessBehavior {
        uint32_t pid;
        std::string process_name;
        int encryption_attempts;
        int files_targeted;
        std::chrono::system_clock::time_point first_attempt;
        std::chrono::system_clock::time_point last_attempt;
        std::vector<std::string> targeted_files;
        bool is_confirmed_ransomware;
    };
    
    std::vector<ProcessBehavior> GetSuspiciousProcesses() const;

private:
    int fanotify_fd_;
    bool running_;
    
    std::unordered_set<uint32_t> whitelisted_pids_;
    std::vector<std::string> whitelisted_paths_;
    
    // Real-time YARA scanner
    std::unique_ptr<RealtimeYaraScanner> yara_scanner_;
    
    // Per-process behavior tracking
    struct ProcessActivity {
        std::string process_name;
        int encryption_attempts;
        std::set<std::string> files_targeted;
        std::chrono::system_clock::time_point first_attempt;
        std::chrono::system_clock::time_point last_attempt;
        bool killed;
        bool quarantined;
    };
    
    std::unordered_map<uint32_t, ProcessActivity> process_behaviors_;
    mutable std::mutex behavior_mutex_;
    
    // Thresholds for confirming ransomware
    static constexpr int ENCRYPTION_ATTEMPT_THRESHOLD = 3;  // 3 attempts = ransomware
    static constexpr int RAPID_ATTEMPT_SECONDS = 60;  // Within 60 seconds
    
    // Statistics
    Statistics stats_;
    mutable std::mutex stats_mutex_;
    
    // Incident logging
    std::ofstream incident_log_;
    std::mutex log_mutex_;
    
    /**
     * Analyze data being written for encryption
     * Returns true if data appears to be encrypted
     */
    bool IsDataEncrypted(const std::vector<uint8_t>& data);
    
    /**
     * Calculate Shannon entropy of data
     */
    double CalculateEntropy(const std::vector<uint8_t>& data);
    
    /**
     * Track encryption attempt and decide action
     * Returns: true to KILL process, false to just block this write
     */
    bool TrackAndDecideAction(uint32_t pid, const std::string& filepath);
    
    /**
     * Check if process behavior confirms ransomware
     */
    bool IsConfirmedRansomware(const ProcessActivity& activity) const;
    
    /**
     * Quarantine the malicious binary
     */
    bool QuarantineProcess(uint32_t pid);
    
    /**
     * Check if file path matches whitelist pattern (with glob support)
     */
    bool IsPathWhitelisted(const std::string& path) const;
    
    /**
     * Get process name from PID
     */
    std::string GetProcessName(uint32_t pid);
    
    /**
     * Get process command line
     */
    std::string GetProcessCommandLine(uint32_t pid);
    
    /**
     * Get process executable path
     */
    std::string GetProcessExecutablePath(uint32_t pid);
    
    /**
     * Log ransomware incident to database and file
     */
    void LogIncident(uint32_t pid, const std::string& process_name, 
                    const std::string& filepath, double entropy, 
                    bool killed, int total_attempts);
    
    /**
     * Match glob pattern (supports *, ?, [...])
     */
    bool MatchGlob(const std::string& pattern, const std::string& text) const;
};

} // namespace realtime
} // namespace koraav

#endif // KORAAV_RANSOMWARE_DETECTOR_H
