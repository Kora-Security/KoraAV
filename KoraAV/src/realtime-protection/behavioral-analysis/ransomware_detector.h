// src/realtime-protection/behavioral-analysis/ransomware_detector.h
// Modern Behavioral Ransomware Detection Engine
// Based on enterprise EDR approaches (CrowdStrike, SentinelOne, etc.)
#ifndef KORAAV_RANSOMWARE_DETECTOR_H
#define KORAAV_RANSOMWARE_DETECTOR_H

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <mutex>
#include <atomic>

namespace koraav {
namespace realtime {

/**
 * Behavioral Ransomware Detector
 * 
 * Detects ransomware by monitoring process behavior patterns:
 * - File operation velocity (writes/sec)
 * - Directory traversal patterns
 * - Mass file rename operations
 * - Extension rewriting behavior
 * - Crypto API usage (OpenSSL, libcrypto)
 * 
 * Similar to enterprise EDR solutions, allows 1-5 files to be touched
 * before taking action (kill + quarantine).
 */
class RansomwareDetector {
public:
    RansomwareDetector();
    ~RansomwareDetector();
    
    /**
     * Initialize detector
     */
    bool Initialize();
    
    /**
     * Track file operation by a process
     * @param tgid Process ID
     * @param path File path
     * @param operation Type: "write", "rename", "delete"
     */
    void TrackFileOperation(uint32_t tgid, const std::string& path, const std::string& operation);
    
    /**
     * Track file rename specifically
     * @param tgid Process ID
     * @param old_path Original filename
     * @param new_path New filename
     */
    void TrackRename(uint32_t tgid, const std::string& old_path, const std::string& new_path);
    
    /**
     * Analyze process behavior and return threat score (0-100)
     * Returns score immediately if threshold exceeded
     */
    int AnalyzeProcess(uint32_t tgid);
    
    /**
     * Get detailed threat indicators for a process
     */
    std::vector<std::string> GetThreatIndicators(uint32_t tgid);
    
    /**
     * Check if process should be whitelisted
     * @param tgid Process ID
     * @param process_name Name of process (from /proc/pid/comm)
     * @return true if process is whitelisted
     */
    bool IsWhitelisted(uint32_t tgid, const std::string& process_name);
    
    /**
     * Clear tracking for exited process
     */
    void CleanupProcess(uint32_t tgid);
    
    /**
     * Get all currently suspicious processes
     */
    std::vector<uint32_t> GetSuspiciousProcesses(int min_score = 70);

private:
    // Track file operations for a process
    struct FileOperation {
        std::string path;
        std::string operation;  // "write", "rename", "delete"
        std::chrono::system_clock::time_point timestamp;
    };
    
    // Track rename operations specifically
    struct RenameOperation {
        std::string old_path;
        std::string new_path;
        std::chrono::system_clock::time_point timestamp;
    };
    
    // Per-process activity tracking
    struct ProcessActivity {
        std::string process_name;
        std::chrono::system_clock::time_point first_activity;
        std::chrono::system_clock::time_point last_activity;
        
        // Operation counts
        uint32_t write_count = 0;
        uint32_t rename_count = 0;
        uint32_t delete_count = 0;
        

        std::unordered_map<std::string, double> pre_write_entropy;
        std::unordered_set<std::string> entropy_checked_files;  // Track which files already checked
        bool entropy_spike_detected = false;

        // Detailed tracking
        std::vector<FileOperation> file_operations;
        std::vector<RenameOperation> rename_operations;
        
        // Unique files/directories touched
        std::unordered_set<std::string> files_touched;
        std::unordered_set<std::string> directories_touched;
        
        // Extension tracking
        std::unordered_map<std::string, uint32_t> extension_changes;  // old_ext -> count
        
        // Velocity tracking (operations per second)
        double operations_per_second = 0.0;
        
        // Behavioral flags
        bool sequential_directory_scan = false;
        bool mass_extension_change = false;
        bool crypto_api_detected = false;
        
        // Advanced detection flags (NEW)
        bool fsync_pattern_detected = false;      // open → write → fsync pattern
        bool suspicious_parent_detected = false;   // Unusual parent/child lineage
        bool backup_tampering_detected = false;    // systemctl stop, backup dir mods
        uint32_t fsync_sequence_count = 0;        // Count of fsync sequences
    };
    
    // Process tracking
    std::unordered_map<uint32_t, ProcessActivity> process_activities_;
    std::mutex activities_mutex_;
    
    // Whitelisted processes (system services, backup tools, etc.)
    std::unordered_set<std::string> whitelisted_processes_;
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> processes_analyzed{0};
        std::atomic<uint64_t> ransomware_detected{0};
        std::atomic<uint64_t> false_positives_prevented{0};
    } stats_;
    
    // Detection thresholds (configurable)
    struct Thresholds {
        double max_ops_per_second = 50.0;      // 50 files/sec is suspicious
        uint32_t max_files_touched = 20;        // 20+ files in short time
        uint32_t max_directories = 10;          // 10+ directories traversed
        uint32_t max_renames = 15;              // 15+ renames
        uint32_t extension_change_threshold = 4; // 4+ files with same ext change
        double time_window_seconds = 10.0;      // Analyze within 10sec window
        uint32_t files_before_action = 5;       // Allow 4 files max (like enterprise EDR)
        double entropy_delta_threshold = 2.5;
    } thresholds_;
    
    // Helper functions
    void InitializeWhitelist();
    int CalculateRansomwareScore(const ProcessActivity& activity);
    bool DetectSequentialTraversal(const ProcessActivity& activity);
    bool DetectMassExtensionChange(const ProcessActivity& activity);
    bool DetectCryptoAPI(uint32_t tgid);
    double CalculateOperationsPerSecond(const ProcessActivity& activity);
    std::string GetFileExtension(const std::string& path);
    std::string GetDirectoryPath(const std::string& path);
    
    // Advanced detection helpers (NEW)
    bool DetectFsyncPattern(uint32_t tgid);
    bool DetectSuspiciousParent(uint32_t tgid);
    bool DetectBackupTampering(uint32_t tgid);
    double CalculateEntropy(const std::string& path, size_t sample_size = 4096);
};

} // namespace realtime
} // namespace koraav

#endif // KORAAV_RANSOMWARE_DETECTOR_H
