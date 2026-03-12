// src/realtime-protection/behavioral-analysis/canary_file_system.h
// Canary File Detection System
// Hidden decoy files that trigger instant ransomware detection
#ifndef KORAAV_CANARY_FILE_SYSTEM_H
#define KORAAV_CANARY_FILE_SYSTEM_H

#include <string>
#include <vector>
#include <unordered_set>
#include <chrono>
#include <mutex>
#include <atomic>

namespace koraav {
namespace realtime {

/**
 * Canary File System
 * 
 * Creates and manages hidden decoy files (canaries) in protected directories.
 * If ransomware touches a canary, triggers instant detection (score = 100).
 * 
 * Strategy:
 * - 1-3 canary files per protected directory
 * - Hidden names (.koraav-xxxxx.ext)
 * - Random generation on startup
 * - Rotation on daemon restart (unpredictable)
 * - Innocuous content (looks like system cache)
 */
class CanaryFileSystem {
public:
    CanaryFileSystem();
    ~CanaryFileSystem();
    
    /**
     * Initialize canary system
     * Creates canary files in protected directories
     * 
     * @param canaries_per_directory Number of canaries per dir (1-3 recommended)
     * @return true if initialized successfully
     */
    bool Initialize(int canaries_per_directory = 2); // default here is 2 if no config var or otherwise was passed to Initialize.
    
    /**
     * Check if a file path is a canary
     * Called from eBPF callback on every file access
     * 
     * @param filepath Path to check
     * @return true if this is a canary file (INSTANT TRIGGER)
     */
    bool IsCanaryFile(const std::string& filepath) const;
    
    /**
     * Rotate canaries (delete old, create new)
     * Called on daemon restart for unpredictability
     */
    void RotateCanaries();
    
    /**
     * Get all active canary paths (for logging/debugging)
     */
    std::vector<std::string> GetCanaryPaths() const;
    
    /**
     * Get statistics
     */
    struct Statistics {
        uint64_t canaries_created;
        uint64_t canaries_triggered;
        uint64_t rotations_performed;
    };
    
    Statistics GetStats() const;

private:
    struct CanaryFile {
        std::string path;
        std::string name;
        std::chrono::system_clock::time_point created;
    };
    
    std::vector<CanaryFile> active_canaries_;
    std::unordered_set<std::string> canary_paths_;  // Fast O(1) lookup
    mutable std::mutex canaries_mutex_;
    
    // ════════════════════════════════════════════════════════════
    // ENTERPRISE APPROACH: Canaries in Real User + System Directories
    // ════════════════════════════════════════════════════════════
    // Strategy 1: Real user directories (installer grants permission)
    // Strategy 2: World-writable system directories
    // Strategy 3: Dedicated system canary directories
    //
    // This is how CrowdStrike Falcon and SentinelOne work.
    // ════════════════════════════════════════════════════════════
    
    std::vector<std::string> protected_dir_patterns_ = {
        // REAL USER DIRECTORIES
        "/home/*/Documents",
        "/home/*/Downloads",
        "/home/*/Desktop",
        "/home/*/Pictures",
        "/home/*/Videos",
        "/home/*/Music",
        "/home/*/.config",
        "/home/*/.local/share",
        
        // ═══════════════════════════════════════════════════════
        // WORLD-WRITABLE SYSTEM DIRECTORIES (1777 permissions)
        // ═══════════════════════════════════════════════════════
        "/tmp",
        "/var/tmp",
        
        // ═══════════════════════════════════════════════════════
        // DEDICATED SYSTEM CANARY DIRECTORIES (koraav owned)
        // These look like real system directories to ransomware
        // ═══════════════════════════════════════════════════════
        "/var/lib/systemb/system_cache",
        "/var/lib/systemb/backup_data",
        "/var/lib/systemb/log_archive",
        "/var/lib/systemb/temp_files",
        
        // ═══════════════════════════════════════════════════════
        // SYSTEM DIRECTORIES (if writable by koraav)
        // ═══════════════════════════════════════════════════════
        "/var/log",      // Usually writable
        "/var/spool",    // Usually writable
        
        // Root user home
        "/root"
    };

    
    // Internal statistics (with atomics)
    struct InternalStats {
        std::atomic<uint64_t> canaries_created{0};
        std::atomic<uint64_t> canaries_triggered{0};
        std::atomic<uint64_t> rotations_performed{0};
    };
    
    mutable InternalStats stats_;
    
    // Helper methods
    void DeleteOldCanaries();
    void CreateCanaries(int count_per_directory);
    bool CreateCanaryFile(const std::string& directory, const std::string& name);
    std::string GenerateCanaryName(const std::string& directory);
    std::string GenerateCanaryContent(const std::string& directory);
    std::vector<std::string> ExpandDirectoryPatterns();
    std::string GetRandomHex(int length);
};

} // namespace realtime
} // namespace koraav

#endif // KORAAV_CANARY_FILE_SYSTEM_H
