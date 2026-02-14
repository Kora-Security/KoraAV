// include/koraav/types.h
#ifndef KORAAV_TYPES_H
#define KORAAV_TYPES_H

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <functional>

namespace koraav {

// Threat severity levels
enum class ThreatLevel {
    CLEAN = 0,
    SUSPICIOUS = 1,
    LOW = 2,
    MEDIUM = 3,
    HIGH = 4,
    CRITICAL = 5
};

// Scan types
enum class ScanType {
    FULL_SCAN,      // Entire filesystem
    QUICK_SCAN,     // Common locations only
    MANUAL_SCAN,    // User-specified paths
    REALTIME_SCAN   // On-access scanning
};

// Detection methods
enum class DetectionMethod {
    HASH_MATCH,          // Known malware hash
    SIGNATURE_MATCH,     // Pattern/signature match
    YARA_RULE,           // YARA rule match
    HIGH_ENTROPY,        // Encrypted/packed file
    SUSPICIOUS_STRINGS,  // Malicious strings found
    HEURISTIC,           // Behavioral heuristic
    STATIC_ANALYSIS,     // Code analysis
    BEHAVIORAL           // Runtime behavior (realtime only)
};

// File type
enum class FileType {
    UNKNOWN,
    ELF_EXECUTABLE,
    SCRIPT_BASH,
    SCRIPT_PYTHON,
    SCRIPT_PERL,
    ARCHIVE,
    DOCUMENT,
    PE_EXECUTABLE,  // Future Windows support
    LIBRARY,
    TEXT
};

// Scan status
enum class ScanStatus {
    NOT_STARTED,
    IN_PROGRESS,
    COMPLETED,
    CANCELLED,
    ERROR
};

// Individual file scan result
struct FileScanResult {
    std::string path;
    ThreatLevel threat_level;
    std::vector<DetectionMethod> detection_methods;
    std::vector<std::string> indicators;  // What triggered detection
    FileType file_type;
    uint64_t file_size;
    std::string hash_md5;
    std::string hash_sha256;
    double entropy;
    bool is_packed;
    std::chrono::system_clock::time_point scan_time;
    
    // Helper
    bool is_threat() const {
        return threat_level != ThreatLevel::CLEAN;
    }
};

// Overall scan results
struct ScanResults {
    ScanType scan_type;
    ScanStatus status;
    
    uint64_t files_scanned;
    uint64_t threats_found;
    uint64_t files_skipped;
    uint64_t errors;
    
    std::vector<FileScanResult> threats;
    std::vector<std::string> scanned_paths;
    
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    
    // Helper
    std::chrono::duration<double> elapsed_time() const {
        return end_time - start_time;
    }
};

// Configuration for scanning
struct ScanConfig {
    bool scan_archives;           // Scan inside zip/tar/etc
    bool follow_symlinks;         // Follow symbolic links
    bool scan_hidden_files;       // Scan dotfiles
    size_t max_file_size;         // Skip files larger than this (bytes)
    size_t max_scan_depth;        // Max directory depth
    std::vector<std::string> exclude_paths;  // Don't scan these
    bool use_hash_db;             // Check against hash database
    bool use_yara;                // Use YARA rules
    bool use_heuristics;          // Use heuristic analysis
    bool use_static_analysis;     // Analyze executables/scripts
    int thread_count;             // Parallel scanning threads
    
    // Defaults
    ScanConfig() :
        scan_archives(true),
        follow_symlinks(true),
        scan_hidden_files(true),
        max_file_size(100 * 1024 * 1024),  // 100MB
        max_scan_depth(32),
        use_hash_db(true),
        use_yara(true),
        use_heuristics(true),
        use_static_analysis(true),
        thread_count(4)
    {}
};

// Progress callback
using ProgressCallback = std::function<void(const std::string& current_file, 
                                            uint64_t files_scanned,
                                            uint64_t threats_found)>;

} // namespace koraav

#endif // KORAAV_TYPES_H
