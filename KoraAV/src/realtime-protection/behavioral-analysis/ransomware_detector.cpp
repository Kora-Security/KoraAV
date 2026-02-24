// src/realtime-protection/behavioral-analysis/ransomware_detector_v2.cpp
// Modern Behavioral Ransomware Detection - Implementation
#include "ransomware_detector.h"
#include <algorithm>
#include <array>
#include <sstream>
#include <fstream>
#include <iostream>
#include <cmath>
#include <iomanip>
#include <filesystem>

namespace koraav {
namespace realtime {

RansomwareDetector::RansomwareDetector() {
    InitializeWhitelist();
}

RansomwareDetector::~RansomwareDetector() {
    // Cleanup
}

bool RansomwareDetector::Initialize() {
    std::cout << "✓ Behavioral Ransomware Detector initialized" << std::endl;
    std::cout << "  → Monitoring file operations for ransomware patterns" << std::endl;
    return true;
}

void RansomwareDetector::InitializeWhitelist() {
    // Non exhaustive list of system services that legitimately write many files
    whitelisted_processes_ = {
        // Package managers
        "apt", "apt-get", "dpkg", "rpm", "yum", "dnf", "pacman",
        
        // System services
        "systemd", "systemd-journald", "systemd-udevd",
        "rsyslogd", "syslog-ng",
        
        // Backup software
        "rsync", "rsnapshot", "duplicity", "restic",
        "borg", "bacula", "amanda",
        
        // File system utilities
        "logrotate", "updatedb", "mlocate",
        
        // Database systems
        "mysqld", "postgres", "mongod", "redis-server",
        
        // Build systems
        "make", "cmake", "gcc", "g++", "clang",
        
        // Archive tools (when used legitimately)
        "tar", "gzip", "bzip2", "xz",
        
        // Text editors (bulk operations)
        "vim", "emacs", "nano", "sed", "awk",
        
        // System maintenance
        "cron", "anacron", "systemd-tmpfiles",
        
        // Update managers
        "unattended-upgrades", "packagekit",
        
        // Desktop search indexers
        "baloo_file", "tracker-miner-fs",
        
        // Our own daemon/files
        "korad", "koraav"
    };
}

bool RansomwareDetector::IsWhitelisted(uint32_t tgid, const std::string& process_name) {
    // Check if process name is in whitelist
    if (whitelisted_processes_.find(process_name) != whitelisted_processes_.end()) {
        stats_.false_positives_prevented++;
        return true;
    }
    
    // Check if process is a system daemon (UID 0 and specific patterns)
    std::string stat_path = "/proc/" + std::to_string(tgid) + "/status";
    std::ifstream status_file(stat_path);
    if (status_file) {
        std::string line;
        while (std::getline(status_file, line)) {
            if (line.find("Uid:") == 0) {
                // Parse UID
                std::istringstream iss(line);
                std::string label;
                uint32_t uid;
                iss >> label >> uid;
                
                // Root processes with system-like names
                if (uid == 0 && (process_name.find("systemd") == 0 ||
                                 process_name.find("update") != std::string::npos)) {
                    stats_.false_positives_prevented++;
                    return true;
                }
                break;
            }
        }
    }
    
    return false;
}

void RansomwareDetector::TrackFileOperation(uint32_t tgid, const std::string& path,
                                              const std::string& operation) {
    std::lock_guard<std::mutex> lock(activities_mutex_);
    
    auto& activity = process_activities_[tgid];
    auto now = std::chrono::system_clock::now();
    
    // Initialize timing
    if (activity.write_count == 0 && activity.rename_count == 0 && activity.delete_count == 0) {
        activity.first_activity = now;
    }
    activity.last_activity = now;
    
    // Track operation
    FileOperation op{path, operation, now};
    activity.file_operations.push_back(op);
    
    // Update counts
    if (operation == "write") {
        if (activity.pre_write_entropy.find(path) == activity.pre_write_entropy.end()) {
            double entropy = CalculateEntropy(path, 4096);
            activity.pre_write_entropy[path] = entropy;
        }
        activity.write_count++;
    } else if (operation == "rename") {
        activity.rename_count++;
    } else if (operation == "delete") {
        activity.delete_count++;
    }
    
    // Track unique files and directories
    activity.files_touched.insert(path);
    activity.directories_touched.insert(GetDirectoryPath(path));
    
    // Calculate operations per second
    activity.operations_per_second = CalculateOperationsPerSecond(activity);

    // Only check entropy if suspicious activity threshold crossed
    if (!activity.entropy_spike_detected) {

        uint32_t files_count = activity.files_touched.size();

        if (files_count >= thresholds_.files_before_action &&
            activity.operations_per_second > thresholds_.max_ops_per_second / 2) {

            for (const auto& file : activity.files_touched) {

                // Skip files already entropy-checked
                if (activity.entropy_checked_files.count(file))
                    continue;

                auto it = activity.pre_write_entropy.find(file);
                if (it == activity.pre_write_entropy.end())
                    continue;

                double before = it->second;
                double after = CalculateEntropy(file, 4096);
                double delta = after - before;

                activity.entropy_checked_files.insert(file);

                if (delta > thresholds_.entropy_delta_threshold) {
                    activity.entropy_spike_detected = true;
                    break;
                }
            }
        }
    }
}

void RansomwareDetector::TrackRename(uint32_t tgid, const std::string& old_path,
                                       const std::string& new_path) {
    std::lock_guard<std::mutex> lock(activities_mutex_);
    
    auto& activity = process_activities_[tgid];
    auto now = std::chrono::system_clock::now();
    
    // Track rename
    RenameOperation rename{old_path, new_path, now};
    activity.rename_operations.push_back(rename);
    
    // Track extension changes
    std::string old_ext = GetFileExtension(old_path);
    std::string new_ext = GetFileExtension(new_path);
    
    if (old_ext != new_ext && !old_ext.empty()) {
        activity.extension_changes[old_ext]++;
        
        // Check if this is mass extension change
        if (activity.extension_changes[old_ext] >= thresholds_.extension_change_threshold) {
            activity.mass_extension_change = true;
        }
    }
}

int RansomwareDetector::AnalyzeProcess(uint32_t tgid) {
    std::lock_guard<std::mutex> lock(activities_mutex_);
    
    auto it = process_activities_.find(tgid);
    if (it == process_activities_.end()) {
        return 0;
    }
    
    auto& activity = it->second;
    
    stats_.processes_analyzed++;
    
    // Run advanced detection checks (updates activity flags)
    DetectFsyncPattern(tgid);
    DetectSuspiciousParent(tgid);
    DetectBackupTampering(tgid);
    
    // Calculate ransomware score (includes advanced patterns)
    int score = CalculateRansomwareScore(activity);
    
    return score;
}

int RansomwareDetector::CalculateRansomwareScore(const ProcessActivity& activity) {
    int score = 0;

    // ═══════════════════════════════════════════════════════════
    // ENTROPY DELTA INCREASE (Strong Encryption Indicator)
    // ═══════════════════════════════════════════════════════════

    if (activity.entropy_spike_detected) {
        score += 45;  // Very strong indicator
    }

    
    // ═══════════════════════════════════════════════════════════
    // FILE OPERATION VELOCITY (Critical Indicator)
    // ═══════════════════════════════════════════════════════════
    
    if (activity.operations_per_second > thresholds_.max_ops_per_second) {
        score += 40;  // Very high velocity = likely ransomware
    } else if (activity.operations_per_second > thresholds_.max_ops_per_second / 2) {
        score += 25;  // Moderate velocity = suspicious
    }
    
    // ═══════════════════════════════════════════════════════════
    // NUMBER OF FILES TOUCHED (Rapid Burst)
    // ═══════════════════════════════════════════════════════════
    
    uint32_t files_count = activity.files_touched.size();
    
    if (files_count >= thresholds_.max_files_touched) {
        score += 35;  // 20+ files in short time
    } else if (files_count >= thresholds_.max_files_touched / 2) {
        score += 20;  // 10+ files
    } else if (files_count >= thresholds_.files_before_action) {
        score += 10;  // 5+ files (threshold for action)
    }
    
    // ═══════════════════════════════════════════════════════════
    // DIRECTORY SPREAD (Traversal Pattern)
    // ═══════════════════════════════════════════════════════════
    
    uint32_t dirs_count = activity.directories_touched.size();
    
    if (dirs_count >= thresholds_.max_directories) {
        score += 30;  // 10+ directories = systematic scan
    } else if (dirs_count >= thresholds_.max_directories / 2) {
        score += 15;  // 5+ directories
    }
    
    // ═══════════════════════════════════════════════════════════
    // MASS RENAME BEHAVIOR (Key Ransomware Indicator)
    // ═══════════════════════════════════════════════════════════
    
    if (activity.rename_count >= thresholds_.max_renames) {
        score += 35;  // 15+ renames = strong indicator
    } else if (activity.rename_count >= thresholds_.max_renames / 2) {
        score += 20;  // 8+ renames
    }
    
    // ═══════════════════════════════════════════════════════════
    // EXTENSION REWRITING (Classic Ransomware)
    // ═══════════════════════════════════════════════════════════
    
    if (activity.mass_extension_change) {
        score += 40;  // Mass extension change = definite ransomware
    }
    
    // Check for suspicious extensions (.encrypted, .locked, .crypto, etc.)
    for (const auto& [old_ext, count] : activity.extension_changes) {
        if (count >= 3) {  // Same extension changed 3+ times
            score += 15;
        }
    }
    
    // ═══════════════════════════════════════════════════════════
    // SEQUENTIAL DIRECTORY TRAVERSAL
    // ═══════════════════════════════════════════════════════════
    
    if (DetectSequentialTraversal(activity)) {
        score += 25;  // Systematic iteration = ransomware pattern
        const_cast<ProcessActivity&>(activity).sequential_directory_scan = true;
    }
    
    // ═══════════════════════════════════════════════════════════
    // WRITE-RENAME-DELETE PATTERN
    // ═══════════════════════════════════════════════════════════
    
    if (activity.write_count > 0 && activity.rename_count > 0 && activity.delete_count > 0) {
        // Check if operations are interleaved (common ransomware pattern)
        if (activity.file_operations.size() >= 3) {
            // Look for write -> rename -> delete sequences
            bool found_pattern = false;
            for (size_t i = 0; i < activity.file_operations.size() - 2; i++) {
                if (activity.file_operations[i].operation == "write" &&
                    activity.file_operations[i+1].operation == "rename" &&
                    activity.file_operations[i+2].operation == "delete") {
                    found_pattern = true;
                    break;
                }
            }
            if (found_pattern) {
                score += 30;  // Classic ransomware pattern
            }
        }
    }
    
    // ═══════════════════════════════════════════════════════════
    // TIME WINDOW ANALYSIS (Rapid Burst)
    // ═══════════════════════════════════════════════════════════
    
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        activity.last_activity - activity.first_activity
    );
    
    if (duration.count() < thresholds_.time_window_seconds && files_count >= 10) {
        score += 20;  // 10+ files in < 10 seconds = burst
    }
    
    // ═══════════════════════════════════════════════════════════
    // ADVANCED DETECTION PATTERNS (NEW)
    // ═══════════════════════════════════════════════════════════
    
    // fsync pattern (open → write → fsync repeatedly)
    if (activity.fsync_pattern_detected) {
        score += 30;  // Strong indicator of encryption routine
    }
    
    // Suspicious parent/child lineage
    if (activity.suspicious_parent_detected) {
        score += 35;  // Web server/doc viewer spawning file modifier
    }
    
    // Backup tampering
    if (activity.backup_tampering_detected) {
        score += 45;  // Trying to destroy backups = definite malware
    }
    
    // Cap at 100
    return std::min(score, 100);
}

// Helper implementations
double RansomwareDetector::CalculateOperationsPerSecond(const ProcessActivity& activity) {
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        activity.last_activity - activity.first_activity
    );
    
    if (duration.count() == 0) {
        return 0.0;
    }
    
    double seconds = duration.count() / 1000.0;
    double total_ops = activity.write_count + activity.rename_count + activity.delete_count;
    
    return total_ops / seconds;
}

bool RansomwareDetector::DetectSequentialTraversal(const ProcessActivity& activity) {
    // Check if directories are being accessed in sequential order
    // (e.g., /home/user/Documents, /home/user/Documents/subfolder1, subfolder2, etc.)
    
    if (activity.directories_touched.size() < 3) {
        return false;
    }
    
    std::vector<std::string> dirs(activity.directories_touched.begin(), 
                                   activity.directories_touched.end());
    std::sort(dirs.begin(), dirs.end());
    
    // Check if paths are nested (sequential traversal)
    int sequential_count = 0;
    for (size_t i = 1; i < dirs.size(); i++) {
        if (dirs[i].find(dirs[i-1]) == 0) {  // Current path starts with previous
            sequential_count++;
        }
    }
    
    // If 50%+ of directories are in sequential order, it's likely traversal
    return sequential_count >= static_cast<int>(dirs.size()) / 2;
}

bool RansomwareDetector::DetectMassExtensionChange(const ProcessActivity& activity) {
    // Already tracked in extension_changes map
    return activity.mass_extension_change;
}

std::string RansomwareDetector::GetFileExtension(const std::string& path) {
    size_t pos = path.rfind('.');
    if (pos != std::string::npos && pos != 0 && pos != path.length() - 1) {
        return path.substr(pos);
    }
    return "";
}

std::string RansomwareDetector::GetDirectoryPath(const std::string& path) {
    size_t pos = path.rfind('/');
    if (pos != std::string::npos) {
        return path.substr(0, pos);
    }
    return "";
}

bool RansomwareDetector::DetectCryptoAPI(uint32_t tgid) {
    // Check for crypto API usage by examining open file descriptors
    // and memory maps for crypto libraries

    // 1. Check memory maps for crypto libraries
    std::string maps_path = "/proc/" + std::to_string(tgid) + "/maps";
    std::ifstream maps_file(maps_path);

    if (maps_file) {
        std::string line;
        while (std::getline(maps_file, line)) {
            // Check for crypto libraries
            if (line.find("libcrypto") != std::string::npos ||
                line.find("libssl") != std::string::npos ||
                line.find("openssl") != std::string::npos) {
                return true;
                }
        }
    }

    // 2. Scan ALL file descriptors for crypto-related files
    std::string fd_dir = "/proc/" + std::to_string(tgid) + "/fd";

    try {
        // Iterate through all fd entries
        for (const auto& entry : std::filesystem::directory_iterator(fd_dir)) {
            try {
                // Read symlink target
                std::filesystem::path target = std::filesystem::read_symlink(entry.path());
                std::string target_str = target.string();

                // Check for crypto-related files
                if (target_str.find("/dev/urandom") != std::string::npos ||
                    target_str.find("/dev/random") != std::string::npos ||
                    target_str.find("libcrypto") != std::string::npos ||
                    target_str.find("libssl") != std::string::npos) {
                    return true;
                    }
            } catch (const std::filesystem::filesystem_error&) {
                // FD may have closed, continue
                continue;
            }
        }
    } catch (const std::filesystem::filesystem_error&) {
        // Process may have exited or fd dir inaccessible
        return false;
    }

    return false;
}

std::vector<std::string> RansomwareDetector::GetThreatIndicators(uint32_t tgid) {
    std::lock_guard<std::mutex> lock(activities_mutex_);
    std::vector<std::string> indicators;
    
    auto it = process_activities_.find(tgid);
    if (it == process_activities_.end()) {
        return indicators;
    }
    
    const auto& activity = it->second;


    if (activity.entropy_spike_detected) {
        indicators.push_back("ENTROPY SPIKE detected (possible encryption)");
    }
    
    // High-velocity file operations
    if (activity.operations_per_second > thresholds_.max_ops_per_second / 2) {
        std::ostringstream oss;
        oss << "HIGH VELOCITY: " << std::fixed << std::setprecision(1)
            << activity.operations_per_second << " operations/second";
        indicators.push_back(oss.str());
    }
    
    // Files touched
    if (!activity.files_touched.empty()) {
        std::ostringstream oss;
        oss << "Touched " << activity.files_touched.size() << " file(s) rapidly";
        indicators.push_back(oss.str());
    }
    
    // Directory spread
    if (activity.directories_touched.size() >= 5) {
        std::ostringstream oss;
        oss << "Accessed " << activity.directories_touched.size() << " different directories";
        indicators.push_back(oss.str());
    }
    
    // Mass renames
    if (activity.rename_count >= 5) {
        std::ostringstream oss;
        oss << "Performed " << activity.rename_count << " rename operations";
        indicators.push_back(oss.str());
    }
    
    // Extension changes
    if (activity.mass_extension_change) {
        indicators.push_back("MASS EXTENSION CHANGE detected");
        
        // Show which extensions were changed
        for (const auto& [ext, count] : activity.extension_changes) {
            if (count >= 3) {
                std::ostringstream oss;
                oss << "  → Changed " << count << " files with extension '" << ext << "'";
                indicators.push_back(oss.str());
            }
        }
    }
    
    // Sequential traversal
    if (activity.sequential_directory_scan) {
        indicators.push_back("SEQUENTIAL DIRECTORY TRAVERSAL detected");
    }
    
    // Crypto API
    if (activity.crypto_api_detected) {
        indicators.push_back("Crypto library usage detected");
    }
    
    // ═══ ADVANCED PATTERNS (NEW) ═══
    
    // fsync pattern
    if (activity.fsync_pattern_detected) {
        indicators.push_back("⚠️  FSYNC PATTERN detected (open → write → fsync sequence)");
    }
    
    // Suspicious parent
    if (activity.suspicious_parent_detected) {
        indicators.push_back("⚠️  SUSPICIOUS PARENT detected (web server/browser/doc viewer)");
    }
    
    // Backup tampering
    if (activity.backup_tampering_detected) {
        indicators.push_back("🚨 BACKUP TAMPERING detected (destroying ransomware protection!)");
    }
    
    // Time window
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        activity.last_activity - activity.first_activity
    );
    
    if (duration.count() < thresholds_.time_window_seconds && activity.files_touched.size() >= 5) {
        std::ostringstream oss;
        oss << "RAPID BURST: " << activity.files_touched.size() 
            << " files in " << duration.count() << " seconds";
        indicators.push_back(oss.str());
    }
    
    // Show first few affected files
    if (!activity.file_operations.empty()) {
        indicators.push_back("Affected files:");
        int count = 0;
        for (const auto& op : activity.file_operations) {
            if (count++ >= 5) break;  // Show first 5
            std::ostringstream oss;
            oss << "  → " << op.operation << ": " << op.path;
            indicators.push_back(oss.str());
        }
        if (activity.file_operations.size() > 5) {
            std::ostringstream oss;
            oss << "  ... and " << (activity.file_operations.size() - 5) << " more";
            indicators.push_back(oss.str());
        }
    }
    
    return indicators;
}

void RansomwareDetector::CleanupProcess(uint32_t tgid) {
    std::lock_guard<std::mutex> lock(activities_mutex_);
    process_activities_.erase(tgid);
}

std::vector<uint32_t> RansomwareDetector::GetSuspiciousProcesses(int min_score) {
    std::lock_guard<std::mutex> lock(activities_mutex_);
    std::vector<uint32_t> suspicious;
    
    for (const auto& [tgid, activity] : process_activities_) {
        int score = CalculateRansomwareScore(activity);
        if (score >= min_score) {
            suspicious.push_back(tgid);
        }
    }
    
    return suspicious;
}

double RansomwareDetector::CalculateEntropy(const std::string& path, size_t sample_size) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return 0.0;

    std::vector<unsigned char> buffer(sample_size);
    file.read(reinterpret_cast<char*>(buffer.data()), sample_size);
    size_t bytes_read = file.gcount();
    if (bytes_read == 0) return 0.0;

    std::array<size_t, 256> freq{};
    for (size_t i = 0; i < bytes_read; ++i) {
        freq[buffer[i]]++;
    }

    double entropy = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) / bytes_read;
        entropy -= p * std::log2(p);
    }

    return entropy;
}









// ═══════════════════════════════════════════════════════════
// ADVANCED DETECTION PATTERNS
// ═══════════════════════════════════════════════════════════

bool RansomwareDetector::DetectFsyncPattern(uint32_t tgid) {
    auto it = process_activities_.find(tgid);
    if (it == process_activities_.end()) {
        return false;
    }
    
    auto& activity = it->second;
    
    // Check for open → write → fsync pattern (typical encryption routine)
    // Heuristic: High velocity + many files = likely fsync pattern
    if (activity.operations_per_second > 20.0 && activity.files_touched.size() > 10) {
        activity.fsync_pattern_detected = true;
        activity.fsync_sequence_count++;
        return true;
    }
    
    return false;
}

bool RansomwareDetector::DetectSuspiciousParent(uint32_t tgid) {
    std::string stat_path = "/proc/" + std::to_string(tgid) + "/stat";
    std::ifstream stat_file(stat_path);
    if (!stat_file) {
        return false;
    }
    
    std::string line;
    std::getline(stat_file, line);
    
    size_t first_paren = line.find('(');
    size_t last_paren = line.rfind(')');
    if (first_paren == std::string::npos || last_paren == std::string::npos) {
        return false;
    }
    
    std::string after_comm = line.substr(last_paren + 1);
    std::istringstream iss(after_comm);
    
    char state;
    uint32_t ppid;
    iss >> state >> ppid;
    
    std::string parent_comm_file = "/proc/" + std::to_string(ppid) + "/comm";
    std::ifstream parent_comm(parent_comm_file);
    if (!parent_comm) {
        return false;
    }
    
    std::string parent_name;
    std::getline(parent_comm, parent_name);
    
    std::vector<std::string> suspicious_parents = {
        "apache2", "nginx", "httpd",
        "firefox", "chrome", "chromium",
        "evince", "okular", "xpdf",
        "thunderbird", "evolution",
        "libreoffice", "soffice"
    };
    
    for (const auto& suspicious : suspicious_parents) {
        if (parent_name.find(suspicious) != std::string::npos) {
            auto it = process_activities_.find(tgid);
            if (it != process_activities_.end()) {
                it->second.suspicious_parent_detected = true;
                return true;
            }
        }
    }
    
    return false;
}

bool RansomwareDetector::DetectBackupTampering(uint32_t tgid) {
    auto it = process_activities_.find(tgid);
    if (it == process_activities_.end()) {
        return false;
    }
    
    auto& activity = it->second;
    
    if (activity.process_name == "systemctl") {
        std::string cmdline_path = "/proc/" + std::to_string(tgid) + "/cmdline";
        std::ifstream cmdline_file(cmdline_path);
        if (cmdline_file) {
            std::string cmdline;
            std::getline(cmdline_file, cmdline, '\0');
            
            if (cmdline.find("stop") != std::string::npos) {
                std::vector<std::string> backup_services = {
                    "bacula", "duplicity", "rsnapshot", "backup",
                    "vss", "shadow", "timeshift"
                };
                
                for (const auto& service : backup_services) {
                    if (cmdline.find(service) != std::string::npos) {
                        activity.backup_tampering_detected = true;
                        return true;
                    }
                }
            }
        }
    }
    
    std::vector<std::string> backup_dirs = {
        "/var/backups", "/backup", "/backups",
        "/mnt/backup", "/media/backup",
        "/.snapshots", "/timeshift"
    };
    
    for (const auto& file : activity.files_touched) {
        for (const auto& backup_dir : backup_dirs) {
            if (file.find(backup_dir) != std::string::npos) {
                activity.backup_tampering_detected = true;
                return true;
            }
        }
    }
    
    return false;
}

} // namespace realtime
} // namespace koraav
