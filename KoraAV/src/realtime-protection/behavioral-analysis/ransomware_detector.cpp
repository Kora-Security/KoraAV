// src/realtime-protection/behavioral-analysis/ransomware_detector.cpp
#include "ransomware_detector.h"
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <cstring>
#include <cmath>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <fnmatch.h>
#include <filesystem>

namespace fs = std::filesystem;

namespace koraav {
namespace realtime {

RansomwareDetector::RansomwareDetector() 
    : fanotify_fd_(-1), running_(false) {
    // Initialize statistics
    stats_.files_checked = 0;
    stats_.encryption_attempts_blocked = 0;
    stats_.processes_killed = 0;
    stats_.whitelisted_operations = 0;
    stats_.false_positives_prevented = 0;
}

RansomwareDetector::~RansomwareDetector() {
    Stop();
    if (incident_log_.is_open()) {
        incident_log_.close();
    }
}

bool RansomwareDetector::Initialize(const std::vector<std::string>& protected_paths) {
    // Open incident log
    fs::create_directories("/opt/koraav/var/logs");
    incident_log_.open("/opt/koraav/var/logs/ransomware-incidents.log", 
                      std::ios::app);
    if (!incident_log_) {
        std::cerr << "Warning: Could not open incident log file" << std::endl;
    }
    
    // Initialize YARA scanner
    yara_scanner_ = std::make_unique<RealtimeYaraScanner>();
    if (yara_scanner_->Initialize("/opt/koraav/share/signatures/yara-rules")) {
        std::cout << "Real-time YARA scanning enabled" << std::endl;
    } else {
        std::cerr << "Warning: YARA scanning disabled (rules not found)" << std::endl;
    }
    
    // Create fanotify instance with permission events
    fanotify_fd_ = fanotify_init(
        FAN_CLASS_CONTENT | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS,
        O_RDONLY | O_LARGEFILE
    );
    
    if (fanotify_fd_ < 0) {
        std::cerr << "Failed to initialize fanotify: " << strerror(errno) << std::endl;
        return false;
    }
    
    // Mark directories for monitoring
    for (const auto& path : protected_paths) {
        int ret = fanotify_mark(
            fanotify_fd_,
            FAN_MARK_ADD | FAN_MARK_MOUNT,
            FAN_OPEN_PERM | FAN_MODIFY | FAN_CLOSE_WRITE,
            AT_FDCWD,
            path.c_str()
        );
        
        if (ret < 0) {
            std::cerr << "Failed to mark path " << path << ": " << strerror(errno) << std::endl;
        }
    }
    
    // Default whitelisted paths
    whitelisted_paths_.push_back("/tmp/koraav-*"); // Placeholder
    
    std::cout << "Ransomware detector initialized on " << protected_paths.size() 
              << " path(s)" << std::endl;
    std::cout << "Encryption attempt threshold: " << ENCRYPTION_ATTEMPT_THRESHOLD 
              << " attempts" << std::endl;
    
    return true;
}

void RansomwareDetector::Run() {
    running_ = true;
    
    char buffer[4096];
    
    while (running_) {
        ssize_t len = read(fanotify_fd_, buffer, sizeof(buffer));
        if (len < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "Error reading fanotify events: " << strerror(errno) << std::endl;
            break;
        }
        
        char* ptr = buffer;
        while (ptr < buffer + len) {
            struct fanotify_event_metadata* metadata = 
                (struct fanotify_event_metadata*)ptr;
            
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                std::cerr << "Fanotify metadata version mismatch" << std::endl;
                break;
            }
            
            if (metadata->mask & FAN_OPEN_PERM) {
                uint32_t pid = metadata->pid;
                int fd = metadata->fd;
                
                char path_buf[PATH_MAX];
                char fd_path[64];
                snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
                ssize_t path_len = readlink(fd_path, path_buf, sizeof(path_buf) - 1);
                
                if (path_len > 0) {
                    path_buf[path_len] = '\0';
                    
                    bool allow = true;
                    
                    // YARA SCAN ON FILE EXECUTION
                    // If file is being opened for execution, scan it with YARA
                    if (metadata->mask & FAN_OPEN_EXEC_PERM) {
                        if (yara_scanner_ && !IsWhitelisted(pid) && !IsPathWhitelisted(path_buf)) {
                            std::vector<std::string> yara_matches;
                            
                            if (!yara_scanner_->QuickScan(path_buf, yara_matches)) {
                                // YARA detected malware!
                                std::cout << "YARA RULE BLOCKED MALWARE EXECUTION" << std::endl;
                                std::cout << "   File: " << path_buf << std::endl;
                                std::cout << "   PID: " << pid << std::endl;
                                std::cout << "   Matches:" << std::endl;
                                
                                for (const auto& rule : yara_matches) {
                                    std::cout << "      • " << rule << std::endl;
                                }
                                
                                // Block, Kill, Quarantine
                                allow = false;
                                kill(pid, SIGKILL);
                                QuarantineProcess(pid);
                                
                                {
                                    std::lock_guard<std::mutex> lock(stats_mutex_);
                                    stats_.processes_killed++;
                                }
                            }
                        }
                    }
                    
                    if (IsWhitelisted(pid) || IsPathWhitelisted(path_buf)) {
                        std::lock_guard<std::mutex> lock(stats_mutex_);
                        stats_.whitelisted_operations++;
                    }
                    
                    struct fanotify_response response;
                    response.fd = fd;
                    response.response = allow ? FAN_ALLOW : FAN_DENY;
                    
                    write(fanotify_fd_, &response, sizeof(response));
                }
                
                close(fd);
            }
            else if (metadata->mask & FAN_MODIFY) {
                uint32_t pid = metadata->pid;
                int fd = metadata->fd;
                
                char path_buf[PATH_MAX];
                char fd_path[64];
                snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
                ssize_t path_len = readlink(fd_path, path_buf, sizeof(path_buf) - 1);
                
                bool allow = true;  // Default: allow write
                
                if (path_len > 0) {
                    path_buf[path_len] = '\0';
                    
                    {
                        std::lock_guard<std::mutex> lock(stats_mutex_);
                        stats_.files_checked++;
                    }
                    
                    if (IsWhitelisted(pid) || IsPathWhitelisted(path_buf)) {
                        // Whitelisted - allow immediately
                        close(fd);
                        ptr += metadata->event_len;
                        continue;
                    }
                    
                    // Read data being written (before allowing it)
                    std::vector<uint8_t> data(4096);
                    lseek(fd, 0, SEEK_SET);
                    ssize_t bytes_read = read(fd, data.data(), data.size());
                    
                    if (bytes_read > 0) {
                        data.resize(bytes_read);
                        
                        // Check for encryption patterns
                        if (IsDataEncrypted(data)) {
                            double entropy = CalculateEntropy(data);
                            
                            // BLOCK THE WRITE - Don't allow encrypted data to be written!
                            allow = false;
                            
                            {
                                std::lock_guard<std::mutex> lock(stats_mutex_);
                                stats_.encryption_attempts_blocked++;
                            }
                            
                            // Track this encryption attempt
                            bool should_kill = TrackAndDecideAction(pid, path_buf);
                            
                            std::string proc_name = GetProcessName(pid);
                            
                            std::cout << "🛡️  ENCRYPTION ATTEMPT BLOCKED!" << std::endl;
                            std::cout << "   Process: " << proc_name << " (PID " << pid << ")" << std::endl;
                            std::cout << "   File: " << path_buf << std::endl;
                            std::cout << "   Entropy: " << entropy << std::endl;
                            std::cout << "   Total attempts by this process: " 
                                      << process_behaviors_[pid].encryption_attempts << std::endl;
                            
                            if (should_kill) {
                                std::cout << "\n🚨 CONFIRMED RANSOMWARE - KILLING PROCESS" << std::endl;
                                std::cout << "   Attempts blocked: " << process_behaviors_[pid].encryption_attempts << std::endl;
                                std::cout << "   Files targeted: " << process_behaviors_[pid].files_targeted.size() << std::endl;
                                std::cout << "   ✓ No files were encrypted (all attempts blocked!)\n" << std::endl;
                                
                                // Kill and quarantine
                                QuarantineProcess(pid);
                                kill(pid, SIGKILL);
                                
                                // Mark as killed
                                {
                                    std::lock_guard<std::mutex> lock(behavior_mutex_);
                                    process_behaviors_[pid].killed = true;
                                }
                                
                                {
                                    std::lock_guard<std::mutex> lock(stats_mutex_);
                                    stats_.processes_killed++;
                                }
                                
                                // Log with full details
                                LogIncident(pid, proc_name, path_buf, entropy, true, 
                                          process_behaviors_[pid].encryption_attempts);
                            } else {
                                // Suspicious but not confirmed yet - blocked this attempt, keep monitoring
                                std::cout << "   ⚠️  Monitoring continues (threshold not reached)" << std::endl;
                                std::cout << "   Threshold: " << ENCRYPTION_ATTEMPT_THRESHOLD 
                                          << " attempts or " << RAPID_ATTEMPT_SECONDS 
                                          << "s rapid attempts\n" << std::endl;
                                std::cout << "BLOCKED ENCRYPTION ATTEMPT (monitoring)" << std::endl;
                                std::cout << "   Process: " << proc_name << " (PID " << pid << ")" << std::endl;
                                std::cout << "   File: " << path_buf << std::endl;
                                std::cout << "   Entropy: " << std::fixed << std::setprecision(2) 
                                         << entropy << "/8.0" << std::endl;
                                std::cout << "   Attempts so far: " << process_behaviors_[pid].encryption_attempts << std::endl;
                                std::cout << "   Threshold: " << ENCRYPTION_ATTEMPT_THRESHOLD << std::endl;
                                
                                {
                                    std::lock_guard<std::mutex> lock(stats_mutex_);
                                    stats_.false_positives_prevented++;
                                }
                                
                                // Log but don't kill yet
                                LogIncident(pid, proc_name, path_buf, entropy, false,
                                          process_behaviors_[pid].encryption_attempts);
                            }
                        }
                    }
                    
                    // Send fanotify response (allow or deny the write)
                    struct fanotify_response response;
                    response.fd = fd;
                    response.response = allow ? FAN_ALLOW : FAN_DENY;
                    write(fanotify_fd_, &response, sizeof(response));
                }
                
                close(fd);
            }
            
            ptr += metadata->event_len;
        }
    }
}

void RansomwareDetector::Stop() {
    running_ = false;
    if (fanotify_fd_ >= 0) {
        close(fanotify_fd_);
        fanotify_fd_ = -1;
    }
}

void RansomwareDetector::WhitelistProcess(uint32_t pid) {
    whitelisted_pids_.insert(pid);
    std::cout << "Whitelisted process PID " << pid << " (requires root)" << std::endl;
}

void RansomwareDetector::RemoveFromWhitelist(uint32_t pid) {
    whitelisted_pids_.erase(pid);
}

bool RansomwareDetector::IsWhitelisted(uint32_t pid) const {
    return whitelisted_pids_.find(pid) != whitelisted_pids_.end();
}

void RansomwareDetector::WhitelistPath(const std::string& pattern) {
    whitelisted_paths_.push_back(pattern);
    std::cout << "Whitelisted path pattern: " << pattern << std::endl;
}

RansomwareDetector::Statistics RansomwareDetector::GetStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

std::vector<RansomwareDetector::ProcessBehavior> RansomwareDetector::GetSuspiciousProcesses() const {
    std::lock_guard<std::mutex> lock(behavior_mutex_);
    
    std::vector<ProcessBehavior> result;
    
    for (const auto& [pid, activity] : process_behaviors_) {
        if (!activity.killed && activity.encryption_attempts > 0) {
            ProcessBehavior behavior;
            behavior.pid = pid;
            behavior.process_name = activity.process_name;
            behavior.encryption_attempts = activity.encryption_attempts;
            behavior.files_targeted = activity.files_targeted.size();
            behavior.first_attempt = activity.first_attempt;
            behavior.last_attempt = activity.last_attempt;
            behavior.is_confirmed_ransomware = IsConfirmedRansomware(activity);
            
            for (const auto& file : activity.files_targeted) {
                behavior.targeted_files.push_back(file);
            }
            
            result.push_back(behavior);
        }
    }
    
    return result;
}

bool RansomwareDetector::TrackAndDecideAction(uint32_t pid, const std::string& filepath) {
    std::lock_guard<std::mutex> lock(behavior_mutex_);
    
    auto& activity = process_behaviors_[pid];
    
    // First time seeing this process
    if (activity.encryption_attempts == 0) {
        activity.process_name = GetProcessName(pid);
        activity.first_attempt = std::chrono::system_clock::now();
        activity.killed = false;
        activity.quarantined = false;
    }
    
    // Update activity
    activity.encryption_attempts++;
    activity.files_targeted.insert(filepath);
    activity.last_attempt = std::chrono::system_clock::now();
    
    // Check if this confirms ransomware behavior
    return IsConfirmedRansomware(activity);
}

bool RansomwareDetector::IsConfirmedRansomware(const ProcessActivity& activity) const {
    // Already killed/handled
    if (activity.killed) {
        return false;
    }
    
    // Threshold 1: Multiple encryption attempts
    if (activity.encryption_attempts >= ENCRYPTION_ATTEMPT_THRESHOLD) {
        return true;
    }
    
    // Threshold 2: Rapid attempts (even if less than threshold)
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        activity.last_attempt - activity.first_attempt
    );
    
    if (activity.encryption_attempts >= 2 && duration.count() < RAPID_ATTEMPT_SECONDS) {
        // 2+ encryption attempts within 60 seconds = likely ransomware
        return true;
    }
    
    // Threshold 3: Many different files targeted
    if (activity.files_targeted.size() >= 5) {
        return true;
    }
    
    return false;
}

bool RansomwareDetector::QuarantineProcess(uint32_t pid) {
    std::string exe_path = GetProcessExecutablePath(pid);
    if (exe_path.empty()) {
        std::cerr << "Could not get executable path for PID " << pid << std::endl;
        return false;
    }
    
    // Create quarantine directory
    fs::create_directories("/opt/koraav/var/quarantine");
    
    // Generate quarantine filename with timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << "/opt/koraav/var/quarantine/ransomware_" << pid << "_" 
        << std::put_time(std::localtime(&time_t_now), "%Y%m%d_%H%M%S");
    
    std::string quarantine_path = oss.str();
    
    // Copy executable to quarantine
    try {
        fs::copy_file(exe_path, quarantine_path, fs::copy_options::overwrite_existing);
        
        std::cout << "Quarantined: " << exe_path << " -> " << quarantine_path << std::endl;
        
        {
            std::lock_guard<std::mutex> lock(behavior_mutex_);
            process_behaviors_[pid].quarantined = true;
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to quarantine " << exe_path << ": " << e.what() << std::endl;
        return false;
    }
}

bool RansomwareDetector::IsDataEncrypted(const std::vector<uint8_t>& data) {
    if (data.size() < 256) {
        return false;
    }
    
    int suspicion_score = 0;  // Accumulate evidence
    
    // METHOD 1: Entropy analysis (most reliable)
    double entropy = CalculateEntropy(data);
    
    if (entropy > 7.8) {
        suspicion_score += 50;  // Very high entropy = likely encrypted
    } else if (entropy > 7.5) {
        suspicion_score += 35;  // High entropy = suspicious
    } else if (entropy > 7.0) {
        suspicion_score += 20;  // Moderately high entropy
    }
    
    // METHOD 2: Chi-square test (uniform byte distribution)
    int freq[256] = {0};
    for (uint8_t byte : data) {
        freq[byte]++;
    }
    
    double expected = data.size() / 256.0;
    double chi_square = 0.0;
    
    for (int i = 0; i < 256; i++) {
        double diff = freq[i] - expected;
        chi_square += (diff * diff) / expected;
    }
    
    // Low chi-square = uniform distribution = likely encrypted
    if (chi_square < 250.0) {
        suspicion_score += 30;  // Very uniform
    } else if (chi_square < 300.0) {
        suspicion_score += 20;  // Somewhat uniform
    }
    
    // METHOD 3: Check for encryption signature patterns
    // Common ransomware add headers/markers
    
    // Check for repeated patterns at start (some ransomware markers)
    if (data.size() >= 16) {
        std::string header(data.begin(), data.begin() + 16);
        if (header.find("ENCRYPTED") != std::string::npos ||
            header.find("LOCKED") != std::string::npos ||
            header.find("CRYPTED") != std::string::npos) {
            suspicion_score += 100;  // Explicit ransomware marker!
        }
    }
    
    // METHOD 4: Check if data lacks normal file signatures
    // Normal files have magic bytes (PDF, JPEG, PNG, etc.)
    bool has_known_format = false;
    
    if (data.size() >= 4) {
        // PDF
        if (data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46) {
            has_known_format = true;
        }
        // JPEG
        else if (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) {
            has_known_format = true;
        }
        // PNG
        else if (data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47) {
            has_known_format = true;
        }
        // ZIP
        else if (data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04) {
            has_known_format = true;
        }
        // DOCX/XLSX (also ZIP-based)
        else if (data[0] == 0x50 && data[1] == 0x4B) {
            has_known_format = true;
        }
        // ELF
        else if (data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46) {
            has_known_format = true;
        }
    }
    
    // If high entropy but NO known format = suspicious
    if (!has_known_format && entropy > 7.0) {
        suspicion_score += 15;
    }
    
    // METHOD 5: Check for low repeating sequences
    // Encrypted data has few repeated byte sequences
    int repeat_count = 0;
    for (size_t i = 0; i < data.size() - 4; i++) {
        if (data[i] == data[i+1] && data[i] == data[i+2] && data[i] == data[i+3]) {
            repeat_count++;
        }
    }
    
    double repeat_ratio = (double)repeat_count / data.size();
    if (repeat_ratio < 0.001 && entropy > 7.0) {
        suspicion_score += 10;  // Very few repeats + high entropy
    }
    
    // DECISION: Threshold-based on accumulated evidence
    // Score >= 70: Definitely encrypted
    // Score >= 50: Likely encrypted
    // Score < 50: Probably not encrypted
    
    if (suspicion_score >= 50) {
        return true;  // Block this write!
    }
    
    return false;
}

double RansomwareDetector::CalculateEntropy(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return 0.0;
    }
    
    int freq[256] = {0};
    for (uint8_t byte : data) {
        freq[byte]++;
    }
    
    double entropy = 0.0;
    size_t size = data.size();
    
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double probability = static_cast<double>(freq[i]) / size;
            entropy -= probability * std::log2(probability);
        }
    }
    
    return entropy;
}

bool RansomwareDetector::IsPathWhitelisted(const std::string& path) const {
    for (const auto& pattern : whitelisted_paths_) {
        if (MatchGlob(pattern, path)) {
            return true;
        }
    }
    return false;
}

bool RansomwareDetector::MatchGlob(const std::string& pattern, const std::string& text) const {
    int result = fnmatch(pattern.c_str(), text.c_str(), FNM_PATHNAME);
    return (result == 0);
}

std::string RansomwareDetector::GetProcessName(uint32_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/comm", pid);
    
    std::ifstream file(path);
    std::string name;
    std::getline(file, name);
    
    return name.empty() ? "unknown" : name;
}

std::string RansomwareDetector::GetProcessCommandLine(uint32_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);
    
    std::ifstream file(path, std::ios::binary);
    std::string cmdline;
    std::getline(file, cmdline, '\0');
    
    std::replace(cmdline.begin(), cmdline.end(), '\0', ' ');
    
    return cmdline;
}

std::string RansomwareDetector::GetProcessExecutablePath(uint32_t pid) {
    char path[64];
    char exe_path[PATH_MAX];
    
    snprintf(path, sizeof(path), "/proc/%u/exe", pid);
    ssize_t len = readlink(path, exe_path, sizeof(exe_path) - 1);
    
    if (len > 0) {
        exe_path[len] = '\0';
        return std::string(exe_path);
    }
    
    return "";
}

void RansomwareDetector::LogIncident(uint32_t pid, const std::string& process_name,
                                    const std::string& filepath, double entropy,
                                    bool killed, int total_attempts) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    
    if (incident_log_.is_open()) {
        incident_log_ << "================== RANSOMWARE DETECTION ==================\n";
        incident_log_ << "Timestamp: " << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S") << "\n";
        incident_log_ << "Process: " << process_name << " (PID: " << pid << ")\n";
        incident_log_ << "Command Line: " << GetProcessCommandLine(pid) << "\n";
        incident_log_ << "Executable: " << GetProcessExecutablePath(pid) << "\n";
        incident_log_ << "Target File: " << filepath << "\n";
        incident_log_ << "Entropy: " << std::fixed << std::setprecision(4) << entropy << "/8.0\n";
        incident_log_ << "Total Attempts: " << total_attempts << "\n";
        incident_log_ << "Action: " << (killed ? "PROCESS KILLED & QUARANTINED" : "WRITE BLOCKED (monitoring)") << "\n";
        incident_log_ << "File Status: SAFE (write prevented)\n";
        incident_log_ << "==========================================================\n";
        incident_log_ << std::endl;
        incident_log_.flush();
    }
}

} // namespace realtime
} // namespace koraav
