// src/realtime-protection/behavioral-analysis/infostealer_detector.cpp
#include "infostealer_detector.h"
#include <algorithm>
#include <sstream>

namespace koraav {
namespace realtime {

InfoStealerDetector::InfoStealerDetector() {
}

void InfoStealerDetector::TrackFileAccess(uint32_t pid, const std::string& path) {
    auto& activity = process_activities_[pid];

    auto now = std::chrono::system_clock::now();

    if (activity.file_access_count == 0 && activity.network_connection_count == 0) {
        activity.first_activity = now;
    }

    activity.last_activity = now;
    activity.file_access_count++;

    activity.file_accesses.push_back({path, now});

    if (IsSensitiveDirectory(path)) {
        activity.sensitive_files_accessed.insert(path);

        std::string category = GetDirectoryCategory(path);
        if (!category.empty()) {
            activity.sensitive_directories.insert(category);
        }
    }
}

void InfoStealerDetector::TrackNetworkConnection(
    uint32_t pid,
    uint32_t dest_ip,
    uint16_t dest_port
) {
    auto& activity = process_activities_[pid];

    auto now = std::chrono::system_clock::now();

    if (activity.file_access_count == 0 && activity.network_connection_count == 0) {
        activity.first_activity = now;
    }

    activity.last_activity = now;
    activity.network_connection_count++;

    activity.network_connections.push_back({dest_ip, dest_port, now});
}

int InfoStealerDetector::AnalyzeProcess(uint32_t pid) {
    auto it = process_activities_.find(pid);
    if (it == process_activities_.end()) {
        return 0;  // No activity tracked
    }
    
    const auto& activity = it->second;
    int score = 0;
    
    // Score based on sensitive file access
    score += CalculateSensitivityScore(activity);
    
    // Exfiltration pattern detection
    if (IsExfiltrationPattern(activity)) {
        score += 50;  // Major red flag
    }
    
    // Multiple sensitive directory categories accessed
    if (activity.sensitive_directories.size() >= 3) {
        score += 30;
    } else if (activity.sensitive_directories.size() >= 2) {
        score += 20;
    }
    
    // High file access rate
    if (activity.file_access_count > 20) {
        score += 10;
    }
    
    // Network connections after file access
    if (activity.file_access_count > 0 && activity.network_connection_count > 0) {
        score += 20;
    }
    
    // Cap at 100
    return std::min(score, 100);
}

std::vector<std::string> InfoStealerDetector::GetThreatIndicators(uint32_t pid) {
    std::vector<std::string> indicators;
    
    auto it = process_activities_.find(pid);
    if (it == process_activities_.end()) {
        return indicators;
    }
    
    const auto& activity = it->second;
    
    // Sensitive files accessed
    if (!activity.sensitive_files_accessed.empty()) {
        std::ostringstream oss;
        oss << "Accessed " << activity.sensitive_files_accessed.size() << " sensitive file(s)";
        indicators.push_back(oss.str());
        
        // List first few
        int count = 0;
        for (const auto& file : activity.sensitive_files_accessed) {
            if (count++ >= 3) break;
            indicators.push_back("  → " + file);
        }
    }
    
    // Sensitive directory categories
    if (!activity.sensitive_directories.empty()) {
        std::ostringstream oss;
        oss << "Accessed sensitive categories: ";
        bool first = true;
        for (const auto& cat : activity.sensitive_directories) {
            if (!first) oss << ", ";
            oss << cat;
            first = false;
        }
        indicators.push_back(oss.str());
    }
    
    // Network connections
    if (activity.network_connection_count > 0) {
        std::ostringstream oss;
        oss << "Made " << activity.network_connection_count << " network connection(s)";
        indicators.push_back(oss.str());
    }
    
    // Exfiltration pattern
    if (IsExfiltrationPattern(activity)) {
        indicators.push_back("EXFILTRATION PATTERN: File access followed by network activity");
    }
    
    // Time window analysis
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        activity.last_activity - activity.first_activity
    );
    
    if (duration.count() < 60 && activity.sensitive_files_accessed.size() >= 3) {
        std::ostringstream oss;
        oss << "RAPID SCANNING: " << activity.sensitive_files_accessed.size()
            << " files in " << duration.count() << " seconds";
        indicators.push_back(oss.str());
    }
    
    return indicators;
}

void InfoStealerDetector::CleanupProcess(uint32_t pid) {
    process_activities_.erase(pid);
}

std::vector<uint32_t> InfoStealerDetector::GetSuspiciousProcesses(int min_score) {
    std::vector<uint32_t> suspicious;
    
    for (const auto& [pid, activity] : process_activities_) {
        int score = AnalyzeProcess(pid);
        if (score >= min_score) {
            suspicious.push_back(pid);
        }
    }
    
    return suspicious;
}

int InfoStealerDetector::CalculateSensitivityScore(const ProcessActivity& activity) {
    int score = 0;
    
    // Base score for each sensitive file
    score += activity.sensitive_files_accessed.size() * 10;
    
    // Bonus for multiple categories
    score += activity.sensitive_directories.size() * 15;
    
    return score;
}

bool InfoStealerDetector::IsSensitiveDirectory(const std::string& path) {
    // Check for sensitive patterns
    const std::vector<std::string> sensitive_patterns = {
        "/.ssh/",
        "/.gnupg/",
        "/.mozilla/",
        "/google-chrome/",
        "/chromium/",
        "/BraveSoftware/",
        "/.config/google-chrome/",
        "/.config/chromium/",
        "/.electrum/",
        "/.exodus/",
        "/wallet",
        "/Documents/",
        "/Downloads/",
        "/.aws/",
        "/.docker/",
        "/.kube/",
        "/passwords",
        "/cookies",
        "/login",
        "/key_data",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/"
    };
    
    for (const auto& pattern : sensitive_patterns) {
        if (path.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

std::string InfoStealerDetector::GetDirectoryCategory(const std::string& path) {
    if (path.find("/.ssh/") != std::string::npos) return "SSH Keys";
    if (path.find("/.gnupg/") != std::string::npos) return "GPG Keys";
    if (path.find("/.mozilla/") != std::string::npos || 
        path.find("/google-chrome/") != std::string::npos ||
        path.find("/chromium/") != std::string::npos) {
        return "Browser Data";
    }

    if (path.find("wallet") != std::string::npos || 
        path.find("/.electrum/") != std::string::npos ||
        path.find("/.exodus/") != std::string::npos) {
        return "Crypto Wallets";
    }

    if (path.find("/Documents/") != std::string::npos) return "Documents";
    if (path.find("/.aws/") != std::string::npos) return "AWS Credentials";
    if (path.find("/.docker/") != std::string::npos) return "Docker Config";
    if (path.find("/.kube/") != std::string::npos) return "Kubernetes Config";

    if (path.find("/etc/passwd") != std::string::npos ||
        path.find("/etc/shadow") != std::string::npos ||
        path.find("/etc/sudoers") != std::string::npos) {
        return "System Credentials";
        }

    if (path.find("/etc/ssh/") != std::string::npos) {
        return "System SSH Config";
    }
}

bool InfoStealerDetector::IsExfiltrationPattern(const ProcessActivity& activity) {

    if (activity.file_accesses.empty() || activity.network_connections.empty()) {
        return false;
    }

    // Find the latest sensitive file access
    std::chrono::system_clock::time_point last_sensitive_access;
    bool found_sensitive = false;

    for (const auto& access : activity.file_accesses) {
        if (IsSensitiveDirectory(access.path)) {
            if (!found_sensitive || access.timestamp > last_sensitive_access) {
                last_sensitive_access = access.timestamp;
                found_sensitive = true;
            }
        }
    }

    if (!found_sensitive) {
        return false;
    }

    // Check if a network connection occurred AFTER sensitive access
    for (const auto& conn : activity.network_connections) {
        if (conn.timestamp > last_sensitive_access) {

            auto delta = std::chrono::duration_cast<std::chrono::seconds>(
                conn.timestamp - last_sensitive_access
            );

            // Exfil typically happens quickly
            if (delta.count() <= 300) {  // 5 minutes
                if (activity.sensitive_files_accessed.size() >= 2) {
                    return true;
                }
            }
        }
    }

    return false;
}

} // namespace realtime
} // namespace koraav
