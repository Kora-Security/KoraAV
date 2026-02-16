// src/realtime-protection/yara-realtime/realtime_yara_scanner.cpp
#include "realtime_yara_scanner.h"
#include <chrono>
#include <filesystem>
#include <iostream>
#include <algorithm>

namespace fs = std::filesystem;

namespace koraav {
namespace realtime {

RealtimeYaraScanner::RealtimeYaraScanner() 
    : max_file_size_(100 * 1024 * 1024) {  // 100MB default
    
    // Initialize statistics
    stats_.files_scanned = 0;
    stats_.malware_detected = 0;
    stats_.skipped_too_large = 0;
    stats_.skipped_whitelisted = 0;
    stats_.avg_scan_time_ms = 0.0;
    
    // Whitelist common safe extensions
    whitelisted_extensions_ = {
        ".txt", ".log", ".md", ".json",  // Text files
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",  // Images
        ".mp3", ".mp4", ".avi", ".mkv", ".wav",  // Media
        ".o", ".a", ".so.1", ".so.2"  // Build artifacts
    };
}

bool RealtimeYaraScanner::Initialize(const std::string& rules_dir) {
    std::cout << "Initializing real-time YARA scanner..." << std::endl;
    
    // Just ensure YaraManager is initialized and loaded
    // We don't create our own scanner anymore!
    YaraManager::Instance().Initialize();
    bool success = YaraManager::Instance().LoadRules(rules_dir);
    
    if (!success) {
        std::cerr << "Failed to load YARA rules from " << rules_dir << std::endl;
        return false;
    }
    
    std::cout << "Real-time YARA scanner ready" << std::endl;
    return true;
}

bool RealtimeYaraScanner::ScanFile(const std::string& path, std::vector<std::string>& matches) {
    // Check if we should scan this file
    size_t file_size = 0;
    try {
        file_size = fs::file_size(path);
    } catch (...) {
        return true;  // Can't get size, assume safe
    }
    
    if (!ShouldScan(path, file_size)) {
        return true;  // Skipped, assume safe
    }
    
    // Time the scan
    auto start = std::chrono::steady_clock::now();
    
    // Scan using centralized YaraManager
    matches = YaraManager::Instance().ScanFile(path);
    
    auto end = std::chrono::steady_clock::now();
    double scan_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Update statistics
    bool malware_found = !matches.empty();
    UpdateStatistics(scan_time_ms, malware_found);
    
    return matches.empty();  // true if clean
}

bool RealtimeYaraScanner::ScanData(const std::vector<char>& data, std::vector<std::string>& matches) {
    if (data.empty()) {
        return true;
    }
    
    // Check size
    if (data.size() > max_file_size_) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.skipped_too_large++;
        return true;  // Skip, assume safe
    }
    
    // Time the scan
    auto start = std::chrono::steady_clock::now();
    
    // Scan using centralized YaraManager
    matches = YaraManager::Instance().ScanMemory(data.data(), data.size());
    
    auto end = std::chrono::steady_clock::now();
    double scan_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Update statistics
    bool malware_found = !matches.empty();
    UpdateStatistics(scan_time_ms, malware_found);
    
    return matches.empty();  // true if clean
}

bool RealtimeYaraScanner::QuickScan(const std::string& path, std::vector<std::string>& matches) {
    // QuickScan now just calls regular scan
    // In the future, we could implement a subset of rules for speed
    return ScanFile(path, matches);
}

bool RealtimeYaraScanner::ShouldScan(const std::string& path, size_t file_size) {
    // Check file size
    if (file_size > max_file_size_) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.skipped_too_large++;
        return false;
    }
    
    // Check whitelist
    if (IsWhitelistedExtension(path)) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.skipped_whitelisted++;
        return false;
    }
    
    return true;
}

void RealtimeYaraScanner::WhitelistExtension(const std::string& ext) {
    whitelisted_extensions_.insert(ext);
}

RealtimeYaraScanner::Statistics RealtimeYaraScanner::GetStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

bool RealtimeYaraScanner::IsWhitelistedExtension(const std::string& path) {
    fs::path p(path);
    std::string ext = p.extension().string();
    
    // Make lowercase for case-insensitive matching
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    return whitelisted_extensions_.count(ext) > 0;
}

void RealtimeYaraScanner::UpdateStatistics(double scan_time_ms, bool malware_found) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.files_scanned++;
    
    if (malware_found) {
        stats_.malware_detected++;
    }
    
    // Update average scan time (running average)
    if (stats_.files_scanned == 1) {
        stats_.avg_scan_time_ms = scan_time_ms;
    } else {
        stats_.avg_scan_time_ms = 
            (stats_.avg_scan_time_ms * (stats_.files_scanned - 1) + scan_time_ms) / stats_.files_scanned;
    }
}

} // namespace realtime
} // namespace koraav
