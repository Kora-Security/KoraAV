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
    stats_.false_positives = 0;
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

RealtimeYaraScanner::~RealtimeYaraScanner() {
}

bool RealtimeYaraScanner::Initialize(const std::string& rules_dir) {
    std::cout << "Initializing real-time YARA scanner..." << std::endl;
    
    // Initialize main scanner with all rules
    yara_scanner_ = std::make_unique<scanner::YaraScanner>();
    if (!yara_scanner_->LoadRules(rules_dir)) {
        std::cerr << "Failed to load YARA rules from " << rules_dir << std::endl;
        return false;
    }
    
    // TODO: Initialize a quick scanner with a subset of critical yara rules
    // For now, use same yara scanner
    quick_scanner_ = std::make_unique<scanner::YaraScanner>();
    quick_scanner_->LoadRules(rules_dir);
    
    std::cout << "Real-time YARA scanner initialized" << std::endl;
    
    return true;
}

bool RealtimeYaraScanner::ScanFile(const std::string& path, std::vector<std::string>& matches) {
    // Check if we should scan this file
    size_t file_size = 0;
    try {
        file_size = fs::file_size(path);
    } catch (...) {
        return true;  // Can't read size, allow
    }
    
    if (!ShouldScan(path, file_size)) {
        return true;  // Skip scanning, assume clean
    }
    
    // Measure scan time
    auto start = std::chrono::high_resolution_clock::now();
    
    // Perform YARA scan
    matches = yara_scanner_->ScanFile(path);
    
    auto end = std::chrono::high_resolution_clock::now();
    double scan_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Update statistics
    bool malware_found = !matches.empty();
    UpdateStatistics(scan_time_ms, malware_found);
    
    if (malware_found) {
        std::cout << "YARA DETECTION in " << path << std::endl;
        for (const auto& rule : matches) {
            std::cout << "   • " << rule << std::endl;
        }
    }
    
    return !malware_found;  // true = clean, false = malicious
}

bool RealtimeYaraScanner::ScanData(const std::vector<char>& data, std::vector<std::string>& matches) {
    if (data.empty()) {
        return true;
    }
    
    // Measure scan time
    auto start = std::chrono::high_resolution_clock::now();
    
    // Perform YARA scan on memory
    matches = yara_scanner_->ScanData(data);
    
    auto end = std::chrono::high_resolution_clock::now();
    double scan_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Update statistics
    bool malware_found = !matches.empty();
    UpdateStatistics(scan_time_ms, malware_found);
    
    return !malware_found;
}

bool RealtimeYaraScanner::QuickScan(const std::string& path, std::vector<std::string>& matches) {
    // TODO: Use quick scanner mentioned above with critical rules only
    // For now, we'll just use a timeout on our regular scanner
    
    auto start = std::chrono::high_resolution_clock::now();
    
    matches = quick_scanner_->ScanFile(path);
    
    auto end = std::chrono::high_resolution_clock::now();
    double scan_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    bool malware_found = !matches.empty();
    UpdateStatistics(scan_time_ms, malware_found);
    
    return !malware_found;
}

bool RealtimeYaraScanner::ShouldScan(const std::string& path, size_t file_size) {
    // Skip if too large
    if (file_size > max_file_size_) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.skipped_too_large++;
        return false;
    }
    
    // Skip if whitelisted extension
    if (IsWhitelistedExtension(path)) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.skipped_whitelisted++;
        return false;
    }
    
    // Skip empty files
    if (file_size == 0) {
        return false;
    }
    
    return true;
}

void RealtimeYaraScanner::WhitelistExtension(const std::string& ext) {
    whitelisted_extensions_.insert(ext);
    std::cout << "Whitelisted extension: " << ext << std::endl;
}

RealtimeYaraScanner::Statistics RealtimeYaraScanner::GetStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

bool RealtimeYaraScanner::IsWhitelistedExtension(const std::string& path) {
    fs::path p(path);
    std::string ext = p.extension().string();
    
    // Convert to lowercase
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    return whitelisted_extensions_.find(ext) != whitelisted_extensions_.end();
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
            (stats_.avg_scan_time_ms * (stats_.files_scanned - 1) + scan_time_ms) / 
            stats_.files_scanned;
    }
}

} // namespace realtime
} // namespace koraav
