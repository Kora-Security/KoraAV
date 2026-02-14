// src/cli/koraav_scanner.cpp
// KoraAV On-Demand Scanner CLI
// Command-line interface for scanning files and directories
#include "../scanner/scanner_engine.h"
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace koraav;
using namespace koraav::scanner;

void PrintResults(const ScanResults& results) {
    std::cout << "\n=== Scan Results ===" << std::endl;
    std::cout << "Scan Type: ";
    switch (results.scan_type) {
        case ScanType::FULL_SCAN: std::cout << "Full Scan"; break;
        case ScanType::QUICK_SCAN: std::cout << "Quick Scan"; break;
        case ScanType::MANUAL_SCAN: std::cout << "Manual Scan"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << std::endl;
    
    std::cout << "Status: ";
    switch (results.status) {
        case ScanStatus::COMPLETED: std::cout << "Completed"; break;
        case ScanStatus::CANCELLED: std::cout << "Cancelled"; break;
        case ScanStatus::ERROR: std::cout << "Error"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << std::endl;
    
    std::cout << "Files Scanned: " << results.files_scanned << std::endl;
    std::cout << "Threats Found: " << results.threats_found << std::endl;
    std::cout << "Files Skipped: " << results.files_skipped << std::endl;
    std::cout << "Errors: " << results.errors << std::endl;
    std::cout << "Elapsed Time: " << std::fixed << std::setprecision(2) 
              << results.elapsed_time().count() << " seconds" << std::endl;
    
    if (results.threats_found > 0) {
        std::cout << "\n=== Threats Detected ===" << std::endl;
        for (const auto& threat : results.threats) {
            std::cout << "\nFile: " << threat.path << std::endl;
            std::cout << "Threat Level: ";
            switch (threat.threat_level) {
                case ThreatLevel::SUSPICIOUS: std::cout << "SUSPICIOUS"; break;
                case ThreatLevel::LOW: std::cout << "LOW"; break;
                case ThreatLevel::MEDIUM: std::cout << "MEDIUM"; break;
                case ThreatLevel::HIGH: std::cout << "HIGH"; break;
                case ThreatLevel::CRITICAL: std::cout << "CRITICAL"; break;
                default: std::cout << "UNKNOWN"; break;
            }
            std::cout << std::endl;
            
            std::cout << "SHA256: " << threat.hash_sha256 << std::endl;
            std::cout << "Entropy: " << std::fixed << std::setprecision(2) 
                      << threat.entropy << std::endl;
            
            std::cout << "Indicators:" << std::endl;
            for (const auto& indicator : threat.indicators) {
                std::cout << "  - " << indicator << std::endl;
            }
        }
    }
}

// Advanced progress tracking
struct ProgressTracker {
    uint64_t total_files = 0;
    uint64_t scanned_files = 0;
    uint64_t threats_found = 0;
    std::string current_file;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_update;
    
    ProgressTracker() {
        start_time = std::chrono::steady_clock::now();
        last_update = start_time;
    }
    
    void Update(const std::string& file, uint64_t scanned, uint64_t threats) {
        scanned_files = scanned;
        threats_found = threats;
        current_file = file;
        last_update = std::chrono::steady_clock::now();
        Display();
    }
    
    void Display() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        
        // Calculate speed (files per second)
        double speed = scanned_files > 0 ? (double)scanned_files / (elapsed + 1) : 0;
        
        // Calculate ETA
        uint64_t remaining = total_files > scanned_files ? total_files - scanned_files : 0;
        uint64_t eta_seconds = speed > 0 ? remaining / speed : 0;
        
        // Clear line and move to beginning
        std::cout << "\r\033[K";
        
        // Progress bar (40 chars wide)
        int progress_percent = total_files > 0 ? (scanned_files * 100) / total_files : 0;
        int bar_width = 40;
        int filled = (bar_width * progress_percent) / 100;
        
        std::cout << "[";
        for (int i = 0; i < bar_width; i++) {
            if (i < filled) {
                std::cout << "█";
            } else if (i == filled) {
                std::cout << "▓";
            } else {
                std::cout << "░";
            }
        }
        std::cout << "] " << std::setw(3) << progress_percent << "% ";
        
        // Stats
        std::cout << "│ " << scanned_files;
        if (total_files > 0) {
            std::cout << "/" << total_files;
        }
        std::cout << " files │ ";
        
        // Threats
        if (threats_found > 0) {
            std::cout << "\033[31m" << threats_found << " threats\033[0m │ ";
        } else {
            std::cout << "\033[32m0 threats\033[0m │ ";
        }
        
        // Speed
        std::cout << std::fixed << std::setprecision(1) << speed << " f/s │ ";
        
        // Time
        std::cout << FormatTime(elapsed) << " elapsed";
        
        if (eta_seconds > 0 && eta_seconds < 86400) {  // Less than 24 hours
            std::cout << " │ ~" << FormatTime(eta_seconds) << " left";
        }
        
        // Current file (truncated to fit)
        if (!current_file.empty()) {
            std::cout << "\n\033[2m📄 " << TruncatePath(current_file, 80) << "\033[0m";
            std::cout << "\033[A";  // Move cursor back up
        }
        
        std::cout.flush();
    }
    
    void Finish() {
        std::cout << "\n";  // New line after progress
    }
    
private:
    std::string FormatTime(uint64_t seconds) {
        if (seconds < 60) {
            return std::to_string(seconds) + "s";
        } else if (seconds < 3600) {
            uint64_t mins = seconds / 60;
            uint64_t secs = seconds % 60;
            return std::to_string(mins) + "m " + std::to_string(secs) + "s";
        } else {
            uint64_t hours = seconds / 3600;
            uint64_t mins = (seconds % 3600) / 60;
            return std::to_string(hours) + "h " + std::to_string(mins) + "m";
        }
    }
    
    std::string TruncatePath(const std::string& path, size_t max_len) {
        if (path.length() <= max_len) {
            return path;
        }
        
        // Show beginning and end of path
        size_t start_len = max_len / 2 - 2;
        size_t end_len = max_len / 2 - 2;
        return path.substr(0, start_len) + "..." + path.substr(path.length() - end_len);
    }
};

// Global progress tracker
static ProgressTracker g_progress;

void ScanProgressCallback(const std::string& file, uint64_t scanned, uint64_t threats) {
    g_progress.Update(file, scanned, threats);
}


int main(int argc, char** argv) {
    std::cout << "   KoraAV Scanner  " << std::endl;
    std::cout << "===================" << std::endl;
    
    if (argc < 2) {
        std::cout << "Usage:" << std::endl;
        std::cout << "  " << argv[0] << " quick              - Quick scan" << std::endl;
        std::cout << "  " << argv[0] << " full               - Full scan" << std::endl;
        std::cout << "  " << argv[0] << " manual <path>...   - Manual scan" << std::endl;
        return 1;
    }
    
    // Create scanner
    ScannerEngine scanner;
    ScanConfig config;
    
    // Configure
    config.thread_count = 4;
    config.max_file_size = 100 * 1024 * 1024;  // 100MB
    config.exclude_paths = {"/proc", "/sys", "/dev"};
    
    scanner.Initialize(config);
    
    // Determine scan type
    std::string scan_type = argv[1];
    ScanResults results;
    
    if (scan_type == "quick") {
        std::cout << "\n🔍 Starting quick scan...\n" << std::endl;
        results = scanner.QuickScan(ScanProgressCallback);
        g_progress.Finish();
    }
    else if (scan_type == "full") {
        std::cout << "\n🔍 Starting full system scan...\n" << std::endl;
        results = scanner.FullScan(ScanProgressCallback);
        g_progress.Finish();
    }
    else if (scan_type == "manual" && argc > 2) {
        std::cout << "\n🔍 Starting manual scan...\n" << std::endl;
        std::vector<std::string> paths;
        for (int i = 2; i < argc; i++) {
            paths.push_back(argv[i]);
        }
        results = scanner.ManualScan(paths, ScanProgressCallback);
        g_progress.Finish();
    }
    else {
        std::cerr << "Invalid scan type or missing paths" << std::endl;
        return 1;
    }
    
    PrintResults(results);
    
    return results.threats_found > 0 ? 1 : 0;
}
