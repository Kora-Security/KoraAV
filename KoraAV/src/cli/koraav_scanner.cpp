// src/cli/koraav_scanner.cpp
// KoraAV On-Demand Scanner CLI
// Command-line interface for scanning files and directories
#include "../scanner/scanner_engine.h"
#include <iostream>
#include <iomanip>

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

void ProgressCallback(const std::string& file, uint64_t scanned, uint64_t threats) {
    std::cout << "\rScanning: " << scanned << " files, " 
              << threats << " threats found...";
    std::cout.flush();
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
        std::cout << "\nStarting quick scan..." << std::endl;
        results = scanner.QuickScan(ProgressCallback);
    }
    else if (scan_type == "full") {
        std::cout << "\nStarting full scan..." << std::endl;
        results = scanner.FullScan(ProgressCallback);
    }
    else if (scan_type == "manual" && argc > 2) {
        std::cout << "\nStarting manual scan..." << std::endl;
        std::vector<std::string> paths;
        for (int i = 2; i < argc; i++) {
            paths.push_back(argv[i]);
        }
        results = scanner.ManualScan(paths, ProgressCallback);
    }
    else {
        std::cerr << "Invalid scan type or missing paths" << std::endl;
        return 1;
    }
    
    std::cout << std::endl;  // New line after progress
    PrintResults(results);
    
    return results.threats_found > 0 ? 1 : 0;
}
