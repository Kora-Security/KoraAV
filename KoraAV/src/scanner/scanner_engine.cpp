// src/scanner/scanner_engine.cpp
#include "scanner_engine.h"
#include <filesystem>
#include <iostream>
#include <unistd.h>
#include <pwd.h>
#include <algorithm>

namespace fs = std::filesystem;

namespace koraav {
namespace scanner {

ScannerEngine::ScannerEngine() 
    : is_scanning_(false), cancel_requested_(false) {
}

ScannerEngine::~ScannerEngine() {
    CancelScan();
}

bool ScannerEngine::Initialize(const ScanConfig& config) {
    config_ = config;
    return file_scanner_.Initialize(config);
}

ScanResults ScannerEngine::FullScan(ProgressCallback progress) {
    std::vector<std::string> roots = {
        "/"  // Scan entire filesystem
    };
    
    return ExecuteScan(roots, ScanType::FULL_SCAN, progress);
}

ScanResults ScannerEngine::QuickScan(ProgressCallback progress) {
    return ExecuteScan(GetQuickScanPaths(), ScanType::QUICK_SCAN, progress);
}

ScanResults ScannerEngine::ManualScan(const std::vector<std::string>& paths,
                                      ProgressCallback progress) {
    return ExecuteScan(paths, ScanType::MANUAL_SCAN, progress);
}

std::vector<std::string> ScannerEngine::GetQuickScanPaths() const {
    std::vector<std::string> paths;
    
    // Get home directory
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) {
            home = pw->pw_dir;
        }
    }
    
    if (home) {
        std::string home_str(home);
        paths.push_back(home_str + "/Downloads");
        paths.push_back(home_str + "/Documents");
        paths.push_back(home_str + "/.local/bin");
        paths.push_back(home_str + "/.config");
    }
    
    // System temp directories
    paths.push_back("/tmp");
    paths.push_back("/var/tmp");
    paths.push_back("/dev/shm");
    
    // Common executable locations
    paths.push_back("/usr/local/bin");
    paths.push_back("/opt");
    
    // User binaries
    if (home) {
        paths.push_back(std::string(home) + "/bin");
    }
    
    // Filter out paths that don't exist
    paths.erase(
        std::remove_if(paths.begin(), paths.end(),
                      [](const std::string& p) { return !fs::exists(p); }),
        paths.end()
    );
    
    return paths;
}

ScanResults ScannerEngine::ExecuteScan(const std::vector<std::string>& root_paths,
                                       ScanType scan_type,
                                       ProgressCallback progress) {
    // Check if already scanning
    if (is_scanning_.exchange(true)) {
        throw std::runtime_error("Scan already in progress");
    }
    
    // Initialize results
    current_results_ = ScanResults();
    current_results_.scan_type = scan_type;
    current_results_.status = ScanStatus::IN_PROGRESS;
    current_results_.start_time = std::chrono::system_clock::now();
    current_results_.scanned_paths = root_paths;
    cancel_requested_ = false;
    
    try {
        // Start worker threads
        for (int i = 0; i < config_.thread_count; i++) {
            worker_threads_.emplace_back(&ScannerEngine::ScanWorker, this);
        }
        
        // Scan all root paths
        for (const auto& root : root_paths) {
            if (cancel_requested_) {
                break;
            }
            
            if (fs::is_directory(root)) {
                ScanDirectory(root, 0, current_results_, progress);
            } else if (fs::is_regular_file(root)) {
                AddToQueue(root);
            }
        }
        
        // Signal workers we're done adding to queue
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            cancel_requested_ = true;
        }
        queue_cv_.notify_all();
        
        // Wait for workers to finish
        for (auto& thread : worker_threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        worker_threads_.clear();
        
        // Finalize results
        current_results_.end_time = std::chrono::system_clock::now();
        current_results_.status = cancel_requested_ ? 
            ScanStatus::CANCELLED : ScanStatus::COMPLETED;
        
    } catch (const std::exception& e) {
        std::cerr << "Scan error: " << e.what() << std::endl;
        current_results_.status = ScanStatus::ERROR;
    }
    
    is_scanning_ = false;
    return current_results_;
}

void ScannerEngine::ScanDirectory(const std::string& dir_path,
                                  size_t depth,
                                  ScanResults& results,
                                  ProgressCallback& progress) {
    // Check depth limit
    if (depth >= config_.max_scan_depth) {
        return;
    }
    
    // Check for cancellation
    if (cancel_requested_) {
        return;
    }
    
    try {
        for (const auto& entry : fs::directory_iterator(dir_path)) {
            if (cancel_requested_) {
                break;
            }
            
            const auto& path = entry.path().string();
            
            if (entry.is_directory()) {
                // Recursively scan subdirectory
                ScanDirectory(path, depth + 1, results, progress);
            } else if (entry.is_regular_file()) {
                // Add file to scan queue
                AddToQueue(path);
            }
        }
    } catch (const fs::filesystem_error& e) {
        // Permission denied, etc.
        std::lock_guard<std::mutex> lock(results_mutex_);
        current_results_.files_skipped++;
    }
}

void ScannerEngine::ScanWorker() {
    std::string path;
    
    while (true) {
        // Get next file from queue
        if (!GetFromQueue(path)) {
            break;  // Queue empty and scan done
        }
        
        try {
            // Scan the file
            FileScanResult result = file_scanner_.ScanFile(path);
            
            // Record result
            RecordResult(result);
            
        } catch (const std::exception& e) {
            std::cerr << "Error scanning " << path << ": " << e.what() << std::endl;
            std::lock_guard<std::mutex> lock(results_mutex_);
            current_results_.errors++;
        }
    }
}

void ScannerEngine::AddToQueue(const std::string& path) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    scan_queue_.push(path);
    queue_cv_.notify_one();
}

bool ScannerEngine::GetFromQueue(std::string& path) {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    
    // Wait for work or completion
    queue_cv_.wait(lock, [this] {
        return !scan_queue_.empty() || cancel_requested_;
    });
    
    if (scan_queue_.empty()) {
        return false;  // Done
    }
    
    path = scan_queue_.front();
    scan_queue_.pop();
    return true;
}

void ScannerEngine::RecordResult(const FileScanResult& result) {
    std::lock_guard<std::mutex> lock(results_mutex_);
    
    current_results_.files_scanned++;
    
    if (result.is_threat()) {
        current_results_.threats_found++;
        current_results_.threats.push_back(result);
    }
}

void ScannerEngine::CancelScan() {
    if (is_scanning_) {
        cancel_requested_ = true;
        queue_cv_.notify_all();
        
        // Wait for workers
        for (auto& thread : worker_threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        worker_threads_.clear();
    }
}

} // namespace scanner
} // namespace koraav
