// src/scanner/scanner_engine.h
#ifndef KORAAV_SCANNER_ENGINE_H
#define KORAAV_SCANNER_ENGINE_H

#include <koraav/types.h>
#include "file_scanner.h"
#include <atomic>
#include <functional>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace koraav {
namespace scanner {

/**
 * Main scanning engine that orchestrates full, quick, and manual scans
 * Manages threading, progress tracking, and result aggregation
 */
class ScannerEngine {
public:
    ScannerEngine();
    ~ScannerEngine();
    
    /**
     * Initialize scanner with configuration
     */
    bool Initialize(const ScanConfig& config);
    
    /**
     * Perform a full system scan
     * Scans entire filesystem (respecting exclude paths)
     */
    ScanResults FullScan(ProgressCallback progress = nullptr);
    
    /**
     * Perform a quick scan
     * Scans common locations: /home, /tmp, /var/tmp, /dev/shm, Downloads, etc.
     */
    ScanResults QuickScan(ProgressCallback progress = nullptr);
    
    /**
     * Perform a manual scan on specific paths
     * @param paths List of files/directories to scan
     */
    ScanResults ManualScan(const std::vector<std::string>& paths,
                           ProgressCallback progress = nullptr);
    
    /**
     * Cancel ongoing scan
     */
    void CancelScan();
    
    /**
     * Check if scan is currently running
     */
    bool IsScanning() const { return is_scanning_.load(); }

private:
    // Internal scan implementation
    ScanResults ExecuteScan(const std::vector<std::string>& root_paths,
                           ScanType scan_type,
                           ProgressCallback progress);
    
    // Recursively scan a directory
    void ScanDirectory(const std::string& dir_path, 
                      size_t depth,
                      ScanResults& results,
                      ProgressCallback& progress);
    
    // Worker thread function for parallel scanning
    void ScanWorker();
    
    // Thread-safe methods
    void AddToQueue(const std::string& path);
    bool GetFromQueue(std::string& path);
    void RecordResult(const FileScanResult& result);
    
    // Common scan locations for quick scan
    std::vector<std::string> GetQuickScanPaths() const;
    
    ScanConfig config_;
    FileScanner file_scanner_;
    
    // Progress callback
    ProgressCallback progress_callback_;
    
    // Threading
    std::atomic<bool> is_scanning_;
    std::atomic<bool> cancel_requested_;
    std::vector<std::thread> worker_threads_;
    
    // Work queue
    std::queue<std::string> scan_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    // Results
    ScanResults current_results_;
    std::mutex results_mutex_;
};

} // namespace scanner
} // namespace koraav

#endif // KORAAV_SCANNER_ENGINE_H
