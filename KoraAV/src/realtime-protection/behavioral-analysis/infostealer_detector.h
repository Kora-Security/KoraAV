// src/realtime-protection/behavioral-analysis/infostealer_detector.h
#ifndef KORAAV_INFOSTEALER_DETECTOR_H
#define KORAAV_INFOSTEALER_DETECTOR_H

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <set>
#include <unordered_set>

namespace koraav {
namespace realtime {

/**
 * Info Stealer Detection Engine
 * Detects data exfiltration attempts by monitoring file access + network patterns
 */
class InfoStealerDetector {
public:
    InfoStealerDetector();
    
    /**
     * Track file access by a process
     */
    void TrackFileAccess(uint32_t pid, const std::string& path);
    
    /**
     * Track network connection by a process
     */
    void TrackNetworkConnection(uint32_t pid, uint32_t dest_ip, uint16_t dest_port);
    
    /**
     * Analyze process behavior and return threat score (0-100)
     * Higher score = more likely to be an info stealer
     */
    int AnalyzeProcess(uint32_t pid);
    
    /**
     * Get detailed threat indicators for a process
     */
    std::vector<std::string> GetThreatIndicators(uint32_t pid);
    
    /**
     * Clear tracking data for exited process
     */
    void CleanupProcess(uint32_t pid);
    
    /**
     * Get all currently suspicious processes
     */
    std::vector<uint32_t> GetSuspiciousProcesses(int min_score = 70);

private:
    struct TimedFileAccess {
        std::string path;
        std::chrono::system_clock::time_point timestamp;
    };

    struct TimedNetworkConnection {
        uint32_t dest_ip;
        uint16_t dest_port;
        std::chrono::system_clock::time_point timestamp;
    };

    struct ProcessActivity {
        int file_access_count = 0;
        int network_connection_count = 0;

        std::chrono::system_clock::time_point first_activity;
        std::chrono::system_clock::time_point last_activity;

        std::vector<TimedFileAccess> file_accesses;
        std::vector<TimedNetworkConnection> network_connections;

        std::unordered_set<std::string> sensitive_files_accessed;
        std::unordered_set<std::string> sensitive_directories;
    };

    std::unordered_map<uint32_t, ProcessActivity> process_activities_;

    // Detection logic
    int CalculateSensitivityScore(const ProcessActivity& activity);
    bool IsSensitiveDirectory(const std::string& path);
    std::string GetDirectoryCategory(const std::string& path);
    bool IsExfiltrationPattern(const ProcessActivity& activity);
};

} // namespace realtime
} // namespace koraav

#endif // KORAAV_INFOSTEALER_DETECTOR_H
