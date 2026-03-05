// src/realtime-protection/behavioral-analysis/c2_detector.h
#ifndef KORAAV_C2_DETECTOR_H
#define KORAAV_C2_DETECTOR_H

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <set>

namespace koraav {
namespace realtime {

/**
 * C2 (Command & Control) Detection Engine
 * Detects malware beaconing and communication with command servers
 */
class C2Detector {
public:
    C2Detector();
    
    /**
     * Track network connection
     */
    void TrackConnection(uint32_t pid, uint32_t dest_ip, uint16_t dest_port);
    
    /**
     * Analyze process for C2 behavior
     * Returns threat score (0-100)
     */
    int AnalyzeProcess(uint32_t pid);
    
    /**
     * Get threat indicators for a process
     */
    std::vector<std::string> GetThreatIndicators(uint32_t pid);
    
    /**
     * Get all suspicious processes
     */
    std::vector<uint32_t> GetSuspiciousProcesses(int min_score = 70);
    
    /**
     * Cleanup process tracking data
     */
    void CleanupProcess(uint32_t pid);

private:
    struct ConnectionInfo {
        uint32_t dest_ip;
        uint16_t dest_port;
        std::chrono::system_clock::time_point timestamp;
    };
    
    struct ProcessActivity {
        std::vector<ConnectionInfo> connections;
        std::set<uint32_t> unique_ips;
        std::set<uint16_t> unique_ports;
        std::chrono::system_clock::time_point first_connection;
        std::chrono::system_clock::time_point last_connection;
        uint32_t connection_count;
        
        // Beaconing detection
        std::vector<int64_t> interval_milliseconds;  // Time between connections
        bool has_regular_pattern;
    };
    
    std::unordered_map<uint32_t, ProcessActivity> process_activities_;
    
    // Detection logic
    bool IsBeaconing(const ProcessActivity& activity);
    bool IsSuspiciousPort(uint16_t port);
    bool IsSuspiciousIP(uint32_t ip);
    int CalculateC2Score(const ProcessActivity& activity);
    std::string IPToString(uint32_t ip);
};

} // namespace realtime
} // namespace koraav

#endif // KORAAV_C2_DETECTOR_H
