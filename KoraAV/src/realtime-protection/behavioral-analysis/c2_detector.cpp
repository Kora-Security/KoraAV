// src/realtime-protection/behavioral-analysis/c2_detector.cpp
#include "c2_detector.h"
#include <algorithm>
#include <cmath>
#include <sstream>
#include <iomanip>

namespace koraav {
namespace realtime {

C2Detector::C2Detector() {
}

void C2Detector::TrackConnection(uint32_t pid, uint32_t dest_ip, uint16_t dest_port) {
    auto& activity = process_activities_[pid];
    
    auto now = std::chrono::system_clock::now();
    
    // Calculate interval if we have previous connections
    if (!activity.connections.empty()) {
        auto last_time = activity.connections.back().timestamp;
        auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_time);
        activity.interval_milliseconds.push_back(interval.count());
    }
    
    // Record connection
    ConnectionInfo conn;
    conn.dest_ip = dest_ip;
    conn.dest_port = dest_port;
    conn.timestamp = now;
    
    activity.connections.push_back(conn);
    activity.unique_ips.insert(dest_ip);
    activity.unique_ports.insert(dest_port);
    activity.connection_count++;
    
    if (activity.connection_count == 1) {
        activity.first_connection = now;
    }
    activity.last_connection = now;
}

int C2Detector::AnalyzeProcess(uint32_t pid) {
    auto it = process_activities_.find(pid);
    if (it == process_activities_.end()) {
        return 0;
    }
    
    return CalculateC2Score(it->second);
}

int C2Detector::CalculateC2Score(const ProcessActivity& activity) {
    int score = 0;
    
    // Not enough data
    if (activity.connection_count < 3) {
        return 0;
    }
    
    // Check for beaconing behavior
    if (IsBeaconing(activity)) {
        score += 60;  // Strong indicator of C2
    }
    
    // High connection frequency
    if (activity.connection_count > 50) {
        score += 20;
    } else if (activity.connection_count > 20) {
        score += 10;
    }
    
    // Connecting to suspicious ports
    for (uint16_t port : activity.unique_ports) {
        if (IsSuspiciousPort(port)) {
            score += 15;
        }
    }
    
    // Multiple unique IPs (scanning or C2 rotation)
    if (activity.unique_ips.size() > 10) {
        score += 25;
    } else if (activity.unique_ips.size() > 5) {
        score += 15;
    }
    
    // Single IP, repeated connections (classic beaconing)
    if (activity.unique_ips.size() == 1 && activity.connection_count > 10) {
        score += 20;
    }
    
    // Check for connections to known suspicious IPs
    for (uint32_t ip : activity.unique_ips) {
        if (IsSuspiciousIP(ip)) {
            score += 30;
        }
    }
    
    return std::min(score, 100);
}

bool C2Detector::IsBeaconing(const ProcessActivity& activity) {
    // Need at least 5 connections to detect pattern
    if (activity.interval_milliseconds.size() < 5) {
        return false;
    }
    
    // Calculate mean and standard deviation of intervals
    double sum = 0.0;
    for (int64_t interval : activity.interval_milliseconds) {
        sum += interval;
    }
    double mean = sum / activity.interval_milliseconds.size();
    
    double variance_sum = 0.0;
    for (int64_t interval : activity.interval_milliseconds) {
        double diff = interval - mean;
        variance_sum += diff * diff;
    }
    double std_dev = std::sqrt(variance_sum / activity.interval_milliseconds.size());
    
    // Coefficient of variation (std_dev / mean)
    // Low CV = regular pattern = beaconing
    double cv = std_dev / mean;
    
    // If CV < 0.3 (30%), it's a very regular pattern
    // Typical beaconing: connections every 60s, 300s, 600s, etc.
    if (cv < 0.3) {
        // Also check that mean interval is reasonable (1s - 1hour)
        if (mean > 1000 && mean < 3600000) {  // 1s to 1hr
            return true;
        }
    }
    
    return false;
}

bool C2Detector::IsSuspiciousPort(uint16_t port) {
    // Common malware C2 ports
    std::set<uint16_t> suspicious_ports = {
        4444,   // Metasploit default
        5555,   // Common reverse shell
        6666, 6667, 6668,  // IRC (often used for botnets)
        7777,   // Trojan port
        8080,   // HTTP proxy (often abused)
        8443,   // HTTPS alt (often used by malware)
        9001, 9002,  // Tor
        31337,  // Elite / Back Orifice
        12345,  // NetBus
        65535,  // Common backdoor
    };
    
    return suspicious_ports.count(port) > 0;
}

bool C2Detector::IsSuspiciousIP(uint32_t ip) {
    // Extract octets
    uint8_t oct1 = (ip >> 24) & 0xFF;
    uint8_t oct2 = (ip >> 16) & 0xFF;
    // oct3 and oct4 not needed for current checks
    
    // Ignore local/private IPs
    if (oct1 == 127) return false;  // Localhost
    if (oct1 == 10) return false;   // Private 10.0.0.0/8
    if (oct1 == 172 && oct2 >= 16 && oct2 <= 31) return false;  // Private 172.16.0.0/12
    if (oct1 == 192 && oct2 == 168) return false;  // Private 192.168.0.0/16
    
    // TODO: Add threat intelligence IP ranges
    // For now, all external IPs are potentially suspicious if other indicators present
    
    return false;
}

std::vector<std::string> C2Detector::GetThreatIndicators(uint32_t pid) {
    std::vector<std::string> indicators;
    
    auto it = process_activities_.find(pid);
    if (it == process_activities_.end()) {
        return indicators;
    }
    
    const auto& activity = it->second;
    
    if (IsBeaconing(activity)) {
        indicators.push_back("⚠️  Regular beaconing pattern detected (C2 communication)");
        
        // Calculate average interval
        if (!activity.interval_milliseconds.empty()) {
            double sum = 0;
            for (auto interval : activity.interval_milliseconds) {
                sum += interval;
            }
            double avg = sum / activity.interval_milliseconds.size();
            
            std::ostringstream oss;
            oss << "   Beacon interval: ~" << std::fixed << std::setprecision(1) 
                << (avg / 1000.0) << " seconds";
            indicators.push_back(oss.str());
        }
    }
    
    if (activity.connection_count > 20) {
        indicators.push_back("High frequency connections: " + 
                           std::to_string(activity.connection_count) + " total");
    }
    
    if (activity.unique_ips.size() > 5) {
        indicators.push_back("Multiple destination IPs: " + 
                           std::to_string(activity.unique_ips.size()));
    }
    
    // List suspicious connections
    for (const auto& conn : activity.connections) {
        if (IsSuspiciousPort(conn.dest_port)) {
            indicators.push_back("Connection to suspicious port: " + 
                               IPToString(conn.dest_ip) + ":" + 
                               std::to_string(conn.dest_port));
        }
    }
    
    return indicators;
}

std::vector<uint32_t> C2Detector::GetSuspiciousProcesses(int min_score) {
    std::vector<uint32_t> suspicious;
    
    for (const auto& [pid, activity] : process_activities_) {
        int score = CalculateC2Score(activity);
        if (score >= min_score) {
            suspicious.push_back(pid);
        }
    }
    
    return suspicious;
}

void C2Detector::CleanupProcess(uint32_t pid) {
    process_activities_.erase(pid);
}

std::string C2Detector::IPToString(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);
    return oss.str();
}

} // namespace realtime
} // namespace koraav
