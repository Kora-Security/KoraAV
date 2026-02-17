// src/daemon/koraav_daemon.h
#ifndef KORAAV_DAEMON_H
#define KORAAV_DAEMON_H

#include "../realtime-protection/behavioral-analysis/infostealer_detector.h"
#include "../realtime-protection/behavioral-analysis/ransomware_detector.h"
#include "../realtime-protection/behavioral-analysis/clickfix_detector.h"
#include "../realtime-protection/behavioral-analysis/c2_detector.h"
#include "../common/quarantine_manager.h"
#include "../common/notification_manager.h"
#include <memory>
#include <atomic>
#include <thread>
#include <string>
#include <vector>


// Forward declarations for libbpf types
struct bpf_object;
struct bpf_program;
struct bpf_link;
struct bpf_map;
struct ring_buffer;


namespace koraav {
namespace daemon {

/**
 * Main KoraAV Real-Time Protection Daemon
 * Coordinates all monitoring and detection engines
 */
class KoraAVDaemon {
public:
    KoraAVDaemon();
    ~KoraAVDaemon();
    
    /**
     * Initialize daemon
     * - Load configuration
     * - Load eBPF programs
     * - Start detection engines
     */
    bool Initialize(const std::string& config_path = "/etc/koraav/koraav.conf");
    
    /**
     * Start the daemon
     * Runs until Stop() is called
     */
    void Run();
    
    /**
     * Stop the daemon
     */
    void Stop();
    
    /**
     * Get daemon status
     */
    bool IsRunning() const { return running_.load(); }

private:
    // Configuration
    struct Config {
        bool enable_file_monitor;
        bool enable_process_monitor;
        bool enable_network_monitor;
        bool detect_infostealer;
        bool detect_ransomware;
        bool detect_clickfix;
        int alert_threshold;
        int block_threshold;
        int lockdown_threshold;
        bool auto_kill;
        bool auto_block_network;
        bool auto_lockdown;
        std::string log_path;
    };
    
    Config config_;
    
    // Detection engines
    std::unique_ptr<realtime::InfoStealerDetector> infostealer_detector_;
    std::unique_ptr<realtime::RansomwareDetector> ransomware_detector_;
    std::unique_ptr<realtime::ClickFixDetector> clickfix_detector_;
    std::unique_ptr<realtime::C2Detector> c2_detector_;
    
    // Quarantine manager
    std::unique_ptr<QuarantineManager> quarantine_manager_;
    
    // Notification manager
    std::unique_ptr<NotificationManager> notification_manager_;
    
    // eBPF objects and programs
    bpf_object* file_monitor_obj_;
    bpf_object* process_monitor_obj_;
    bpf_object* network_monitor_obj_;
    
    bpf_program* file_monitor_prog_;
    bpf_program* process_monitor_prog_;
    bpf_program* network_monitor_prog_;
    
    // eBPF programs (file descriptors)
    int file_monitor_fd_;
    int process_monitor_fd_;
    int network_monitor_fd_;
    
    // eBPF links (for detaching)
    bpf_link* file_monitor_link_;
    bpf_link* process_monitor_link_;
    bpf_link* network_monitor_link_;
    
    // Ring buffers
    void* file_events_ringbuf_;
    void* process_events_ringbuf_;
    void* network_events_ringbuf_;
    
    // Control
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    
    // Event processing threads
    std::thread ransomware_thread_;  // Ransomware detector (fanotify loop)
    std::thread file_event_thread_;      // eBPF ring buffer poller (fast, no analysis)
    std::thread process_event_thread_;   // eBPF ring buffer poller (fast, no analysis)
    std::thread network_event_thread_;   // eBPF ring buffer poller (fast, no analysis)
    std::thread file_analysis_thread_;   // Analyses queued file events (slow, heavy)
    std::thread process_analysis_thread_;// Analyses queued process events
    std::thread network_analysis_thread_;// Analyses queued network events
    std::thread analysis_thread_;        // Periodic threat aggregation
    
    // Event counters (for status logging)
    std::atomic<uint64_t> file_events_received_{0};
    std::atomic<uint64_t> process_events_received_{0};
    std::atomic<uint64_t> network_events_received_{0};
    std::atomic<uint64_t> threats_detected_{0};
    
    // Initialization
    bool LoadConfiguration(const std::string& config_path);
    bool LoadeBPFPrograms();
    bool AttacheBPFProbes();
    
    // Event processing - split into fast poller + slow analyser per channel
    void ProcessFileEvents();       // Fast: drains eBPF ring buffer → queue
    void AnalyzeFileEvents();       // Slow: analyses queued file events
    void ProcessProcessEvents();    // Fast: drains eBPF ring buffer → queue
    void AnalyzeProcessEvents();    // Slow: analyses queued process events
    void ProcessNetworkEvents();    // Fast: drains eBPF ring buffer → queue
    void AnalyzeNetworkEvents();    // Slow: analyses queued network events
    void RunPeriodicAnalysis();     // Periodic threat aggregation + status
    
    // Threat response
    void HandleThreat(uint32_t pid, const std::string& threat_type, 
                     int score, const std::vector<std::string>& indicators);
    void KillProcess(uint32_t pid);
    void BlockProcessNetwork(uint32_t pid);
    void LockdownSystem();
    void LogThreat(uint32_t pid, const std::string& threat_type, 
                   int score, const std::vector<std::string>& indicators);
    
    // Helper functions
    bool SetSecureBits();
    bool IsSensitiveFile(const std::string& path);
    std::string GetProcessName(uint32_t pid);
    std::string GetProcessCommandLine(uint32_t pid);
};

} // namespace daemon
} // namespace koraav

#endif // KORAAV_DAEMON_H
