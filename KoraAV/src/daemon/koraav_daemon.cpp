// src/daemon/koraav_daemon.cpp
#include "koraav_daemon.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cerrno>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

namespace koraav {
namespace daemon {

KoraAVDaemon::KoraAVDaemon() 
    : file_monitor_obj_(nullptr),
      process_monitor_obj_(nullptr),
      network_monitor_obj_(nullptr),
      file_monitor_prog_(nullptr),
      process_monitor_prog_(nullptr),
      network_monitor_prog_(nullptr),
      file_monitor_fd_(-1),
      process_monitor_fd_(-1),
      network_monitor_fd_(-1),
      file_monitor_link_(nullptr),
      process_monitor_link_(nullptr),
      network_monitor_link_(nullptr),
      file_events_ringbuf_(nullptr),
      process_events_ringbuf_(nullptr),
      network_events_ringbuf_(nullptr),
      running_(false),
      initialized_(false) {
}

KoraAVDaemon::~KoraAVDaemon() {
    Stop();
}

bool KoraAVDaemon::Initialize(const std::string& config_path) {
    if (initialized_.exchange(true)) {
        std::cerr << "Daemon already initialized" << std::endl;
        return false;
    }
    
    std::cout << "Initializing KoraAV Daemon..." << std::endl;
    
    // Increase rlimit for BPF
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        std::cerr << "Warning: Failed to increase RLIMIT_MEMLOCK" << std::endl;
    }
    
    // Load configuration
    if (!LoadConfiguration(config_path)) {
        std::cerr << "Failed to load configuration" << std::endl;
        initialized_ = false;
        return false;
    }
    
    // Load and attach eBPF programs
    if (config_.enable_file_monitor || config_.enable_process_monitor || config_.enable_network_monitor) {
        std::cout << "Loading eBPF programs..." << std::endl;
        if (!LoadeBPFPrograms()) {
            std::cerr << "Warning: eBPF programs not loaded (may not be available)" << std::endl;
        } else {
            std::cout << "eBPF programs loaded" << std::endl;
            if (!AttacheBPFProbes()) {
                std::cerr << "Warning: Failed to attach eBPF probes" << std::endl;
            } else {
                std::cout << "eBPF probes attached" << std::endl;
            }
        }
    }
    
    // Create detection engines
    if (config_.detect_infostealer) {
        infostealer_detector_ = std::make_unique<realtime::InfoStealerDetector>();
        if (!infostealer_detector_->Initialize()) {
            std::cerr << "Failed to initialize info stealer detector" << std::endl;
        } else {
            std::cout << "Info stealer detector initialized" << std::endl;
        }
    }
    
    if (config_.detect_ransomware) {
        ransomware_detector_ = std::make_unique<realtime::RansomwareDetector>();
        if (!ransomware_detector_->Initialize()) {
            std::cerr << "Failed to initialize ransomware detector" << std::endl;
        } else {
            std::cout << "Ransomware detector initialized" << std::endl;
        }
    }
    
    if (config_.detect_clickfix) {
        clickfix_detector_ = std::make_unique<realtime::ClickFixDetector>();
        if (!clickfix_detector_->Initialize()) {
            std::cerr << "Failed to initialize ClickFix detector" << std::endl;
        } else {
            std::cout << "ClickFix detector initialized" << std::endl;
        }
    }
    
    std::cout << "KoraAV Daemon has been initialized successfully!" << std::endl;
    return true;
}

void KoraAVDaemon::Run() {
    if (!initialized_) {
        std::cerr << "Daemon not initialized" << std::endl;
        return;
    }
    
    if (running_.exchange(true)) {
        std::cerr << "Daemon already running" << std::endl;
        return;
    }
    
    std::cout << "Starting KoraAV Real-Time Protection..." << std::endl;
    
    // Start detection engines
    if (ransomware_detector_) {
        ransomware_detector_->Start();
        std::cout << "✓ Ransomware protection active" << std::endl;
    }
    
    if (infostealer_detector_) {
        infostealer_detector_->Start();
        std::cout << "✓ Info stealer protection active" << std::endl;
    }
    
    if (clickfix_detector_) {
        clickfix_detector_->Start();
        std::cout << "✓ ClickFix protection active" << std::endl;
    }
    
    // Start event processing threads if eBPF is loaded
    if (file_monitor_fd_ >= 0 && config_.enable_file_monitor) {
        file_event_thread_ = std::thread(&KoraAVDaemon::ProcessFileEvents, this);
        std::cout << "✓ File monitoring active" << std::endl;
    }
    
    if (process_monitor_fd_ >= 0 && config_.enable_process_monitor) {
        process_event_thread_ = std::thread(&KoraAVDaemon::ProcessProcessEvents, this);
        std::cout << "✓ Process monitoring active" << std::endl;
    }
    
    if (network_monitor_fd_ >= 0 && config_.enable_network_monitor) {
        network_event_thread_ = std::thread(&KoraAVDaemon::ProcessNetworkEvents, this);
        std::cout << "✓ Network monitoring active" << std::endl;
    }
    
    // Start periodic analysis thread
    analysis_thread_ = std::thread(&KoraAVDaemon::RunPeriodicAnalysis, this);
    
    std::cout << "✓ KoraAV is now protecting your system" << std::endl;
    std::cout << "Daemon running (managed by systemd)" << std::endl;
    
    // Notify systemd we're ready
    const char* notify_socket = getenv("NOTIFY_SOCKET");
    if (notify_socket) {
        // Send READY to systemd
        int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (fd >= 0) {
            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, notify_socket, sizeof(addr.sun_path) - 1);
            
            const char* ready_msg = "READY=1\nSTATUS=Real-time protection active\n";
            sendto(fd, ready_msg, strlen(ready_msg), 0, (struct sockaddr*)&addr, sizeof(addr));
            close(fd);
        }
    }
    
    // Main event loop - just wait for shutdown
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Send watchdog keepalive to systemd
        if (notify_socket) {
            int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
            if (fd >= 0) {
                struct sockaddr_un addr;
                memset(&addr, 0, sizeof(addr));
                addr.sun_family = AF_UNIX;
                strncpy(addr.sun_path, notify_socket, sizeof(addr.sun_path) - 1);
                
                const char* watchdog_msg = "WATCHDOG=1\n";
                sendto(fd, watchdog_msg, strlen(watchdog_msg), 0, (struct sockaddr*)&addr, sizeof(addr));
                close(fd);
            }
        }
    }
    
    std::cout << "Stopping KoraAV..." << std::endl;
}

void KoraAVDaemon::Stop() {
    if (!running_.exchange(false)) {
        return;  // Already stopped
    }
    
    std::cout << "Stopping detection engines..." << std::endl;
    
    // Stop detection engines
    if (ransomware_detector_) {
        ransomware_detector_->Stop();
    }
    
    if (infostealer_detector_) {
        infostealer_detector_->Stop();
    }
    
    if (clickfix_detector_) {
        clickfix_detector_->Stop();
    }
    
    // Wait for threads to finish
    if (file_event_thread_.joinable()) {
        file_event_thread_.join();
    }
    if (process_event_thread_.joinable()) {
        process_event_thread_.join();
    }
    if (network_event_thread_.joinable()) {
        network_event_thread_.join();
    }
    if (analysis_thread_.joinable()) {
        analysis_thread_.join();
    }
    
    // Cleanup eBPF resources
    if (file_monitor_link_) {
        bpf_link__destroy(file_monitor_link_);
        file_monitor_link_ = nullptr;
    }
    if (process_monitor_link_) {
        bpf_link__destroy(process_monitor_link_);
        process_monitor_link_ = nullptr;
    }
    if (network_monitor_link_) {
        bpf_link__destroy(network_monitor_link_);
        network_monitor_link_ = nullptr;
    }
    
    if (file_events_ringbuf_) {
        ring_buffer__free((struct ring_buffer*)file_events_ringbuf_);
        file_events_ringbuf_ = nullptr;
    }
    if (process_events_ringbuf_) {
        ring_buffer__free((struct ring_buffer*)process_events_ringbuf_);
        process_events_ringbuf_ = nullptr;
    }
    if (network_events_ringbuf_) {
        ring_buffer__free((struct ring_buffer*)network_events_ringbuf_);
        network_events_ringbuf_ = nullptr;
    }
    
    if (file_monitor_obj_) {
        bpf_object__close(file_monitor_obj_);
        file_monitor_obj_ = nullptr;
    }
    if (process_monitor_obj_) {
        bpf_object__close(process_monitor_obj_);
        process_monitor_obj_ = nullptr;
    }
    if (network_monitor_obj_) {
        bpf_object__close(network_monitor_obj_);
        network_monitor_obj_ = nullptr;
    }
    
    file_monitor_fd_ = -1;
    process_monitor_fd_ = -1;
    network_monitor_fd_ = -1;
    
    std::cout << "✓ KoraAV stopped" << std::endl;
}

bool KoraAVDaemon::LoadConfiguration(const std::string& config_path) {
    // Set defaults
    config_.enable_file_monitor = true;
    config_.enable_process_monitor = true;
    config_.enable_network_monitor = true;
    config_.detect_infostealer = true;
    config_.detect_ransomware = true;
    config_.detect_clickfix = true;
    config_.alert_threshold = 61;
    config_.block_threshold = 81;
    config_.lockdown_threshold = 96;
    config_.auto_kill = true;
    config_.auto_block_network = true;
    config_.auto_lockdown = false;
    config_.log_path = "/opt/koraav/var/logs";
    
    // Try to load from file
    std::ifstream file(config_path);
    if (!file.is_open()) {
        std::cout << "Config file not found, using defaults" << std::endl;
        return true;  // Use defaults
    }
    
    std::cout << "Loading configuration from " << config_path << std::endl;
    
    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#' || line[0] == '[') {
            continue;
        }
        
        // Parse key = value
        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) {
            continue;
        }
        
        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);
        
        // Trim whitespace
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);
        
        // Apply configuration
        if (key == "detect_infostealer") {
            config_.detect_infostealer = (value == "true");
        } else if (key == "detect_ransomware") {
            config_.detect_ransomware = (value == "true");
        } else if (key == "detect_clickfix") {
            config_.detect_clickfix = (value == "true");
        } else if (key == "alert_threshold") {
            config_.alert_threshold = std::stoi(value);
        } else if (key == "block_threshold") {
            config_.block_threshold = std::stoi(value);
        } else if (key == "auto_kill") {
            config_.auto_kill = (value == "true");
        } else if (key == "auto_block_network") {
            config_.auto_block_network = (value == "true");
        } else if (key == "log_path") {
            config_.log_path = value;
        }
    }
    
    std::cout << "KoraAV Config Loaded!" << std::endl;
    return true;
}

bool KoraAVDaemon::LoadeBPFPrograms() {
    // Try to load eBPF programs from standard locations
    const char* bpf_paths[] = {
        "/opt/koraav/lib/bpf/file_monitor.bpf.o",
        "/opt/koraav/lib/bpf/process_monitor.bpf.o",
        "/opt/koraav/lib/bpf/network_monitor.bpf.o"
    };
    
    bool any_loaded = false;
    
    // Load file monitor
    if (access(bpf_paths[0], F_OK) == 0) {
        file_monitor_obj_ = bpf_object__open(bpf_paths[0]);
        if (file_monitor_obj_) {
            if (bpf_object__load(file_monitor_obj_) == 0) {
                // Find the program by name
                file_monitor_prog_ = bpf_object__find_program_by_name(file_monitor_obj_, "monitor_file_open");
                if (file_monitor_prog_) {
                    file_monitor_fd_ = bpf_program__fd(file_monitor_prog_);
                    any_loaded = true;
                    std::cout << "File monitor loaded" << std::endl;
                } else {
                    std::cerr << "Could not find monitor_file_open program" << std::endl;
                }
            } else {
                std::cerr << "Failed to load file monitor object: " << strerror(errno) << std::endl;
                bpf_object__close(file_monitor_obj_);
                file_monitor_obj_ = nullptr;
            }
        } else {
            std::cerr << "Failed to open file monitor: " << strerror(errno) << std::endl;
        }
    }
    
    // Load process monitor
    if (access(bpf_paths[1], F_OK) == 0) {
        process_monitor_obj_ = bpf_object__open(bpf_paths[1]);
        if (process_monitor_obj_) {
            if (bpf_object__load(process_monitor_obj_) == 0) {
                process_monitor_prog_ = bpf_object__find_program_by_name(process_monitor_obj_, "monitor_process_exec");
                if (process_monitor_prog_) {
                    process_monitor_fd_ = bpf_program__fd(process_monitor_prog_);
                    any_loaded = true;
                    std::cout << "Process monitor loaded" << std::endl;
                } else {
                    std::cerr << "Could not find monitor_process_exec program" << std::endl;
                }
            } else {
                std::cerr << "Failed to load process monitor object: " << strerror(errno) << std::endl;
                bpf_object__close(process_monitor_obj_);
                process_monitor_obj_ = nullptr;
            }
        } else {
            std::cerr << "Failed to open process monitor: " << strerror(errno) << std::endl;
        }
    }
    
    // Load network monitor
    if (access(bpf_paths[2], F_OK) == 0) {
        network_monitor_obj_ = bpf_object__open(bpf_paths[2]);
        if (network_monitor_obj_) {
            if (bpf_object__load(network_monitor_obj_) == 0) {
                network_monitor_prog_ = bpf_object__find_program_by_name(network_monitor_obj_, "monitor_network_connect");
                if (network_monitor_prog_) {
                    network_monitor_fd_ = bpf_program__fd(network_monitor_prog_);
                    any_loaded = true;
                    std::cout << "Network monitor loaded" << std::endl;
                } else {
                    std::cerr << "Could not find monitor_network_connect program" << std::endl;
                }
            } else {
                std::cerr << "Failed to load network monitor object: " << strerror(errno) << std::endl;
                bpf_object__close(network_monitor_obj_);
                network_monitor_obj_ = nullptr;
            }
        } else {
            std::cerr << "Failed to open network monitor: " << strerror(errno) << std::endl;
        }
    }
    
    return any_loaded;
}

bool KoraAVDaemon::AttacheBPFProbes() {
    // Attach loaded programs to kernel hooks
    bool any_attached = false;
    
    if (file_monitor_prog_) {
        // Attach to file open tracepoint (syscalls/sys_enter_openat)
        file_monitor_link_ = bpf_program__attach_tracepoint(
            file_monitor_prog_,
            "syscalls",
            "sys_enter_openat"
        );
        
        if (file_monitor_link_) {
            std::cout << "File monitor attached to sys_enter_openat" << std::endl;
            any_attached = true;
        } else {
            std::cerr << "Failed to attach file monitor: " << strerror(errno) << std::endl;
            // Try alternative tracepoint
            file_monitor_link_ = bpf_program__attach_tracepoint(
                file_monitor_prog_,
                "syscalls",
                "sys_enter_open"
            );
            if (file_monitor_link_) {
                std::cout << "File monitor attached to sys_enter_open (fallback)" << std::endl;
                any_attached = true;
            }
        }
    }
    
    if (process_monitor_prog_) {
        // Attach to process exec tracepoint (sched/sched_process_exec)
        process_monitor_link_ = bpf_program__attach_tracepoint(
            process_monitor_prog_,
            "sched",
            "sched_process_exec"
        );
        
        if (process_monitor_link_) {
            std::cout << "Process monitor attached to sched_process_exec" << std::endl;
            any_attached = true;
        } else {
            std::cerr << "Failed to attach process monitor: " << strerror(errno) << std::endl;
        }
    }
    
    if (network_monitor_prog_) {
        // Attach to network connect tracepoint (syscalls/sys_enter_connect)
        network_monitor_link_ = bpf_program__attach_tracepoint(
            network_monitor_prog_,
            "syscalls",
            "sys_enter_connect"
        );
        
        if (network_monitor_link_) {
            std::cout << "Network monitor attached to sys_enter_connect" << std::endl;
            any_attached = true;
        } else {
            std::cerr << "Failed to attach network monitor: " << strerror(errno) << std::endl;
        }
    }
    
    if (!any_attached) {
        std::cerr << "Warning: No eBPF programs were successfully attached" << std::endl;
        std::cerr << "Real-time monitoring may not function correctly" << std::endl;
        return false;
    }
    
    return true;
}

void KoraAVDaemon::ProcessFileEvents() {
    std::cout << "File event processor started" << std::endl;
    
    while (running_) {
        // Poll ring buffer for file events
        if (file_events_ringbuf_) {
            ring_buffer__poll((struct ring_buffer*)file_events_ringbuf_, 100);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    std::cout << "File event processor stopped" << std::endl;
}

void KoraAVDaemon::ProcessProcessEvents() {
    std::cout << "Process event processor started" << std::endl;
    
    while (running_) {
        // Poll ring buffer for process events
        if (process_events_ringbuf_) {
            ring_buffer__poll((struct ring_buffer*)process_events_ringbuf_, 100);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    std::cout << "Process event processor stopped" << std::endl;
}

void KoraAVDaemon::ProcessNetworkEvents() {
    std::cout << "Network event processor started" << std::endl;
    
    while (running_) {
        // Poll ring buffer for network events
        if (network_events_ringbuf_) {
            ring_buffer__poll((struct ring_buffer*)network_events_ringbuf_, 100);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    std::cout << "Network event processor stopped" << std::endl;
}

void KoraAVDaemon::RunPeriodicAnalysis() {
    std::cout << "Periodic analysis thread started" << std::endl;
    
    while (running_) {
        // Run periodic checks every 5 seconds
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        // Check for suspicious processes from detection engines
        if (ransomware_detector_) {
            auto suspicious = ransomware_detector_->GetSuspiciousProcesses();
            for (const auto& proc : suspicious) {
                if (proc.is_confirmed_ransomware) {
                    std::vector<std::string> indicators;
                    for (const auto& file : proc.targeted_files) {
                        indicators.push_back("Encrypted: " + file);
                    }
                    HandleThreat(proc.pid, "Ransomware", proc.threat_score, indicators);
                }
            }
        }
        
        if (infostealer_detector_) {
            auto suspicious = infostealer_detector_->GetSuspiciousProcesses();
            for (const auto& proc : suspicious) {
                if (proc.is_confirmed_infostealer) {
                    std::vector<std::string> indicators;
                    for (const auto& file : proc.accessed_files) {
                        indicators.push_back("Accessed: " + file);
                    }
                    HandleThreat(proc.pid, "InfoStealer", proc.threat_score, indicators);
                }
            }
        }
    }
    
    std::cout << "Periodic analysis thread stopped" << std::endl;
}

void KoraAVDaemon::HandleThreat(uint32_t pid, const std::string& threat_type,
                                int score, const std::vector<std::string>& indicators) {
    LogThreat(pid, threat_type, score, indicators);
    
    std::cout << "THREAT DETECTED: " << threat_type << " (PID " << pid << ", Score " << score << ")" << std::endl;
    
    if (score >= config_.lockdown_threshold && config_.auto_lockdown) {
        std::cout << "CRITICAL THREAT - Initiating system lockdown" << std::endl;
        LockdownSystem();
    } else if (score >= config_.block_threshold) {
        if (config_.auto_block_network) {
            BlockProcessNetwork(pid);
        }
        if (config_.auto_kill) {
            KillProcess(pid);
        }
    } else if (score >= config_.alert_threshold) {
        std::cout << "Alert threshold reached for PID " << pid << std::endl;
    }
}

void KoraAVDaemon::KillProcess(uint32_t pid) {
    std::cout << " --> Killing malicious process PID " << pid << " (" << GetProcessName(pid) << ")" << std::endl;
    kill(pid, SIGKILL);
}

void KoraAVDaemon::BlockProcessNetwork(uint32_t pid) {
    std::cout << " --> Blocking network for PID " << pid << std::endl;
    
    // Use nftables to block process
    std::string cmd = "nft add rule inet filter output meta skuid " + std::to_string(pid) + " drop 2>/dev/null";
    system(cmd.c_str());
    
    // Fallback to iptables
    cmd = "iptables -A OUTPUT -m owner --pid-owner " + std::to_string(pid) + " -j DROP 2>/dev/null";
    system(cmd.c_str());
}

void KoraAVDaemon::LockdownSystem() {
    std::cout << "SYSTEM LOCKDOWN INITIATED" << std::endl;
    
    // Remount filesystem read-only
    std::cout << " --> Remounting filesystem read-only..." << std::endl;
    system("mount -o remount,ro / 2>/dev/null");
    
    // Block all network (except localhost)
    std::cout << "  → Blocking network traffic..." << std::endl;
    system("nft add table inet lockdown 2>/dev/null");
    system("nft add chain inet lockdown output { type filter hook output priority 0 \\; } 2>/dev/null");
    system("nft add rule inet lockdown output oif lo accept 2>/dev/null");
    system("nft add rule inet lockdown output drop 2>/dev/null");
    
    std::cout << "SYSTEM LOCKED - Use 'sudo koraav unlock --all' to restore" << std::endl;
}

void KoraAVDaemon::LogThreat(uint32_t pid, const std::string& threat_type,
                             int score, const std::vector<std::string>& indicators) {
    // Create log directory if it doesn't exist
    system(("mkdir -p " + config_.log_path).c_str());
    
    std::string log_file = config_.log_path + "/threats.log";
    std::ofstream log(log_file, std::ios::app);
    
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    char time_buf[100];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now_c));
    
    log << "[" << time_buf << "] ";
    log << "PID=" << pid << " ";
    log << "Type=" << threat_type << " ";
    log << "Score=" << score << " ";
    log << "Process=" << GetProcessName(pid) << " ";
    log << "CMD=" << GetProcessCommandLine(pid) << " ";
    log << "Indicators: ";
    for (const auto& ind : indicators) {
        log << ind << "; ";
    }
    log << std::endl;
}

std::string KoraAVDaemon::GetProcessName(uint32_t pid) {
    std::string comm_path = "/proc/" + std::to_string(pid) + "/comm";
    std::ifstream file(comm_path);
    std::string name;
    if (file) {
        std::getline(file, name);
    }
    return name.empty() ? "unknown" : name;
}

std::string KoraAVDaemon::GetProcessCommandLine(uint32_t pid) {
    std::string cmdline_path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream file(cmdline_path);
    std::string cmdline;
    if (file) {
        std::getline(file, cmdline, '\0');
    }
    return cmdline.empty() ? "" : cmdline;
}

} // namespace daemon
} // namespace koraav
