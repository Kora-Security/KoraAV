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
#include <sys/prctl.h>
#include <linux/securebits.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <unordered_set>
#include <chrono>
#include <unordered_map>
#include <linux/limits.h>


struct YaraCacheEntry {
    time_t mtime;
    ino_t inode;
    bool is_clean;
    std::chrono::steady_clock::time_point cached_at;
};

static std::unordered_map<std::string, YaraCacheEntry> yara_scan_cache;
static std::mutex yara_cache_mutex;
static constexpr size_t MAX_YARA_CACHE_SIZE = 10000;






namespace koraav {
namespace daemon {

// ─────────────────────────────────────────────────────────
// Thread-safe event queue for producer/consumer pattern.
// eBPF callbacks (producers) push events here instantly.
// Analysis threads (consumers) process them separately.
// This prevents callbacks from doing heavy work and blocking.
// ─────────────────────────────────────────────────────────
template<typename T>
class EventQueue {
public:
    void Push(const T& event) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() < MAX_QUEUE_SIZE) {
            queue_.push(event);
            ++queue_size_;
            cv_.notify_one();
        }
        // If full, silently drop - better than blocking
    }

    bool Pop(T& event, int timeout_ms = 100) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!cv_.wait_for(lock,
                          std::chrono::milliseconds(timeout_ms),
                          [this] { return !queue_.empty() || stopped_; })) {
            return false;  // Timeout
        }
        if (stopped_ && queue_.empty()) {
            return false;
        }
        event = queue_.front();
        queue_.pop();
        --queue_size_;
        return true;
    }

    void Stop() {
        std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
        cv_.notify_all();
    }

    bool Empty() {
        return queue_size_ == 0;
    }

    size_t Size() const {
        return queue_size_;
    }

private:
    static constexpr size_t MAX_QUEUE_SIZE = 10000;
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool stopped_ = false;
    std::atomic<size_t> queue_size_{0};
};

// Event structs (mirror the eBPF structs exactly)
struct FileEventData {
    uint64_t timestamp;
    uint32_t tgid;
    uint32_t uid;
    uint32_t flags;
    uint32_t mode;
    char comm[16];
    char filename[256];
};

struct ProcessEventData {
    uint64_t timestamp;
    uint32_t tgid;
    uint32_t ptgid;
    uint32_t uid;
    char comm[16];
    char cmdline[256];
};

struct NetworkEventData {
    uint64_t timestamp;
    uint32_t tgid;
    uint32_t uid;
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    char comm[16];
};


bool KoraAVDaemon::SetSecureBits() {
    // SecureBits only work when running as a non-root user with capabilities.
    // When running as root, skip silently - root doesn't need securebits.
    if (getuid() == 0) {
        return true;  // Running as root, securebits not needed
    }

    int securebits = SECBIT_KEEP_CAPS |
                     SECBIT_KEEP_CAPS_LOCKED |
                     SECBIT_NO_SETUID_FIXUP |
                     SECBIT_NO_SETUID_FIXUP_LOCKED |
                     SECBIT_NOROOT |
                     SECBIT_NOROOT_LOCKED;

    if (prctl(PR_SET_SECUREBITS, securebits) < 0) {
        // This is non-fatal, only warn at debug level
        return false;
    }

    std::cout << "✓ SecureBits locked" << std::endl;
    return true;
}


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
      initialized_(false),
      yara_manager_(nullptr) {
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
    
    // Initialize quarantine manager
    quarantine_manager_ = std::make_unique<QuarantineManager>("/opt/koraav/var/quarantine");
    std::cout << "✓ Quarantine manager initialized" << std::endl;
    
    // Initialize notification manager
    notification_manager_ = std::make_unique<NotificationManager>();
    std::cout << "✓ Notification manager initialized" << std::endl;
    
    // Load and attach eBPF programs
    if (config_.enable_file_monitor || config_.enable_process_monitor || config_.enable_network_monitor) {
        std::cout << "Loading eBPF programs..." << std::endl;
        if (!LoadeBPFPrograms()) {
            std::cerr << "Warning: eBPF programs not loaded (may not be available)" << std::endl;
        } else {
            std::cout << "✓ eBPF programs loaded" << std::endl;
            if (!AttacheBPFProbes()) {
                std::cerr << "Warning: Failed to attach eBPF probes" << std::endl;
            } else {
                std::cout << "✓ eBPF probes attached" << std::endl;
            }
        }
    }
    
    // Create detection engines
    if (config_.detect_infostealer) {
        infostealer_detector_ = std::make_unique<realtime::InfoStealerDetector>();
        std::cout << "✓ Info stealer detector initialized" << std::endl;
    }
    
    if (config_.detect_ransomware) {
        ransomware_detector_ = std::make_unique<realtime::RansomwareDetector>();
        
        if (!ransomware_detector_->Initialize()) {
            std::cerr << "Failed to initialize ransomware detector" << std::endl;
        } else {
            std::cout << "✓ Ransomware detector initialized" << std::endl;
        }
    }

    // Initialize snapshot system
    snapshot_system_ = std::make_unique<realtime::SnapshotSystem>();
    if (!snapshot_system_->Initialize()) {
        std::cerr << "Warning: Snapshot/Rollback system not available" << std::endl;
        return false;
    }
    
    // Initialize canary file system
    canary_system_ = std::make_unique<realtime::CanaryFileSystem>();
    if (!canary_system_->Initialize(2)) {  // 2 canaries per directory
        std::cerr << "Warning: Canary file system initialization failed" << std::endl;
        return false;
    }
    
    if (config_.detect_clickfix) {
        clickfix_detector_ = std::make_unique<realtime::ClickFixDetector>();
        std::cout << "✓ ClickFix detector initialized" << std::endl;
    }
    
    // Initialize C2 detector
    c2_detector_ = std::make_unique<realtime::C2Detector>();
    std::cout << "✓ C2 detector initialized" << std::endl;
    
    // Secure our bits
    SetSecureBits();

    std::cout << "✓ KoraAV Daemon initialized successfully" << std::endl;
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


    // Start use of yara rules
    if (config_.enable_yara) {
        try {
            yara_manager_ = &YaraManager::Instance();  // ✅ Get singleton instance
            if (!yara_manager_->IsReady()) {
                if (!yara_manager_->Initialize()) {
                    std::cerr << "⚠️  YARA initialization failed" << std::endl;
                    yara_manager_ = nullptr;
                } else if (!yara_manager_->LoadRules(config_.yara_rules_path)) {
                    std::cerr << "⚠️  YARA rules loading failed" << std::endl;
                    yara_manager_ = nullptr;
                } else {
                    std::cout << "✓ YARA scanner initialized" << std::endl;
                }
            } else {
                // Already initialized (singleton)
                std::cout << "✓ YARA scanner ready" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "⚠️  YARA error: " << e.what() << std::endl;
            yara_manager_ = nullptr;
        }
    }
    
    // Start detection engines
    // Ransomware detector is now passive (no separate thread needed)
    if (ransomware_detector_) {
        std::cout << "✓ Ransomware protection active (behavioral analysis)" << std::endl;
    }

    // Start snapshot creation thread (every 5 minutes)
    std::thread snapshot_thread([this]() {
        std::cout << "Snapshot thread started (5-minute intervals)" << std::endl;

        while (running_) {
            // Sleep 5 minutes
            std::this_thread::sleep_for(std::chrono::minutes(5));

            if (snapshot_system_) {
                std::string snap_id = snapshot_system_->CreateSnapshot();
                if (!snap_id.empty()) {
                    std::cout << "📸 Snapshot created: " << snap_id << std::endl;
                }
            }
        }

        std::cout << "Snapshot thread stopped" << std::endl;
    });
    
    if (infostealer_detector_) {
        std::cout << "✓ Info stealer protection active" << std::endl;
    }
    
    if (clickfix_detector_) {
        std::cout << "✓ ClickFix protection active" << std::endl;
    }
    
    // Start event processing threads if eBPF is loaded
    if (file_monitor_fd_ >= 0 && config_.enable_file_monitor) {
        file_event_thread_    = std::thread(&KoraAVDaemon::ProcessFileEvents, this);
        file_analysis_thread_ = std::thread(&KoraAVDaemon::AnalyzeFileEvents, this);
        std::cout << "✓ File monitoring active" << std::endl;
    }
    
    if (process_monitor_fd_ >= 0 && config_.enable_process_monitor) {
        process_event_thread_    = std::thread(&KoraAVDaemon::ProcessProcessEvents, this);
        process_analysis_thread_ = std::thread(&KoraAVDaemon::AnalyzeProcessEvents, this);
        std::cout << "✓ Process monitoring active" << std::endl;
    }
    
    if (network_monitor_fd_ >= 0 && config_.enable_network_monitor) {
        network_event_thread_    = std::thread(&KoraAVDaemon::ProcessNetworkEvents, this);
        network_analysis_thread_ = std::thread(&KoraAVDaemon::AnalyzeNetworkEvents, this);
        std::cout << "✓ Network monitoring active" << std::endl;
    }
    
    // Start periodic analysis thread
    analysis_thread_ = std::thread(&KoraAVDaemon::RunPeriodicAnalysis, this);
    
    std::cout << "✓ KoraAV is now protecting your system" << std::endl;
    std::cout << "Daemon running (managed by systemd)" << std::endl;
    snapshot_thread.join();
    
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
    
    // Behavioral detectors are passive (no Stop() needed)
    
    // Wait for threads to finish
    if (file_event_thread_.joinable())         file_event_thread_.join();
    if (file_analysis_thread_.joinable())      file_analysis_thread_.join();
    if (process_event_thread_.joinable())      process_event_thread_.join();
    if (process_analysis_thread_.joinable())   process_analysis_thread_.join();
    if (network_event_thread_.joinable())      network_event_thread_.join();
    if (network_analysis_thread_.joinable())   network_analysis_thread_.join();
    if (analysis_thread_.joinable())           analysis_thread_.join();
    
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
    std::cout << "Loading configuration from: " << config_path << std::endl;

    // Set defaults FIRST
    config_.enable_file_monitor = true;
    config_.enable_process_monitor = true;
    config_.enable_network_monitor = true;

    config_.detect_infostealer = true;
    config_.detect_ransomware = true;
    config_.detect_clickfix = true;
    config_.detect_c2 = true;


    // NEW: Canary defaults
    config_.enable_canary_files = true;
    config_.canaries_per_directory = 3;

    // NEW: Snapshot defaults
    config_.enable_snapshots = true;
    config_.snapshot_interval_minutes = 5;
    config_.max_snapshots = 6;
    config_.snapshot_dir = "/.snapshots/koraav";
    config_.snapshot_type = "auto";
    config_.snapshot_retention_minutes = 30;


    config_.alert_threshold = 61;
    config_.block_threshold = 81;
    config_.lockdown_threshold = 96;


    // NEW: Detection thresholds
    config_.entropy_delta_threshold = 2.5;
    config_.max_ops_per_second = 50.0;
    config_.max_files_touched = 20;
    config_.max_directories = 10;
    config_.max_renames = 15;
    config_.extension_change_threshold = 4;
    config_.time_window_seconds = 10.0;



    config_.auto_kill = true;
    config_.auto_quarantine = true;

    config_.auto_block_network_infostealer = true;   // Block active exfil
    config_.auto_block_network_c2 = true;            // Block C2 beaconing
    config_.auto_block_network_clickfix = false;     // Already blocked
    config_.auto_block_network_ransomware = false;   // Already killed

    // SYSTEM LOCKDOWN - DEFAULT OFF - (Mount system as read only)
    config_.auto_lockdown = false;

    // Ransomware behavioral defaults (legacy - kept for compatibility)
    // config_.ransomware_files_before_action = 4;
    // config_.ransomware_max_ops_per_second = 50.0;
    // config_.ransomware_max_directories = 10;
    // config_.ransomware_max_renames = 15;
    // config_.ransomware_time_window = 10.0; //10s

    config_.log_path = "/opt/koraav/var/logs";
    config_.enable_detailed_logging = false;

    config_.enable_yara = true;
    config_.yara_rules_path = "/opt/koraav/share/signatures/yara-rules";
    config_.yara_scan_on_execution = true;
    config_.yara_scan_on_download = true;

    config_.process_whitelist_file = "/etc/koraav/process-whitelist.conf";

    // Try to open config file
    std::ifstream config_file(config_path);
    if (!config_file) {
        std::cout << "Warning: Config file not found, using defaults" << std::endl;
        return true;  // Use defaults
    }

    // Parse config file
    std::string line, current_section;
    while (std::getline(config_file, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);

        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;

        // Section headers
        if (line[0] == '[' && line[line.length()-1] == ']') {
            current_section = line.substr(1, line.length()-2);
            continue;
        }

        // Parse key = value
        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;

        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);

        // Trim
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);

        // Parse based on section
        if (current_section == "monitoring") {
            if (key == "enable_file_monitor") config_.enable_file_monitor = (value == "true");
            else if (key == "enable_process_monitor") config_.enable_process_monitor = (value == "true");
            else if (key == "enable_network_monitor") config_.enable_network_monitor = (value == "true");
        }
        else if (current_section == "detection") {
            if (key == "detect_infostealer") config_.detect_infostealer = (value == "true");
            else if (key == "detect_ransomware") config_.detect_ransomware = (value == "true");
            else if (key == "detect_clickfix") config_.detect_clickfix = (value == "true");
            else if (key == "detect_c2") config_.detect_c2 = (value == "true");
            // NEW: Canary settings
            else if (key == "enable_canary_files") config_.enable_canary_files = (value == "true");
            else if (key == "canaries_per_directory") config_.canaries_per_directory = std::stoi(value);
            // NEW: Snapshot settings
            else if (key == "enable_snapshots") config_.enable_snapshots = (value == "true");
            else if (key == "snapshot_interval_minutes") config_.snapshot_interval_minutes = std::stoi(value);
            else if (key == "max_snapshots") config_.max_snapshots = std::stoi(value);
        }
        else if (current_section == "thresholds") {
            if (key == "alert_threshold") config_.alert_threshold = std::stoi(value);
            else if (key == "block_threshold") config_.block_threshold = std::stoi(value);
            else if (key == "lockdown_threshold") config_.lockdown_threshold = std::stoi(value);
            else if (key == "entropy_delta_threshold") config_.entropy_delta_threshold = std::stod(value);
            else if (key == "max_ops_per_second") config_.max_ops_per_second = std::stod(value);
            else if (key == "max_files_touched") config_.max_files_touched = std::stoi(value);
            else if (key == "max_directories") config_.max_directories = std::stoi(value);
            else if (key == "max_renames") config_.max_renames = std::stoi(value);
            else if (key == "extension_change_threshold") config_.extension_change_threshold = std::stoi(value);
            else if (key == "time_window_seconds") config_.time_window_seconds = std::stod(value);
        }
        else if (current_section == "response") {
            if (key == "auto_kill") config_.auto_kill = (value == "true");
            else if (key == "auto_quarantine") config_.auto_quarantine = (value == "true");

            // Situational network blocking
            else if (key == "auto_block_network_infostealer") config_.auto_block_network_infostealer = (value == "true");
            else if (key == "auto_block_network_c2") config_.auto_block_network_c2 = (value == "true");
            else if (key == "auto_block_network_clickfix") config_.auto_block_network_clickfix = (value == "true");
            else if (key == "auto_block_network_ransomware") config_.auto_block_network_ransomware = (value == "true");
            else if (key == "auto_rollback_on_ransomware") config_.auto_rollback_on_ransomware = (value == "true");
            else if (key == "auto_lockdown") config_.auto_lockdown = (value == "true");
        }
        // else if (current_section == "ransomware") {
        //     if (key == "files_before_action")
        //         config_.ransomware_files_before_action = std::stoi(value);
        //     else if (key == "max_operations_per_second")
        //         config_.ransomware_max_ops_per_second = std::stod(value);
        //     else if (key == "max_directories_touched")
        //         config_.ransomware_max_directories = std::stoi(value);
        //     else if (key == "max_renames")
        //         config_.ransomware_max_renames = std::stoi(value);
        //     else if (key == "time_window_seconds")
        //         config_.ransomware_time_window = std::stod(value);
        // }
        else if (current_section == "snapshots") {
            if (key == "snapshot_dir") config_.snapshot_dir = value;
            else if (key == "snapshot_type") config_.snapshot_type = value;
            else if (key == "snapshot_retention_minutes") config_.snapshot_retention_minutes = std::stoi(value);
        }
        else if (current_section == "logging") {
            if (key == "log_path") config_.log_path = value;
            else if (key == "enable_detailed_logging") config_.enable_detailed_logging = (value == "true");
        }
        else if (current_section == "yara") {
            if (key == "enable_yara") config_.enable_yara = (value == "true");
            else if (key == "rules_path") config_.yara_rules_path = value;
            else if (key == "scan_on_execution") config_.yara_scan_on_execution = (value == "true");
            else if (key == "scan_on_download") config_.yara_scan_on_download = (value == "true");
        }
        else if (current_section == "whitelist") {
            if (key == "process_whitelist_file") config_.process_whitelist_file = value;
        }
    }

    std::cout << "✓ Configuration loaded successfully" << std::endl;

    // Log important settings
    if (config_.auto_lockdown) {
        std::cout << "⚠️  WARNING: System lockdown is ENABLED (threshold: "
        << config_.lockdown_threshold << ")" << std::endl;
    }

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
                // Find the program by its actual name: trace_openat
                file_monitor_prog_ = bpf_object__find_program_by_name(file_monitor_obj_, "trace_openat");
                if (file_monitor_prog_) {
                    file_monitor_fd_ = bpf_program__fd(file_monitor_prog_);
                    any_loaded = true;
                    std::cout << "  ✓ File monitor loaded (trace_openat)" << std::endl;
                } else {
                    std::cerr << "  ✗ Could not find trace_openat program" << std::endl;
                }
            } else {
                std::cerr << "  ✗ Failed to load file monitor object: " << strerror(errno) << std::endl;
                bpf_object__close(file_monitor_obj_);
                file_monitor_obj_ = nullptr;
            }
        } else {
            std::cerr << "  ✗ Failed to open file monitor: " << strerror(errno) << std::endl;
        }
    }
    
    // Load process monitor
    if (access(bpf_paths[1], F_OK) == 0) {
        process_monitor_obj_ = bpf_object__open(bpf_paths[1]);
        if (process_monitor_obj_) {
            if (bpf_object__load(process_monitor_obj_) == 0) {
                // Find the program by its actual name: trace_execve
                process_monitor_prog_ = bpf_object__find_program_by_name(process_monitor_obj_, "trace_execve");
                if (process_monitor_prog_) {
                    process_monitor_fd_ = bpf_program__fd(process_monitor_prog_);
                    any_loaded = true;
                    std::cout << "  ✓ Process monitor loaded (trace_execve)" << std::endl;
                } else {
                    std::cerr << "  ✗ Could not find trace_execve program" << std::endl;
                }
            } else {
                std::cerr << "  ✗ Failed to load process monitor object: " << strerror(errno) << std::endl;
                bpf_object__close(process_monitor_obj_);
                process_monitor_obj_ = nullptr;
            }
        } else {
            std::cerr << "  ✗ Failed to open process monitor: " << strerror(errno) << std::endl;
        }
    }
    
    // Load network monitor
    if (access(bpf_paths[2], F_OK) == 0) {
        network_monitor_obj_ = bpf_object__open(bpf_paths[2]);
        if (network_monitor_obj_) {
            if (bpf_object__load(network_monitor_obj_) == 0) {
                // Find the program by its actual name: trace_tcp_connect
                network_monitor_prog_ = bpf_object__find_program_by_name(network_monitor_obj_, "trace_tcp_connect");
                if (network_monitor_prog_) {
                    network_monitor_fd_ = bpf_program__fd(network_monitor_prog_);
                    any_loaded = true;
                    std::cout << "  ✓ Network monitor loaded (trace_tcp_connect)" << std::endl;
                } else {
                    std::cerr << "  ✗ Could not find trace_tcp_connect program" << std::endl;
                }
            } else {
                std::cerr << "  ✗ Failed to load network monitor object: " << strerror(errno) << std::endl;
                bpf_object__close(network_monitor_obj_);
                network_monitor_obj_ = nullptr;
            }
        } else {
            std::cerr << "  ✗ Failed to open network monitor: " << strerror(errno) << std::endl;
        }
    }
    
    return any_loaded;
}

bool KoraAVDaemon::AttacheBPFProbes() {
    // Attach loaded programs to kernel hooks
    // Note: Programs auto-attach based on SEC() declarations, but we can also manually attach
    bool any_attached = false;
    
    if (file_monitor_prog_) {
        // Program is SEC("tracepoint/syscalls/sys_enter_openat")
        // It will auto-attach, but we can get the link for tracking
        file_monitor_link_ = bpf_program__attach(file_monitor_prog_);
        
        if (file_monitor_link_) {
            std::cout << "  ✓ File monitor attached to sys_enter_openat" << std::endl;
            any_attached = true;
        } else {
            std::cerr << "  ✗ Failed to attach file monitor: " << strerror(errno) << std::endl;
        }
    }
    
    if (process_monitor_prog_) {
        // Program is SEC("tracepoint/syscalls/sys_enter_execve")
        process_monitor_link_ = bpf_program__attach(process_monitor_prog_);
        
        if (process_monitor_link_) {
            std::cout << "  ✓ Process monitor attached to sys_enter_execve" << std::endl;
            any_attached = true;
        } else {
            std::cerr << "  ✗ Failed to attach process monitor: " << strerror(errno) << std::endl;
        }
    }
    
    if (network_monitor_prog_) {
        // Program is SEC("kprobe/tcp_connect")
        network_monitor_link_ = bpf_program__attach(network_monitor_prog_);
        
        if (network_monitor_link_) {
            std::cout << "  ✓ Network monitor attached to tcp_connect" << std::endl;
            any_attached = true;
        } else {
            std::cerr << "  ✗ Failed to attach network monitor: " << strerror(errno) << std::endl;
        }
    }
    
    if (!any_attached) {
        std::cerr << "Warning: No eBPF programs were successfully attached" << std::endl;
        std::cerr << "Real-time monitoring may not function correctly" << std::endl;
        return false;
    }
    
    // Create ring buffers for event communication
    std::cout << "\nCreating ring buffers for event processing..." << std::endl;
    
    // Process events ring buffer (for ClickFix detection)
    if (process_monitor_obj_) {
        struct bpf_map* process_events_map = bpf_object__find_map_by_name(process_monitor_obj_, "process_events");
        if (process_events_map) {
            int map_fd = bpf_map__fd(process_events_map);
            if (map_fd >= 0) {
                // Callback is already defined in ProcessProcessEvents(), just create the ring buffer
                // The actual callback will be used when polling
                process_events_ringbuf_ = (void*)1;  // Mark as available (will be created in ProcessProcessEvents)
                std::cout << "  ✓ Process events ring buffer ready (ClickFix enabled)" << std::endl;
            }
        }
    }
    
    // Network events ring buffer (for C2 detection)
    if (network_monitor_obj_) {
        struct bpf_map* network_events_map = bpf_object__find_map_by_name(network_monitor_obj_, "network_events");
        if (network_events_map) {
            int map_fd = bpf_map__fd(network_events_map);
            if (map_fd >= 0) {
                network_events_ringbuf_ = (void*)1;  // Mark as available
                std::cout << "  ✓ Network events ring buffer ready (C2 detection enabled)" << std::endl;
            }
        }
    }
    
    // File events ring buffer
    if (file_monitor_obj_) {
        struct bpf_map* file_events_map = bpf_object__find_map_by_name(file_monitor_obj_, "file_events");
        if (file_events_map) {
            int map_fd = bpf_map__fd(file_events_map);
            if (map_fd >= 0) {
                file_events_ringbuf_ = (void*)1;  // Mark as available
                std::cout << "  ✓ File events ring buffer ready" << std::endl;
            }
        }
    }
    
    return true;
}



bool KoraAVDaemon::IsSensitiveFile(const std::string& path) {
    // Check for sensitive file patterns AND directories
    // IMPORTANT: Match directory patterns too, not just specific files,
    // because eBPF events often report directory paths (e.g. ~/.ssh/)
    static const std::vector<std::string> sensitive_patterns = {
        // SSH keys (directory AND specific files)
        "/.ssh/",
        "/id_rsa",
        "/id_ed25519",
        "/id_ecdsa",
        "/authorized_keys",

        // GPG keys
        "/.gnupg/",
        "/secring.gpg",
        "/private-keys",

        // Browser data
        "/.mozilla/",
        "/google-chrome/",
        "/chromium/",
        "/BraveSoftware/",
        "/Library/Application Support/Google/Chrome/",
        "/Library/Application Support/Firefox/",

        // Crypto wallets
        "/wallet",
        "/.bitcoin/",
        "/.ethereum/",
        "/.metamask/",
        "/Electrum/",

        // Password managers
        "/.password-store/",
        "/KeePass/",
        "/1Password/",

        // AWS/Docker/Kube credentials
        "/.aws/",
        "/.docker/",
        "/.kube/",

        // Database credentials
        "/.my.cnf",
        "/.pgpass",

        // Environment files
        "/.env",

        // Documents, Downloads, and Pictures
        "/Documents/",
        "/Downloads/",
        "/Pictures",

        // Common credential files
        "/credentials",
        "/secrets",
        "/token",
        "/auth.json",
        "/passwords",
        "/cookies",
        "/login",
        "/etc/passwd",
        "/etc/shadow"
    };

    // Convert to lowercase for case-insensitive matching
    std::string lower_path = path;
    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);

    // Check if path contains any sensitive patterns
    for (const auto& pattern : sensitive_patterns) {
        if (lower_path.find(pattern) != std::string::npos) {
            return true;
        }
    }

    return false;
}



// ─────────────────────────────────────────────────────────────────────────────
// FILE EVENT PROCESSING
// Split into two parts:
//   1. ProcessFileEvents()     - Fast poller, just pushes raw events to queue
//   2. AnalyzeFileEvents()     - Consumer, does heavy detection work
// ─────────────────────────────────────────────────────────────────────────────

static EventQueue<FileEventData> g_file_event_queue;

void KoraAVDaemon::ProcessFileEvents() {
    std::cout << "File event processor started" << std::endl;

    if (!file_events_ringbuf_) {
        std::cout << "File events ring buffer not available, skipping" << std::endl;
        return;
    }

    struct bpf_map* map = bpf_object__find_map_by_name(file_monitor_obj_, "file_events");
    if (!map) { std::cerr << "Failed to find file_events map" << std::endl; return; }

    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) { std::cerr << "Failed to get file_events map FD" << std::endl; return; }

    // FAST callback - just copy event to queue and return immediately
    // NO heavy processing here, that's done in AnalyzeFileEvents()
    auto callback = [](void* ctx, void* data, size_t data_sz) -> int {
        if (data_sz < sizeof(FileEventData)) return 0;

        auto* daemon = static_cast<KoraAVDaemon*>(ctx);
        FileEventData evt;
        memcpy(&evt, data, sizeof(FileEventData));
        daemon->file_events_received_++;
        g_file_event_queue.Push(evt);
        return 0;
    };

    struct ring_buffer* rb = ring_buffer__new(map_fd, callback, this, nullptr);
    if (!rb) { std::cerr << "Failed to create file ring buffer" << std::endl; return; }

    std::cout << "✓ File events ring buffer polling started (InfoStealer detection active)" << std::endl;

    // Poll loop - just drains the ring buffer into the queue
    while (running_) {
        ring_buffer__poll(rb, 100);  // 100ms timeout
    }

    ring_buffer__free(rb);
    g_file_event_queue.Stop();
    std::cout << "File event processor stopped" << std::endl;
}

void KoraAVDaemon::AnalyzeFileEvents() {
    FileEventData evt;
    static int event_count = 0;
    
    while (running_ || !g_file_event_queue.Empty()) {
        if (!g_file_event_queue.Pop(evt, 200)) continue;

        std::string filename(evt.filename, strnlen(evt.filename, sizeof(evt.filename)));
        std::string proc_name(evt.comm, strnlen(evt.comm, sizeof(evt.comm)));

        if (filename.empty() || evt.tgid == 0) continue;

        // DEBUG: Log first 20 events to see what's happening
        if (++event_count <= 20) {
            std::cout << "[DEBUG AnalyzeFile " << event_count << "] File: " << filename 
                      << " | PID: " << evt.tgid << " | Proc: " << proc_name << std::endl;
        }


        if (snapshot_system_) {
            std::string process_name = GetProcessName(evt.tgid);
            std::string command = GetProcessCommandLine(evt.tgid);

            if (snapshot_system_->IsSnapshotDeletionAttempt(command)) {
                std::cout << "🚨 SNAPSHOT DELETION ATTEMPT DETECTED!" << std::endl;
                std::cout << "   Process: " << process_name << " (PID " << evt.tgid << ")" << std::endl;
                std::cout << "   Command: " << command << std::endl;

                // INSTANT KILL
                KillProcess(evt.tgid);
                if (quarantine_manager_) {
                    quarantine_manager_->QuarantineProcess(evt.tgid, "SNAPSHOT_DELETION_ATTEMPT");
                }

                // Alert
                if (notification_manager_) {
                    notification_manager_->SendThreatAlert(
                        "SNAPSHOT_DELETION_ATTEMPT",
                        process_name,
                        evt.tgid,
                        100,  // Max score
                        {"Attempt to delete ransomware protection snapshots detected."}
                    );
                }
            }
        }


        // ═══════════════════════════════════════════════════════════
        // CHECK CANARY FILES (Instant Trigger)
        // ═══════════════════════════════════════════════════════════
        
        if (canary_system_ && canary_system_->IsCanaryFile(filename)) {
            std::cout << "🚨 CANARY FILE TRIGGERED!" << std::endl;
            std::cout << "   File: " << filename << std::endl;
            std::cout << "   Process: " << proc_name << " (PID " << evt.tgid << ")" << std::endl;
            
            // INSTANT KILL - No scoring, no delay
            KillProcess(evt.tgid);
            
            // Quarantine
            if (quarantine_manager_) {
                quarantine_manager_->QuarantineProcess(evt.tgid, "CANARY_FILE_TRIGGERED");
            }
            
            // Rollback filesystem
            if (snapshot_system_) {
                std::cout << "🔄 Rolling back filesystem..." << std::endl;
                if (snapshot_system_->RollbackToLatestSnapshot()) {
                    std::cout << "✅ Filesystem rolled back successfully!" << std::endl;
                }
            }
            
            // Alert
            if (notification_manager_) {
                notification_manager_->SendThreatAlert(
                    "CANARY_FILE_TRIGGERED",
                    proc_name,
                    evt.tgid,
                    100,  // Max score
                    {"Hidden canary file accessed - ransomware detected instantly"}
                );
            }
            
            threats_detected_++;
            continue;  // Skip further processing
        }



        // ═══════════════════════════════════════════════════════════
        // YARA SIGNATURE SCAN (On Download/Write)
        // ═══════════════════════════════════════════════════════════

        if (yara_manager_ && config_.yara_scan_on_download) {
            // Check if this is a newly written file (download scenario)
            // We can scan on close() events or completed writes

            std::vector<std::string> yara_matches = yara_manager_->ScanFile(filename);
            if (!yara_matches.empty()) {
                std::cout << "🚨 YARA DETECTION!" << std::endl;
                std::cout << "   File: " << filename << std::endl;
                std::cout << "   Matches: " << yara_matches.size() << std::endl;

                for (const auto& match : yara_matches) {
                    std::cout << "   - " << match << std::endl;
                }

                // Kill process
                KillProcess(evt.tgid);

                // Quarantine
                if (quarantine_manager_) {
                    quarantine_manager_->QuarantineFile(filename, "YARA:" + yara_matches[0]);
                }

                // Alert
                if (notification_manager_) {
                    notification_manager_->SendThreatAlert(
                        "YARA_DETECTION",
                        proc_name,
                        evt.tgid,
                        100,  // Signature match = definite malware
                        yara_matches
                    );
                }

                threats_detected_++;
                continue;  // Skip further processing
            }
        }


        //Ransomware
        bool is_sensitive = IsSensitiveFile(filename);
        if (ransomware_detector_ && is_sensitive) {
            // Track for ransomware detection
            ransomware_detector_->TrackFileOperation(evt.tgid, filename, "write");
            int score = ransomware_detector_->AnalyzeProcess(evt.tgid);

            // If ransomware detected
            if (score >= config_.block_threshold) {
                auto indicators = ransomware_detector_->GetThreatIndicators(evt.tgid);

                // Handle threat (kill, quarantine, rollback)
                threats_detected_++;
                HandleThreat(evt.tgid, "Ransomware", score, indicators);
            }
        }



        
        if (event_count <= 20) {
            std::cout << "[DEBUG] IsSensitiveFile(" << filename << ") = " 
                      << (is_sensitive ? "TRUE" : "FALSE") << std::endl;
        }
        
        if (infostealer_detector_ && is_sensitive) {
            if (event_count <= 20) {
                std::cout << "[DEBUG] ✓ Tracking file access for PID " << evt.tgid << std::endl;
            }
            
            infostealer_detector_->TrackFileAccess(evt.tgid, filename);
            int score = infostealer_detector_->AnalyzeProcess(evt.tgid);

            if (event_count <= 20 || score > 0) {
                std::cout << "[DEBUG] InfoStealer score for PID " << evt.tgid << ": " << score
                          << " (threshold: " << config_.alert_threshold << ")" << std::endl;
            }

            if (score >= config_.alert_threshold) {
                auto indicators = infostealer_detector_->GetThreatIndicators(evt.tgid);
                threats_detected_++;
                HandleThreat(evt.tgid, "InfoStealer", score, indicators);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROCESS EVENT PROCESSING
// ─────────────────────────────────────────────────────────────────────────────

static EventQueue<ProcessEventData> g_process_event_queue;

void KoraAVDaemon::ProcessProcessEvents() {
    std::cout << "Process event processor started" << std::endl;

    if (!process_events_ringbuf_) {
        std::cout << "Process events ring buffer not available, skipping" << std::endl;
        return;
    }

    struct bpf_map* map = bpf_object__find_map_by_name(process_monitor_obj_, "process_events");
    if (!map) { std::cerr << "Failed to find process_events map" << std::endl; return; }

    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) { std::cerr << "Failed to get process_events map FD" << std::endl; return; }

    // FAST callback - just copy to queue
    auto callback = [](void* ctx, void* data, size_t data_sz) -> int {
        if (data_sz < sizeof(ProcessEventData)) return 0;

        auto* daemon = static_cast<KoraAVDaemon*>(ctx);
        ProcessEventData evt;
        memcpy(&evt, data, sizeof(ProcessEventData));
        daemon->process_events_received_++;
        g_process_event_queue.Push(evt);
        return 0;
    };

    struct ring_buffer* rb = ring_buffer__new(map_fd, callback, this, nullptr);
    if (!rb) { std::cerr << "Failed to create process ring buffer" << std::endl; return; }

    std::cout << "✓ Process events ring buffer polling started (ClickFix active)" << std::endl;

    while (running_) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);
    g_process_event_queue.Stop();
    std::cout << "Process event processor stopped" << std::endl;
}

void KoraAVDaemon::AnalyzeProcessEvents() {
    ProcessEventData evt;
    while (running_ || !g_process_event_queue.Empty()) {
        if (!g_process_event_queue.Pop(evt, 200)) continue;

        if (evt.tgid == 0) continue;

        // Read full cmdline from /proc (OK to do here in analysis thread)
        std::string cmdline = GetProcessCommandLine(evt.tgid);
        std::string proc_name(evt.comm, strnlen(evt.comm, sizeof(evt.comm)));

        if (cmdline.empty() && proc_name.empty()) continue;

        // ClickFix analysis
        if (clickfix_detector_) {
            std::string to_analyze = cmdline.empty() ? proc_name : cmdline;
            int score = clickfix_detector_->AnalyzeCommand(to_analyze, proc_name);

            if (score >= 50) {
                auto indicators = clickfix_detector_->GetThreatIndicators(to_analyze);
                std::cout << "🚨 ClickFix detected malicious command: "
                    << proc_name << " → " << to_analyze
                    << " (score: " << score << ")" << std::endl;
                threats_detected_++;
                HandleThreat(evt.tgid, "ClickFix", score, indicators);
            }
        }
        // ═══════════════════════════════════════════════════════════
        // YARA SCAN ON EXECUTION
        // ═══════════════════════════════════════════════════════════

        if (yara_manager_ && config_.yara_scan_on_execution) {
            std::string exe_path = "/proc/" + std::to_string(evt.tgid) + "/exe";
            char real_path[PATH_MAX];
            ssize_t len = readlink(exe_path.c_str(), real_path, sizeof(real_path) - 1);

            if (len != -1) {
                real_path[len] = '\0';
                std::string executable(real_path);

                bool should_scan = true;
                bool cached_malware = false;

                // CHECK CACHE
                {
                    std::lock_guard<std::mutex> lock(yara_cache_mutex);

                    auto it = yara_scan_cache.find(executable);
                    if (it != yara_scan_cache.end()) {
                        // Cache entry exists - verify file hasn't changed
                        struct stat st;
                        if (stat(executable.c_str(), &st) == 0) {
                            // Check if file was modified since last scan
                            if (it->second.mtime == st.st_mtime &&
                                it->second.inode == st.st_ino) {
                                // File unchanged - trust cache
                                should_scan = false;

                                if (!it->second.is_clean) {
                                    // Cache says it's malware - treat as fresh detection
                                    cached_malware = true;
                                }
                            // else: it's clean, skip scanning entirely
                            } else {
                                // File modified - invalidate cache entry
                                yara_scan_cache.erase(it);
                                should_scan = true;
                            }

                        } else {
                            // Can't stat file - invalidate cache and rescan
                            yara_scan_cache.erase(it);
                            should_scan = true;
                        }
                    }
                    // else: not in cache, must scan
                }

                // ─────────────────────────────────────────────────────────
                // HANDLE CACHED MALWARE (no need to re-scan)
                // ─────────────────────────────────────────────────────────
                if (cached_malware) {
                    std::cout << "🚨 YARA DETECTION (CACHED)!" << std::endl;
                    std::cout << "   Binary: " << executable << std::endl;
                    std::cout << "   PID: " << evt.tgid << std::endl;
                    std::cout << "   [Previously detected malware re-executed]" << std::endl;

                    KillProcess(evt.tgid);

                    if (quarantine_manager_) {
                        quarantine_manager_->QuarantineFile(executable, "YARA:CACHED_MALWARE");
                    }

                    if (notification_manager_) {
                        notification_manager_->SendThreatAlert(
                            "YARA_EXECUTION_BLOCKED",
                            executable,
                            evt.tgid,
                            100,
                            {"Previously detected malware re-executed"}
                        );
                    }

                    threats_detected_++;
                    continue;
                }

                // ─────────────────────────────────────────────────────────
                // SCAN FILE (cache miss or invalidated)
                // ─────────────────────────────────────────────────────────
                if (should_scan) {
                    std::vector<std::string> yara_matches = yara_manager_->ScanFile(executable);
                    bool is_clean = yara_matches.empty();

                    // ─────────────────────────────────────────────────
                    // UPDATE CACHE
                    // ─────────────────────────────────────────────────
                    {
                        std::lock_guard<std::mutex> lock(yara_cache_mutex);

                        // Cache size limit - implement LRU eviction
                        if (yara_scan_cache.size() >= MAX_YARA_CACHE_SIZE) {
                            // Find oldest cache entry
                            auto oldest = yara_scan_cache.begin();
                            for (auto it = yara_scan_cache.begin(); it != yara_scan_cache.end(); ++it) {
                                if (it->second.cached_at < oldest->second.cached_at) {
                                    oldest = it;
                                }
                            }
                            yara_scan_cache.erase(oldest);
                        }

                        // Add/update cache entry
                        struct stat st;
                        if (stat(executable.c_str(), &st) == 0) {
                            yara_scan_cache[executable] = {
                                st.st_mtime,
                                st.st_ino,
                                is_clean,
                                std::chrono::steady_clock::now()
                            };
                        }
                    }

                    // ─────────────────────────────────────────────────
                    // HANDLE MALWARE DETECTION
                    // ─────────────────────────────────────────────────
                    if (!is_clean) {
                        std::cout << "🚨 YARA DETECTION ON EXECUTION!" << std::endl;
                        std::cout << "   Binary: " << executable << std::endl;
                        std::cout << "   PID: " << evt.tgid << std::endl;
                        std::cout << "   Matches: " << yara_matches.size() << std::endl;

                        for (const auto& match : yara_matches) {
                            std::cout << "   - " << match << std::endl;
                        }

                        KillProcess(evt.tgid);

                        if (quarantine_manager_) {
                            quarantine_manager_->QuarantineFile(executable, "YARA:" + yara_matches[0]);
                        }

                        if (notification_manager_) {
                            notification_manager_->SendThreatAlert(
                                "YARA_EXECUTION_BLOCKED",
                                executable,
                                evt.tgid,
                                100,
                                yara_matches
                            );
                        }

                        threats_detected_++;
                        continue;
                    }
                    // else: is_clean = true, cached for future, continue to next event

                }
                // else: should_scan = false (clean cache hit), continue to next event
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NETWORK EVENT PROCESSING
// ─────────────────────────────────────────────────────────────────────────────

static EventQueue<NetworkEventData> g_network_event_queue;

void KoraAVDaemon::ProcessNetworkEvents() {
    std::cout << "Network event processor started" << std::endl;

    if (!network_events_ringbuf_) {
        std::cout << "Network events ring buffer not available, skipping" << std::endl;
        return;
    }

    struct bpf_map* map = bpf_object__find_map_by_name(network_monitor_obj_, "network_events");
    if (!map) { std::cerr << "Failed to find network_events map" << std::endl; return; }

    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) { std::cerr << "Failed to get network_events map FD" << std::endl; return; }

    // FAST callback - just copy to queue
    auto callback = [](void* ctx, void* data, size_t data_sz) -> int {
        if (data_sz < sizeof(NetworkEventData)) return 0;

        auto* daemon = static_cast<KoraAVDaemon*>(ctx);
        NetworkEventData evt;
        memcpy(&evt, data, sizeof(NetworkEventData));
        daemon->network_events_received_++;
        g_network_event_queue.Push(evt);
        return 0;
    };

    struct ring_buffer* rb = ring_buffer__new(map_fd, callback, this, nullptr);
    if (!rb) { std::cerr << "Failed to create network ring buffer" << std::endl; return; }

    std::cout << "✓ Network events ring buffer polling started (C2 detection active)" << std::endl;

    while (running_) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);
    g_network_event_queue.Stop();
    std::cout << "Network event processor stopped" << std::endl;
}

void KoraAVDaemon::AnalyzeNetworkEvents() {
    NetworkEventData evt;
    while (running_ || !g_network_event_queue.Empty()) {
        if (!g_network_event_queue.Pop(evt, 200)) continue;

        if (evt.tgid == 0 || evt.daddr == 0) continue;

        // C2 analysis
        if (c2_detector_) {
            c2_detector_->TrackConnection(evt.tgid, evt.daddr, evt.dport);
            int score = c2_detector_->AnalyzeProcess(evt.tgid);

            if (score >= config_.alert_threshold) {
                auto indicators = c2_detector_->GetThreatIndicators(evt.tgid);
                threats_detected_++;
                HandleThreat(evt.tgid, "C2_Communication", score, indicators);
            }
        }

        // InfoStealer exfil tracking
        if (infostealer_detector_) {
            infostealer_detector_->TrackNetworkConnection(evt.tgid, evt.daddr, evt.dport);

            int score = infostealer_detector_->AnalyzeProcess(evt.tgid);

            if (score >= config_.alert_threshold) {
                auto indicators = infostealer_detector_->GetThreatIndicators(evt.tgid);
                threats_detected_++;
                HandleThreat(evt.tgid, "InfoStealer", score, indicators);
            }
        }
    }
}

void KoraAVDaemon::RunPeriodicAnalysis() {
    std::cout << "Periodic analysis thread started" << std::endl;

    int tick = 0;

    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        tick++;

        // ── Status report every 60 seconds ──────────────────────────────────
        if (tick % 12 == 0) {
            std::lock_guard<std::mutex> lock(yara_cache_mutex);
            std::cout << "  YARA Cache: " << yara_scan_cache.size() << " entries" << std::endl;
            std::cout << "\n📊 [Status] Events received — "
                      << "File: " << file_events_received_.load()
                      << "  Process: " << process_events_received_.load()
                      << "  Network: " << network_events_received_.load()
                      << "  Threats: " << threats_detected_.load()
                      << std::endl;
            CleanupExpiredThreats();
        }

        // ── Ransomware: check confirmed threats ──────────────────────────────
        // if (ransomware_detector_) {
        //     auto suspicious = ransomware_detector_->GetSuspiciousProcesses();
        //     for (const auto& proc : suspicious) {
        //         if (proc.is_confirmed_ransomware) {
        //             std::vector<std::string> indicators;
        //             for (const auto& file : proc.targeted_files) {
        //                 indicators.push_back("Encrypted: " + file);
        //             }
        //             int score = std::min(100, 60 + proc.encryption_attempts * 10
        //                                       + (proc.files_targeted >= 5 ? 25 : 0));
        //             threats_detected_++;
        //             HandleThreat(proc.pid, "Ransomware", score, indicators);
        //         }
        //     }
        // }

        // ── InfoStealer: check accumulated scores ────────────────────────────
        if (infostealer_detector_) {
            auto suspicious_pids = infostealer_detector_->GetSuspiciousProcesses(70);
            for (const auto& tgid : suspicious_pids) {
                int score = infostealer_detector_->AnalyzeProcess(tgid);
                if (score >= config_.block_threshold) {
                    auto indicators = infostealer_detector_->GetThreatIndicators(tgid);
                    threats_detected_++;
                    HandleThreat(tgid, "InfoStealer", score, indicators);
                }
            }
        }

        // ── C2: check accumulated scores ─────────────────────────────────────
        if (c2_detector_) {
            auto suspicious_pids = c2_detector_->GetSuspiciousProcesses(70);
            for (const auto& tgid : suspicious_pids) {
                int score = c2_detector_->AnalyzeProcess(tgid);
                if (score >= config_.alert_threshold) {
                    auto indicators = c2_detector_->GetThreatIndicators(tgid);
                    threats_detected_++;
                    HandleThreat(tgid, "C2_Communication", score, indicators);
                }
            }
        }
    }

    std::cout << "Periodic analysis thread stopped" << std::endl;
}

void KoraAVDaemon::HandleThreat(uint32_t tgid, const std::string& threat_type,
                                int score, const std::vector<std::string>& indicators) {

    // Check if already handled (deduplication)
    if (IsThreatAlreadyHandled(tgid, threat_type)) {
        return;
    }

    MarkThreatHandled(tgid, threat_type, score);

    // Log the threat first
    LogThreat(tgid, threat_type, score, indicators);

    // Get process info for notification
    std::string process_name = GetProcessName(tgid);
    std::string process_cmd = GetProcessCommandLine(tgid);

    // Send desktop notification FIRST (before console output)
    if (notification_manager_) {
        notification_manager_->SendThreatAlert(threat_type, process_name, tgid, score, indicators);
    }

    // Display threat notification (console)
    std::cout << "\n";
    std::cout << "═══════════════════════════════════════════════════════════" << std::endl;
    std::cout << "🚨 THREAT DETECTED!" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════" << std::endl;
    std::cout << "Type:         " << threat_type << std::endl;
    std::cout << "Threat Score: " << score << "/100" << std::endl;
    std::cout << "Process:      " << process_name << " (PID " << tgid << ")" << std::endl;
    if (!process_cmd.empty()) {
        std::cout << "Command:      " << process_cmd << std::endl;
    }
    std::cout << "\nIndicators:" << std::endl;
    for (const auto& indicator : indicators) {
        std::cout << "  • " << indicator << std::endl;
    }
    std::cout << "───────────────────────────────────────────────────────────" << std::endl;

    // ═══════════════════════════════════════════════════════════
    // RESPONSE DETERMINATION (Score-based + Threat-specific)
    // ═══════════════════════════════════════════════════════════

    // CRITICAL THREAT (≥96) - Most aggressive response
    if (score >= config_.lockdown_threshold && config_.auto_lockdown) {
        std::cout << "⚠️  CRITICAL THREAT (Score ≥" << config_.lockdown_threshold << ")" << std::endl;
        std::cout << "Action:       SYSTEM LOCKDOWN" << std::endl;
        std::cout << "═══════════════════════════════════════════════════════════\n" << std::endl;

        // Kill process first
        if (config_.auto_kill) {
            KillProcess(tgid);
        }

        // Quarantine
        if (config_.auto_quarantine && quarantine_manager_) {
            std::string quarantine_path = quarantine_manager_->QuarantineProcess(tgid, threat_type);
            if (!quarantine_path.empty()) {
                std::cout << "✓ Malware quarantined to: " << quarantine_path << std::endl;
                if (notification_manager_) {
                    notification_manager_->SendQuarantineNotification(threat_type, process_name, quarantine_path);
                }
            }
        }

        // System lockdown (OPTIONAL - user must enable)
        LockdownSystem();

        if (notification_manager_) {
            notification_manager_->SendLockdownNotification();
        }
    }

    // HIGH THREAT (≥81) - Kill + Quarantine + Situational Network Block
    else if (score >= config_.block_threshold) {
        std::cout << "⚠️  HIGH THREAT (Score ≥" << config_.block_threshold << ")" << std::endl;
        std::cout << "Action:       KILL + QUARANTINE";

        // Kill process
        if (config_.auto_kill) {
            KillProcess(tgid);
        }

        // Quarantine
        if (config_.auto_quarantine && quarantine_manager_) {
            std::string quarantine_path = quarantine_manager_->QuarantineProcess(tgid, threat_type);
            if (!quarantine_path.empty()) {
                std::cout << " + QUARANTINED" << std::endl;
                if (notification_manager_) {
                    notification_manager_->SendQuarantineNotification(threat_type, process_name, quarantine_path);
                }
            } else {
                std::cout << std::endl;
            }
        } else {
            std::cout << std::endl;
        }

        // ═══════════════════════════════════════════════════════════
        // ROLLBACK FILESYSTEM FOR RANSOMWARE
        // ═══════════════════════════════════════════════════════════
        if (threat_type == "Ransomware" && snapshot_system_) {
            std::cout << "🔄 Initiating filesystem rollback..." << std::endl;

            bool rolled_back = snapshot_system_->RollbackToLatestSnapshot();

            if (rolled_back) {
                std::cout << "✅ Filesystem rolled back successfully!" << std::endl;
                std::cout << "   Max data loss: 5 minutes" << std::endl;
                
                // Alert about rollback
                if (notification_manager_) {
                    notification_manager_->SendThreatAlert(
                        "FILESYSTEM_ROLLBACK",
                        process_name,
                        tgid,
                        score,
                        {"Filesystem rolled back to latest snapshot", "Max 5 minutes of data loss"}
                    );
                }
            } else {
                std::cerr << "❌ Rollback failed - :(" << std::endl;
            }
        }


        // ═══════════════════════════════════════════════════════════
        // SITUATIONAL NETWORK BLOCKING
        // ═══════════════════════════════════════════════════════════
        bool should_block_network = false;
        if (threat_type == "InfoStealer" && config_.auto_block_network_infostealer) {
            // Check if process has active network connections
            if (HasActiveNetworkConnections(tgid)) {
                should_block_network = true;
                std::cout << "  → Network blocked: Active exfiltration detected" << std::endl;
            }
        }
        else if (threat_type == "C2_Communication" && config_.auto_block_network_c2) {
            should_block_network = true;
            std::cout << "  → Network blocked: C2 communication detected" << std::endl;
        }
        else if (threat_type == "ClickFix" && config_.auto_block_network_clickfix) {
            should_block_network = true;
            std::cout << "  → Network blocked: ClickFix attack" << std::endl;
        }
        else if (threat_type == "Ransomware" && config_.auto_block_network_ransomware) {
            // Usually false - ransomware is already killed
            should_block_network = true;
            std::cout << "  → Network blocked: Ransomware" << std::endl;
        }

        if (should_block_network) {
            BlockProcessNetwork(tgid);
        }

        std::cout << "═══════════════════════════════════════════════════════════\n" << std::endl;
    }

    // SUSPICIOUS ACTIVITY (≥61) - Alert Only
    else if (score >= config_.alert_threshold) {
        std::cout << "⚠️  SUSPICIOUS ACTIVITY (Score ≥" << config_.alert_threshold << ")" << std::endl;
        std::cout << "Action:       MONITORING (no action taken)" << std::endl;
        std::cout << "═══════════════════════════════════════════════════════════\n" << std::endl;
    }
}

// Helper function to check for active network connections
bool KoraAVDaemon::HasActiveNetworkConnections(uint32_t tgid) {
    // Check /proc/[pid]/net/tcp for established connections
    std::string tcp_path = "/proc/" + std::to_string(tgid) + "/net/tcp";
    std::ifstream tcp_file(tcp_path);

    if (!tcp_file) {
        return false;
    }

    std::string line;
    std::getline(tcp_file, line);  // Skip header

    while (std::getline(tcp_file, line)) {
        // Check if connection state is ESTABLISHED (01)
        if (line.find(" 01 ") != std::string::npos) {
            return true;
        }
    }

    return false;
}

void KoraAVDaemon::KillProcess(uint32_t tgid) {
    std::cout << "  → Killing malicious process PID " << tgid << " (" << GetProcessName(tgid) << ")" << std::endl;
    kill(tgid, SIGKILL);
}

void KoraAVDaemon::BlockProcessNetwork(uint32_t tgid) {
    std::cout << "  → Blocking network for PID " << tgid << std::endl;
    
    // Use nftables to block process
    std::string cmd = "nft add rule inet filter output meta skuid " + std::to_string(tgid) + " drop 2>/dev/null";
    system(cmd.c_str());
    
    // Fallback to iptables
    cmd = "iptables -A OUTPUT -m owner --pid-owner " + std::to_string(tgid) + " -j DROP 2>/dev/null";
    system(cmd.c_str());
}

void KoraAVDaemon::LockdownSystem() {
    std::cout << "🔒 SYSTEM LOCKDOWN INITIATED" << std::endl;
    
    // Remount filesystem read-only
    std::cout << "  → Remounting filesystem read-only..." << std::endl;
    system("mount -o remount,ro / 2>/dev/null");
    
    // Block all network (except localhost)
    std::cout << "  → Blocking network traffic..." << std::endl;
    system("nft add table inet lockdown 2>/dev/null");
    system("nft add chain inet lockdown output { type filter hook output priority 0 \\; } 2>/dev/null");
    system("nft add rule inet lockdown output oif lo accept 2>/dev/null");
    system("nft add rule inet lockdown output drop 2>/dev/null");
    
    std::cout << "🔒 SYSTEM LOCKED - Use 'koraav unlock --all' to restore" << std::endl;
}

void KoraAVDaemon::LogThreat(uint32_t tgid, const std::string& threat_type,
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
    log << "PID=" << tgid << " ";
    log << "Type=" << threat_type << " ";
    log << "Score=" << score << " ";
    log << "Process=" << GetProcessName(tgid) << " ";
    log << "CMD=" << GetProcessCommandLine(tgid) << " ";
    log << "Indicators: ";
    for (const auto& ind : indicators) {
        log << ind << "; ";
    }
    log << std::endl;
}

std::string KoraAVDaemon::GetProcessName(uint32_t tgid) {
    std::string comm_path = "/proc/" + std::to_string(tgid) + "/comm";
    std::ifstream file(comm_path);
    std::string name;
    if (file) {
        std::getline(file, name);
    }
    return name.empty() ? "unknown" : name;
}

std::string KoraAVDaemon::GetProcessCommandLine(uint32_t tgid) {
    std::string cmdline_path = "/proc/" + std::to_string(tgid) + "/cmdline";
    std::ifstream file(cmdline_path);
    std::string cmdline;
    if (file) {
        std::getline(file, cmdline, '\0');
    }
    return cmdline.empty() ? "" : cmdline;
}



bool KoraAVDaemon::IsThreatAlreadyHandled(uint32_t tgid, const std::string& threat_type) {
    std::lock_guard<std::mutex> lock(reported_threat_mutex_);
    uint64_t starttime = GetProcessStartTime(tgid);
    std::string key = std::to_string(tgid) + ":" + threat_type + ":" + std::to_string(starttime);
    return reported_threats_.find(key) != reported_threats_.end();
}

void KoraAVDaemon::MarkThreatHandled(uint32_t tgid, const std::string& threat_type, int score) {
    std::lock_guard<std::mutex> lock(reported_threat_mutex_);
    uint64_t starttime = GetProcessStartTime(tgid);
    std::string key = std::to_string(tgid) + ":" + threat_type + ":" + std::to_string(starttime);
    auto it = reported_threats_.find(key);
    if (it != reported_threats_.end()) {
        it->second.last_score = std::max(it->second.last_score, score);
        it->second.last_seen = std::chrono::steady_clock::now();
    } else {
        reported_threats_[key] = {score, std::chrono::steady_clock::now()};
    }
}


void KoraAVDaemon::CleanupExpiredThreats(std::chrono::seconds expiration) {
    std::lock_guard<std::mutex> lock(reported_threat_mutex_);
    auto now = std::chrono::steady_clock::now();

    for (auto it = reported_threats_.begin(); it != reported_threats_.end(); ) {
        if (now - it->second.last_seen > expiration) {
            it = reported_threats_.erase(it);
        } else {
            ++it;
        }
    }
}


uint64_t KoraAVDaemon::GetProcessStartTime(uint32_t tgid) {
    std::string stat_path = "/proc/" + std::to_string(tgid) + "/stat";
    std::ifstream file(stat_path);
    if (!file) return 0;
    std::string line;
    std::getline(file, line);
    std::istringstream iss(line);
    std::string tmp;
    uint64_t starttime = 0;
    for (int i = 0; i < 22; ++i) iss >> tmp; // skip fields
    iss >> starttime;
    return starttime;
}




} // namespace daemon
} // namespace koraav
