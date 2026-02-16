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

namespace koraav {
namespace daemon {


bool KoraAVDaemon::SetSecureBits() {
    // Set securebits AFTER systemd has done capability transition
    int securebits = SECBIT_KEEP_CAPS |
                     SECBIT_KEEP_CAPS_LOCKED |
                     SECBIT_NO_SETUID_FIXUP |
                     SECBIT_NO_SETUID_FIXUP_LOCKED |
                     SECBIT_NOROOT |
                     SECBIT_NOROOT_LOCKED;

    if (prctl(PR_SET_SECUREBITS, securebits) < 0) {
        std::cerr << "Warning: Failed to set securebits: " << strerror(errno) << std::endl;
        // Don't fail - we still have NoNewPrivileges from systemd
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
        
        // Build protected paths from config
        std::vector<std::string> protected_paths = {
            "/home",
            "/root",
            "/opt",
            "/var",
            "/srv"
        };
        
        if (!ransomware_detector_->Initialize(protected_paths)) {
            std::cerr << "Failed to initialize ransomware detector" << std::endl;
        } else {
            std::cout << "✓ Ransomware detector initialized" << std::endl;
        }
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
    
    // Start detection engines
    if (ransomware_detector_) {
        // Ransomware detector needs its own thread (Run() is blocking)
        ransomware_thread_ = std::thread([this]() {
            ransomware_detector_->Run();
        });
        std::cout << "✓ Ransomware protection active" << std::endl;
    }
    
    if (infostealer_detector_) {
        std::cout << "✓ Info stealer protection active" << std::endl;
    }
    
    if (clickfix_detector_) {
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
    
    // InfoStealer and ClickFix don't have Stop() methods (passive detectors)
    
    // Wait for threads to finish
    if (ransomware_thread_.joinable()) {
        ransomware_thread_.join();
    }
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
    
    std::cout << "✓ Configuration loaded" << std::endl;
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
    // Check for sensitive file patterns
    static const std::vector<std::string> sensitive_patterns = {
        // SSH keys
        "/.ssh/id_rsa",
        "/.ssh/id_ed25519",
        "/.ssh/id_ecdsa",
        "/.ssh/authorized_keys",

        // GPG keys
        "/.gnupg/",
        "/.gnupg/secring.gpg",
        "/.gnupg/private-keys",

        // Browser data
        "/.mozilla/firefox/",
        "/.config/google-chrome/",
        "/.config/chromium/",
        "/Library/Application Support/Google/Chrome/",
        "/Library/Application Support/Firefox/",

        // Crypto wallets
        "/.bitcoin/wallet.dat",
        "/.ethereum/keystore/",
        "/.metamask/",
        "/Electrum/wallets/",

        // Password managers
        "/.password-store/",
        "/KeePass/",
        "/1Password/",

        // AWS credentials
        "/.aws/credentials",
        "/.aws/config",

        // Database credentials
        "/.my.cnf",
        "/.pgpass",

        // Environment files
        "/.env",
        "/.env.local",

        // Common credential files
        "/credentials.json",
        "/secrets.json",
        "/token.json",
        "/auth.json"
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



void KoraAVDaemon::ProcessFileEvents() {
    std::cout << "File event processor started" << std::endl;

    if (!file_events_ringbuf_) {
        std::cout << "File events ring buffer not available, skipping" << std::endl;
        return;
    }

    // Get the map FD
    struct bpf_map* file_events_map = bpf_object__find_map_by_name(file_monitor_obj_, "file_events");
    if (!file_events_map) {
        std::cerr << "Failed to find file_events map" << std::endl;
        return;
    }

    int map_fd = bpf_map__fd(file_events_map);
    if (map_fd < 0) {
        std::cerr << "Failed to get file_events map FD" << std::endl;
        return;
    }

    // Define ring buffer callback for file events
    // CRITICAL: Use struct with proper context passing
    struct CallbackContext {
        KoraAVDaemon* daemon;
    };

    CallbackContext ctx = { this };

    auto callback = [](void *ctx_ptr, void *data, size_t data_sz) -> int {
        try {
            // SAFE: Get daemon pointer from context
            CallbackContext* ctx = static_cast<CallbackContext*>(ctx_ptr);
            KoraAVDaemon* daemon = ctx->daemon;

            if (!daemon) return 0;

            // Define event structure (must match eBPF program)
            struct file_event {
                uint64_t timestamp;
                uint32_t pid;
                uint32_t uid;
                uint32_t flags;        // open() flags
                uint32_t mode;         // file mode
                char filename[256];    // path being accessed
                char comm[16];         // process name
            };

            if (data_sz < sizeof(file_event)) {
                return 0;
            }

            auto *event = static_cast<const file_event*>(data);

            // SAFETY: Validate event data
            if (event->pid == 0) {
                return 0;  // Invalid event
            }

            std::string filename(event->filename);
            std::string proc_name(event->comm);

            // Skip empty filenames
            if (filename.empty()) {
                return 0;
            }

            // Track file access for InfoStealer detector
            if (daemon->infostealer_detector_) {
                // Check if this is a sensitive file (credentials, crypto wallets, etc.)
                if (daemon->IsSensitiveFile(filename)) {
                    daemon->infostealer_detector_->TrackFileAccess(event->pid, filename);

                    // Analyze if too many sensitive files are being accessed
                    int score = daemon->infostealer_detector_->AnalyzeProcess(event->pid);
                    if (score >= 80) {
                        auto indicators = daemon->infostealer_detector_->GetThreatIndicators(event->pid);

                        std::cout << "\n🚨 SUSPICIOUS FILE ACCESS DETECTED!" << std::endl;
                        std::cout << "   Process: " << proc_name << " (PID " << event->pid << ")" << std::endl;
                        std::cout << "   File: " << filename << std::endl;
                        std::cout << "   InfoStealer Score: " << score << "/100" << std::endl;

                        daemon->HandleThreat(event->pid, "InfoStealer", score, indicators);
                    }
                }
            }

            // Track file modifications for Ransomware detector
            if (daemon->ransomware_detector_) {
                // Check if this is a write operation
                bool is_write = (event->flags & (O_WRONLY | O_RDWR)) != 0;

                if (is_write) {
                    // Ransomware detector tracks this internally via fanotify
                    // But we can also pass file access info if needed
                    // (Currently ransomware detector uses its own fanotify monitoring)
                }
            }

            return 0;
        } catch (const std::exception& e) {
            std::cerr << "Exception in file callback: " << e.what() << std::endl;
            return 0;
        } catch (...) {
            std::cerr << "Unknown exception in file callback" << std::endl;
            return 0;
        }
    };

    // Create the actual ring buffer with callback
    struct ring_buffer* rb = ring_buffer__new(map_fd, callback, &ctx, nullptr);
    if (!rb) {
        std::cerr << "Failed to create ring buffer for file events" << std::endl;
        return;
    }

    std::cout << "✓ File events ring buffer polling started (InfoStealer detection active)" << std::endl;

    // Poll ring buffer for events
    while (running_) {
        // Poll with 100ms timeout
        int ret = ring_buffer__poll(rb, 100);
        if (ret < 0 && ret != -EINTR) {
            std::cerr << "Error polling file events ring buffer: " << ret << std::endl;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Cleanup
    ring_buffer__free(rb);
    std::cout << "File event processor stopped" << std::endl;
}

void KoraAVDaemon::ProcessProcessEvents() {
    std::cout << "Process event processor started" << std::endl;

    if (!process_events_ringbuf_) {
        std::cout << "Process events ring buffer not available, skipping" << std::endl;
        return;
    }

    // Get the map FD
    struct bpf_map* process_events_map = bpf_object__find_map_by_name(process_monitor_obj_, "process_events");
    if (!process_events_map) {
        std::cerr << "Failed to find process_events map" << std::endl;
        return;
    }

    int map_fd = bpf_map__fd(process_events_map);
    if (map_fd < 0) {
        std::cerr << "Failed to get process_events map FD" << std::endl;
        return;
    }

    // Define ring buffer callback for process events
    // CRITICAL: Use static function with proper context passing
    struct CallbackContext {
        KoraAVDaemon* daemon;
    };

    CallbackContext ctx = { this };

    auto callback = [](void *ctx_ptr, void *data, size_t data_sz) -> int {
        try {
            // SAFE: Get daemon pointer from context
            CallbackContext* ctx = static_cast<CallbackContext*>(ctx_ptr);
            KoraAVDaemon* daemon = ctx->daemon;

            if (!daemon) return 0;

            // Define event structure (must match eBPF program)
            struct process_event {
                uint64_t timestamp;
                uint32_t pid;
                uint32_t ppid;
                uint32_t uid;
                char comm[16];
            };

            if (data_sz < sizeof(process_event)) {
                return 0;
            }

            auto *event = static_cast<const process_event*>(data);

            // SAFETY: Check if pid is valid
            if (event->pid == 0) return 0;

            // Get full command line from /proc
            std::string cmdline = daemon->GetProcessCommandLine(event->pid);
            if (cmdline.empty()) return 0;  // Process already gone

            std::string proc_name(event->comm);

            // Analyze with ClickFix detector
            if (daemon->clickfix_detector_) {
                int score = daemon->clickfix_detector_->AnalyzeCommand(cmdline, proc_name);

                if (score >= 80) {
                    // Malicious command detected!
                    auto indicators = daemon->clickfix_detector_->GetThreatIndicators(cmdline);

                    std::cout << "\n🚨 MALICIOUS COMMAND DETECTED!" << std::endl;
                    std::cout << "   Process: " << proc_name << " (PID " << event->pid << ")" << std::endl;
                    std::cout << "   Command: " << cmdline << std::endl;
                    std::cout << "   Score: " << score << "/100" << std::endl;

                    daemon->HandleThreat(event->pid, "ClickFix", score, indicators);
                } else if (score >= 60) {
                    // Suspicious but not confirmed
                    std::cout << "⚠️  Suspicious command (score: " << score << "): " << cmdline << std::endl;
                }
            }

            return 0;
        } catch (const std::exception& e) {
            std::cerr << "Exception in process callback: " << e.what() << std::endl;
            return 0;
        } catch (...) {
            std::cerr << "Unknown exception in process callback" << std::endl;
            return 0;
        }
    };

    // Create the actual ring buffer with callback
    struct ring_buffer* rb = ring_buffer__new(map_fd, callback, &ctx, nullptr);
    if (!rb) {
        std::cerr << "Failed to create ring buffer for process events" << std::endl;
        return;
    }

    std::cout << "✓ Process events ring buffer polling started (ClickFix active)" << std::endl;

    // Poll ring buffer for events
    while (running_) {
        // Poll with 100ms timeout
        int ret = ring_buffer__poll(rb, 100);
        if (ret < 0 && ret != -EINTR) {
            std::cerr << "Error polling process events ring buffer: " << ret << std::endl;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Cleanup
    ring_buffer__free(rb);
    std::cout << "Process event processor stopped" << std::endl;
}

void KoraAVDaemon::ProcessNetworkEvents() {
    std::cout << "Network event processor started" << std::endl;

    if (!network_events_ringbuf_) {
        std::cout << "Network events ring buffer not available, skipping" << std::endl;
        return;
    }

    // Get the map FD
    struct bpf_map* network_events_map = bpf_object__find_map_by_name(network_monitor_obj_, "network_events");
    if (!network_events_map) {
        std::cerr << "Failed to find network_events map" << std::endl;
        return;
    }

    int map_fd = bpf_map__fd(network_events_map);
    if (map_fd < 0) {
        std::cerr << "Failed to get network_events map FD" << std::endl;
        return;
    }

    // Define ring buffer callback for network events
    // CRITICAL: Use struct with proper context passing
    struct CallbackContext {
        KoraAVDaemon* daemon;
    };

    CallbackContext ctx = { this };

    auto callback = [](void *ctx_ptr, void *data, size_t data_sz) -> int {
        try {
            // SAFE: Get daemon pointer from context
            CallbackContext* ctx = static_cast<CallbackContext*>(ctx_ptr);
            KoraAVDaemon* daemon = ctx->daemon;

            if (!daemon) return 0;

            // Define event structure (must match eBPF program)
            struct network_event {
                uint64_t timestamp;
                uint32_t pid;
                uint32_t uid;
                uint32_t saddr;   // Source IP
                uint32_t daddr;   // Destination IP
                uint16_t sport;   // Source port
                uint16_t dport;   // Destination port
                char comm[16];
            };

            if (data_sz < sizeof(network_event)) {
                return 0;
            }

            auto *event = static_cast<const network_event*>(data);

            // SAFETY: Validate event data
            if (event->pid == 0 || event->daddr == 0) {
                return 0;  // Invalid event
            }

            // Track connection with C2 detector
            if (daemon->c2_detector_) {
                daemon->c2_detector_->TrackConnection(event->pid, event->daddr, event->dport);
            }

            // Also track for InfoStealer (potential exfiltration)
            if (daemon->infostealer_detector_) {
                daemon->infostealer_detector_->TrackNetworkConnection(event->pid, event->daddr, event->dport);
            }

            return 0;
        } catch (const std::exception& e) {
            std::cerr << "Exception in network callback: " << e.what() << std::endl;
            return 0;
        } catch (...) {
            std::cerr << "Unknown exception in network callback" << std::endl;
            return 0;
        }
    };

    // Create the actual ring buffer with callback
    struct ring_buffer* rb = ring_buffer__new(map_fd, callback, &ctx, nullptr);
    if (!rb) {
        std::cerr << "Failed to create ring buffer for network events" << std::endl;
        return;
    }

    std::cout << "✓ Network events ring buffer polling started (C2 detection active)" << std::endl;

    // Poll ring buffer for events
    while (running_) {
        // Poll with 100ms timeout
        int ret = ring_buffer__poll(rb, 100);
        if (ret < 0 && ret != -EINTR) {
            std::cerr << "Error polling network events ring buffer: " << ret << std::endl;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Cleanup
    ring_buffer__free(rb);
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
                    
                    // Calculate threat score based on behavior
                    int score = 60;  // Base score for suspicious
                    score += proc.encryption_attempts * 10;  // +10 per attempt
                    score += (proc.files_targeted >= 5) ? 25 : 0;  // +25 if many files
                    score = std::min(score, 100);  // Cap at 100
                    
                    HandleThreat(proc.pid, "Ransomware", score, indicators);
                }
            }
        }
        
        if (infostealer_detector_) {
            auto suspicious_pids = infostealer_detector_->GetSuspiciousProcesses(70);
            for (const auto& pid : suspicious_pids) {
                int score = infostealer_detector_->AnalyzeProcess(pid);
                auto indicators = infostealer_detector_->GetThreatIndicators(pid);
                
                // Only trigger on high confidence (score >= 80)
                if (score >= 80) {
                    HandleThreat(pid, "InfoStealer", score, indicators);
                }
            }
        }
        
        // Check for C2 communication
        if (c2_detector_) {
            auto suspicious_pids = c2_detector_->GetSuspiciousProcesses(70);
            for (const auto& pid : suspicious_pids) {
                int score = c2_detector_->AnalyzeProcess(pid);
                auto indicators = c2_detector_->GetThreatIndicators(pid);
                
                // Trigger on high confidence (score >= 75 for C2)
                if (score >= 75) {
                    HandleThreat(pid, "C2_Communication", score, indicators);
                }
            }
        }
    }
    
    std::cout << "Periodic analysis thread stopped" << std::endl;
}

void KoraAVDaemon::HandleThreat(uint32_t pid, const std::string& threat_type,
                                int score, const std::vector<std::string>& indicators) {
    // Log the threat first
    LogThreat(pid, threat_type, score, indicators);
    
    // Get process info for notification
    std::string process_name = GetProcessName(pid);
    std::string process_cmd = GetProcessCommandLine(pid);
    
    // Send desktop notification FIRST (before console output)
    if (notification_manager_) {
        notification_manager_->SendThreatAlert(threat_type, process_name, pid, score, indicators);
    }
    
    // Display threat notification (console)
    std::cout << "\n";
    std::cout << "═══════════════════════════════════════════════════════════" << std::endl;
    std::cout << "🚨 THREAT DETECTED!" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════" << std::endl;
    std::cout << "Type:         " << threat_type << std::endl;
    std::cout << "Threat Score: " << score << "/100" << std::endl;
    std::cout << "Process:      " << process_name << " (PID " << pid << ")" << std::endl;
    if (!process_cmd.empty()) {
        std::cout << "Command:      " << process_cmd << std::endl;
    }
    std::cout << "\nIndicators:" << std::endl;
    for (const auto& indicator : indicators) {
        std::cout << "  • " << indicator << std::endl;
    }
    std::cout << "───────────────────────────────────────────────────────────" << std::endl;
    
    // Determine action based on score and config
    if (score >= config_.lockdown_threshold && config_.auto_lockdown) {
        std::cout << "⚠️  CRITICAL THREAT (Score ≥" << config_.lockdown_threshold << ")" << std::endl;
        std::cout << "Action:       SYSTEM LOCKDOWN" << std::endl;
        std::cout << "═══════════════════════════════════════════════════════════\n" << std::endl;
        
        // Kill process first
        KillProcess(pid);
        
        // Quarantine
        if (quarantine_manager_) {
            std::string quarantine_path = quarantine_manager_->QuarantineProcess(pid, threat_type);
            if (!quarantine_path.empty()) {
                std::cout << "✓ Malware quarantined to: " << quarantine_path << std::endl;
                if (notification_manager_) {
                    notification_manager_->SendQuarantineNotification(threat_type, process_name, quarantine_path);
                }
            }
        }
        
        // Lockdown system
        LockdownSystem();
        
        // Send lockdown notification
        if (notification_manager_) {
            notification_manager_->SendLockdownNotification();
        }
        
    } else if (score >= config_.block_threshold) {
        std::cout << "⚠️  HIGH THREAT (Score ≥" << config_.block_threshold << ")" << std::endl;
        std::cout << "Action:       KILL & QUARANTINE" << std::endl;
        std::cout << "═══════════════════════════════════════════════════════════\n" << std::endl;
        
        // Block network if configured
        if (config_.auto_block_network) {
            BlockProcessNetwork(pid);
        }
        
        // Kill process
        if (config_.auto_kill) {
            KillProcess(pid);
        }
        
        // Quarantine the malware
        if (quarantine_manager_) {
            std::string quarantine_path = quarantine_manager_->QuarantineProcess(pid, threat_type);
            if (!quarantine_path.empty()) {
                std::cout << "✓ Malware quarantined to: " << quarantine_path << std::endl;
                if (notification_manager_) {
                    notification_manager_->SendQuarantineNotification(threat_type, process_name, quarantine_path);
                }
            }
        }
        
        std::cout << "✓ Threat neutralized and quarantined" << std::endl;
        
    } else if (score >= config_.alert_threshold) {
        std::cout << "⚠️  SUSPICIOUS ACTIVITY (Score ≥" << config_.alert_threshold << ")" << std::endl;
        std::cout << "Action:       MONITORING (no action taken)" << std::endl;
        std::cout << "═══════════════════════════════════════════════════════════\n" << std::endl;
        std::cout << "ℹ️  Process is being monitored. Will auto-kill if threat score increases." << std::endl;
    }
    
    std::cout << std::endl;
}

void KoraAVDaemon::KillProcess(uint32_t pid) {
    std::cout << "  → Killing malicious process PID " << pid << " (" << GetProcessName(pid) << ")" << std::endl;
    kill(pid, SIGKILL);
}

void KoraAVDaemon::BlockProcessNetwork(uint32_t pid) {
    std::cout << "  → Blocking network for PID " << pid << std::endl;
    
    // Use nftables to block process
    std::string cmd = "nft add rule inet filter output meta skuid " + std::to_string(pid) + " drop 2>/dev/null";
    system(cmd.c_str());
    
    // Fallback to iptables
    cmd = "iptables -A OUTPUT -m owner --pid-owner " + std::to_string(pid) + " -j DROP 2>/dev/null";
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
