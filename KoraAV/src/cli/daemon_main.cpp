// src/cli/daemon_main.cpp
// KoraAV Daemon Entry Point

#include "../daemon/koraav_daemon.h"
#include <iostream>
#include <signal.h>
#include <unistd.h>

using namespace koraav::daemon;

// Global daemon instance for signal handling
static KoraAVDaemon* g_daemon = nullptr;

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nReceived shutdown signal..." << std::endl;
        if (g_daemon) {
            g_daemon->Stop();
        }
    }
}

void show_usage(const char* prog) {
    std::cout << "KoraAV Real-Time Protection Daemon (Korad)\n" << std::endl;
    std::cout << "Usage: " << prog << " [options]\n" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -c <config>    Configuration file (default: /etc/koraav/koraav.conf)" << std::endl;
    std::cout << "  -f, --foreground    Run in foreground (don't daemonize)" << std::endl;
    std::cout << "  -h, --help     Show this help" << std::endl;
    std::cout << "  -v, --version  Show version" << std::endl;
    std::cout << std::endl;
}

int main(int argc, char** argv) {
    std::string config_path = "/etc/koraav/koraav.conf";
    bool foreground = false;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            show_usage(argv[0]);
            return 0;
        }
        else if (arg == "-v" || arg == "--version") {
            std::cout << "Korad v0.4.0" << std::endl;
            return 0;
        }
        else if (arg == "-c" && i + 1 < argc) {
            config_path = argv[++i];
        }
        else if (arg == "-f" || arg == "--foreground") {
            foreground = true;
        }
        else {
            std::cerr << "Unknown option: " << arg << std::endl;
            show_usage(argv[0]);
            return 1;
        }
    }
    
    // Check if running as root
    if (getuid() != 0) {
        std::cerr << "Error: Korad must be run as root" << std::endl;
        std::cerr << "Run: sudo " << argv[0] << std::endl;
        return 1;
    }
    
    std::cout << "╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║              Korad - Real-Time Protection v0.4.0           ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
    
    // Create daemon instance
    KoraAVDaemon daemon;
    g_daemon = &daemon;
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize
    if (!daemon.Initialize(config_path)) {
        std::cerr << "Failed to initialize daemon" << std::endl;
        return 1;
    }
    
    // Daemonize if not in foreground mode
    if (!foreground) {
        std::cout << "Daemonizing..." << std::endl;
        
        pid_t pid = fork();
        if (pid < 0) {
            std::cerr << "Fork failed" << std::endl;
            return 1;
        }
        
        if (pid > 0) {
            // Parent process - exit
            std::cout << "Daemon started with PID " << pid << std::endl;
            std::cout << "Logs: /opt/koraav/var/logs/" << std::endl;
            std::cout << "Stop with: sudo systemctl stop koraav" << std::endl;
            return 0;
        }
        
        // Child process continues
        setsid();  // Create new session
        
        // Redirect stdout/stderr to log file
        freopen("/opt/koraav/var/logs/daemon.log", "a", stdout);
        freopen("/opt/koraav/var/logs/daemon.log", "a", stderr);
    }
    
    // Run daemon
    daemon.Run();
    
    return 0;
}
