// src/daemon/control_socket.cpp
// Unix domain socket implementation for daemon control

#include "control_socket.h"
#include <iostream>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

namespace koraav {
namespace daemon {

ControlSocket::ControlSocket(const std::string& socket_path)
    : socket_path_(socket_path), listen_fd_(-1), running_(false) {
}

ControlSocket::~ControlSocket() {
    Stop();
}

bool ControlSocket::Start() {
    // Create socket directory if doesn't exist
    std::string socket_dir = socket_path_.substr(0, socket_path_.find_last_of('/'));
    
    // Create directory with proper error handling
    if (mkdir(socket_dir.c_str(), 0755) != 0 && errno != EEXIST) {
        std::cerr << "Failed to create socket directory " << socket_dir 
                  << ": " << strerror(errno) << std::endl;
        std::cerr << "Trying to create parent directories..." << std::endl;
        
        // Try creating parent directories
        std::string cmd = "mkdir -p " + socket_dir;
        if (system(cmd.c_str()) != 0) {
            std::cerr << "Failed to create socket directory (even with mkdir -p)" << std::endl;
            return false;
        }
    }
    
    // Remove old socket file if exists
    unlink(socket_path_.c_str());
    
    // Create Unix domain socket
    listen_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        std::cerr << "Failed to create control socket: " << strerror(errno) << std::endl;
        return false;
    }
    
    // Bind to socket path
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);
    
    if (bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to bind control socket: " << strerror(errno) << std::endl;
        close(listen_fd_);
        return false;
    }
    
    // ════════════════════════════════════════════════════════════
    // CRITICAL SECURITY: Set socket permissions to root-only
    // ════════════════════════════════════════════════════════════
    // chmod 600 = srw------- (only owner can read/write)
    // This prevents non-root users from querying canary paths
    if (chmod(socket_path_.c_str(), 0600) < 0) {
        std::cerr << "Failed to set socket permissions: " << strerror(errno) << std::endl;
        close(listen_fd_);
        unlink(socket_path_.c_str());
        return false;
    }
    
    // Listen for connections
    if (listen(listen_fd_, 5) < 0) {
        std::cerr << "Failed to listen on control socket: " << strerror(errno) << std::endl;
        close(listen_fd_);
        unlink(socket_path_.c_str());
        return false;
    }
    
    std::cout << "✓ Control socket listening at: " << socket_path_ << std::endl;
    std::cout << "  Permissions: 0600 (root-only access)" << std::endl;
    
    // Start listening thread
    running_ = true;
    listen_thread_ = std::thread(&ControlSocket::ListenLoop, this);
    
    return true;
}

void ControlSocket::Stop() {
    if (!running_) return;
    
    running_ = false;
    
    // Close listen socket to unblock accept()
    if (listen_fd_ >= 0) {
        shutdown(listen_fd_, SHUT_RDWR);
        close(listen_fd_);
        listen_fd_ = -1;
    }
    
    // Wait for listen thread to finish
    if (listen_thread_.joinable()) {
        listen_thread_.join();
    }
    
    // Remove socket file
    unlink(socket_path_.c_str());
    
    std::cout << "✓ Control socket closed" << std::endl;
}

void ControlSocket::RegisterHandler(const std::string& command,
                                    std::function<std::string()> handler) {
    handlers_[command] = handler;
}

void ControlSocket::ListenLoop() {
    while (running_) {
        // Accept incoming connection
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(listen_fd_, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (running_) {
                std::cerr << "Accept failed: " << strerror(errno) << std::endl;
            }
            continue;
        }
        
        // ════════════════════════════════════════════════════════════
        // SECURITY CHECK: Verify client credentials
        // ════════════════════════════════════════════════════════════
        struct ucred cred;
        socklen_t cred_len = sizeof(cred);
        if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == 0) {
            // Only allow root (UID 0)
            if (cred.uid != 0) {
                std::cout << "⚠️  Control socket: Rejected connection from UID " 
                         << cred.uid << " (not root)" << std::endl;
                
                const char* msg = "ERROR: Permission denied (root required)\n";
                write(client_fd, msg, strlen(msg));
                close(client_fd);
                continue;
            }
            
            std::cout << "✓ Control socket: Accepted connection from root (PID " 
                     << cred.pid << ")" << std::endl;
        }
        
        // Handle client request
        HandleClient(client_fd);
        close(client_fd);
    }
}

void ControlSocket::HandleClient(int client_fd) {
    char buffer[1024];
    ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
    
    if (n <= 0) {
        return;
    }
    
    buffer[n] = '\0';
    
    // Remove trailing newline
    std::string command(buffer);
    if (!command.empty() && command.back() == '\n') {
        command.pop_back();
    }
    
    std::cout << "  Command received: " << command << std::endl;
    
    // Process command
    std::string response = ProcessCommand(command);
    
    // Send response
    write(client_fd, response.c_str(), response.length());
}

std::string ControlSocket::ProcessCommand(const std::string& command) {
    // Check if handler registered
    auto it = handlers_.find(command);
    if (it != handlers_.end()) {
        return it->second();
    }
    
    // Unknown command
    return "ERROR: Unknown command: " + command + "\n"
           "Available commands: LIST_CANARIES, STATUS, STATS\n";
}

} // namespace daemon
} // namespace koraav
