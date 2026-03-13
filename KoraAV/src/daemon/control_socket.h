// src/daemon/control_socket.h
// Unix domain socket for daemon control/queries
// Permissions: root-only access for security

#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <map>

namespace koraav {
namespace daemon {

class ControlSocket {
public:
    ControlSocket(const std::string& socket_path = "/var/run/koraav/korad.sock");
    ~ControlSocket();
    
    // Start listening for commands
    bool Start();
    
    // Stop listening
    void Stop();
    
    // Register command handlers
    void RegisterHandler(const std::string& command, 
                        std::function<std::string()> handler);
    
private:
    void ListenLoop();
    void HandleClient(int client_fd);
    std::string ProcessCommand(const std::string& command);
    
    std::string socket_path_;
    int listen_fd_;
    std::atomic<bool> running_;
    std::thread listen_thread_;
    
    // Command handlers
    std::map<std::string, std::function<std::string()>> handlers_;
};

} // namespace daemon
} // namespace koraav
