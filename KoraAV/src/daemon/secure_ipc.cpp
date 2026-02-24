// src/daemon/secure_ipc.cpp
#include "secure_ipc.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <iostream>
#include <cstring>
#include <filesystem>

namespace fs = std::filesystem;

namespace koraav {
namespace daemon {

SecureIPC::SecureIPC() 
    : socket_fd_(-1), running_(false) {
}

SecureIPC::~SecureIPC() {
    Stop();
}

bool SecureIPC::Initialize(const std::string& socket_path) {
    socket_path_ = socket_path;
    
    // Remove existing socket if present
    unlink(socket_path_.c_str());
    
    // Verify parent directory is secure
    fs::path parent = fs::path(socket_path_).parent_path();
    if (!fs::exists(parent)) {
        fs::create_directories(parent);
        fs::permissions(parent, fs::perms::owner_all, fs::perm_options::replace);
    }
    
    if (!VerifySocketSecurity(parent.string())) {
        std::cerr << "Socket directory is not secure" << std::endl;
        return false;
    }
    
    // Create Unix domain socket
    socket_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd_ < 0) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return false;
    }
    
    // Set socket options for security
    int optval = 1;
    setsockopt(socket_fd_, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval));
    
    // Bind to path
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);
    
    if (bind(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to bind socket: " << strerror(errno) << std::endl;
        close(socket_fd_);
        return false;
    }
    
    // Set restrictive permissions on socket
    if (!SetSocketPermissions()) {
        close(socket_fd_);
        unlink(socket_path_.c_str());
        return false;
    }
    
    // Listen for connections
    if (listen(socket_fd_, 5) < 0) {
        std::cerr << "Failed to listen on socket: " << strerror(errno) << std::endl;
        close(socket_fd_);
        unlink(socket_path_.c_str());
        return false;
    }
    
    std::cout << "IPC initialized at " << socket_path_ << std::endl;
    
    return true;
}

void SecureIPC::Run() {
    running_ = true;
    
    while (running_) {
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(socket_fd_, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR && !running_) {
                break;
            }
            std::cerr << "Accept failed: " << strerror(errno) << std::endl;
            continue;
        }
        
        // Handle client in same thread (commands are fast)
        HandleClient(client_fd);
        close(client_fd);
    }
}

void SecureIPC::Stop() {
    running_ = false;
    
    if (socket_fd_ >= 0) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
    
    unlink(socket_path_.c_str());
}

void SecureIPC::RegisterCommand(const std::string& command, CommandHandler handler) {
    command_handlers_[command] = handler;
}

bool SecureIPC::AuthenticateClient(int client_fd, ClientCredentials& creds) {
    // Use SO_PEERCRED to get client credentials
    struct ucred ucred;
    socklen_t len = sizeof(ucred);
    
    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) < 0) {
        std::cerr << "Failed to get peer credentials: " << strerror(errno) << std::endl;
        return false;
    }
    
    creds.uid = ucred.uid;
    creds.gid = ucred.gid;
    creds.pid = ucred.pid;
    creds.is_root = (ucred.uid == 0);
    
    // Log authentication
    struct passwd* pw = getpwuid(creds.uid);
    std::string username = pw ? pw->pw_name : std::to_string(creds.uid);
    
    std::cout << "IPC connection from: " << username 
              << " (UID:" << creds.uid << " PID:" << creds.pid << ")" << std::endl;
    
    return true;
}

bool SecureIPC::AuthorizeCommand(const std::string& command, const ClientCredentials& creds) {
    // Commands that require root
    static const std::vector<std::string> root_commands = {
        "UNLOCK_FILESYSTEM",
        "UNLOCK_NETWORK",
        "UNLOCK_ALL",
        "KILL_PROCESS",
        "QUARANTINE",
        "WHITELIST_ADD",
        "WHITELIST_REMOVE"
    };
    
    for (const auto& root_cmd : root_commands) {
        if (command.find(root_cmd) == 0) {
            if (!creds.is_root) {
                std::cerr << "Authorization denied: " << command 
                         << " requires root (UID=" << creds.uid << ")" << std::endl;
                return false;
            }
        }
    }
    
    // Read-only commands allowed for all users | may change this.
    return true;
}

void SecureIPC::HandleClient(int client_fd) {
    ClientCredentials creds;
    
    // Authenticate client using SO_PEERCRED
    if (!AuthenticateClient(client_fd, creds)) {
        const char* error = "ERROR: Authentication failed\n";
        write(client_fd, error, strlen(error));
        return;
    }
    
    // Read command
    char buffer[4096];
    ssize_t bytes = read(client_fd, buffer, sizeof(buffer) - 1);
    
    if (bytes <= 0) {
        return;
    }
    
    buffer[bytes] = '\0';
    std::string command(buffer);
    
    // Remove trailing newline
    if (!command.empty() && command.back() == '\n') {
        command.pop_back();
    }
    
    // Authorize command
    if (!AuthorizeCommand(command, creds)) {
        const char* error = "ERROR: Permission denied\n";
        write(client_fd, error, strlen(error));
        return;
    }
    
    // Find command handler
    std::string cmd_name = command.substr(0, command.find(' '));
    std::string args = "";
    
    size_t space_pos = command.find(' ');
    if (space_pos != std::string::npos) {
        args = command.substr(space_pos + 1);
    }
    
    auto it = command_handlers_.find(cmd_name);
    if (it != command_handlers_.end()) {
        // Execute command handler
        std::string response = it->second(args, creds.uid, creds.pid);
        write(client_fd, response.c_str(), response.length());
    } else {
        std::string error = "ERROR: Unknown command: " + cmd_name + "\n";
        write(client_fd, error.c_str(), error.length());
    }
}

bool SecureIPC::SetSocketPermissions() {
    // Set socket permissions to 0600 (owner read/write only)
    if (chmod(socket_path_.c_str(), S_IRUSR | S_IWUSR) != 0) {
        std::cerr << "Failed to set socket permissions: " << strerror(errno) << std::endl;
        return false;
    }
    
    // Ensure socket is owned by root
    if (chown(socket_path_.c_str(), 0, 0) != 0) {
        std::cerr << "Failed to set socket ownership: " << strerror(errno) << std::endl;
        return false;
    }
    
    return true;
}

bool SecureIPC::VerifySocketSecurity(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
    
    // Directory must be owned by root
    if (st.st_uid != 0) {
        std::cerr << "Socket directory not owned by root" << std::endl;
        return false;
    }
    
    // Directory must not be world-writable
    if (st.st_mode & S_IWOTH) {
        std::cerr << "Socket directory is world-writable (insecure)" << std::endl;
        return false;
    }
    
    return true;
}

} // namespace daemon
} // namespace koraav
