// src/daemon/secure_ipc.h
#ifndef KORAAV_SECURE_IPC_H
#define KORAAV_SECURE_IPC_H

#include <string>
#include <functional>
#include <map>

namespace koraav {
namespace daemon {

/**
 * Secure IPC Handler
 * Unix domain socket with SO_PEERCRED authentication
 * Hardens daemon communication against unauthorized access
 */
class SecureIPC {
public:
    SecureIPC();
    ~SecureIPC();
    
    bool Initialize(const std::string& socket_path = "/opt/koraav/var/run/koraav.sock");
    
    /**
     * Start listening for commands
     */
    void Run();
    
    /**
     * Stop IPC server
     */
    void Stop();
    
    /**
     * Register command handler
     */
    using CommandHandler = std::function<std::string(const std::string& args, uid_t uid, pid_t pid)>;
    void RegisterCommand(const std::string& command, CommandHandler handler);

private:
    int socket_fd_;
    bool running_;
    std::string socket_path_;
    
    std::map<std::string, CommandHandler> command_handlers_;
    
    /**
     * Authenticate client using SO_PEERCRED
     */
    struct ClientCredentials {
        uid_t uid;
        gid_t gid;
        pid_t pid;
        bool is_root;
    };
    
    bool AuthenticateClient(int client_fd, ClientCredentials& creds);
    
    /**
     * Verify client has permission for command
     */
    bool AuthorizeCommand(const std::string& command, const ClientCredentials& creds);
    
    /**
     * Handle client connection
     */
    void HandleClient(int client_fd);
    
    /**
     * Set strict socket permissions
     */
    bool SetSocketPermissions();
    
    /**
     * Check if socket path is secure
     */
    bool VerifySocketSecurity(const std::string& path);
};

} // namespace daemon
} // namespace koraav

#endif // KORAAV_SECURE_IPC_H
