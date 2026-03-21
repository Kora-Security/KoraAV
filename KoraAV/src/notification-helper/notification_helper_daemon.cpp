// src/notification-helper/notification_helper_daemon.cpp
// User-space notification daemon for KoraAV
// Runs as logged-in user, receives notification requests from system daemon

#include <iostream>
#include <string>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <sstream>
#include <vector>

// Simple JSON parser for our limited use case
class SimpleJSON {
public:
    static std::string get(const std::string& json, const std::string& key) {
        std::string search = "\"" + key + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";

        pos += search.length();
        // Skip whitespace and opening quote
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
        if (pos >= json.length() || json[pos] != '"') return "";
        pos++; // Skip opening quote

        // Find closing quote
        size_t end = json.find('"', pos);
        if (end == std::string::npos) return "";

        return json.substr(pos, end - pos);
    }
};

class NotificationHelper {
private:
    int sock_fd_;
    bool running_;
    std::string socket_path_;

    static NotificationHelper* instance_;

public:
    NotificationHelper(const std::string& socket_path)
    : sock_fd_(-1), running_(true), socket_path_(socket_path) {
        instance_ = this;
    }

    ~NotificationHelper() {
        cleanup();
    }

    static void signalHandler(int signal) {
        if (instance_) {
            std::cout << "\nReceived signal " << signal << ", shutting down..." << std::endl;
            instance_->running_ = false;
        }
    }

    bool initialize() {
        // Create socket directory if needed
        std::string socket_dir = socket_path_.substr(0, socket_path_.find_last_of('/'));

        std::cout << "Creating socket directory: " << socket_dir << std::endl;

        // Try to create directory (will fail if exists, that's OK)
        if (mkdir(socket_dir.c_str(), 0755) < 0) {
            if (errno != EEXIST) {
                std::cerr << "Warning: Could not create socket directory: " << strerror(errno) << std::endl;
                std::cerr << "Checking if directory exists..." << std::endl;

                // Check if directory actually exists
                struct stat st;
                if (stat(socket_dir.c_str(), &st) != 0) {
                    std::cerr << "ERROR: Socket directory does not exist and cannot be created!" << std::endl;
                    std::cerr << "Please run as root or ensure " << socket_dir << " exists" << std::endl;
                    return false;
                }

                if (!S_ISDIR(st.st_mode)) {
                    std::cerr << "ERROR: " << socket_dir << " exists but is not a directory!" << std::endl;
                    return false;
                }

                std::cout << "Directory already exists, continuing..." << std::endl;
            }
        } else {
            std::cout << "✓ Created socket directory" << std::endl;
        }

        // Remove old socket if exists
        unlink(socket_path_.c_str());

        std::cout << "Creating Unix socket at: " << socket_path_ << std::endl;

        // Create Unix socket
        sock_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock_fd_ < 0) {
            std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
            return false;
        }

        // Bind to socket path
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

        if (bind(sock_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "Failed to bind socket: " << strerror(errno) << std::endl;
            close(sock_fd_);
            return false;
        }

        // Make socket writable by daemon
        chmod(socket_path_.c_str(), 0666);

        // Listen for connections
        if (listen(sock_fd_, 5) < 0) {
            std::cerr << "Failed to listen: " << strerror(errno) << std::endl;
            close(sock_fd_);
            return false;
        }

        std::cout << "KoraAV notification helper listening on " << socket_path_ << std::endl;
        return true;
    }

    bool sendNotification(const std::string& title, const std::string& message, const std::string& urgency) {
        // Try notify-send first (most reliable)
        std::vector<std::string> cmd = {
            "notify-send",
            "-u", urgency,
            "-a", "KoraAV",
            "-i", "security-high",
            title,
            message
        };

        if (executeCommand(cmd)) {
            return true;
        }

        // Fallback: gdbus
        std::string urgency_byte = "1";
        if (urgency == "low") urgency_byte = "0";
        else if (urgency == "critical") urgency_byte = "2";

        std::vector<std::string> gdbus_cmd = {
            "gdbus", "call", "--session",
            "--dest", "org.freedesktop.Notifications",
            "--object-path", "/org/freedesktop/Notifications",
            "--method", "org.freedesktop.Notifications.Notify",
            "KoraAV", "0", "security-high",
            title, message,
            "[]", "{}", "5000"
        };

        return executeCommand(gdbus_cmd);
    }

    bool executeCommand(const std::vector<std::string>& args) {
        std::vector<char*> c_args;
        for (const auto& arg : args) {
            c_args.push_back(const_cast<char*>(arg.c_str()));
        }
        c_args.push_back(nullptr);

        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            execvp(c_args[0], c_args.data());
            exit(1); // If exec fails
        } else if (pid > 0) {
            // Parent process
            int status;
            waitpid(pid, &status, 0);
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }

        return false;
    }

    void run() {
        while (running_) {
            // Accept connection (with timeout)
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(sock_fd_, &readfds);

            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            int ret = select(sock_fd_ + 1, &readfds, nullptr, nullptr, &timeout);
            if (ret < 0) {
                if (errno == EINTR) continue; // Signal interrupted
                std::cerr << "select() error: " << strerror(errno) << std::endl;
                break;
            }

            if (ret == 0) continue; // Timeout, check running_ flag

            // Accept connection
            int client_fd = accept(sock_fd_, nullptr, nullptr);
            if (client_fd < 0) {
                if (errno == EINTR) continue;
                std::cerr << "accept() error: " << strerror(errno) << std::endl;
                continue;
            }

            // Handle request
            handleRequest(client_fd);
            close(client_fd);
        }
    }

    void handleRequest(int client_fd) {
        char buffer[4096];
        ssize_t bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

        if (bytes <= 0) return;

        buffer[bytes] = '\0';
        std::string request(buffer);

        // Parse JSON
        std::string title = SimpleJSON::get(request, "title");
        std::string message = SimpleJSON::get(request, "message");
        std::string urgency = SimpleJSON::get(request, "urgency");

        if (title.empty()) title = "KoraAV Alert";
        if (urgency.empty()) urgency = "normal";

        // Send notification
        bool success = sendNotification(title, message, urgency);

        // Send response
        std::string response = success ? "{\"success\":true}" : "{\"success\":false}";
        send(client_fd, response.c_str(), response.length(), 0);

        if (success) {
            std::cout << "✅ Notification sent: " << title << std::endl;
        } else {
            std::cerr << "❌ Notification failed: " << title << std::endl;
        }
    }

    void cleanup() {
        if (sock_fd_ >= 0) {
            close(sock_fd_);
            sock_fd_ = -1;
        }
        unlink(socket_path_.c_str());
    }
};

NotificationHelper* NotificationHelper::instance_ = nullptr;

int main() {
    // Use XDG_RUNTIME_DIR if available, otherwise fallback to /tmp
    // This ensures the user can write to the socket location
    const char* runtime_dir = getenv("XDG_RUNTIME_DIR");
    std::string socket_path;

    if (runtime_dir) {
        socket_path = std::string(runtime_dir) + "/koraav-notifications.sock";
    } else {
        socket_path = "/tmp/koraav-notifications.sock";
    }

    // Setup signal handlers
    signal(SIGINT, NotificationHelper::signalHandler);
    signal(SIGTERM, NotificationHelper::signalHandler);

    // Create and run helper
    NotificationHelper helper(socket_path);

    if (!helper.initialize()) {
        std::cerr << "Failed to initialize notification helper" << std::endl;
        std::cerr << "Socket path: " << socket_path << std::endl;
        return 1;
    }

    helper.run();

    std::cout << "Notification helper stopped" << std::endl;
    return 0;
}
