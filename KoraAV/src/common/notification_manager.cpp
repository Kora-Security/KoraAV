// src/common/notification_manager.cpp
// Desktop Notification Manager - Works across all desktop environments
// Uses gdbus/dbus-send executed as the logged-in user

#include "notification_manager.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

namespace koraav {

NotificationManager::NotificationManager() : initialized_(false) {
    // Check if notification tools are available
    initialized_ = TestDBusConnection();
    
    if (initialized_) {
        std::cout << "✓ Notification manager initialized" << std::endl;
    } else {
        std::cout << "⚠️  Notification manager: Desktop notifications unavailable (will use console fallback)" << std::endl;
    }
}

NotificationManager::~NotificationManager() {
    // Nothing to clean up
}

void NotificationManager::SendThreatAlert(const std::string& threat_type,
                                          const std::string& process_name,
                                          uint32_t pid,
                                          int threat_score,
                                          const std::vector<std::string>& indicators) {
    // Build message
    std::ostringstream title;
    title << "🚨 " << threat_type << " Detected!";
    
    std::ostringstream message;
    message << "Process: " << process_name << " (PID " << pid << ")\\n";
    message << "Threat Score: " << threat_score << "/100\\n";
    
    if (!indicators.empty()) {
        message << "Indicators:\\n";
        for (const auto& indicator : indicators) {
            message << "  • " << indicator << "\\n";
        }
    }
    
    // Also log to console (always visible in journalctl)
    std::cout << "\n[NOTIFICATION] " << title.str() << std::endl;
    std::cout << message.str() << std::endl;
    
    // Send desktop notification
    SendNotification(title.str(), message.str(), Urgency::CRITICAL);
}

bool NotificationManager::SendNotification(const std::string& title,
                                          const std::string& message,
                                          Urgency urgency) {
    if (!initialized_) {
        // Fallback to console only
        std::cout << "\n[NOTIFICATION] " << title << "\n" << message << "\n" << std::endl;
        return false;
    }
    
    // Send via gdbus/notify-send as the logged-in user
    return SendDBusNotification(title, message, urgency);
}

bool NotificationManager::TestDBusConnection() {
    // Check if we can find a logged-in user
    std::string username = GetLoggedInUser();
    if (username.empty()) {
        std::cerr << "[NOTIFICATION DEBUG] No logged-in user found" << std::endl;
        return false;
    }
    
    std::cout << "[NOTIFICATION DEBUG] Found logged-in user: " << username << std::endl;
    
    // Check if gdbus or notify-send is available
    if (system("command -v gdbus >/dev/null 2>&1") == 0) {
        std::cout << "[NOTIFICATION DEBUG] gdbus is available" << std::endl;
        return true;
    }
    
    if (system("command -v notify-send >/dev/null 2>&1") == 0) {
        std::cout << "[NOTIFICATION DEBUG] notify-send is available" << std::endl;
        return true;
    }
    
    std::cerr << "[NOTIFICATION DEBUG] No notification tools found (gdbus or notify-send)" << std::endl;
    return false;
}

std::string NotificationManager::GetUserDBusAddress() {
    // Get logged-in user's DBUS session address
    std::string username = GetLoggedInUser();
    if (username.empty()) {
        return "";
    }
    
    // Get user's UID
    struct passwd* pw = getpwnam(username.c_str());
    if (!pw) {
        return "";
    }
    
    // Standard session bus address
    std::ostringstream dbus_addr;
    dbus_addr << "unix:path=/run/user/" << pw->pw_uid << "/bus";
    
    return dbus_addr.str();
}

std::string NotificationManager::GetLoggedInUser() {
    // Get first logged-in user
    FILE* pipe = popen("who | awk '{print $1}' | head -1", "r");
    if (!pipe) return "";
    
    char buffer[256];
    std::string username;
    if (fgets(buffer, sizeof(buffer), pipe)) {
        username = buffer;
        // Trim newline
        if (!username.empty() && username.back() == '\n') {
            username.pop_back();
        }
    }
    pclose(pipe);
    
    return username;
}

std::string NotificationManager::EscapeForShell(const std::string& str) {
    std::string escaped;
    for (char c : str) {
        if (c == '\'' || c == '"' || c == '\\' || c == '$' || c == '`' || c == '!') {
            escaped += '\\';
        }
        escaped += c;
    }
    return escaped;
}

bool NotificationManager::SendDBusNotification(const std::string& title,
                                               const std::string& message,
                                               Urgency urgency) {
    // Get logged-in user
    std::string username = GetLoggedInUser();
    if (username.empty()) {
        std::cout << "\n[NOTIFICATION FALLBACK] " << title << "\n" << message << "\n" << std::endl;
        return false;
    }
    
    // Get user's UID for DBUS address
    struct passwd* pw = getpwnam(username.c_str());
    if (!pw) {
        std::cout << "\n[NOTIFICATION FALLBACK] " << title << "\n" << message << "\n" << std::endl;
        return false;
    }
    
    std::string dbus_address = "unix:path=/run/user/" + std::to_string(pw->pw_uid) + "/bus";
    
    // Escape strings for shell
    std::string escaped_title = EscapeForShell(title);
    std::string escaped_message = EscapeForShell(message);
    
    // Build urgency parameter
    std::string urgency_str;
    switch (urgency) {
        case Urgency::LOW:
            urgency_str = "0";
            break;
        case Urgency::CRITICAL:
            urgency_str = "2";
            break;
        default:
            urgency_str = "1";
            break;
    }
    
    // Try gdbus first (more reliable)
    // NO runuser/sudo needed - just set DBUS_SESSION_BUS_ADDRESS!
    std::ostringstream gdbus_cmd;
    
    gdbus_cmd << "DBUS_SESSION_BUS_ADDRESS=" << dbus_address << " "
              << "gdbus call --session "
              << "--dest org.freedesktop.Notifications "
              << "--object-path /org/freedesktop/Notifications "
              << "--method org.freedesktop.Notifications.Notify "
              << "\"KoraAV\" 0 \"security-high\" "
              << "\"" << escaped_title << "\" "
              << "\"" << escaped_message << "\" "
              << "[] "
              << "{\\\"urgency\\\": <byte " << urgency_str << ">} "
              << "10000 2>&1";
    
    std::cout << "[NOTIFICATION DEBUG] Trying gdbus..." << std::endl;
    
    FILE* pipe = popen(gdbus_cmd.str().c_str(), "r");
    if (pipe) {
        char buffer[256];
        std::string output;
        while (fgets(buffer, sizeof(buffer), pipe)) {
            output += buffer;
        }
        int result = pclose(pipe);
        
        if (result == 0 && output.find("uint32") != std::string::npos) {
            std::cout << "[NOTIFICATION DEBUG] Desktop notification sent via gdbus" << std::endl;
            return true;
        }
        
        if (!output.empty()) {
            std::cout << "[NOTIFICATION DEBUG] gdbus output: " << output << std::endl;
        }
    }
    
    // Fallback: try notify-send
    std::ostringstream notify_cmd;
    notify_cmd << " "
               << "env DBUS_SESSION_BUS_ADDRESS=" << dbus_address << " "
               << "notify-send -a KoraAV -u ";
    
    switch (urgency) {
        case Urgency::LOW:
            notify_cmd << "low ";
            break;
        case Urgency::CRITICAL:
            notify_cmd << "critical ";
            break;
        default:
            notify_cmd << "normal ";
            break;
    }
    
    notify_cmd << "\"" << escaped_title << "\" "
               << "\"" << escaped_message << "\" "
               << "2>&1";
    
    std::cout << "[NOTIFICATION DEBUG] Trying notify-send..." << std::endl;
    
    pipe = popen(notify_cmd.str().c_str(), "r");
    if (pipe) {
        char buffer[256];
        std::string output;
        while (fgets(buffer, sizeof(buffer), pipe)) {
            output += buffer;
        }
        int result = pclose(pipe);
        
        if (result == 0) {
            std::cout << "[NOTIFICATION DEBUG] Desktop notification sent via notify-send" << std::endl;
            return true;
        }
        
        if (!output.empty()) {
            std::cout << "[NOTIFICATION DEBUG] notify-send output: " << output << std::endl;
        }
    }
    
    // Both failed - console fallback
    std::cout << "\n[NOTIFICATION FALLBACK] " << title << "\n" << message << "\n" << std::endl;
    return false;
}

void NotificationManager::SendQuarantineNotification(const std::string& threat_type,
                                                     const std::string& process_name,
                                                     const std::string& quarantine_path) {
    // Build title and message
    std::ostringstream title;
    title << "🔒 File Quarantined";
    
    std::ostringstream message;
    message << "Threat Type: " << threat_type << "\\n";
    message << "Process: " << process_name << "\\n";
    message << "Location: " << quarantine_path;
    
    // Log to console (always visible in journalctl)
    std::cout << "\n[NOTIFICATION] " << title.str() << std::endl;
    std::cout << message.str() << std::endl;
    
    // Send desktop notification
    SendNotification(title.str(), message.str(), Urgency::NORMAL);
}

void NotificationManager::SendLockdownNotification() {
    std::string title = "🚨 SYSTEM LOCKDOWN INITIATED";
    std::string message = "KoraAV has detected a severe threat.\\n"
                         "System has been locked down to prevent damage.\\n"
                         "Check logs: sudo journalctl -u korad";
    
    // Log to console (always visible in journalctl)
    std::cout << "\n[NOTIFICATION] " << title << std::endl;
    std::cout << message << std::endl;
    
    // Send desktop notification (CRITICAL urgency)
    SendNotification(title, message, Urgency::CRITICAL);
}

} // namespace koraav
