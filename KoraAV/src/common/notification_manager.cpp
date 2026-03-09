// src/common/notification_manager.cpp
#include "notification_manager.h"
#include <iostream>
#include <sstream>
#include <cstdlib>

namespace koraav {

NotificationManager::NotificationManager() : initialized_(false) {
    initialized_ = InitializeLibnotify();
}

NotificationManager::~NotificationManager() {
    CleanupLibnotify();
}

bool NotificationManager::InitializeLibnotify() {
    // Check if we're running in a graphical environment
    const char* display = std::getenv("DISPLAY");
    if (!display || display[0] == '\0') {
        // No display, notifications won't work
        return false;
    }
    
    return true;
}

void NotificationManager::CleanupLibnotify() {
    // Cleanup if needed
}

bool NotificationManager::SendThreatAlert(const std::string& threat_type,
                                         const std::string& process_name,
                                         uint32_t pid,
                                         int threat_score,
                                         const std::vector<std::string>& indicators) {
    std::ostringstream title;
    title << "🚨 " << threat_type << " Detected!";
    
    std::ostringstream message;
    message << "<b>Process:</b> " << process_name << " (PID " << pid << ")\n";
    message << "<b>Threat Score:</b> " << threat_score << "/100\n\n";
    
    if (!indicators.empty()) {
        message << "<b>Indicators:</b>\n";
        int count = 0;
        for (const auto& indicator : indicators) {
            if (count++ >= 3) {
                message << "  ... and " << (indicators.size() - 3) << " more\n";
                break;
            }
            message << "  • " << indicator << "\n";
        }
    }
    
    message << "\n<b>Action:</b> ";
    if (threat_score >= 96) {
        message << "⚠️ SYSTEM LOCKDOWN INITIATED";
    } else if (threat_score >= 81) {
        message << "Process killed and quarantined";
    } else {
        message << "Monitoring process";
    }
    
    Urgency urgency = Urgency::NORMAL;
    if (threat_score >= 96) {
        urgency = Urgency::CRITICAL;
    } else if (threat_score >= 81) {
        urgency = Urgency::CRITICAL;
    }
    
    return SendNotification(title.str(), message.str(), urgency);
}

bool NotificationManager::SendQuarantineNotification(const std::string& threat_type,
                                                    const std::string& process_name,
                                                    const std::string& quarantine_path) {
    std::ostringstream title;
    title << "✓ Threat Quarantined";
    
    std::ostringstream message;
    message << "<b>Type:</b> " << threat_type << "\n";
    message << "<b>Process:</b> " << process_name << "\n\n";
    message << "Malware has been isolated and can no longer harm your system.\n\n";
    message << "<b>Location:</b> " << quarantine_path;
    
    return SendNotification(title.str(), message.str(), Urgency::NORMAL);
}

bool NotificationManager::SendLockdownNotification() {
    std::string title = "🔒 SYSTEM LOCKDOWN ACTIVE";
    std::string message = 
        "<b>Critical threat detected!</b>\n\n"
        "Your system has been locked down to prevent further damage:\n"
        "  • Filesystem is now read-only\n"
        "  • Network access blocked\n\n"
        "To restore your system, run:\n"
        "<tt>sudo koraav unlock --all</tt>";
    
    return SendNotification(title, message, Urgency::CRITICAL);
}

bool NotificationManager::SendNotification(const std::string& title,
                                          const std::string& message,
                                          Urgency urgency) {
    if (!initialized_) {
        // Fallback to console if no GUI
        std::cout << "\n[NOTIFICATION] " << title << "\n" << message << "\n" << std::endl;
        return false;
    }
    
    // Get logged-in user info
    std::string username = GetLoggedInUser();
    std::string user_display = GetUserDisplay(username);
    
    if (username.empty() || user_display.empty()) {
        // Fallback to console
        std::cout << "\n[NOTIFICATION] " << title << "\n" << message << "\n" << std::endl;
        return false;
    }
    
    // Build notify-send command
    std::ostringstream cmd;
    
    // Run as user with their DISPLAY
    cmd << "su " << username << " -c \"";
    cmd << "DISPLAY=" << user_display << " ";
    cmd << "notify-send ";
    
    // Set urgency
    switch (urgency) {
        case Urgency::LOW:
            cmd << "-u low ";
            break;
        case Urgency::NORMAL:
            cmd << "-u normal ";
            break;
        case Urgency::CRITICAL:
            cmd << "-u critical ";
            break;
    }
    
    // Add icon and app name
    cmd << "-i security-high ";
    cmd << "-a 'KoraAV' ";
    
    // Timeout
    if (urgency == Urgency::CRITICAL) {
        cmd << "-t 0 ";  // Doesn't expire
    } else {
        cmd << "-t 10000 ";  // 10 seconds
    }
    
    // Escape title and message for shell
    std::string escaped_title = EscapeForShell(title);
    std::string escaped_message = EscapeForShell(message);
    
    cmd << "'" << escaped_title << "' ";
    cmd << "'" << escaped_message << "'";
    cmd << "\" 2>/dev/null &";
    
    // Execute
    int result = system(cmd.str().c_str());
    
    return (result == 0);
}

std::string NotificationManager::GetUrgencyString(Urgency urgency) {
    switch (urgency) {
        case Urgency::LOW: return "low";
        case Urgency::NORMAL: return "normal";
        case Urgency::CRITICAL: return "critical";
    }
    return "normal";
}

std::string NotificationManager::GetThreatIcon(int score) {
    if (score >= 90) return "dialog-error";
    if (score >= 70) return "dialog-warning";
    return "dialog-information";
}

std::string NotificationManager::GetLoggedInUser() {
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

std::string NotificationManager::GetUserDisplay(const std::string& username) {
    if (username.empty()) return ":0";
    
    // Check common displays
    std::vector<std::string> displays = {":0", ":1", ":10"};
    
    for (const auto& display : displays) {
        std::string check = "su " + username + " -c 'DISPLAY=" + display + " xdpyinfo >/dev/null 2>&1'";
        if (system(check.c_str()) == 0) {
            return display;
        }
    }
    
    return ":0";  // Default fallback
}

std::string NotificationManager::EscapeForShell(const std::string& str) {
    std::string escaped;
    for (char c : str) {
        if (c == '\'' || c == '"' || c == '\\' || c == '$' || c == '`') {
            escaped += '\\';
        }
        escaped += c;
    }
    return escaped;
}

} // namespace koraav
