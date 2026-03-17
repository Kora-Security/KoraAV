// src/common/notification_manager.h
// Desktop Notification Manager
#ifndef KORAAV_NOTIFICATION_MANAGER_H
#define KORAAV_NOTIFICATION_MANAGER_H

#include <string>
#include <vector>
#include <cstdint>

namespace koraav {

/**
 * Desktop Notification Manager
 * Sends GUI notifications using gdbus/notify-send as the logged-in user
 * Works across all desktop environments
 */
class NotificationManager {
public:
    NotificationManager();
    ~NotificationManager();
    
    enum class Urgency {
        LOW,
        NORMAL,
        CRITICAL
    };
    
    /**
     * Send a threat detected notification
     */
    void SendThreatAlert(const std::string& threat_type,
                        const std::string& process_name,
                        uint32_t pid,
                        int threat_score,
                        const std::vector<std::string>& indicators);
    
    /**
     * Send a quarantine notification
     */
    void SendQuarantineNotification(const std::string& threat_type,
                                    const std::string& process_name,
                                    const std::string& quarantine_path);
    
    /**
     * Send a system lockdown notification
     */
    void SendLockdownNotification();
    
    /**
     * Send a custom notification
     */
    bool SendNotification(const std::string& title,
                         const std::string& message,
                         Urgency urgency = Urgency::NORMAL);

private:
    bool initialized_;
    
    // Helper methods
    bool TestDBusConnection();
    std::string GetUserDBusAddress();
    std::string GetLoggedInUser();
    std::string EscapeForShell(const std::string& str);
    
    // Send notification via gdbus/notify-send
    bool SendDBusNotification(const std::string& title,
                             const std::string& message,
                             Urgency urgency);
};

} // namespace koraav

#endif // KORAAV_NOTIFICATION_MANAGER_H
