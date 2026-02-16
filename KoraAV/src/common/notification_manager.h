// src/common/notification_manager.h
#ifndef KORAAV_NOTIFICATION_MANAGER_H
#define KORAAV_NOTIFICATION_MANAGER_H

#include <string>
#include <vector>
#include <cstdint>

namespace koraav {

/**
 * Desktop Notification Manager
 * Sends GUI notifications to user desktop
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
    bool SendThreatAlert(const std::string& threat_type,
                        const std::string& process_name,
                        uint32_t pid,
                        int threat_score,
                        const std::vector<std::string>& indicators);
    
    /**
     * Send a quarantine notification
     */
    bool SendQuarantineNotification(const std::string& threat_type,
                                   const std::string& process_name,
                                   const std::string& quarantine_path);
    
    /**
     * Send a system lockdown notification
     */
    bool SendLockdownNotification();
    
    /**
     * Send a custom notification
     */
    bool SendNotification(const std::string& title,
                         const std::string& message,
                         Urgency urgency = Urgency::NORMAL);

private:
    bool initialized_;
    
    bool InitializeLibnotify();
    void CleanupLibnotify();
    std::string GetUrgencyString(Urgency urgency);
    std::string GetThreatIcon(int score);
};

} // namespace koraav

#endif // KORAAV_NOTIFICATION_MANAGER_H
