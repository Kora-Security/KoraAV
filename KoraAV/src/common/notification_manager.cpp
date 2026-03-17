// src/common/notification_manager.cpp
// Desktop Notification Manager - Direct DBUS implementation
// Works across all desktop environments (KDE, GNOME, XFCE, etc.)

#include "notification_manager.h"
#include <cstring>
#include <dbus/dbus.h>
#include <fstream>
#include <iostream>
#include <pwd.h>
#include <sstream>
#include <unistd.h>

namespace koraav {

    NotificationManager::NotificationManager()
    : initialized_(false)
    {
        // Test DBUS connection
        initialized_ = TestDBusConnection();

        if (initialized_) {
            std::cout << "✓ Notification manager initialized (DBUS)" << std::endl;
        } else {
            std::cout << "⚠️  Notification manager: DBUS not available (will use "
            "console fallback)"
            << std::endl;
        }
    }

    NotificationManager::~NotificationManager()
    {
        // Nothing to clean up
    }

    void
    NotificationManager::SendThreatAlert(const std::string& threat_type,
                                         const std::string& process_name,
                                         uint32_t pid,
                                         int threat_score,
                                         const std::vector<std::string>& indicators)
    {
        // Build message
        std::ostringstream title;
        title << "🚨 " << threat_type << " Detected!";

        std::ostringstream message;
        message << "Process: " << process_name << " (PID " << pid << ")\n";
        message << "Threat Score: " << threat_score << "/100\n";

        if (!indicators.empty()) {
            message << "Indicators:\n";
            for (const auto& indicator : indicators) {
                message << "  • " << indicator << "\n";
            }
        }

        // Also log to console (always visible in journalctl)
        std::cout << "\n[NOTIFICATION] " << title.str() << std::endl;
        std::cout << message.str() << std::endl;

        // Send desktop notification
        SendNotification(title.str(), message.str(), Urgency::CRITICAL);
    }

    bool
    NotificationManager::SendNotification(const std::string& title,
                                          const std::string& message,
                                          Urgency urgency)
    {
        if (!initialized_) {
            // Fallback to console only
            std::cout << "\n[NOTIFICATION] " << title << "\n"
            << message << "\n"
            << std::endl;
            return false;
        }

        // Try DBUS notification
        return SendDBusNotification(title, message, urgency);
    }

    bool
    NotificationManager::TestDBusConnection()
    {
        DBusError error;
        dbus_error_init(&error);

        // Try to connect to session bus
        DBusConnection* conn = dbus_bus_get(DBUS_BUS_SESSION, &error);

        if (dbus_error_is_set(&error)) {
            std::cerr << "[DBUS DEBUG] Session bus connection failed: " << error.message
            << std::endl;
            dbus_error_free(&error);
            return false;
        }

        if (conn == nullptr) {
            std::cerr << "[DBUS DEBUG] Session bus connection is null" << std::endl;
            return false;
        }

        // Don't close connection - we'll reuse it
        // dbus_connection_unref(conn);

        std::cout << "[DBUS DEBUG] Session bus connection successful" << std::endl;
        return true;
    }

    std::string
    NotificationManager::GetUserDBusAddress()
    {
        // Try to get logged-in user's DBUS session address
        std::string username = GetLoggedInUser();
        if (username.empty()) {
            return "";
        }

        // Get user's UID
        struct passwd* pw = getpwnam(username.c_str());
        if (!pw) {
            return "";
        }

        // Try standard session bus address
        std::ostringstream dbus_addr;
        dbus_addr << "unix:path=/run/user/" << pw->pw_uid << "/bus";

        return dbus_addr.str();
    }

    std::string
    NotificationManager::GetLoggedInUser()
    {
        // Get first logged-in user
        FILE* pipe = popen("who | awk '{print $1}' | head -1", "r");
        if (!pipe)
            return "";

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

    bool
    NotificationManager::SendDBusNotification(const std::string& title,
                                              const std::string& message,
                                              Urgency urgency)
    {
        DBusError error;
        dbus_error_init(&error);

        // ═══════════════════════════════════════════════════════════════
        // CRITICAL: Connect to SESSION bus (user's desktop session)
        // ═══════════════════════════════════════════════════════════════

        // First, try to get user's DBUS address
        std::string user_dbus = GetUserDBusAddress();

        DBusConnection* conn = nullptr;

        if (!user_dbus.empty()) {
            // Try to connect using user's specific session bus
            std::cout << "[DBUS DEBUG] Trying user session bus: " << user_dbus
            << std::endl;

            // Set environment variable temporarily
            setenv("DBUS_SESSION_BUS_ADDRESS", user_dbus.c_str(), 1);

            conn = dbus_bus_get(DBUS_BUS_SESSION, &error);

            if (dbus_error_is_set(&error)) {
                std::cerr << "[DBUS DEBUG] User session bus failed: " << error.message
                << std::endl;
                dbus_error_free(&error);
                conn = nullptr;
            }
        }

        // Fallback: try default session bus
        if (conn == nullptr) {
            std::cout << "[DBUS DEBUG] Trying default session bus" << std::endl;
            conn = dbus_bus_get(DBUS_BUS_SESSION, &error);

            if (dbus_error_is_set(&error)) {
                std::cerr << "[DBUS DEBUG] Default session bus failed: " << error.message
                << std::endl;
                dbus_error_free(&error);

                // Final fallback: console only
                std::cout << "\n[NOTIFICATION FALLBACK] " << title << "\n"
                << message << "\n"
                << std::endl;
                return false;
            }
        }

        if (conn == nullptr) {
            std::cerr << "[DBUS DEBUG] All DBUS connection attempts failed"
            << std::endl;
            std::cout << "\n[NOTIFICATION FALLBACK] " << title << "\n"
            << message << "\n"
            << std::endl;
            return false;
        }

        std::cout << "[DBUS DEBUG] DBUS connection established" << std::endl;

        // ═══════════════════════════════════════════════════════════════
        // Call org.freedesktop.Notifications.Notify
        // ═══════════════════════════════════════════════════════════════
        // This is the standard notification API used by ALL desktop environments
        // ═══════════════════════════════════════════════════════════════

        DBusMessage* msg =
        dbus_message_new_method_call("org.freedesktop.Notifications", // destination
                                     "/org/freedesktop/Notifications", // path
                                     "org.freedesktop.Notifications",  // interface
                                     "Notify"                          // method
        );

        if (msg == nullptr) {
            std::cerr << "[DBUS DEBUG] Failed to create message" << std::endl;
            dbus_connection_unref(conn);
            return false;
        }

        // Prepare arguments for Notify method:
        // Notify(app_name, replaces_id, icon, summary, body, actions, hints, timeout)

        const char* app_name = "KoraAV";
        dbus_uint32_t replaces_id = 0;          // Don't replace
        const char* app_icon = "security-high"; // Standard icon
        const char* summary = title.c_str();
        const char* body = message.c_str();
        dbus_int32_t timeout = 10000; // 10 seconds

        // Empty arrays for actions and hints
        DBusMessageIter args, array;
        dbus_message_iter_init_append(msg, &args);

        // app_name
        if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &app_name)) {
            std::cerr << "[DBUS DEBUG] Failed to append app_name" << std::endl;
            dbus_message_unref(msg);
            dbus_connection_unref(conn);
            return false;
        }

        // replaces_id
        if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &replaces_id)) {
            std::cerr << "[DBUS DEBUG] Failed to append replaces_id" << std::endl;
            dbus_message_unref(msg);
            dbus_connection_unref(conn);
            return false;
        }

        // app_icon
        if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &app_icon)) {
            std::cerr << "[DBUS DEBUG] Failed to append app_icon" << std::endl;
            dbus_message_unref(msg);
            dbus_connection_unref(conn);
            return false;
        }

        // summary (title)
        if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &summary)) {
            std::cerr << "[DBUS DEBUG] Failed to append summary" << std::endl;
            dbus_message_unref(msg);
            dbus_connection_unref(conn);
            return false;
        }

        // body (message)
        if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &body)) {
            std::cerr << "[DBUS DEBUG] Failed to append body" << std::endl;
            dbus_message_unref(msg);
            dbus_connection_unref(conn);
            return false;
        }

        // actions (empty array)
        if (!dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "s", &array)) {
            std::cerr << "[DBUS DEBUG] Failed to open actions array" << std::endl;
            dbus_message_unref(msg);
            dbus_connection_unref(conn);
            return false;
        }
        dbus_message_iter_close_container(&args, &array);

        // hints (dict - urgency level)
        DBusMessageIter dict, entry, variant;
        if (!dbus_message_iter_open_container(
            &args, DBUS_TYPE_ARRAY, "{sv}", &dict)) {
            std::cerr << "[DBUS DEBUG] Failed to open hints dict" << std::endl;
        dbus_message_unref(msg);
        dbus_connection_unref(conn);
        return false;
            }

            // Add urgency hint
            const char* urgency_key = "urgency";
            dbus_uint32_t urgency_value;

            switch (urgency) {
                case Urgency::LOW:
                    urgency_value = 0;
                    break;
                case Urgency::CRITICAL:
                    urgency_value = 2;
                    break;
                default:
                    urgency_value = 1; // NORMAL
                    break;
            }

            dbus_message_iter_open_container(
                &dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
            dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &urgency_key);
            dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "y", &variant);
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_BYTE, &urgency_value);
            dbus_message_iter_close_container(&entry, &variant);
            dbus_message_iter_close_container(&dict, &entry);

            dbus_message_iter_close_container(&args, &dict);

            // timeout
            if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_INT32, &timeout)) {
                std::cerr << "[DBUS DEBUG] Failed to append timeout" << std::endl;
                dbus_message_unref(msg);
                dbus_connection_unref(conn);
                return false;
            }

            std::cout << "[DBUS DEBUG] Sending notification: " << title << std::endl;

            // Send the message and wait for reply
            DBusMessage* reply =
            dbus_connection_send_with_reply_and_block(conn, msg, 1000, &error);

            // Clean up message
            dbus_message_unref(msg);

            if (dbus_error_is_set(&error)) {
                std::cerr << "[DBUS DEBUG] Notification send failed: " << error.message
                << std::endl;
                dbus_error_free(&error);
                dbus_connection_unref(conn);

                // Console fallback
                std::cout << "\n[NOTIFICATION FALLBACK] " << title << "\n"
                << message << "\n"
                << std::endl;
                return false;
            }

            if (reply) {
                // Get notification ID (we don't use it, but good for debugging)
                dbus_uint32_t notification_id = 0;
                if (dbus_message_get_args(reply,
                    &error,
                    DBUS_TYPE_UINT32,
                    &notification_id,
                    DBUS_TYPE_INVALID)) {
                    std::cout << "[DBUS DEBUG] Notification sent successfully (ID: "
                    << notification_id << ")" << std::endl;
                    }
                    dbus_message_unref(reply);
            }

            // Don't unref connection - keep it alive for future notifications
            // dbus_connection_unref(conn);

            return true;
    }

    void
    NotificationManager::SendQuarantineNotification(
        const std::string& threat_type,
        const std::string& process_name,
        const std::string& quarantine_path)
    {
        // Build title and message
        std::ostringstream title;
        title << "🔒 File Quarantined";

        std::ostringstream message;
        message << "Threat Type: " << threat_type << "\n";
        message << "Process: " << process_name << "\n";
        message << "Location: " << quarantine_path;

        // Log to console (always visible in journalctl)
        std::cout << "\n[NOTIFICATION] " << title.str() << std::endl;
        std::cout << message.str() << std::endl;

        // Send desktop notification
        SendNotification(title.str(), message.str(), Urgency::NORMAL);
    }

    void
    NotificationManager::SendLockdownNotification()
    {
        std::string title = "🚨 SYSTEM LOCKDOWN INITIATED";
        std::string message = "KoraAV has detected a severe threat.\n"
        "System has been locked down to prevent damage.\n"
        "Check logs: sudo journalctl -u korad";

        // Log to console (always visible in journalctl)
        std::cout << "\n[NOTIFICATION] " << title << std::endl;
        std::cout << message << std::endl;

        // Send desktop notification (CRITICAL urgency)
        SendNotification(title, message, Urgency::CRITICAL);
    }

} // namespace koraav
