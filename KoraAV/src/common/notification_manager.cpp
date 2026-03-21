// src/common/notification_manager.cpp
// Desktop Notification Manager - Socket-based notification helper
// System daemon sends notifications via Unix socket to user-space helper

#include "notification_manager.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <pwd.h>
#include <sstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace koraav {

NotificationManager::NotificationManager()
  : initialized_(false)
{
  // Check if notification tools are available
  initialized_ = TestDBusConnection();

  if (initialized_) {
    std::cout << "✓ Notification manager initialized" << std::endl;
  } else {
    std::cout << "⚠️  Notification manager: Desktop notifications unavailable "
                 "(will use console fallback)"
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

  // Send via gdbus/notify-send as the logged-in user
  return SendDBusNotification(title, message, urgency);
}

bool
NotificationManager::TestDBusConnection()
{
  // Check if we can find a logged-in user
  std::string username = GetLoggedInUser();
  if (username.empty()) {
    std::cerr << "[NOTIFICATION DEBUG] No logged-in user found" << std::endl;
    return false;
  }

  std::cout << "[NOTIFICATION DEBUG] Found logged-in user: " << username
            << std::endl;

  // Check if gdbus or notify-send is available
  if (system("command -v gdbus >/dev/null 2>&1") == 0) {
    std::cout << "[NOTIFICATION DEBUG] gdbus is available" << std::endl;
    return true;
  }

  if (system("command -v notify-send >/dev/null 2>&1") == 0) {
    std::cout << "[NOTIFICATION DEBUG] notify-send is available" << std::endl;
    return true;
  }

  std::cerr
    << "[NOTIFICATION DEBUG] No notification tools found (gdbus or notify-send)"
    << std::endl;
  return false;
}

std::string
NotificationManager::GetUserDBusAddress()
{
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

std::string
NotificationManager::EscapeForShell(const std::string& str)
{
  std::string escaped;
  for (char c : str) {
    if (c == '\'' || c == '"' || c == '\\' || c == '$' || c == '`' ||
        c == '!') {
      escaped += '\\';
    }
    escaped += c;
  }
  return escaped;
}

std::string
NotificationManager::EscapeJSON(const std::string& str)
{
  std::string escaped;
  for (char c : str) {
    switch (c) {
      case '"':  escaped += "\\\""; break;
      case '\\': escaped += "\\\\"; break;
      case '\n': escaped += "\\n"; break;
      case '\r': escaped += "\\r"; break;
      case '\t': escaped += "\\t"; break;
      default:   escaped += c; break;
    }
  }
  return escaped;
}

bool
NotificationManager::SendDBusNotification(const std::string& title,
                                          const std::string& message,
                                          Urgency urgency)
{
  // ═══════════════════════════════════════════════════════════
  // ENTERPRISE SOLUTION: Socket-based notification
  // Socket location: /run/user/<UID>/koraav-notifications.sock
  // Installer adds koraav to user's group for secure access
  // ═══════════════════════════════════════════════════════════
  
  // Get logged-in user to find their runtime directory
  std::string username = GetLoggedInUser();
  if (username.empty()) {
    std::cout << "[NOTIFICATION] Could not detect logged-in user" << std::endl;
    std::cout << "[NOTIFICATION FALLBACK] " << title << "\n" << message << std::endl;
    return false;
  }
  
  struct passwd* pw = getpwnam(username.c_str());
  if (!pw) {
    std::cout << "[NOTIFICATION] Could not get user info for: " << username << std::endl;
    std::cout << "[NOTIFICATION FALLBACK] " << title << "\n" << message << std::endl;
    return false;
  }
  
  // Construct socket path in user's runtime directory
  std::string socket_path = "/run/user/" + std::to_string(pw->pw_uid) + "/koraav-notifications.sock";
  
  std::cout << "[NOTIFICATION] Attempting to send notification to user: " << username 
            << " (UID " << pw->pw_uid << ")" << std::endl;
  std::cout << "[NOTIFICATION] Socket path: " << socket_path << std::endl;
  
  // Map urgency
  std::string urgency_str;
  switch (urgency) {
    case Urgency::LOW:
      urgency_str = "low";
      break;
    case Urgency::CRITICAL:
      urgency_str = "critical";
      break;
    default:
      urgency_str = "normal";
      break;
  }
  
  // Build JSON request
  std::ostringstream json;
  json << "{"
       << "\"title\":\"" << EscapeJSON(title) << "\","
       << "\"message\":\"" << EscapeJSON(message) << "\","
       << "\"urgency\":\"" << urgency_str << "\""
       << "}";
  
  std::string request = json.str();
  
  // Connect to helper socket
  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0) {
    std::cout << "[NOTIFICATION FALLBACK] " << title << "\n" << message << std::endl;
    return false;
  }
  
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
  
  if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    close(sock);
    std::cout << "[NOTIFICATION] Helper not running - notifications unavailable" << std::endl;
    std::cout << "  Expected socket at: " << socket_path << std::endl;
    std::cout << "[NOTIFICATION FALLBACK] " << title << "\n" << message << std::endl;
    return false;
  }
  
  // Send request
  ssize_t sent = send(sock, request.c_str(), request.length(), 0);
  if (sent < 0) {
    close(sock);
    std::cout << "[NOTIFICATION FALLBACK] " << title << "\n" << message << std::endl;
    return false;
  }
  
  // Receive response
  char buffer[1024];
  ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
  close(sock);
  
  if (received > 0) {
    buffer[received] = '\0';
    std::string response(buffer);
    
    if (response.find("\"success\":true") != std::string::npos) {
      std::cout << "✅ Desktop notification sent" << std::endl;
      return true;
    }
  }
  
  std::cout << "[NOTIFICATION FALLBACK] " << title << "\n" << message << std::endl;
  return false;
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
  message << "Threat Type: " << threat_type << "\\n";
  message << "Process: " << process_name << "\\n";
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
