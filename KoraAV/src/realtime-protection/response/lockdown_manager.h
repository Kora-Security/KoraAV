// src/realtime-protection/response/lockdown_manager.h
#ifndef KORAAV_LOCKDOWN_MANAGER_H
#define KORAAV_LOCKDOWN_MANAGER_H

#include "firewall_manager.h"
#include "../../common/capabilities_manager.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <memory>

namespace koraav {
namespace realtime {

/**
 * System Lockdown Manager
 * Manages filesystem lockdown and network isolation
 * Uses capabilities instead of root
 * Uses nftables (with iptables fallback) for network blocking
 */
class LockdownManager {
public:
    LockdownManager();
    ~LockdownManager();
    
    /**
     * Lock down filesystem (make read-only)
     * Saves current state for restoration
     */
    bool LockdownFilesystem(const std::vector<std::string>& paths);
    
    /**
     * Restore filesystem to original state
     */
    bool RestoreFilesystem();
    
    /**
     * Block network for a specific process
     * Returns rule ID for later removal
     */
    int BlockProcessNetwork(uint32_t pid);
    
    /**
     * Block all network traffic
     * Returns rule ID for later removal
     */
    int BlockAllNetwork();
    
    /**
     * Restore network for specific process
     */
    bool RestoreProcessNetwork(int rule_id);
    
    /**
     * Restore all network traffic
     */
    bool RestoreAllNetwork();
    
    /**
     * Check if system is currently locked down
     */
    bool IsFilesystemLocked() const { return filesystem_locked_; }
    bool IsNetworkBlocked() const { return !network_rules_.empty(); }
    
    /**
     * Get lockdown status details
     */
    struct LockdownStatus {
        bool filesystem_locked;
        std::vector<std::string> locked_paths;
        int network_rules_active;
        std::chrono::system_clock::time_point lockdown_time;
        std::string reason;
    };
    
    LockdownStatus GetStatus() const;
    
    /**
     * Emergency unlock (for CLI use)
     * Requires administrator confirmation
     */
    bool EmergencyUnlock(const std::string& admin_password);

private:
    // Capabilities manager
    std::unique_ptr<common::CapabilitiesManager> caps_manager_;
    
    // Firewall manager (nftables/iptables)
    std::unique_ptr<FirewallManager> firewall_;
    
    // Filesystem state
    struct MountState {
        std::string path;
        std::string original_options;
        bool was_readonly;
    };
    
    bool filesystem_locked_;
    std::vector<MountState> saved_mount_states_;
    std::chrono::system_clock::time_point lockdown_time_;
    std::string lockdown_reason_;
    
    // Network state
    struct NetworkRule {
        int id;
        uint32_t pid;  // 0 for global block
        std::string iptables_rule;
        std::chrono::system_clock::time_point created;
    };
    
    std::unordered_map<int, NetworkRule> network_rules_;
    int next_rule_id_;
    
    // Helper methods
    std::string GetMountOptions(const std::string& path);
    bool RemountReadOnly(const std::string& path);
    bool RemountWithOptions(const std::string& path, const std::string& options);
    bool AddIptablesRule(const std::string& rule);
    bool RemoveIptablesRule(const std::string& rule);
    std::string GenerateIptablesRule(uint32_t pid);
    
    // State persistence
    bool SaveState(const std::string& state_file = "/opt/koraav/var/run/lockdown.state");
    bool LoadState(const std::string& state_file = "/opt/koraav/var/run/lockdown.state");
};

} // namespace realtime
} // namespace koraav

#endif // KORAAV_LOCKDOWN_MANAGER_H
