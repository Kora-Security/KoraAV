// src/realtime-protection/response/lockdown_manager.cpp
#include "lockdown_manager.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sys/mount.h>
#include <mntent.h>

namespace koraav {
namespace realtime {

LockdownManager::LockdownManager() 
    : filesystem_locked_(false), next_rule_id_(1) {
    // Initialize capabilities manager
    caps_manager_ = std::make_unique<common::CapabilitiesManager>();
    
    // Initialize firewall manager
    firewall_ = std::make_unique<FirewallManager>();
    firewall_->Initialize();
    
    // Try to restore previous state if daemon crashed
    LoadState();
}

LockdownManager::~LockdownManager() {
    // Emergency cleanup - restore everything
    if (filesystem_locked_) {
        std::cerr << "Warning: Filesystem still locked on shutdown, restoring..." << std::endl;
        RestoreFilesystem();
    }
    
    if (!network_rules_.empty()) {
        std::cerr << "Warning: Network rules still active, removing..." << std::endl;
        RestoreAllNetwork();
    }
}

bool LockdownManager::LockdownFilesystem(const std::vector<std::string>& paths) {
    // Check for CAP_SYS_ADMIN capability
    if (!caps_manager_->HasCapability("CAP_SYS_ADMIN")) {
        std::cerr << "ERROR: Filesystem lockdown requires CAP_SYS_ADMIN capability" << std::endl;
        std::cerr << "Ensure koraav daemon has proper capabilities set" << std::endl;
        return false;
    }
    
    if (filesystem_locked_) {
        std::cerr << "Filesystem already locked" << std::endl;
        return false;
    }
    
    std::cout << "LOCKING DOWN FILESYSTEM.." << std::endl;
    
    // Save current state for each path
    for (const auto& path : paths) {
        MountState state;
        state.path = path;
        state.original_options = GetMountOptions(path);
        state.was_readonly = (state.original_options.find("ro") != std::string::npos);
        
        saved_mount_states_.push_back(state);
        
        // Remount as read-only
        if (!RemountReadOnly(path)) {
            std::cerr << "Failed to lock " << path << std::endl;
            // Continue with other paths
        } else {
            std::cout << "   Locked: " << path << std::endl;
        }
    }
    
    filesystem_locked_ = true;
    lockdown_time_ = std::chrono::system_clock::now();
    
    // Save state to disk
    SaveState();
    
    std::cout << "FILESYSTEM LOCKED - " << paths.size() << " path(s)" << std::endl;
    std::cout << "   To unlock: sudo koraav unlock --filesystem" << std::endl;
    
    return true;
}

bool LockdownManager::RestoreFilesystem() {
    // Check for CAP_SYS_ADMIN capability
    if (!caps_manager_->HasCapability("CAP_SYS_ADMIN")) {
        std::cerr << "ERROR: Filesystem restore requires CAP_SYS_ADMIN capability" << std::endl;
        std::cerr << "Run: sudo koraav unlock --filesystem" << std::endl;
        return false;
    }
    
    if (!filesystem_locked_) {
        std::cout << "Filesystem not locked" << std::endl;
        return true;
    }
    
    std::cout << "RESTORING FILESYSTEM.." << std::endl;
    
    bool all_success = true;
    
    // Restore each mount point to original state
    for (const auto& state : saved_mount_states_) {
        if (state.was_readonly) {
            // Was already read-only, leave it
            std::cout << state.path << " (was already read-only)" << std::endl;
        } else {
            // Restore to read-write
            if (!RemountWithOptions(state.path, "rw")) {
                std::cerr << "   Failed to restore " << state.path << std::endl;
                all_success = false;
            } else {
                std::cout << "   Restored: " << state.path << std::endl;
            }
        }
    }
    
    saved_mount_states_.clear();
    filesystem_locked_ = false;
    
    // Remove state file
    std::remove("/opt/koraav/var/run/lockdown.state");
    
    if (all_success) {
        std::cout << "FILESYSTEM RESTORED!" << std::endl;
    } else {
        std::cout << "FILESYSTEM PARTIALLY RESTORED (some errors occurred)" << std::endl;
    }
    
    return all_success;
}

int LockdownManager::BlockProcessNetwork(uint32_t pid) {
    // Check for CAP_NET_ADMIN capability
    if (!caps_manager_->HasCapability("CAP_NET_ADMIN")) {
        std::cerr << "ERROR: Network blocking requires CAP_NET_ADMIN capability" << std::endl;
        return -1;
    }
    
    // Use firewall manager
    return firewall_->BlockProcess(pid);
}

int LockdownManager::BlockAllNetwork() {
    // Check for CAP_NET_ADMIN capability
    if (!caps_manager_->HasCapability("CAP_NET_ADMIN")) {
        std::cerr << "ERROR: Network blocking requires CAP_NET_ADMIN capability" << std::endl;
        return -1;
    }
    
    // Use firewall manager
    return firewall_->BlockAll();
}

bool LockdownManager::RestoreProcessNetwork(int rule_id) {
    return firewall_->UnblockRule(rule_id);
}

bool LockdownManager::RestoreAllNetwork() {
    return firewall_->UnblockAll();
}

LockdownManager::LockdownStatus LockdownManager::GetStatus() const {
    LockdownStatus status;
    status.filesystem_locked = filesystem_locked_;
    
    for (const auto& state : saved_mount_states_) {
        status.locked_paths.push_back(state.path);
    }
    
    status.network_rules_active = network_rules_.size();
    status.lockdown_time = lockdown_time_;
    status.reason = lockdown_reason_;
    
    return status;
}

bool LockdownManager::EmergencyUnlock(const std::string&) {
    
    // Check for required capabilities
    if (!caps_manager_->HasCapability("CAP_SYS_ADMIN") || 
        !caps_manager_->HasCapability("CAP_NET_ADMIN")) {
        std::cerr << "ERROR: Emergency unlock requires CAP_SYS_ADMIN and CAP_NET_ADMIN" << std::endl;
        std::cerr << "Please run: sudo koraav unlock --all" << std::endl;
        return false;
    }
    
    std::cout << "EMERGENCY UNLOCK INITIATED!" << std::endl;
    std::cout << "Running with required capabilities" << std::endl;
    
    bool fs_ok = RestoreFilesystem();
    bool net_ok = RestoreAllNetwork();
    
    if (fs_ok && net_ok) {
        std::cout << "SYSTEM UNLOCKED!" << std::endl;
        return true;
    } else {
        std::cout << "SYSTEM PARTIALLY UNLOCKED (check logs)" << std::endl;
        return false;
    }
}

std::string LockdownManager::GetMountOptions(const std::string& path) {
    FILE* mtab = setmntent("/etc/mtab", "r");
    if (!mtab) {
        return "";
    }
    
    struct mntent* entry;
    std::string options;
    
    while ((entry = getmntent(mtab)) != nullptr) {
        if (std::string(entry->mnt_dir) == path) {
            options = entry->mnt_opts;
            break;
        }
    }
    
    endmntent(mtab);
    return options;
}

bool LockdownManager::RemountReadOnly(const std::string& path) {
    // Use mount syscall to remount as read-only
    int ret = mount(nullptr, path.c_str(), nullptr, MS_REMOUNT | MS_RDONLY, nullptr);
    
    if (ret != 0) {
        std::cerr << "mount() failed for " << path << ": " << strerror(errno) << std::endl;
        
        // Fallback to mount command
        std::string cmd = "mount -o remount,ro " + path + " 2>&1";
        int result = system(cmd.c_str());
        return (result == 0);
    }
    
    return true;
}

bool LockdownManager::RemountWithOptions(const std::string& path, const std::string& options) {
    // Use mount command
    std::string cmd = "mount -o remount," + options + " " + path + " 2>&1";
    int result = system(cmd.c_str());
    return (result == 0);
}

bool LockdownManager::AddIptablesRule(const std::string& rule) {
    std::string cmd = "iptables -A " + rule + " 2>&1";
    int result = system(cmd.c_str());
    return (result == 0);
}

bool LockdownManager::RemoveIptablesRule(const std::string& rule) {
    std::string cmd = "iptables -D " + rule + " 2>&1";
    int result = system(cmd.c_str());
    return (result == 0);
}

std::string LockdownManager::GenerateIptablesRule(uint32_t pid) {
    std::ostringstream oss;
    oss << "OUTPUT -m owner --pid-owner " << pid << " -j DROP";
    return oss.str();
}

bool LockdownManager::SaveState(const std::string& state_file) {
    std::ofstream file(state_file);
    if (!file) {
        return false;
    }
    
    // Save filesystem state
    file << "filesystem_locked=" << filesystem_locked_ << "\n";
    file << "lockdown_time=" << std::chrono::system_clock::to_time_t(lockdown_time_) << "\n";
    
    for (const auto& state : saved_mount_states_) {
        file << "mount=" << state.path << ":" << state.original_options 
             << ":" << state.was_readonly << "\n";
    }
    
    // Save network rules
    for (const auto& [id, rule] : network_rules_) {
        file << "network=" << id << ":" << rule.pid << ":" << rule.iptables_rule << "\n";
    }
    
    return true;
}

bool LockdownManager::LoadState(const std::string& state_file) {
    std::ifstream file(state_file);
    if (!file) {
        return false;  // No previous state
    }
    
    std::cout << "Loading previous lockdown state from " << state_file << std::endl;
    
    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // Parse key=value format
        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) {
            continue;
        }
        
        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);
        
        if (key == "filesystem_locked") {
            filesystem_locked_ = (value == "1" || value == "true");
        }
        else if (key == "lockdown_time") {
            time_t timestamp = std::stol(value);
            lockdown_time_ = std::chrono::system_clock::from_time_t(timestamp);
        }
        else if (key == "mount") {
            // Format: mount=path:options:was_readonly
            size_t colon1 = value.find(':');
            size_t colon2 = value.find(':', colon1 + 1);
            
            if (colon1 != std::string::npos && colon2 != std::string::npos) {
                MountState state;
                state.path = value.substr(0, colon1);
                state.original_options = value.substr(colon1 + 1, colon2 - colon1 - 1);
                state.was_readonly = (value.substr(colon2 + 1) == "1" || 
                                     value.substr(colon2 + 1) == "true");
                
                saved_mount_states_.push_back(state);
            }
        }
        else if (key == "network") {
            // Format: network=id:pid:rule
            size_t colon1 = value.find(':');
            size_t colon2 = value.find(':', colon1 + 1);
            
            if (colon1 != std::string::npos && colon2 != std::string::npos) {
                NetworkRule rule;
                rule.id = std::stoi(value.substr(0, colon1));
                rule.pid = std::stoul(value.substr(colon1 + 1, colon2 - colon1 - 1));
                rule.iptables_rule = value.substr(colon2 + 1);
                rule.created = std::chrono::system_clock::now();
                
                network_rules_[rule.id] = rule;
                
                // Track highest ID
                if (rule.id >= next_rule_id_) {
                    next_rule_id_ = rule.id + 1;
                }
            }
        }
    }
    
    if (filesystem_locked_) {
        std::cout << "Previous filesystem lockdown detected" << std::endl;
        std::cout << "   Locked paths: " << saved_mount_states_.size() << std::endl;
        std::cout << "   To restore: sudo koraav unlock --filesystem" << std::endl;
    }
    
    if (!network_rules_.empty()) {
        std::cout << "Previous network blocks detected" << std::endl;
        std::cout << "   Active rules: " << network_rules_.size() << std::endl;
        std::cout << "   To restore: sudo koraav unlock --network" << std::endl;
    }
    
    return true;
}

} // namespace realtime
} // namespace koraav
