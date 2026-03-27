// src/common/capabilities_manager.cpp
#include "capabilities_manager.h"
#include <sys/capability.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <iostream>
#include <map>

namespace koraav {
namespace common {

// Map of capability names to descriptions
static const std::map<std::string, std::string> cap_descriptions = {
    {"CAP_SYS_ADMIN", "Mount filesystems, manage namespaces (for lockdown)"},
    {"CAP_NET_ADMIN", "Modify network configuration (for nftables/iptables)"},
    {"CAP_KILL", "Send signals to processes (kill ransomware)"},
    {"CAP_DAC_READ_SEARCH", "Bypass file read permission checks (scan all files)"},
    {"CAP_SYS_PTRACE", "Trace arbitrary processes (for process monitoring)"},
    {"CAP_SYS_RESOURCE", "Override resource limits"},
    {"CAP_BPF", "Use eBPF programs (for real-time monitoring)"},
    {"CAP_PERFMON", "Use performance monitoring (for eBPF)"}
};

CapabilitiesManager::CapabilitiesManager() {
}

CapabilitiesManager::~CapabilitiesManager() {
}

std::vector<std::string> CapabilitiesManager::GetRequiredCapabilities() {
    return {
        "CAP_SYS_ADMIN",        // For mount operations (lockdown)
        "CAP_NET_ADMIN",        // For nftables/iptables (network blocking)
        "CAP_KILL",             // For killing malicious processes
        "CAP_DAC_READ_SEARCH",  // For reading all files during scan
        "CAP_SYS_PTRACE",       // For process tree inspection
        "CAP_BPF",              // For eBPF program loading (kernel 5.8+)
        "CAP_PERFMON"           // For eBPF performance monitoring (kernel 5.8+)
    };
}

bool CapabilitiesManager::HasRequiredCapabilities() {
    auto required = GetRequiredCapabilities();
    
    for (const auto& cap_name : required) {
        if (!HasCapability(cap_name)) {
            std::cerr << "Missing required capability: " << cap_name << std::endl;
            std::cerr << "  " << GetCapabilityDescription(cap_name) << std::endl;
            return false;
        }
    }
    
    return true;
}

bool CapabilitiesManager::HasCapability(const std::string& cap_name) {
    int cap = CapabilityFromName(cap_name);
    if (cap < 0) {
        return false;
    }
    
    return CheckCapability(cap);
}

bool CapabilitiesManager::CheckCapability(int cap) {
    cap_t caps = cap_get_proc();
    if (!caps) {
        return false;
    }
    
    cap_flag_value_t value;
    int result = cap_get_flag(caps, cap, CAP_EFFECTIVE, &value);
    
    cap_free(caps);
    
    return (result == 0 && value == CAP_SET);
}

int CapabilitiesManager::CapabilityFromName(const std::string& name) {
    // Remove CAP_ prefix if present
    std::string cap_name = name;
    if (cap_name.find("CAP_") == 0) {
        cap_name = cap_name.substr(4);
    }
    
    // Map common capabilities
    static const std::map<std::string, int> cap_map = {
        {"SYS_ADMIN", CAP_SYS_ADMIN},
        {"NET_ADMIN", CAP_NET_ADMIN},
        {"KILL", CAP_KILL},
        {"DAC_READ_SEARCH", CAP_DAC_READ_SEARCH},
        {"SYS_PTRACE", CAP_SYS_PTRACE},
        {"SYS_RESOURCE", CAP_SYS_RESOURCE},
#ifdef CAP_BPF
        {"BPF", CAP_BPF},
#endif
#ifdef CAP_PERFMON
        {"PERFMON", CAP_PERFMON}
#endif
    };
    
    auto it = cap_map.find(cap_name);
    if (it != cap_map.end()) {
        return it->second;
    }
    
    return -1;
}

std::string CapabilitiesManager::CapabilityToName(int cap) {
    char* name = cap_to_name(cap);
    if (!name) {
        return "UNKNOWN";
    }
    
    std::string result = name;
    cap_free(name);
    
    return "CAP_" + result;
}

bool CapabilitiesManager::DropUnnecessaryCapabilities() {
    // Get current capabilities
    cap_t caps = cap_get_proc();
    if (!caps) {
        std::cerr << "Failed to get process capabilities" << std::endl;
        return false;
    }
    
    // Clear all capabilities
    cap_clear(caps);
    
    // Add back only required capabilities
    auto required = GetRequiredCapabilities();
    
    for (const auto& cap_name : required) {
        int cap = CapabilityFromName(cap_name);
        if (cap >= 0) {
            cap_value_t cap_list[1] = {static_cast<cap_value_t>(cap)};
            
            // Set in effective, permitted, and inheritable
            cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET);
            cap_set_flag(caps, CAP_PERMITTED, 1, cap_list, CAP_SET);
            cap_set_flag(caps, CAP_INHERITABLE, 1, cap_list, CAP_SET);
        }
    }
    
    // Apply new capability set
    if (cap_set_proc(caps) != 0) {
        std::cerr << "Failed to set process capabilities" << std::endl;
        cap_free(caps);
        return false;
    }
    
    cap_free(caps);
    
    // Prevent gaining new privileges
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        std::cerr << "Warning: Failed to set NO_NEW_PRIVS" << std::endl;
    }
    
    std::cout << "Dropped unnecessary capabilities (privilege separation)" << std::endl;
    
    return true;
}

bool CapabilitiesManager::VerifyExecutableCapabilities(const std::string& path) {
    cap_t caps = cap_get_file(path.c_str());
    if (!caps) {
        return false;
    }
    
    auto required = GetRequiredCapabilities();
    bool all_present = true;
    
    for (const auto& cap_name : required) {
        int cap = CapabilityFromName(cap_name);
        if (cap < 0) continue;
        
        cap_flag_value_t value;
        cap_value_t cap_list[1] = {static_cast<cap_value_t>(cap)};
        
        if (cap_get_flag(caps, cap_list[0], CAP_EFFECTIVE, &value) != 0 || value != CAP_SET) {
            all_present = false;
            break;
        }
    }
    
    cap_free(caps);
    return all_present;
}

std::string CapabilitiesManager::GetCapabilityDescription(const std::string& cap_name) {
    auto it = cap_descriptions.find(cap_name);
    if (it != cap_descriptions.end()) {
        return it->second;
    }
    return "Unknown capability";
}

void CapabilitiesManager::PrintCapabilityStatus() {
    std::cout << "\n=== KoraAV Capability Status ===" << std::endl;
    
    auto required = GetRequiredCapabilities();
    
    for (const auto& cap_name : required) {
        bool has = HasCapability(cap_name);
        
        std::cout << (has ? "✓" : "✗") << " " << cap_name;
        
        if (!has) {
            std::cout << " (MISSING)";
        }
        
        std::cout << std::endl;
        std::cout << "  -> " << GetCapabilityDescription(cap_name) << std::endl;
    }
    
    std::cout << "================================" << std::endl;
}

} // namespace common
} // namespace koraav
