// src/realtime-protection/response/firewall_manager.h
#ifndef KORAAV_FIREWALL_MANAGER_H
#define KORAAV_FIREWALL_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace koraav {
namespace realtime {

/**
 * Firewall Manager
 * Handles network blocking using nftables (preferred) with iptables fallback
 */
class FirewallManager {
public:
    enum class FirewallType {
        NFTABLES,
        IPTABLES,
        NONE
    };
    
    FirewallManager();
    ~FirewallManager();
    
    /**
     * Initialize firewall (detect nftables/iptables)
     */
    bool Initialize();
    
    /**
     * Block network for specific process
     */
    int BlockProcess(uint32_t pid);
    
    /**
     * Block all outgoing network traffic
     */
    int BlockAll();
    
    /**
     * Restore network for specific rule
     */
    bool UnblockRule(int rule_id);
    
    /**
     * Restore all network rules
     */
    bool UnblockAll();
    
    /**
     * Get active firewall type
     */
    FirewallType GetFirewallType() const { return firewall_type_; }
    
    /**
     * Get firewall type name
     */
    std::string GetFirewallTypeName() const;

private:
    FirewallType firewall_type_;
    int next_rule_id_;
    
    struct FirewallRule {
        int id;
        uint32_t pid;  // 0 for global block
        std::string rule_data;
        FirewallType type;
    };
    
    std::map<int, FirewallRule> active_rules_;
    
    // Detection
    bool DetectNftables();
    bool DetectIptables();
    
    // nftables operations
    bool InitializeNftables();
    bool CreateNftablesChain();
    bool AddNftablesRule(uint32_t pid, std::string& rule_data);
    bool RemoveNftablesRule(const std::string& rule_data);
    
    // iptables operations
    bool AddIptablesRule(uint32_t pid, std::string& rule_data);
    bool RemoveIptablesRule(const std::string& rule_data);
    
    // Utilities
    bool RunCommand(const std::string& command);
    std::string GetCommandOutput(const std::string& command);
};

} // namespace realtime
} // namespace koraav

#endif // KORAAV_FIREWALL_MANAGER_H
