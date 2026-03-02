// src/realtime-protection/response/firewall_manager.cpp
#include "firewall_manager.h"
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <cstdint>
#include <array>
#include <memory>

namespace koraav {
namespace realtime {

FirewallManager::FirewallManager() 
    : firewall_type_(FirewallType::NONE), next_rule_id_(1) {
}

FirewallManager::~FirewallManager() {
    // Cleanup all rules on destruction
    UnblockAll();
}

bool FirewallManager::Initialize() {
    std::cout << "Detecting firewall system..." << std::endl;
    
    // Try nftables first
    if (DetectNftables()) {
        firewall_type_ = FirewallType::NFTABLES;
        std::cout << "Using nftables" << std::endl;
        
        if (!InitializeNftables()) {
            std::cerr << "Failed to initialize nftables, trying iptables..." << std::endl;
            firewall_type_ = FirewallType::NONE;
        } else {
            return true;
        }
    }
    
    // Fallback to iptables
    if (DetectIptables()) {
        firewall_type_ = FirewallType::IPTABLES;
        std::cout << "Using iptables (fallback)" << std::endl;
        std::cout << "  Consider installing nftables for better security" << std::endl;
        return true;
    }
    
    std::cerr << "No firewall system found (nftables or iptables is required)" << std::endl;
    return false;
    // TODO: Install nftables if neither are found.
}

int FirewallManager::BlockProcess(uint32_t pid) {
    if (firewall_type_ == FirewallType::NONE) {
        std::cerr << "No firewall system available" << std::endl;
        return -1;
    }
    
    std::string rule_data;
    bool success = false;
    
    if (firewall_type_ == FirewallType::NFTABLES) {
        success = AddNftablesRule(pid, rule_data);
    } else {
        success = AddIptablesRule(pid, rule_data);
    }
    
    if (!success) {
        return -1;
    }
    
    int rule_id = next_rule_id_++;
    
    FirewallRule rule;
    rule.id = rule_id;
    rule.pid = pid;
    rule.rule_data = rule_data;
    rule.type = firewall_type_;
    
    active_rules_[rule_id] = rule;
    
    std::cout << "Blocked network access for PID " << pid << " (rule #" << rule_id << ")" << std::endl;
    
    return rule_id;
}

int FirewallManager::BlockAll() {
    if (firewall_type_ == FirewallType::NONE) {
        std::cerr << "No firewall system available, unable to block network access" << std::endl;
        return -1;
    }
    
    std::string rule_data;
    bool success = false;
    
    if (firewall_type_ == FirewallType::NFTABLES) {
        // Block all output
        rule_data = "koraav-block-all";
        std::string cmd = "nft add rule inet koraav output counter drop comment \"" + rule_data + "\"";
        success = RunCommand(cmd);
    } else {
        // iptables fallback
        rule_data = "OUTPUT -j DROP -m comment --comment koraav-block-all";
        success = AddIptablesRule(0, rule_data);
    }
    
    if (!success) {
        return -1;
    }
    
    int rule_id = next_rule_id_++;
    
    FirewallRule rule;
    rule.id = rule_id;
    rule.pid = 0;
    rule.rule_data = rule_data;
    rule.type = firewall_type_;
    
    active_rules_[rule_id] = rule;
    
    std::cout << "Blocked ALL network traffic (rule #" << rule_id << ")" << std::endl;
    
    return rule_id;
}

bool FirewallManager::UnblockRule(int rule_id) {
    auto it = active_rules_.find(rule_id);
    if (it == active_rules_.end()) {
        return false;
    }
    
    const auto& rule = it->second;
    bool success = false;
    
    if (rule.type == FirewallType::NFTABLES) {
        success = RemoveNftablesRule(rule.rule_data);
    } else {
        success = RemoveIptablesRule(rule.rule_data);
    }
    
    if (success) {
        active_rules_.erase(it);
        std::cout << "Unblocked rule #" << rule_id << std::endl;
    }
    
    return success;
}

bool FirewallManager::UnblockAll() {
    std::vector<int> rule_ids;
    for (const auto& [id, rule] : active_rules_) {
        rule_ids.push_back(id);
    }
    
    bool all_success = true;
    for (int id : rule_ids) {
        if (!UnblockRule(id)) {
            all_success = false;
        }
    }
    
    return all_success;
}

std::string FirewallManager::GetFirewallTypeName() const {
    switch (firewall_type_) {
        case FirewallType::NFTABLES: return "nftables";
        case FirewallType::IPTABLES: return "iptables";
        case FirewallType::NONE: return "none";
    }
    return "unknown";
}

bool FirewallManager::DetectNftables() {
    // Check if nft command exists and works
    std::string output = GetCommandOutput("nft --version 2>&1");
    return (output.find("nftables") != std::string::npos);
}

bool FirewallManager::DetectIptables() {
    // Check if iptables command exists
    std::string output = GetCommandOutput("iptables --version 2>&1");
    return (output.find("iptables") != std::string::npos);
}

bool FirewallManager::InitializeNftables() {
    // Create koraav table if it doesn't exist
    std::string check = GetCommandOutput("nft list table inet koraav 2>&1");
    
    if (check.find("No such file") != std::string::npos || 
        check.find("does not exist") != std::string::npos) {
        
        // Create table
        if (!RunCommand("nft add table inet koraav")) {
            return false;
        }
        
        std::cout << "  Created nftables table 'koraav'" << std::endl;
    }
    
    // Create chain
    return CreateNftablesChain();
}

bool FirewallManager::CreateNftablesChain() {
    // Check if chain exists
    std::string check = GetCommandOutput("nft list chain inet koraav output 2>&1");
    
    if (check.find("No such file") != std::string::npos ||
        check.find("does not exist") != std::string::npos) {
        
        // Create output chain with priority 0 (before normal processing)
        if (!RunCommand("nft add chain inet koraav output { type filter hook output priority 0 \\; }")) {
            return false;
        }
        
        std::cout << "  Created nftables chain 'output'" << std::endl;
    }
    
    return true;
}

bool FirewallManager::AddNftablesRule(uint32_t pid, std::string& rule_data) {
    std::ostringstream oss;
    rule_data = "koraav-pid-" + std::to_string(pid);
    
    // nftables rule to block by process ID
    oss << "nft add rule inet koraav output "
        << "meta skuid " << pid << " "
        << "counter drop "
        << "comment \"" << rule_data << "\"";
    
    return RunCommand(oss.str());
}

bool FirewallManager::RemoveNftablesRule(const std::string& rule_data) {
    // List rules with handles
    std::string output = GetCommandOutput("nft -a list chain inet koraav output");
    
    // Find handle for our rule
    std::istringstream iss(output);
    std::string line;
    std::string handle;
    
    while (std::getline(iss, line)) {
        if (line.find(rule_data) != std::string::npos) {
            // Extract handle number
            size_t pos = line.find("# handle ");
            if (pos != std::string::npos) {
                handle = line.substr(pos + 9);
                // Trim whitespace
                handle.erase(0, handle.find_first_not_of(" \t"));
                handle.erase(handle.find_last_not_of(" \t\n\r") + 1);
                break;
            }
        }
    }
    
    if (handle.empty()) {
        std::cerr << "Could not find nftables rule: " << rule_data << std::endl;
        return false;
    }
    
    std::string cmd = "nft delete rule inet koraav output handle " + handle;
    return RunCommand(cmd);
}

bool FirewallManager::AddIptablesRule(uint32_t pid, std::string& rule_data) {
    std::ostringstream oss;
    
    if (pid == 0) {
        // Global block
        rule_data = "OUTPUT -j DROP -m comment --comment \"koraav-global\"";
    } else {
        // Per-process block
        oss << "OUTPUT -m owner --uid-owner " << pid 
            << " -j DROP -m comment --comment \"koraav-pid-" << pid << "\"";
        rule_data = oss.str();
    }
    
    std::string cmd = "iptables -A " + rule_data;
    return RunCommand(cmd);
}

bool FirewallManager::RemoveIptablesRule(const std::string& rule_data) {
    std::string cmd = "iptables -D " + rule_data;
    return RunCommand(cmd);
}

bool FirewallManager::RunCommand(const std::string& command) {
    int result = system(command.c_str());
    return (result == 0);
}

std::string FirewallManager::GetCommandOutput(const std::string& command) {
    std::array<char, 128> buffer;
    std::string result;
    
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    
    if (!pipe) {
        return "";
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    return result;
}

} // namespace realtime
} // namespace koraav
