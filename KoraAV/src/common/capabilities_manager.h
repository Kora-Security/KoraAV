// src/common/capabilities_manager.h
#ifndef KORAAV_CAPABILITIES_MANAGER_H
#define KORAAV_CAPABILITIES_MANAGER_H

#include <string>
#include <vector>

namespace koraav {
namespace common {

/**
 * Capabilities Manager
 * Manages Linux capabilities for privilege separation
 * Uses libcap for fine-grained permissions instead of full root
 */
class CapabilitiesManager {
public:
    CapabilitiesManager();
    ~CapabilitiesManager();
    
    /**
     * Check if running with required capabilities
     */
    bool HasRequiredCapabilities();
    
    /**
     * List of required capabilities for KoraAV daemon
     */
    static std::vector<std::string> GetRequiredCapabilities();
    
    /**
     * Check specific capability
     */
    bool HasCapability(const std::string& cap_name);
    
    /**
     * Drop all capabilities except required ones
     * Called after initialization to reduce attack surface
     */
    bool DropUnnecessaryCapabilities();
    
    /**
     * Verify capabilities are set on executable
     */
    static bool VerifyExecutableCapabilities(const std::string& path);
    
    /**
     * Get human-readable capability description
     */
    static std::string GetCapabilityDescription(const std::string& cap_name);
    
    void PrintCapabilityStatus();

private:
    bool CheckCapability(int cap);
    int CapabilityFromName(const std::string& name);
    std::string CapabilityToName(int cap);
};

} // namespace common
} // namespace koraav

#endif // KORAAV_CAPABILITIES_MANAGER_H
