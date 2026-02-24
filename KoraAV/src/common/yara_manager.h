// src/common/yara_manager.h
#ifndef KORAAV_YARA_MANAGER_H
#define KORAAV_YARA_MANAGER_H

#include <string>
#include <vector>
#include <mutex>
#include <memory>

// Forward declare YARA types to avoid including yara.h in header
struct YR_RULES;

namespace koraav {

/**
 * Centralized YARA Rules Manager (Singleton)
 * 
 * This is the SINGLE source of truth for YARA rules in KoraAV.
 * Both the CLI scanner and real-time daemon use THIS SAME INSTANCE.
 * 
 * Rules are loaded from: /opt/koraav/share/signatures/yara-rules/
 * 
 * Features:
 * - Runtime loading (no compilation into binary)
 * - Hot-reload support (add rules without restart)
 * - Thread-safe scanning
 * - Recursive directory scanning
 * - Subdirectory organization supported
 */
class YaraManager {
public:
    // Get singleton instance
    static YaraManager& Instance();
    
    // Initialize YARA library (call once at startup)
    bool Initialize();
    
    // Load/reload all rules from directory
    // Scans recursively, so subdirectories are supported
    bool LoadRules(const std::string& rules_dir = "/opt/koraav/share/signatures/yara-rules");
    
    // Reload rules (for when user adds new .yar files)
    bool Reload();
    
    // Scan operations (thread-safe)
    std::vector<std::string> ScanFile(const std::string& path);
    std::vector<std::string> ScanMemory(const void* data, size_t size);
    
    // Status
    bool IsReady() const;
    std::string GetRulesDirectory() const { return rules_dir_; }
    int GetRuleCount() const;
    
    // Cleanup
    void Shutdown();
    
private:
    YaraManager();
    ~YaraManager();
    
    // Singleton - no copying
    YaraManager(const YaraManager&) = delete;
    YaraManager& operator=(const YaraManager&) = delete;
    
    YR_RULES* rules_;
    std::string rules_dir_;
    bool initialized_;
    mutable std::mutex mutex_;  // Thread safety for scanning
    
    // Helper to load rules from directory
    bool LoadRulesInternal(const std::string& dir);
};

} // namespace koraav

#endif // KORAAV_YARA_MANAGER_H
