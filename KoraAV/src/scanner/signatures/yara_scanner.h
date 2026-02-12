// src/scanner/signatures/yara_scanner.h
#ifndef KORAAV_YARA_SCANNER_H
#define KORAAV_YARA_SCANNER_H

#include <string>
#include <vector>
#include <memory>
#include <yara.h>

namespace koraav {
namespace scanner {

/**
 * YARA rule-based scanning
 * Full integration with libyara
 */
class YaraScanner {
public:
    YaraScanner();
    ~YaraScanner();
    
    // Disable copy (YARA rules aren't copyable)
    YaraScanner(const YaraScanner&) = delete;
    YaraScanner& operator=(const YaraScanner&) = delete;
    
    /**
     * Load all .yar and .yara files from a directory
     */
    bool LoadRules(const std::string& rules_dir);
    
    /**
     * Load a single rule file
     */
    bool LoadRuleFile(const std::string& rule_path);
    
    /**
     * Scan data in memory
     * Returns list of rule names that matched
     */
    std::vector<std::string> ScanData(const std::vector<char>& data);
    
    /**
     * Scan a file on disk
     */
    std::vector<std::string> ScanFile(const std::string& path);
    
    /**
     * Check if YARA is initialized
     */
    bool IsInitialized() const { return rules_ != nullptr; }
    
private:
    YR_RULES* rules_;
    bool yara_initialized_;
    
    // Helper to compile rules from directory
    bool CompileRulesFromDirectory(const std::string& dir, YR_COMPILER* compiler);
};

} // namespace scanner
} // namespace koraav

#endif // KORAAV_YARA_SCANNER_H
