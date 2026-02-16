// src/scanner/signatures/yara_scanner.h
#ifndef KORAAV_YARA_SCANNER_H
#define KORAAV_YARA_SCANNER_H

#include "../../common/yara_manager.h"
#include <string>
#include <vector>

namespace koraav {
namespace scanner {

/**
 * YARA Scanner Wrapper
 * 
 * This is now just a thin wrapper around the centralized YaraManager.
 * All actual YARA operations go through YaraManager::Instance().
 * 
 * This class exists for backwards compatibility with existing code.
 */
class YaraScanner {
public:
    YaraScanner();
    ~YaraScanner() = default;
    
    /**
     * Load all .yar files from directory
     * (Delegates to YaraManager)
     */
    bool LoadRules(const std::string& rules_dir);
    
    /**
     * Scan data in memory
     */
    std::vector<std::string> ScanData(const std::vector<char>& data);
    
    /**
     * Scan a file on disk
     */
    std::vector<std::string> ScanFile(const std::string& path);
    
    /**
     * Check if YARA is ready
     */
    bool IsInitialized() const;
};

} // namespace scanner
} // namespace koraav

#endif // KORAAV_YARA_SCANNER_H
