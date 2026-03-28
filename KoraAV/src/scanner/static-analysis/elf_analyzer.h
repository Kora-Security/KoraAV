// src/scanner/static-analysis/elf_analyzer.h
#ifndef KORAAV_ELF_ANALYZER_H
#define KORAAV_ELF_ANALYZER_H

#include <string>
#include <vector>
#include <set>

namespace koraav {
namespace scanner {

/**
 * ELF binary analyzer
 * Analyzes Linux executables and shared libraries for suspicious characteristics
 */
class ELFAnalyzer {
public:
    /**
     * Returns list of threat indicators found
     */
    std::vector<std::string> Analyze(const std::string& path);
    
private:
    // Check for suspicious imported functions
    std::vector<std::string> CheckImports(const std::string& path);
    
    // Check security features (NX, PIE, RELRO, Stack Canary)
    std::vector<std::string> CheckSecurityFeatures(const std::string& path);
    
    // Check for suspicious sections
    std::vector<std::string> CheckSections(const std::string& path);
    
    // Check for packing/obfuscation
    bool CheckPacked(const std::string& path);
    
    // Get list of dangerous function imports
    static const std::set<std::string>& GetDangerousFunctions();
    
    // Get list of network-related functions
    static const std::set<std::string>& GetNetworkFunctions();
};

} // namespace scanner
} // namespace koraav

#endif // KORAAV_ELF_ANALYZER_H
