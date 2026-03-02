// src/realtime-protection/behavioral-analysis/clickfix_detector.h
#ifndef KORAAV_CLICKFIX_DETECTOR_H
#define KORAAV_CLICKFIX_DETECTOR_H

#include <string>
#include <vector>
#include <unordered_map>
#include <regex>

namespace koraav {
namespace realtime {

/**
 * ClickFix / Malicious Command Detector
 * Detects social engineering attacks that trick users into running malicious commands
 * (PowerShell, bash, curl|bash, etc.)
 */
class ClickFixDetector {
public:
    ClickFixDetector();
    
    /**
     * Analyze a command line for malicious patterns
     * Returns threat score (0-100)
     */
    int AnalyzeCommand(const std::string& cmdline, const std::string& process_name);
    
    /**
     * Get detailed threat indicators for a command
     */
    std::vector<std::string> GetThreatIndicators(const std::string& cmdline);
    
    /**
     * Check if command matches known ClickFix patterns
     */
    bool IsClickFixPattern(const std::string& cmdline);
    
    /**
     * Check if command is obfuscated
     */
    bool IsObfuscated(const std::string& cmdline);

private:
    struct MaliciousPattern {
        std::string name;
        std::regex pattern;
        int severity;  // 1-100
        std::string description;
    };
    
    std::vector<MaliciousPattern> patterns_;
    
    void InitializePatterns();
    int CalculateObfuscationScore(const std::string& cmdline);
    bool HasBase64Payload(const std::string& cmdline);
    bool HasDownloadAndExecute(const std::string& cmdline);
    bool HasReverseShell(const std::string& cmdline);
};

} // namespace realtime
} // namespace koraav

#endif // KORAAV_CLICKFIX_DETECTOR_H
