// src/scanner/static-analysis/script_analyzer.h
#ifndef KORAAV_SCRIPT_ANALYZER_H
#define KORAAV_SCRIPT_ANALYZER_H

#include <koraav/types.h>
#include <string>
#include <vector>

namespace koraav {
namespace scanner {

class ScriptAnalyzer {
public:
    /**
     * Analyze shell/Python/Perl scripts for malicious content
     */
    std::vector<std::string> Analyze(const std::string& path, FileType type);
    
private:
    std::vector<std::string> AnalyzeBashScript(const std::string& content);
    std::vector<std::string> AnalyzePythonScript(const std::string& content);
};

} // namespace scanner
} // namespace koraav

#endif
