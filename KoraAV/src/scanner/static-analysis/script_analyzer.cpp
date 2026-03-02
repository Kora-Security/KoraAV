// src/scanner/static-analysis/script_analyzer.cpp
#include "script_analyzer.h"
#include <fstream>
#include <sstream>
#include <regex>

namespace koraav {
namespace scanner {

std::vector<std::string> ScriptAnalyzer::Analyze(const std::string& path, FileType type) {
    // Read file
    std::ifstream file(path);
    if (!file) {
        return {};
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    switch (type) {
        case FileType::SCRIPT_BASH:
            return AnalyzeBashScript(content);
        case FileType::SCRIPT_PYTHON:
            return AnalyzePythonScript(content);
        default:
            return {};
    }
}

std::vector<std::string> ScriptAnalyzer::AnalyzeBashScript(const std::string& content) {
    std::vector<std::string> threats;
    
    // Malicious patterns
    struct Pattern {
        std::string regex;
        std::string description;
    };
    
    std::vector<Pattern> patterns = {
        {R"(/dev/tcp/)", "Bash reverse shell pattern"},
        {R"(nc.*-e)", "Netcat reverse shell"},
        {R"(curl.*\|.*bash)", "Download and execute"},
        {R"(wget.*\|.*sh)", "Download and execute"},
        {R"(eval.*\$\()", "Eval with command substitution"},
        {R"(base64.*-d)", "Base64 decode (obfuscation)"},
        {R"(chmod.*\+x.*&&)", "Make executable and run"},
        {R"(rm\s+-rf\s+/)", "Dangerous delete command"},
    };
    
    for (const auto& pattern : patterns) {
        std::regex r(pattern.regex);
        if (std::regex_search(content, r)) {
            threats.push_back(pattern.description);
        }
    }
    
    return threats;
}

std::vector<std::string> ScriptAnalyzer::AnalyzePythonScript(const std::string& content) {
    std::vector<std::string> threats;
    
    struct Pattern {
        std::string regex;
        std::string description;
    };
    
    std::vector<Pattern> patterns = {
        {R"(import\s+socket)", "Network socket usage"},
        {R"(import\s+subprocess)", "Subprocess execution"},
        {R"(exec\()", "Dynamic code execution"},
        {R"(eval\()", "Dynamic code evaluation"},
        {R"(__import__)", "Dynamic import"},
        {R"(base64\.b64decode)", "Base64 decode (obfuscation)"},
        {R"(requests\.get.*\.content)", "Download content"},
        {R"(os\.system)", "OS command execution"},
    };
    
    for (const auto& pattern : patterns) {
        std::regex r(pattern.regex);
        if (std::regex_search(content, r)) {
            threats.push_back(pattern.description);
        }
    }
    
    return threats;
}

} // namespace scanner
} // namespace koraav
