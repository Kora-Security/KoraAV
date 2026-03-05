// src/realtime-protection/behavioral-analysis/clickfix_detector.cpp
#include "clickfix_detector.h"
#include <algorithm>

namespace koraav {
namespace realtime {

ClickFixDetector::ClickFixDetector() {
    InitializePatterns();
}

void ClickFixDetector::InitializePatterns() {
    // PowerShell download and execute patterns
    patterns_.push_back({
        "PowerShell IEX DownloadString",
        std::regex(R"(IEX.*DownloadString)", std::regex::icase),
        90,
        "PowerShell download and execute"
    });
    
    patterns_.push_back({
        "PowerShell Invoke-WebRequest Execute",
        std::regex(R"(Invoke-WebRequest.*\|.*iex)", std::regex::icase),
        90,
        "PowerShell download and execute via IWR"
    });
    
    patterns_.push_back({
        "PowerShell Invoke-Expression",
        std::regex(R"(Invoke-Expression)", std::regex::icase),
        60,
        "PowerShell dynamic code execution"
    });
    
    // NEW: DNS-based ClickFix pattern (Microsoft Defender research, Feb 2026)
    patterns_.push_back({
        "ClickFix DNS Lookup Payload",
        std::regex(R"(nslookup.*\|.*findstr.*Name:.*for\s+/f)", std::regex::icase),
        95,
        "DNS TXT record payload delivery (ClickFix variant)"
    });
    
    patterns_.push_back({
        "DNS TXT Record Parse and Execute",
        std::regex(R"(nslookup.*\d+\.\d+\.\d+\.\d+.*findstr)", std::regex::icase),
        90,
        "DNS lookup with parsing (potential payload delivery)"
    });
    
    patterns_.push_back({
        "For Loop Token Parsing",
        std::regex(R"(for\s+/f.*tokens.*delims.*in.*do.*@?echo)", std::regex::icase),
        70,
        "Command output parsing with for loop (common in ClickFix)"
    });
    
    // Bash download and execute
    patterns_.push_back({
        "Curl Pipe Bash",
        std::regex(R"(curl.*\|.*bash)", std::regex::icase),
        95,
        "Download and execute via curl"
    });
    
    patterns_.push_back({
        "Wget Pipe Bash",
        std::regex(R"(wget.*\|.*sh)", std::regex::icase),
        95,
        "Download and execute via wget"
    });
    
    patterns_.push_back({
        "Curl Silent Execute",
        std::regex(R"(curl.*-s.*http.*\|.*sh)", std::regex::icase),
        95,
        "Silent download and execute"
    });
    
    // Reverse shells
    patterns_.push_back({
        "Bash Reverse Shell /dev/tcp",
        std::regex(R"(/dev/tcp/\d+\.\d+\.\d+\.\d+)", std::regex::icase),
        100,
        "Bash reverse shell via /dev/tcp"
    });
    
    patterns_.push_back({
        "Netcat Reverse Shell",
        std::regex(R"(nc.*-e.*/bin/(ba)?sh)", std::regex::icase),
        100,
        "Netcat reverse shell"
    });
    
    patterns_.push_back({
        "Python Reverse Shell",
        std::regex(R"(python.*socket.*connect.*exec)", std::regex::icase),
        100,
        "Python reverse shell"
    });
    
    // Base64 obfuscation
    patterns_.push_back({
        "PowerShell Base64 Encoded Command",
        std::regex(R"(-e(nc(odedcommand)?)?.*[A-Za-z0-9+/]{50,})", std::regex::icase),
        80,
        "PowerShell with base64 encoded payload"
    });
    
    patterns_.push_back({
        "Bash Base64 Decode Execute",
        std::regex(R"(base64.*-d.*\|.*(bash|sh))", std::regex::icase),
        85,
        "Base64 decode and execute"
    });
    
    patterns_.push_back({
        "Echo Base64 Execute",
        std::regex(R"(echo.*\|.*base64.*-d.*\|.*(bash|sh))", std::regex::icase),
        90,
        "Echo base64 payload and execute"
    });
    
    // Hidden execution
    patterns_.push_back({
        "PowerShell Hidden Window",
        std::regex(R"(-w(indowstyle)?\s+hidden)", std::regex::icase),
        70,
        "PowerShell with hidden window"
    });
    
    patterns_.push_back({
        "PowerShell Bypass Execution Policy",
        std::regex(R"(-e(xecutionpolicy)?\s+bypass)", std::regex::icase),
        70,
        "PowerShell bypass execution policy"
    });
    
    patterns_.push_back({
        "PowerShell No Profile",
        std::regex(R"(-nop(rofile)?)", std::regex::icase),
        50,
        "PowerShell skip profile loading"
    });
    
    // Credential theft
    patterns_.push_back({
        "Mimikatz Execution",
        std::regex(R"(mimikatz|sekurlsa|lsadump)", std::regex::icase),
        100,
        "Credential dumping tool (Mimikatz)"
    });
    
    patterns_.push_back({
        "LaZagne Execution",
        std::regex(R"(lazagne)", std::regex::icase),
        95,
        "Password recovery tool (LaZagne)"
    });
    
    // System modification
    patterns_.push_back({
        "Disable Windows Defender",
        std::regex(R"(Set-MpPreference.*-DisableReal)", std::regex::icase),
        100,
        "Attempt to disable Windows Defender"
    });
    
    patterns_.push_back({
        "Add User to Administrators",
        std::regex(R"(net\s+localgroup.*administrators.*\/add)", std::regex::icase),
        90,
        "Adding user to administrators group"
    });
    
    // Fileless malware
    patterns_.push_back({
        "Reflective PE Injection",
        std::regex(R"(Invoke-ReflectivePEInjection)", std::regex::icase),
        100,
        "Reflective PE injection technique"
    });
    
    patterns_.push_back({
        "In-Memory Execution",
        std::regex(R"(Invoke-Shellcode|Invoke-DllInjection)", std::regex::icase),
        95,
        "In-memory code injection"
    });
    
    // Typical ClickFix patterns
    patterns_.push_back({
        "ClickFix PowerShell Pattern",
        std::regex(R"(powershell.*-w.*hidden.*-e.*[A-Za-z0-9+/]{100,})", std::regex::icase),
        100,
        "Typical ClickFix social engineering pattern"
    });
}

int ClickFixDetector::AnalyzeCommand(const std::string& cmdline, const std::string& process_name) {
    int max_score = 0;
    
    // Check against all patterns
    for (const auto& pattern : patterns_) {
        if (std::regex_search(cmdline, pattern.pattern)) {
            max_score = std::max(max_score, pattern.severity);
        }
    }
    
    // Add obfuscation score
    int obf_score = CalculateObfuscationScore(cmdline);
    max_score = std::max(max_score, obf_score);
    
    // Bonus for suspicious process names
    if (process_name == "powershell" || process_name == "powershell.exe" ||
        process_name == "pwsh" || process_name == "bash" || process_name == "sh") {
        // Already suspicious due to shell usage
        max_score += 5;
    }
    
    return std::min(max_score, 100);
}

std::vector<std::string> ClickFixDetector::GetThreatIndicators(const std::string& cmdline) {
    std::vector<std::string> indicators;
    
    // Check all patterns
    for (const auto& pattern : patterns_) {
        if (std::regex_search(cmdline, pattern.pattern)) {
            indicators.push_back(pattern.name + ": " + pattern.description);
        }
    }
    
    // Additional indicators
    if (HasBase64Payload(cmdline)) {
        indicators.push_back("Base64 encoded payload detected");
    }
    
    if (HasDownloadAndExecute(cmdline)) {
        indicators.push_back("⚠ Download-and-execute pattern");
    }
    
    if (HasReverseShell(cmdline)) {
        indicators.push_back("🚨 REVERSE SHELL DETECTED");
    }
    
    if (IsObfuscated(cmdline)) {
        indicators.push_back("Command appears to be obfuscated");
    }
    
    // Check for extremely long commands (often suspicious)
    if (cmdline.length() > 500) {
        indicators.push_back("Unusually long command (" + std::to_string(cmdline.length()) + " characters)");
    }
    
    return indicators;
}

bool ClickFixDetector::IsClickFixPattern(const std::string& cmdline) {
    // ClickFix typically involves:
    // 1. PowerShell with hidden window
    // 2. Encoded command (base64)
    // 3. Downloaded from the internet
    
    bool has_powershell = cmdline.find("powershell") != std::string::npos ||
                         cmdline.find("pwsh") != std::string::npos;
    
    bool has_hidden = cmdline.find("-w hidden") != std::string::npos ||
                     cmdline.find("-windowstyle hidden") != std::string::npos;
    
    bool has_encoded = cmdline.find("-e ") != std::string::npos ||
                      cmdline.find("-encodedcommand") != std::string::npos;
    
    bool has_download = cmdline.find("DownloadString") != std::string::npos ||
                       cmdline.find("Invoke-WebRequest") != std::string::npos ||
                       cmdline.find("wget") != std::string::npos ||
                       cmdline.find("curl") != std::string::npos;
    
    // ClickFix pattern: PowerShell + (Hidden OR Encoded) + Download
    if (has_powershell && (has_hidden || has_encoded)) {
        return true;
    }
    
    // Or bash download-and-execute
    if (has_download && (cmdline.find("| bash") != std::string::npos || 
                         cmdline.find("| sh") != std::string::npos)) {
        return true;
    }
    
    return false;
}

bool ClickFixDetector::IsObfuscated(const std::string& cmdline) {
    return CalculateObfuscationScore(cmdline) > 50;
}

int ClickFixDetector::CalculateObfuscationScore(const std::string& cmdline) {
    int score = 0;
    
    // Count base64-like strings
    std::regex base64_regex("[A-Za-z0-9+/]{30,}");
    auto words_begin = std::sregex_iterator(cmdline.begin(), cmdline.end(), base64_regex);
    auto words_end = std::sregex_iterator();
    int base64_count = std::distance(words_begin, words_end);
    
    if (base64_count > 0) {
        score += 40;
    }
    
    // Check for excessive special characters (obfuscation)
    int special_chars = 0;
    for (char c : cmdline) {
        if (!std::isalnum(c) && c != ' ' && c != '/' && c != '\\' && c != '-' && c != '.') {
            special_chars++;
        }
    }
    
    if (cmdline.length() > 0) {
        double special_ratio = static_cast<double>(special_chars) / cmdline.length();
        if (special_ratio > 0.3) {  // More than 30% special chars
            score += 30;
        }
    }
    
    // Multiple encoding layers
    if (cmdline.find("base64") != std::string::npos && 
        cmdline.find("gzip") != std::string::npos) {
        score += 20;
    }
    
    return score;
}

bool ClickFixDetector::HasBase64Payload(const std::string& cmdline) {
    // Look for base64 strings longer than 50 characters
    std::regex base64_regex("[A-Za-z0-9+/]{50,}");
    return std::regex_search(cmdline, base64_regex);
}

bool ClickFixDetector::HasDownloadAndExecute(const std::string& cmdline) {
    std::string lower = cmdline;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    bool has_download = lower.find("downloadstring") != std::string::npos ||
                       lower.find("invoke-webrequest") != std::string::npos ||
                       lower.find("wget") != std::string::npos ||
                       lower.find("curl") != std::string::npos;
    
    bool has_execute = lower.find("iex") != std::string::npos ||
                      lower.find("invoke-expression") != std::string::npos ||
                      lower.find("| bash") != std::string::npos ||
                      lower.find("| sh") != std::string::npos;
    
    return has_download && has_execute;
}

bool ClickFixDetector::HasReverseShell(const std::string& cmdline) {
    std::string lower = cmdline;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // Check for common reverse shell patterns
    if (lower.find("/dev/tcp/") != std::string::npos) return true;
    if (lower.find("nc") != std::string::npos && lower.find("-e") != std::string::npos) return true;
    if (lower.find("socket.connect") != std::string::npos) return true;
    if (lower.find("reverse_tcp") != std::string::npos) return true;
    
    return false;
}

} // namespace realtime
} // namespace koraav
