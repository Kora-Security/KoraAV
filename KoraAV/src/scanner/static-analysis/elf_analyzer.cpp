// src/scanner/static-analysis/elf_analyzer.cpp
#include "elf_analyzer.h"
#include <elf.h>
#include <fstream>
#include <cstring>
#include <array>

namespace koraav {
namespace scanner {

// Dangerous functions that malware often uses
const std::set<std::string>& ELFAnalyzer::GetDangerousFunctions() {
    static std::set<std::string> dangerous = {
        "system", "exec", "execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe",
        "popen", "fork", "vfork", "clone",
        "ptrace",  // Debugging/anti-debugging
        "dlopen", "dlsym",  // Dynamic loading
        "mmap", "mprotect",  // Memory manipulation
        "kill", "killpg",  // Process killing
        "setuid", "setgid", "seteuid", "setegid",  // Privilege escalation
        "chroot",  // Change root
        "iopl", "ioperm"  // Direct I/O access
    };
    return dangerous;
}

const std::set<std::string>& ELFAnalyzer::GetNetworkFunctions() {
    static std::set<std::string> network = {
        "socket", "bind", "connect", "listen", "accept",
        "send", "recv", "sendto", "recvfrom",
        "sendmsg", "recvmsg",
        "gethostbyname", "getaddrinfo"
    };
    return network;
}

std::vector<std::string> ELFAnalyzer::Analyze(const std::string& path) {
    std::vector<std::string> threats;
    
    // Check imports
    auto import_threats = CheckImports(path);
    threats.insert(threats.end(), import_threats.begin(), import_threats.end());
    
    // Check security features
    auto security_threats = CheckSecurityFeatures(path);
    threats.insert(threats.end(), security_threats.begin(), security_threats.end());
    
    // Check sections
    auto section_threats = CheckSections(path);
    threats.insert(threats.end(), section_threats.begin(), section_threats.end());
    
    // Check if packed
    if (CheckPacked(path)) {
        threats.push_back("Possibly packed/obfuscated binary");
    }
    
    return threats;
}

std::vector<std::string> ELFAnalyzer::CheckImports(const std::string& path) {
    std::vector<std::string> threats;
    
    // Use readelf command to get imports
    std::string cmd = "readelf -s \"" + path + "\" 2>/dev/null | grep FUNC | grep UND";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return threats;
    }
    
    char buffer[1024];
    std::set<std::string> found_dangerous;
    std::set<std::string> found_network;
    
    while (fgets(buffer, sizeof(buffer), pipe)) {
        std::string line(buffer);
        
        // Check for dangerous functions
        for (const auto& func : GetDangerousFunctions()) {
            if (line.find(func) != std::string::npos) {
                found_dangerous.insert(func);
            }
        }
        
        // Check for network functions
        for (const auto& func : GetNetworkFunctions()) {
            if (line.find(func) != std::string::npos) {
                found_network.insert(func);
            }
        }
    }
    
    pclose(pipe);
    
    // Report findings
    if (found_dangerous.size() >= 3) {
        std::string funcs;
        int count = 0;
        for (const auto& f : found_dangerous) {
            if (count++ > 0) funcs += ", ";
            funcs += f;
            if (count >= 5) {
                funcs += "...";
                break;
            }
        }
        threats.push_back("Multiple dangerous functions: " + funcs);
    }
    
    if (found_network.size() >= 2) {
        threats.push_back("Network capability detected");
    }
    
    // Specific dangerous combinations
    if (found_dangerous.count("system") && found_network.size() > 0) {
        threats.push_back("Network + system() execution (backdoor pattern)");
    }
    
    if (found_dangerous.count("ptrace")) {
        threats.push_back("Uses ptrace (anti-debugging/injection)");
    }
    
    if (found_dangerous.count("setuid") || found_dangerous.count("setgid")) {
        threats.push_back("Privilege escalation functions");
    }
    
    return threats;
}

std::vector<std::string> ELFAnalyzer::CheckSecurityFeatures(const std::string& path) {
    std::vector<std::string> threats;
    
    // Check with checksec-like analysis
    std::string cmd = "readelf -l \"" + path + "\" 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return threats;
    }
    
    char buffer[1024];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe)) {
        output += buffer;
    }
    pclose(pipe);
    
    // Check for NX (No-Execute) bit
    if (output.find("GNU_STACK") != std::string::npos) {
        // Check if executable stack
        if (output.find("GNU_STACK") != std::string::npos && 
            output.find("RWE") != std::string::npos) {
            threats.push_back("Executable stack (NX disabled)");
        }
    }
    
    // Check for PIE (Position Independent Executable)
    cmd = "readelf -h \"" + path + "\" 2>/dev/null | grep Type";
    pipe = popen(cmd.c_str(), "r");
    if (pipe) {
        output.clear();
        while (fgets(buffer, sizeof(buffer), pipe)) {
            output += buffer;
        }
        pclose(pipe);
        
        if (output.find("EXEC") != std::string::npos) {
            // Not PIE
            threats.push_back("No PIE (not position independent)");
        }
    }
    
    // Check for RELRO
    cmd = "readelf -l \"" + path + "\" 2>/dev/null | grep GNU_RELRO";
    pipe = popen(cmd.c_str(), "r");
    if (pipe) {
        output.clear();
        while (fgets(buffer, sizeof(buffer), pipe)) {
            output += buffer;
        }
        pclose(pipe);
        
        if (output.empty()) {
            threats.push_back("No RELRO (relocations not read-only)");
        }
    }
    
    return threats;
}

std::vector<std::string> ELFAnalyzer::CheckSections(const std::string& path) {
    std::vector<std::string> threats;
    
    // Get section list
    std::string cmd = "readelf -S \"" + path + "\" 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return threats;
    }
    
    char buffer[1024];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe)) {
        output += buffer;
    }
    pclose(pipe);
    
    // Check for unusual sections
    if (output.find(".UPX") != std::string::npos) {
        threats.push_back("UPX packer detected");
    }
    
    return threats;
}

bool ELFAnalyzer::CheckPacked(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    // Read ELF header
    Elf64_Ehdr ehdr;
    file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    
    if (!file || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        return false;
    }
    
    // Check for UPX magic
    file.seekg(0);
    std::array<char, 4096> buffer;
    file.read(buffer.data(), buffer.size());
    
    std::string data(buffer.data(), file.gcount());
    if (data.find("UPX!") != std::string::npos) {
        return true;
    }
    
    // Check section count - packed binaries often have very few sections
    if (ehdr.e_shnum < 5) {
        return true;
    }
    
    return false;
}

} // namespace scanner
} // namespace koraav
