// src/cli/rule_manager.cpp
// User-friendly YARA rule management CLI

#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <unistd.h>

namespace fs = std::filesystem;

void print_usage(const char* prog) {
    std::cout << R"(
KoraAV Rule Manager Help- Manage YARA detection rules

Usage:
  koraav-rules add <rule-file>              Add a new YARA rule
  koraav-rules remove <rule-name>           Remove a YARA rule
  koraav-rules list                         List all active YARA rules
  koraav-rules validate <rule-file>         Validate YARA rule syntax
  koraav-rules reload                       Reload all YARA rules (restart daemon)
  koraav-rules update                       Update YARA rules from online sources
  koraav-rules info <rule-name>             Show YARA rule details

Examples:
  # Validate before adding
  koraav-rules validate my-malware.yar

  # Add your own custom rule
  sudo koraav-rules add my-malware.yar
  
  # Update to latest signatures
  sudo koraav-rules update
  
  # List all rules
  koraav-rules list
  
  # Remove a rule
  sudo koraav-rules remove My_Custom_Rule

Rule Locations:
  System rules:  /opt/koraav/share/signatures/yara-rules/
  User rules:    /opt/koraav/share/signatures/yara-rules/user/
  
After adding/removing rules, run:
  sudo koraav-rules reload
  or
  sudo systemctl restart koraav
)" << std::endl;
}

bool validate_rule(const std::string& rule_path) {
    std::cout << "Validating YARA rule: " << rule_path << std::endl;
    
    if (!fs::exists(rule_path)) {
        std::cerr << "Error: File not found: " << rule_path << std::endl;
        return false;
    }
    
    // Use yarac to validate
    std::string cmd = "yarac -w " + rule_path + " /dev/null 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    
    if (!pipe) {
        std::cerr << "Error: Could not run yarac validator" << std::endl;
        return false;
    }
    
    char buffer[256];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe)) {
        output += buffer;
    }
    
    int result = pclose(pipe);
    
    if (result == 0) {
        std::cout << "Rule is valid!" << std::endl;
        return true;
    } else {
        std::cerr << "Rule validation failed:" << std::endl;
        std::cerr << output << std::endl;
        return false;
    }
}

bool add_rule(const std::string& rule_path) {
    if (!validate_rule(rule_path)) {
        return false;
    }
    
    if (geteuid() != 0) {
        std::cerr << "Error: Adding rules requires root privileges" << std::endl;
        std::cerr << "Run: sudo koraav-rules add " << rule_path << std::endl;
        return false;
    }
    
    // Create user rules directory
    std::string user_rules_dir = "/opt/koraav/share/signatures/yara-rules/user";
    fs::create_directories(user_rules_dir);
    
    // Get filename
    fs::path source(rule_path);
    std::string filename = source.filename().string();
    std::string dest = user_rules_dir + "/" + filename;
    
    // Copy rule file
    try {
        fs::copy_file(rule_path, dest, fs::copy_options::overwrite_existing);
        std::cout << "Rule added: " << dest << std::endl;
        std::cout << std::endl;
        std::cout << "To activate newly added rules:" << std::endl;
        std::cout << "  sudo koraav-rules reload" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error copying rule: " << e.what() << std::endl;
        return false;
    }
}

bool remove_rule(const std::string& rule_name) {
    if (geteuid() != 0) {
        std::cerr << "Error: Removing rules requires root privileges" << std::endl;
        return false;
    }
    
    std::string user_rules_dir = "/opt/koraav/share/signatures/yara-rules/user";
    
    // Find rule file
    for (const auto& entry : fs::directory_iterator(user_rules_dir)) {
        if (entry.path().extension() == ".yar" || entry.path().extension() == ".yara") {
            std::string filename = entry.path().filename().string();
            if (filename.find(rule_name) != std::string::npos) {
                fs::remove(entry.path());
                std::cout << "Removed rule: " << filename << std::endl;
                std::cout << "Reload rules to apply changes." << std::endl;
                return true;
            }
        }
    }
    
    std::cerr << "Rule not found: " << rule_name << std::endl;
    return false;
}

void list_rules() {
    std::cout << "=== Active YARA Rules ===" << std::endl;
    std::cout << std::endl;
    
    // System rules
    std::cout << "System Rules (/opt/koraav/share/signatures/yara-rules/):" << std::endl;
    std::string system_dir = "/opt/koraav/share/signatures/yara-rules";
    
    int count = 0;
    for (const auto& entry : fs::directory_iterator(system_dir)) {
        if (entry.is_regular_file() && 
            (entry.path().extension() == ".yar" || entry.path().extension() == ".yara")) {
            std::cout << "  • " << entry.path().filename().string() << std::endl;
            count++;
        }
    }
    std::cout << "  Total: " << count << " rules" << std::endl;
    std::cout << std::endl;
    
    // User rules
    std::cout << "User Rules (/opt/koraav/share/signatures/yara-rules/user/):" << std::endl;
    std::string user_dir = "/opt/koraav/share/signatures/yara-rules/user";
    
    if (fs::exists(user_dir)) {
        count = 0;
        for (const auto& entry : fs::directory_iterator(user_dir)) {
            if (entry.is_regular_file() && 
                (entry.path().extension() == ".yar" || entry.path().extension() == ".yara")) {
                std::cout << "  • " << entry.path().filename().string() << std::endl;
                count++;
            }
        }
        std::cout << "  Total: " << count << " user rules" << std::endl;
    } else {
        std::cout << "  No user rules" << std::endl;
    }
}

void show_rule_info(const std::string& rule_name) {
    std::cout << "=== Rule Info ===" << std::endl;
    std::cout << "Rule: " << rule_name << std::endl;
    std::cout << std::endl;
    
    // Search for rule file
    std::vector<std::string> search_paths = {
        "/opt/koraav/share/signatures/yara-rules",
        "/opt/koraav/share/signatures/yara-rules/user"
    };
    
    for (const auto& dir : search_paths) {
        if (!fs::exists(dir)) continue;
        
        for (const auto& entry : fs::directory_iterator(dir)) {
            if (entry.path().filename().string().find(rule_name) != std::string::npos) {
                std::cout << "File: " << entry.path() << std::endl;
                std::cout << "Size: " << fs::file_size(entry.path()) << " bytes" << std::endl;
                std::cout << std::endl;
                std::cout << "Content:" << std::endl;
                std::cout << "─────────────────────────────────────" << std::endl;
                
                std::ifstream file(entry.path());
                std::string line;
                while (std::getline(file, line)) {
                    std::cout << line << std::endl;
                }
                std::cout << "─────────────────────────────────────" << std::endl;
                return;
            }
        }
    }
    
    std::cerr << "Rule not found: " << rule_name << std::endl;
}

bool reload_rules() {
    if (geteuid() != 0) {
        std::cerr << "Error: Reloading rules requires root privileges" << std::endl;
        std::cerr << "Run: sudo koraav-rules reload" << std::endl;
        return false;
    }
    
    std::cout << "Reloading YARA rules..." << std::endl;
    
    // Send HUP signal to daemon to reload rules
    int result = system("systemctl reload koraav 2>/dev/null || systemctl restart koraav");
    
    if (result == 0) {
        std::cout << "Reloaded rules successfully!" << std::endl;
        return true;
    } else {
        std::cerr << "Error reloading rules (is koraav daemon running?)" << std::endl;
        return false;
    }
}

bool update_rules() {
    if (geteuid() != 0) {
        std::cerr << "Error: Updating rules requires root privileges" << std::endl;
        return false;
    }
    
    std::cout << "Updating YARA rules from online sources..." << std::endl;
    std::cout << std::endl;
    
    // Update from GitHub repositories
    // TODO: Parse repo files, look for "Linux.", add to list, and then add yara files from list to "linux_public_extended.yar"
    // For now, we'll just use this one as a placeholder until I add more sources, etc.
    std::vector<std::pair<std::string, std::string>> sources = {
        {"https://raw.githubusercontent.com/reversinglabs/reversinglabs-yara-rules/refs/heads/develop/yara/ransomware/Linux.Ransomware.Helldown.yara",
         "linux_public_extended.yar"}
    };
    
    std::string rules_dir = "/opt/koraav/share/signatures/yara-rules";
    bool success = true;
    
    for (const auto& [url, filename] : sources) {
        std::cout << "Downloading: " << filename << "..." << std::endl;
        
        std::string cmd = "curl -sSL '" + url + "' -o '" + rules_dir + "/" + filename + "' 2>&1";
        int result = system(cmd.c_str());
        
        if (result == 0) {
            // Validate downloaded rule
            if (validate_rule(rules_dir + "/" + filename)) {
                std::cout << filename << " updated!" << std::endl;
            } else {
                std::cerr << filename << " validation failed, removing.." << std::endl;
                fs::remove(rules_dir + "/" + filename);
                success = false;
            }
        } else {
            std::cerr << "Failed to download " << filename << std::endl;
            success = false;
        }
    }
    
    if (success) {
        std::cout << std::endl;
        std::cout << "Rules updated successfully" << std::endl;
        std::cout << "Reloading..." << std::endl;
        reload_rules();
    }
    
    return success;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    std::string command = argv[1];
    
    if (command == "add") {
        if (argc < 3) {
            std::cerr << "Error: Missing rule file" << std::endl;
            std::cerr << "Usage: koraav-rules add <rule-file>" << std::endl;
            return 1;
        }
        return add_rule(argv[2]) ? 0 : 1;
    }
    else if (command == "remove") {
        if (argc < 3) {
            std::cerr << "Error: Missing rule name" << std::endl;
            return 1;
        }
        return remove_rule(argv[2]) ? 0 : 1;
    }
    else if (command == "list") {
        list_rules();
        return 0;
    }
    else if (command == "validate") {
        if (argc < 3) {
            std::cerr << "Error: Missing rule file" << std::endl;
            return 1;
        }
        return validate_rule(argv[2]) ? 0 : 1;
    }
    else if (command == "reload") {
        return reload_rules() ? 0 : 1;
    }
    else if (command == "update") {
        return update_rules() ? 0 : 1;
    }
    else if (command == "info") {
        if (argc < 3) {
            std::cerr << "Error: Missing rule name" << std::endl;
            return 1;
        }
        show_rule_info(argv[2]);
        return 0;
    }
    else {
        std::cerr << "Unknown command: " << command << std::endl;
        print_usage(argv[0]);
        return 1;
    }
}
