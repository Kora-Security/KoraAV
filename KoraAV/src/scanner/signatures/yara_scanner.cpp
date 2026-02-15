// src/scanner/signatures/yara_scanner.cpp
#include "yara_scanner.h"
#include <yara.h>
#include <iostream>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace koraav {
namespace scanner {

// Callback for YARA rule matches
static int yara_callback(YR_SCAN_CONTEXT* /* context */, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        auto* matches = static_cast<std::vector<std::string>*>(user_data);
        matches->push_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

YaraScanner::YaraScanner() : rules_(nullptr), yara_initialized_(false) {
    // Initialize YARA library
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize YARA library" << std::endl;
        return;
    }
    yara_initialized_ = true;
}

YaraScanner::~YaraScanner() {
    if (rules_) {
        yr_rules_destroy(rules_);
        rules_ = nullptr;
    }
    
    if (yara_initialized_) {
        yr_finalize();
    }
}

bool YaraScanner::LoadRules(const std::string& rules_dir) {
    if (!yara_initialized_) {
        std::cerr << "YARA not initialized" << std::endl;
        return false;
    }
    
    // Check if directory exists
    if (!fs::exists(rules_dir)) {
        std::cerr << "No YARA rules found in " << rules_dir << std::endl;
        return false;
    }
    
    if (!fs::is_directory(rules_dir)) {
        std::cerr << "YARA rules path is not a directory: " << rules_dir << std::endl;
        return false;
    }
    
    YR_COMPILER* compiler = nullptr;
    int result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to create YARA compiler" << std::endl;
        return false;
    }
    
    // Compile all rules from directory
    bool success = CompileRulesFromDirectory(rules_dir, compiler);
    
    if (success) {
        // Get compiled rules
        result = yr_compiler_get_rules(compiler, &rules_);
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to get compiled YARA rules" << std::endl;
            success = false;
        }
    }
    
    yr_compiler_destroy(compiler);
    return success;
}

bool YaraScanner::LoadRuleFile(const std::string& rule_path) {
    if (!yara_initialized_) {
        return false;
    }
    
    YR_COMPILER* compiler = nullptr;
    int result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        return false;
    }
    
    // Open and compile the rule file
    FILE* rule_file = fopen(rule_path.c_str(), "r");
    if (!rule_file) {
        std::cerr << "Failed to open YARA rule file: " << rule_path << std::endl;
        yr_compiler_destroy(compiler);
        return false;
    }
    
    // Check for compilation errors BEFORE they cause assertions
    int errors = yr_compiler_add_file(compiler, rule_file, nullptr, rule_path.c_str());
    fclose(rule_file);
    
    if (errors > 0) {
        std::cerr << "YARA compilation errors in " << rule_path << std::endl;
        
        // Print error messages if available
        YR_COMPILER_ERROR_INFO* error_info;
        yr_compiler_get_error_info(compiler, &error_info);
        if (error_info) {
            std::cerr << "  Line " << error_info->line_number 
                      << ": " << error_info->message << std::endl;
        }
        
        yr_compiler_destroy(compiler);
        return false;
    }
    
    // Get compiled rules
    result = yr_compiler_get_rules(compiler, &rules_);
    yr_compiler_destroy(compiler);
    
    return result == ERROR_SUCCESS;
}

bool YaraScanner::CompileRulesFromDirectory(const std::string& dir, YR_COMPILER* compiler) {
    if (!fs::exists(dir) || !fs::is_directory(dir)) {
        std::cerr << "YARA rules directory not found: " << dir << std::endl;
        return false;
    }
    
    int rule_count = 0;
    int failed_count = 0;
    std::vector<std::string> failed_files;
    
    // Iterate through all .yar and .yara files
    try {
        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            
            std::string ext = entry.path().extension().string();
            if (ext != ".yar" && ext != ".yara") {
                continue;
            }
            
            std::string path = entry.path().string();
            
            // Try to open the file
            FILE* rule_file = fopen(path.c_str(), "r");
            if (!rule_file) {
                std::cerr << "Warning: Could not open " << path << std::endl;
                failed_count++;
                failed_files.push_back(path);
                continue;
            }
            
            // CRITICAL FIX: Check for YARA compilation errors
            // Get YARA's internal error count BEFORE compiling
            int yara_errors_before = yr_compiler_get_error_count(compiler);
            
            // Try to compile the file
            int compile_result = yr_compiler_add_file(compiler, rule_file, nullptr, path.c_str());
            fclose(rule_file);
            
            // Get YARA's internal error count AFTER compiling
            int yara_errors_after = yr_compiler_get_error_count(compiler);
            
            if (compile_result != 0 || yara_errors_after > yara_errors_before) {
                // Compilation had errors
                std::cerr << "Warning: Compilation errors in " << path << std::endl;
                
                // Print the specific errors from YARA
                YR_COMPILER_ERROR_INFO* error_info;
                yr_compiler_get_error_info(compiler, &error_info);
                if (error_info) {
                    std::cerr << "  Line " << error_info->line_number 
                              << ": " << error_info->message << std::endl;
                }
                
                failed_count++;
                failed_files.push_back(path);
                
                // IMPORTANT: Continue loading other rules
                // Don't return false here - we want to load what we can
                continue;
            }
            
            // Success!
            rule_count++;
            std::cout << "  ✓ Loaded: " << entry.path().filename().string() << std::endl;
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error while loading YARA rules: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error while loading YARA rules: " << e.what() << std::endl;
        return false;
    }
    
    // Print summary
    std::cout << "\nYARA Rules Summary:" << std::endl;
    std::cout << "  Successfully loaded: " << rule_count << " files" << std::endl;
    
    if (failed_count > 0) {
        std::cout << "  Failed to load: " << failed_count << " files" << std::endl;
        std::cout << "  Failed files:" << std::endl;
        for (const auto& file : failed_files) {
            std::cout << "    • " << fs::path(file).filename().string() << std::endl;
        }
    }
    
    // Return true if we loaded at least one rule
    // Return false only if we loaded zero rules
    if (rule_count == 0) {
        std::cerr << "\n❌ No YARA rules successfully loaded from " << dir << std::endl;
        std::cerr << "YARA scanning will be disabled." << std::endl;
        return false;
    }
    
    std::cout << "✓ YARA scanner ready with " << rule_count << " rule file(s)\n" << std::endl;
    return true;
}

std::vector<std::string> YaraScanner::ScanData(const std::vector<char>& data) {
    std::vector<std::string> matches;
    
    if (!rules_ || data.empty()) {
        return matches;
    }
    
    // Scan the data
    int result = yr_rules_scan_mem(
        rules_,
        reinterpret_cast<const uint8_t*>(data.data()),
        data.size(),
        0,  // flags
        yara_callback,
        &matches,
        0   // timeout (0 = no timeout)
    );
    
    if (result != ERROR_SUCCESS) {
        std::cerr << "YARA scan error: " << result << std::endl;
    }
    
    return matches;
}

std::vector<std::string> YaraScanner::ScanFile(const std::string& path) {
    std::vector<std::string> matches;
    
    if (!rules_) {
        return matches;
    }
    
    // Scan the file
    int result = yr_rules_scan_file(
        rules_,
        path.c_str(),
        0,  // flags
        yara_callback,
        &matches,
        0   // timeout
    );
    
    if (result != ERROR_SUCCESS) {
        std::cerr << "YARA scan error on " << path << ": " << result << std::endl;
    }
    
    return matches;
}

} // namespace scanner
} // namespace koraav
