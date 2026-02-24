// src/common/yara_manager.cpp

// CRITICAL: Disable assertions in YARA to prevent crashes
#ifdef assert
#undef assert
#endif
#define assert(x) ((void)0)

#include "yara_manager.h"
#include <yara.h>
#include <iostream>
#include <filesystem>
#include <cstring>

namespace fs = std::filesystem;

namespace koraav {

// Scan callback
static int scan_callback(YR_SCAN_CONTEXT* /* context */, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        auto* matches = (std::vector<std::string>*)user_data;
        matches->push_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

// Error callback
static void compiler_error_callback(
    int error_level,
    const char* file_name,
    int line_number,
    #if YR_MAJOR_VERSION >= 4
    const YR_RULE* /* rule */,
    #endif
    const char* message,
    void* /* user_data */)
{
    if (error_level == YARA_ERROR_LEVEL_ERROR) {
        std::cerr << "YARA Error [" << (file_name ? file_name : "?") 
                  << ":" << line_number << "]: " 
                  << (message ? message : "unknown") << std::endl;
    }
}

YaraManager& YaraManager::Instance() {
    static YaraManager instance;
    return instance;
}

YaraManager::YaraManager() 
    : rules_(nullptr), 
      initialized_(false) {
}

YaraManager::~YaraManager() {
    Shutdown();
}

bool YaraManager::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (initialized_) {
        return true;  // Already initialized
    }
    
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize YARA library: " << result << std::endl;
        return false;
    }
    
    initialized_ = true;
    std::cout << "YARA library initialized" << std::endl;
    return true;
}

bool YaraManager::LoadRules(const std::string& rules_dir) {
    if (!initialized_) {
        std::cerr << "YARA not initialized. Call Initialize() first." << std::endl;
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Clean up old rules
    if (rules_) {
        yr_rules_destroy(rules_);
        rules_ = nullptr;
    }
    
    rules_dir_ = rules_dir;
    return LoadRulesInternal(rules_dir);
}

bool YaraManager::Reload() {
    if (rules_dir_.empty()) {
        std::cerr << "No rules directory set. Call LoadRules() first." << std::endl;
        return false;
    }
    return LoadRules(rules_dir_);
}

bool YaraManager::LoadRulesInternal(const std::string& dir) {
    // Check directory exists
    if (!fs::exists(dir)) {
        std::cerr << "YARA rules directory does not exist: " << dir << std::endl;
        return false;
    }
    
    if (!fs::is_directory(dir)) {
        std::cerr << "Not a directory: " << dir << std::endl;
        return false;
    }
    
    std::cout << "Loading YARA rules from: " << dir << std::endl;
    
    // Create single compiler for ALL rules
    YR_COMPILER* compiler = nullptr;
    int result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to create YARA compiler" << std::endl;
        return false;
    }
    
    yr_compiler_set_callback(compiler, compiler_error_callback, nullptr);
    
    int successful_files = 0;
    int failed_files = 0;
    
    try {
        // Recursively scan all .yar and .yara files
        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            
            std::string ext = entry.path().extension().string();
            if (ext != ".yar" && ext != ".yara") {
                continue;
            }
            
            std::string path = entry.path().string();
            std::string filename = entry.path().filename().string();
            
            // Try to open file
            FILE* file = fopen(path.c_str(), "r");
            if (!file) {
                std::cerr << "Cannot open: " << filename << std::endl;
                failed_files++;
                continue;
            }
            
            // Try to compile
            std::cout << "  Loading: " << filename << " ... ";
            
            int errors = yr_compiler_add_file(compiler, file, nullptr, filename.c_str());
            fclose(file);
            
            if (errors > 0) {
                std::cout << "FAILED (" << errors << " errors)" << std::endl;
                failed_files++;
                // Don't return - keep loading other files
                continue;
            }
            
            std::cout << "OK" << std::endl;
            successful_files++;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception while loading rules: " << e.what() << std::endl;
        yr_compiler_destroy(compiler);
        return false;
    }
    
    // Check if we got any rules
    if (successful_files == 0) {
        std::cerr << "No YARA rules could be loaded" << std::endl;
        std::cerr << "  Failed: " << failed_files << " files" << std::endl;
        yr_compiler_destroy(compiler);
        return false;
    }
    
    // Extract compiled rules
    result = yr_compiler_get_rules(compiler, &rules_);
    yr_compiler_destroy(compiler);
    
    if (result != ERROR_SUCCESS || !rules_) {
        std::cerr << "Failed to get compiled rules" << std::endl;
        return false;
    }
    
    std::cout << "YARA scanner ready: " << successful_files << " rule files loaded" << std::endl;
    if (failed_files > 0) {
        std::cout << "  Note: " << failed_files << " files skipped due to errors" << std::endl;
    }
    
    return true;
}

std::vector<std::string> YaraManager::ScanFile(const std::string& path) {
    std::vector<std::string> matches;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!rules_) {
        return matches;  // No rules loaded
    }
    
    int result = yr_rules_scan_file(
        rules_,
        path.c_str(),
        0,
        scan_callback,
        &matches,
        0
    );
    
    if (result != ERROR_SUCCESS) {
        std::cerr << "YARA scan failed on " << path << ": " << result << std::endl;
    }
    
    return matches;
}

std::vector<std::string> YaraManager::ScanMemory(const void* data, size_t size) {
    std::vector<std::string> matches;
    
    if (!data || size == 0) {
        return matches;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!rules_) {
        return matches;
    }
    
    int result = yr_rules_scan_mem(
        rules_,
        (const uint8_t*)data,
        size,
        0,
        scan_callback,
        &matches,
        0
    );
    
    if (result != ERROR_SUCCESS) {
        std::cerr << "YARA scan failed on memory: " << result << std::endl;
    }
    
    return matches;
}

bool YaraManager::IsReady() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_ != nullptr;
}

int YaraManager::GetRuleCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!rules_) {
        return 0;
    }
    
    // Count rules
    int count = 0;
    YR_RULE* rule = nullptr;
    
    yr_rules_foreach(rules_, rule) {
        count++;
    }
    
    return count;
}

void YaraManager::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (rules_) {
        yr_rules_destroy(rules_);
        rules_ = nullptr;
    }
    
    if (initialized_) {
        yr_finalize();
        initialized_ = false;
    }
}

} // namespace koraav
