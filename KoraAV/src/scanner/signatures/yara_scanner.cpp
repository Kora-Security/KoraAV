// src/scanner/signatures/yara_scanner.cpp

#include "yara_scanner.h"
#include <iostream>

namespace koraav {
namespace scanner {

YaraScanner::YaraScanner() {
    // Ensure YaraManager is initialized
    YaraManager::Instance().Initialize();
}

bool YaraScanner::LoadRules(const std::string& rules_dir) {
    // Delegate to YaraManager
    return YaraManager::Instance().LoadRules(rules_dir);
}

std::vector<std::string> YaraScanner::ScanData(const std::vector<char>& data) {
    if (data.empty()) {
        return {};
    }
    // Delegate to YaraManager
    return YaraManager::Instance().ScanMemory(data.data(), data.size());
}

std::vector<std::string> YaraScanner::ScanFile(const std::string& path) {
    // Delegate to YaraManager
    return YaraManager::Instance().ScanFile(path);
}

bool YaraScanner::IsInitialized() const {
    return YaraManager::Instance().IsReady();
}

} // namespace scanner
} // namespace koraav
