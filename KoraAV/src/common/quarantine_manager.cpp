// src/common/quarantine_manager.cpp
#include "quarantine_manager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <filesystem>
#include <ctime>
#include <unistd.h>
#include <limits.h>

namespace fs = std::filesystem;

namespace koraav {

QuarantineManager::QuarantineManager(const std::string& quarantine_dir)
    : quarantine_dir_(quarantine_dir) {
    // Create quarantine directory with readable permissions
    try {
        fs::create_directories(quarantine_dir_);
        
        // ════════════════════════════════════════════════════════
        // Set permissions to allow viewing (but not modifying)
        // 0755 = rwxr-xr-x (root can write, others can read/list)
        // ════════════════════════════════════════════════════════
        fs::permissions(quarantine_dir_, 
                       fs::perms::owner_all | 
                       fs::perms::group_read | fs::perms::group_exec |
                       fs::perms::others_read | fs::perms::others_exec,
                       fs::perm_options::replace);
    } catch (const std::exception& e) {
        std::cerr << "Failed to create quarantine directory: " << e.what() << std::endl;
    }
}

std::string QuarantineManager::QuarantineProcess(uint32_t pid, const std::string& threat_type) {
    std::string exe_path = GetProcessExecutablePath(pid);
    if (exe_path.empty()) {
        std::cerr << "Could not get executable path for PID " << pid << std::endl;
        return "";
    }
    
    return QuarantineFile(exe_path, threat_type);
}

std::string QuarantineManager::QuarantineFile(const std::string& file_path, 
                                               const std::string& threat_type) {
    if (!fs::exists(file_path)) {
        std::cerr << "File does not exist: " << file_path << std::endl;
        return "";
    }
    
    // ════════════════════════════════════════════════════════
    // Handle large binaries and system files gracefully
    // ════════════════════════════════════════════════════════
    
    // Check file size
    uintmax_t file_size = 0;
    try {
        file_size = fs::file_size(file_path);
    } catch (...) {
        file_size = 0;
    }
    
    // Skip quarantine for very large files (>100 MB)
    // Just log and create info file instead
    if (file_size > 100 * 1024 * 1024) {
        std::cout << "⚠️  File too large to quarantine (" << (file_size / 1024 / 1024) 
                  << " MB): " << file_path << std::endl;
        std::cout << "   Creating info file only (binary already killed)" << std::endl;
        
        // Create info file without copying binary
        std::string quarantine_path = GenerateQuarantineName(file_path, threat_type);
        std::string meta_path = quarantine_path + ".info";
        
        try {
            std::ofstream meta(meta_path);
            auto now = std::chrono::system_clock::now();
            auto time_t_now = std::chrono::system_clock::to_time_t(now);
            
            meta << "Original Path: " << file_path << "\n";
            meta << "Threat Type: " << threat_type << "\n";
            meta << "Quarantined: " << std::ctime(&time_t_now);
            meta << "File Size: " << file_size << " bytes\n";
            meta << "Note: Binary too large, not copied (process was killed)\n";
            meta.close();
            
            std::cout << "✓ Created quarantine info: " << meta_path << std::endl;
            return meta_path;
        } catch (const std::exception& e) {
            std::cerr << "Failed to create info file: " << e.what() << std::endl;
            return "";
        }
    }
    
    // Generate quarantine filename
    std::string quarantine_path = GenerateQuarantineName(file_path, threat_type);
    
    try {
        // Try to copy file
        std::error_code ec;
        fs::copy_file(file_path, quarantine_path, 
                     fs::copy_options::overwrite_existing, ec);
        
        if (ec) {
            // If copy fails, at least create info file
            std::cerr << "Failed to copy file (" << ec.message() << "): " << file_path << std::endl;
            std::cerr << "Creating info file only" << std::endl;
            
            std::string meta_path = quarantine_path + ".info";
            std::ofstream meta(meta_path);
            auto now = std::chrono::system_clock::now();
            auto time_t_now = std::chrono::system_clock::to_time_t(now);
            
            meta << "Original Path: " << file_path << "\n";
            meta << "Threat Type: " << threat_type << "\n";
            meta << "Quarantined: " << std::ctime(&time_t_now);
            meta << "Error: " << ec.message() << "\n";
            meta << "Note: Binary not copied (process was killed)\n";
            meta.close();
            
            return meta_path;
        }
        
        // Set read-only permissions on quarantined file
        fs::permissions(quarantine_path, 
                       fs::perms::owner_read | fs::perms::group_read,
                       fs::perm_options::replace);
        
        // Create metadata file
        std::string meta_path = quarantine_path + ".info";
        std::ofstream meta(meta_path);
        
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        
        meta << "Original Path: " << file_path << "\n";
        meta << "Threat Type: " << threat_type << "\n";
        meta << "Quarantined: " << std::ctime(&time_t_now);
        meta << "SHA256: [TODO: Calculate hash]\n";
        meta.close();
        
        std::cout << "✓ Quarantined: " << file_path << " -> " << quarantine_path << std::endl;
        
        return quarantine_path;
        
    } catch (const std::exception& e) {
        std::cerr << "Failed to quarantine file: " << e.what() << std::endl;
        return "";
    }
}

std::vector<std::string> QuarantineManager::ListQuarantine() {
    std::vector<std::string> items;
    
    try {
        for (const auto& entry : fs::directory_iterator(quarantine_dir_)) {
            // Skip .info files
            if (entry.path().extension() == ".info") {
                continue;
            }
            items.push_back(entry.path().string());
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to list quarantine: " << e.what() << std::endl;
    }
    
    return items;
}

bool QuarantineManager::RestoreFile(const std::string& quarantine_path, 
                                    const std::string& original_path) {
    try {
        // Read metadata to verify
        std::string meta_path = quarantine_path + ".info";
        if (!fs::exists(meta_path)) {
            std::cerr << "Metadata file not found" << std::endl;
            return false;
        }
        
        // Restore file
        fs::copy_file(quarantine_path, original_path, 
                     fs::copy_options::overwrite_existing);
        
        // Restore original permissions
        fs::permissions(original_path, 
                       fs::perms::owner_all | fs::perms::group_read | fs::perms::others_read,
                       fs::perm_options::replace);
        
        std::cout << "✓ Restored: " << quarantine_path << " -> " << original_path << std::endl;
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Failed to restore file: " << e.what() << std::endl;
        return false;
    }
}

bool QuarantineManager::DeleteQuarantined(const std::string& quarantine_path) {
    try {
        fs::remove(quarantine_path);
        fs::remove(quarantine_path + ".info");
        
        std::cout << "✓ Deleted quarantined file: " << quarantine_path << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Failed to delete quarantined file: " << e.what() << std::endl;
        return false;
    }
}

std::string QuarantineManager::GetProcessExecutablePath(uint32_t pid) {
    std::string exe_link = "/proc/" + std::to_string(pid) + "/exe";
    
    char buf[PATH_MAX];
    ssize_t len = readlink(exe_link.c_str(), buf, sizeof(buf) - 1);
    
    if (len != -1) {
        buf[len] = '\0';
        return std::string(buf);
    }
    
    return "";
}

std::string QuarantineManager::GenerateQuarantineName(const std::string& original_path,
                                                       const std::string& threat_type,
                                                       uint32_t pid) {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    
    // Extract filename from path
    std::string filename = fs::path(original_path).filename().string();
    
    std::ostringstream oss;
    oss << quarantine_dir_ << "/" 
        << threat_type << "_"
        << filename << "_";
    
    if (pid > 0) {
        oss << "pid" << pid << "_";
    }
    
    oss << std::put_time(std::localtime(&time_t_now), "%Y%m%d_%H%M%S");
    
    return oss.str();
}

} // namespace koraav
