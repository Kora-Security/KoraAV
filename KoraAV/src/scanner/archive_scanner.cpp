// src/scanner/archive_scanner.cpp
#include "archive_scanner.h"
#include "file_scanner.h"
#include <filesystem>
#include <cstdlib>
#include <iostream>
#include <unistd.h>

namespace fs = std::filesystem;

namespace koraav {
namespace scanner {

bool ArchiveScanner::IsArchive(const std::string& path) {
    return DetectArchiveType(path) != ArchiveType::UNKNOWN;
}

ArchiveScanner::ArchiveType ArchiveScanner::DetectArchiveType(const std::string& path) {
    std::string lower_path = path;
    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);
    
    if (lower_path.ends_with(".zip")) return ArchiveType::ZIP;
    if (lower_path.ends_with(".tar")) return ArchiveType::TAR;
    if (lower_path.ends_with(".tar.gz") || lower_path.ends_with(".tgz")) return ArchiveType::TAR_GZ;
    if (lower_path.ends_with(".tar.bz2") || lower_path.ends_with(".tbz2")) return ArchiveType::TAR_BZ2;
    if (lower_path.ends_with(".tar.xz") || lower_path.ends_with(".txz")) return ArchiveType::TAR_XZ;
    if (lower_path.ends_with(".7z")) return ArchiveType::SEVEN_ZIP;
    if (lower_path.ends_with(".rar")) return ArchiveType::RAR;
    
    return ArchiveType::UNKNOWN;
}

std::string ArchiveScanner::ExtractArchive(const std::string& path) {
    // Create temporary directory
    char temp_template[] = "/tmp/koraav-extract-XXXXXX";
    char* temp_dir = mkdtemp(temp_template);
    if (!temp_dir) {
        std::cerr << "Failed to create temp directory" << std::endl;
        return "";
    }
    
    std::string temp_path(temp_dir);
    ArchiveType type = DetectArchiveType(path);
    
    // Build extraction command based on type
    std::string cmd;
    switch (type) {
        case ArchiveType::ZIP:
            cmd = "unzip -q -d \"" + temp_path + "\" \"" + path + "\" 2>/dev/null";
            break;
            
        case ArchiveType::TAR:
            cmd = "tar -xf \"" + path + "\" -C \"" + temp_path + "\" 2>/dev/null";
            break;
            
        case ArchiveType::TAR_GZ:
            cmd = "tar -xzf \"" + path + "\" -C \"" + temp_path + "\" 2>/dev/null";
            break;
            
        case ArchiveType::TAR_BZ2:
            cmd = "tar -xjf \"" + path + "\" -C \"" + temp_path + "\" 2>/dev/null";
            break;
            
        case ArchiveType::TAR_XZ:
            cmd = "tar -xJf \"" + path + "\" -C \"" + temp_path + "\" 2>/dev/null";
            break;
            
        case ArchiveType::SEVEN_ZIP:
            cmd = "7z x -o\"" + temp_path + "\" \"" + path + "\" >/dev/null 2>&1";
            break;
            
        case ArchiveType::RAR:
            cmd = "unrar x -o+ \"" + path + "\" \"" + temp_path + "\" >/dev/null 2>&1";
            break;
            
        default:
            CleanupExtraction(temp_path);
            return "";
    }
    
    // Execute extraction
    int result = system(cmd.c_str());
    if (result != 0) {
        std::cerr << "Failed to extract archive: " << path << std::endl;
        CleanupExtraction(temp_path);
        return "";
    }
    
    return temp_path;
}

void ArchiveScanner::CleanupExtraction(const std::string& temp_dir) {
    if (temp_dir.empty() || !fs::exists(temp_dir)) {
        return;
    }
    
    // Remove temporary directory
    try {
        fs::remove_all(temp_dir);
    } catch (const std::exception& e) {
        std::cerr << "Warning: Failed to cleanup " << temp_dir << ": " << e.what() << std::endl;
    }
}

std::vector<FileScanResult> ArchiveScanner::ScanArchive(
    const std::string& path,
    FileScanner& scanner,
    size_t max_depth) 
{
    std::vector<FileScanResult> threats;
    
    if (max_depth == 0) {
        std::cerr << "Warning: Max archive depth reached, skipping: " << path << std::endl;
        return threats;
    }
    
    // Extract archive
    std::string temp_dir = ExtractArchive(path);
    if (temp_dir.empty()) {
        return threats;
    }
    
    // TODO: If zip bomb, etc. detected, stop it.
    try {
        // Scan all extracted files
        for (const auto& entry : fs::recursive_directory_iterator(temp_dir)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            
            std::string file_path = entry.path().string();
            
            // Check if this is a nested archive
            if (IsArchive(file_path)) {
                // Recursively scan nested archive
                auto nested_threats = ScanArchive(file_path, scanner, max_depth - 1);
                threats.insert(threats.end(), nested_threats.begin(), nested_threats.end());
            } else {
                // Scan regular file
                FileScanResult result = scanner.ScanFile(file_path);
                if (result.is_threat()) {
                    // Update path to show it's from archive
                    result.path = path + " -> " + entry.path().filename().string();
                    threats.push_back(result);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error scanning archive contents: " << e.what() << std::endl;
    }
    
    // Cleanup
    CleanupExtraction(temp_dir);
    
    return threats;
}

} // namespace scanner
} // namespace koraav
