// src/realtime-protection/behavioral-analysis/canary_file_system.cpp
#include "canary_file_system.h"
#include <iostream>
#include <fstream>
#include <random>
#include <sys/stat.h>
#include <glob.h>
#include <unistd.h>
#include <filesystem>

namespace fs = std::filesystem;
namespace koraav {
namespace realtime {

CanaryFileSystem::CanaryFileSystem() {
}

CanaryFileSystem::~CanaryFileSystem() {
    // Clean up canaries on shutdown
    DeleteOldCanaries();
}

bool CanaryFileSystem::Initialize(int canaries_per_directory) {
    std::cout << "═══════════════════════════════════════════════════════════" << std::endl;
    std::cout << "🐦 Canary File System Initializing" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════" << std::endl;
    
    // Delete any old canaries from previous run
    DeleteOldCanaries();
    
    // Create new canaries
    CreateCanaries(canaries_per_directory);
    
    std::cout << "✓ Created " << active_canaries_.size() << " canary files" << std::endl;
    std::cout << "✓ Any modification triggers instant detection (score = 100)" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════" << std::endl;
    
    return true;
}

void CanaryFileSystem::CreateCanaries(int count_per_directory) {
    std::lock_guard<std::mutex> lock(canaries_mutex_);
    
    // Expand directory patterns (e.g., /home/* → /home/user1, /home/user2, ...)
    std::vector<std::string> directories = ExpandDirectoryPatterns();
    
    for (const auto& dir : directories) {
        for (int i = 0; i < count_per_directory; ++i) {
            std::string canary_name = GenerateCanaryName();
            
            if (CreateCanaryFile(dir, canary_name)) {
                CanaryFile canary;
                canary.path = dir + "/" + canary_name;
                canary.name = canary_name;
                canary.created = std::chrono::system_clock::now();
                
                active_canaries_.push_back(canary);
                canary_paths_.insert(canary.path);
                stats_.canaries_created++;
            }
        }
    }
}

bool CanaryFileSystem::CreateCanaryFile(const std::string& directory, const std::string& name) {
    // Check if directory exists
    struct stat st;
    if (stat(directory.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        return false;
    }
    
    std::string filepath = directory + "/" + name;
    
    // Create file with innocuous content
    std::ofstream file(filepath);
    if (!file) {
        return false;
    }
    
    file << GenerateCanaryContent(directory);
    file.close();
    
    // Set normal permissions (don't make it obvious)
    chmod(filepath.c_str(), 0644);
    
    return true;
}

std::string CanaryFileSystem::GenerateCanaryName() {
    // Generate random hidden filename that looks like system cache
    // TODO: Make ".koraav-" random as well so malware can't just look for hidden files starting with such and ignore them.
    std::string prefix = ".koraav-";
    std::string suffix = GetRandomHex(8);
    
    // Random extension to blend in
    std::vector<std::string> extensions = {".txt", ".conf", ".cache", ".tmp", ".log", ".doc"};
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, extensions.size() - 1);
    
    return prefix + suffix + extensions[dis(gen)];
}

std::string CanaryFileSystem::GenerateCanaryContent(const std::string& directory) {
    // Get a random existing file from same directory
    std::vector<std::string> templates;

    for (const auto& entry : fs::directory_iterator(directory)) {
        if (entry.is_regular_file() &&
            entry.file_size() > 100 &&
            entry.file_size() < 10000) {
            templates.push_back(entry.path());
            }
    }

    if (!templates.empty()) {
        // Pick random template
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, templates.size() - 1);

        std::string template_file = templates[dis(gen)];

        // Copy first 1KB of content
        std::ifstream in(template_file, std::ios::binary);
        std::string content;
        content.resize(1024);
        in.read(&content[0], 1024);
        content.resize(in.gcount());

        return content;  // Real file content!
    }
    // Fallback to Innocuous content that looks like system configuration cache stuff.
    return "# System configuration cache\n"
           "# Auto-generated - do not modify\n"
           "timestamp=06182326\n"
           "checksum=deadbeef\n"
           "version=1.0.7\n";
}

std::string CanaryFileSystem::GetRandomHex(int length) {
    static const char hex_chars[] = "0123456789abcdef";
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::string result;
    for (int i = 0; i < length; ++i) {
        result += hex_chars[dis(gen)];
    }
    
    return result;
}

std::vector<std::string> CanaryFileSystem::ExpandDirectoryPatterns() {
    std::vector<std::string> expanded;
    
    for (const auto& pattern : protected_dir_patterns_) {
        if (pattern.find('*') != std::string::npos) {
            // Expand glob pattern
            glob_t glob_result;
            if (glob(pattern.c_str(), GLOB_TILDE, nullptr, &glob_result) == 0) {
                for (size_t i = 0; i < glob_result.gl_pathc; ++i) {
                    expanded.push_back(glob_result.gl_pathv[i]);
                }
                globfree(&glob_result);
            }
        } else {
            // Direct path
            expanded.push_back(pattern);
        }
    }
    
    return expanded;
}

void CanaryFileSystem::DeleteOldCanaries() {
    std::lock_guard<std::mutex> lock(canaries_mutex_);
    
    for (const auto& canary : active_canaries_) {
        unlink(canary.path.c_str());
    }
    
    active_canaries_.clear();
    canary_paths_.clear();
}

bool CanaryFileSystem::IsCanaryFile(const std::string& filepath) const {
    std::lock_guard<std::mutex> lock(canaries_mutex_);
    
    // Fast O(1) lookup in unordered_set
    bool is_canary = canary_paths_.find(filepath) != canary_paths_.end();
    
    if (is_canary) {
        stats_.canaries_triggered++;
    }
    
    return is_canary;
}

void CanaryFileSystem::RotateCanaries() {
    std::cout << "🔄 Rotating canary files for unpredictability..." << std::endl;
    
    DeleteOldCanaries();
    CreateCanaries(2);  // Recreate with default count
    
    stats_.rotations_performed++;
    
    std::cout << "✓ Canaries rotated - new locations/names" << std::endl;
}

std::vector<std::string> CanaryFileSystem::GetCanaryPaths() const {
    std::lock_guard<std::mutex> lock(canaries_mutex_);
    
    std::vector<std::string> paths;
    paths.reserve(active_canaries_.size());
    
    for (const auto& canary : active_canaries_) {
        paths.push_back(canary.path);
    }
    
    return paths;
}

CanaryFileSystem::Statistics CanaryFileSystem::GetStats() const {
    Statistics snapshot;
    snapshot.canaries_created = stats_.canaries_created.load();
    snapshot.canaries_triggered = stats_.canaries_triggered.load();
    snapshot.rotations_performed = stats_.rotations_performed.load();
    return snapshot;
}

} // namespace realtime
} // namespace koraav
