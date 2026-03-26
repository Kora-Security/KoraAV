// src/realtime-protection/behavioral-analysis/canary_file_system.cpp
#include "canary_file_system.h"
#include <iostream>
#include <fstream>
#include <random>
#include <sys/stat.h>
#include <glob.h>
#include <unistd.h>
#include <filesystem>
#include <cstring>

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
            // Generate context-aware canary name based on directory
            std::string canary_name = GenerateCanaryName(dir);
            
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
    // ════════════════════════════════════════════════════════
    // Check if directory exists - if not, silently skip
    // (Directories should exist from installer, but user dirs vary)
    // ════════════════════════════════════════════════════════
    struct stat st;
    if (stat(directory.c_str(), &st) != 0) {
        // Directory doesn't exist - skip silently (normal for some user dirs)
        return false;
    }
    
    if (!S_ISDIR(st.st_mode)) {
        // Not a directory - skip silently
        return false;
    }
    
    // ════════════════════════════════════════════════════════
    // Check if koraav user can write to this directory
    // ════════════════════════════════════════════════════════
    std::string test_file = directory + "/.koraav_write_test";
    std::ofstream test(test_file);
    if (!test) {
        // Can't write here - skip silently (permission issue)
        return false;
    }
    test.close();
    unlink(test_file.c_str());
    
    // ════════════════════════════════════════════════════════
    // Create canary file
    // ════════════════════════════════════════════════════════
    std::string filepath = directory + "/" + name;
    
    std::ofstream file(filepath);
    if (!file) {
        // Can't create file - skip silently
        return false;
    }
    
    file << GenerateCanaryContent(directory);
    file.close();
    
    // Verify it was created
    if (stat(filepath.c_str(), &st) != 0) {
        return false;
    }
    
    // // ═══════════════════════════════════════════════════════════════
    // // CRITICAL: Change ownership to match the directory owner
    // // ═══════════════════════════════════════════════════════════════
    // // Get directory ownership
    // struct stat dir_stat;
    // if (stat(directory.c_str(), &dir_stat) == 0) {
    //     // Change canary file to match directory owner
    //     // This way the user can write to their own canaries!
    //     if (chown(filepath.c_str(), dir_stat.st_uid, dir_stat.st_gid) != 0) {
    //         std::cerr << "⚠️  Warning: Could not change canary ownership: " << filepath << std::endl;
    //         // Don't fail - file is still usable
    //     }
    // }
    
    // ═══════════════════════════════════════════════════════════════
    // CRITICAL: Make canary files WORLD-WRITABLE (0666)
    // ═══════════════════════════════════════════════════════════════
    // Ransomware running as ANY user must be able to write to these files
    // Otherwise they won't trigger detection!
    // 
    // 0666 = -rw-rw-rw- (everyone can read and write)
    // This looks like a normal user document file
    // ═══════════════════════════════════════════════════════════════
    if (chmod(filepath.c_str(), 0666) != 0) {
        unlink(filepath.c_str());
        return false;
    }
    
    std::cout << "✓ Created canary: " << filepath << std::endl;
    return true;
}

std::string CanaryFileSystem::GenerateCanaryName(const std::string& directory) {
    // ═══════════════════════════════════════════════════════════════
    // CONTEXT-AWARE CANARY NAMING
    // ═══════════════════════════════════════════════════════════════
    // Inspect the directory and blend in with existing files:
    //  - If dir has .txt files → create .txt canaries
    //  - If dir has hidden files → create hidden canaries
    //  - If dir has .doc/.pdf → create similar canaries
    //  - Match the style of surroundings!
    // ═══════════════════════════════════════════════════════════════
    
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Analyze existing files in directory
    std::vector<std::string> existing_extensions;
    int hidden_count = 0;
    int visible_count = 0;
    
    try {
        for (const auto& entry : fs::directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                
                // Count hidden vs visible
                if (filename[0] == '.') {
                    hidden_count++;
                } else {
                    visible_count++;
                }
                
                // Collect extensions
                size_t dot_pos = filename.find_last_of('.');
                if (dot_pos != std::string::npos && dot_pos > 0) {
                    std::string ext = filename.substr(dot_pos);
                    existing_extensions.push_back(ext);
                }
            }
        }
    } catch (...) {
        // If can't read directory, use generic approach
    }
    
    // Decide: hidden or visible based on directory content
    bool make_hidden;
    if (hidden_count + visible_count == 0) {
        // Empty directory - 50/50
        make_hidden = (rd() % 2 == 0);
    } else {
        // Match the ratio of hidden:visible files
        int total = hidden_count + visible_count;
        int hidden_probability = (hidden_count * 100) / total;
        make_hidden = ((rd() % 100) < hidden_probability);
    }
    
    // Choose extension based on what exists in directory
    std::string extension;
    if (!existing_extensions.empty() && (rd() % 3 != 0)) {  // 66% use existing
        std::uniform_int_distribution<> ext_dis(0, existing_extensions.size() - 1);
        extension = existing_extensions[ext_dis(gen)];
    } else {  // 33% use generic extensions
        std::vector<std::string> generic_exts = {
            ".txt", ".doc", ".docx", ".pdf", ".conf", ".cfg", 
            ".cache", ".tmp", ".log", ".dat", ".bak", ".old"
        };
        std::uniform_int_distribution<> ext_dis(0, generic_exts.size() - 1);
        extension = generic_exts[ext_dis(gen)];
    }
    
    // Generate base filename
    std::vector<std::string> prefixes = {
        "config", "temp", "cache", "backup", "notes", "data", 
        "settings", "sync", "index", "metadata", "thumbnail",
        "preview", "draft", "archive", "document", "file",
        "image", "photo", "screenshot", "recording", "download"
    };
    
    std::vector<std::string> suffixes = {
        "backup", "temp", "old", "new", "copy", "draft",
        "final", "v1", "v2", "v3", "2024", "2025", "2026", "data"
    };
    
    std::uniform_int_distribution<> prefix_dis(0, prefixes.size() - 1);
    std::uniform_int_distribution<> suffix_dis(0, suffixes.size() - 1);
    std::uniform_int_distribution<> pattern_dis(0, 3);
    
    std::string base;
    switch (pattern_dis(gen)) {
        case 0:
            // "config_backup"
            base = prefixes[prefix_dis(gen)] + "_" + suffixes[suffix_dis(gen)];
            break;
        case 1:
            // "temp_20240309"
            base = prefixes[prefix_dis(gen)] + "_" + 
                   std::to_string(20240000 + (rd() % 10000));
            break;
        case 2:
            // "file_a1b2c3d4"
            base = prefixes[prefix_dis(gen)] + "_" + GetRandomHex(8);
            break;
        case 3:
            // "data-backup"
            base = prefixes[prefix_dis(gen)] + "-" + suffixes[suffix_dis(gen)];
            break;
    }
    
    std::string filename;
    if (make_hidden) {
        filename = "." + base + extension;
    } else {
        filename = base + extension;
    }
    
    return filename;
}

std::string CanaryFileSystem::GenerateCanaryContent(const std::string& directory) {
    // Get a random existing file from same directory
    std::vector<std::string> templates;
    
    // Track which files we've already used (static to persist across calls)
    static std::unordered_set<std::string> used_templates;

    for (const auto& entry : fs::directory_iterator(directory)) {
        if (entry.is_regular_file() &&
            entry.file_size() > 100 &&
            entry.file_size() < 10000) {
            templates.push_back(entry.path());
            }
    }

    if (!templates.empty()) {
        // Pick random template that hasn't been used yet
        std::random_device rd;
        std::mt19937 gen(rd());
        
        // Try to find unused template first
        std::vector<std::string> unused_templates;
        for (const auto& t : templates) {
            if (used_templates.find(t) == used_templates.end()) {
                unused_templates.push_back(t);
            }
        }
        
        // If all templates used, clear the set and start over
        if (unused_templates.empty()) {
            used_templates.clear();
            unused_templates = templates;
        }
        
        std::uniform_int_distribution<> dis(0, unused_templates.size() - 1);
        std::string template_file = unused_templates[dis(gen)];
        
        // Mark as used
        used_templates.insert(template_file);

        // Copy first 1KB of content
        std::ifstream in(template_file, std::ios::binary);
        std::string content;
        content.resize(1024);
        in.read(&content[0], 1024);
        content.resize(in.gcount());

        return content;  // Real file content!
    }
    
    // Fallback: Generate random unique content
    std::random_device rd;
    std::string random_hex = GetRandomHex(8);
    
    return "# System configuration cache\n"
           "# Auto-generated - do not modify\n"
           "session_id=" + random_hex + "\n"
           "timestamp=" + std::to_string(rd()) + "\n"
           "checksum=" + GetRandomHex(8) + "\n"
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
