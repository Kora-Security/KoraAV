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
#include <algorithm>
#include <chrono>
#include <cstring>
#include <sys/stat.h>

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
        // Default extension skip list — file types that cannot realistically carry executable malware and would waste scan time.
        // May change this
        skip_extensions_ = {
            // Plain text / data
            ".txt", ".log", ".md", ".csv", ".json", ".xml", ".yaml", ".yml",
            // Images
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico",
            // Audio / video
            ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav", ".flac", ".ogg",
            // Build artefacts (object files, static/shared libs versioned symlinks)
            ".o", ".a", ".so.1", ".so.2", ".so.3",
            // Compressed archives are scanned by ArchiveScanner separately
            // — do NOT skip .zip/.tar here; leave that to the archive path
        };
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

        // ── Pre-scan validation ───────────────────────────────────────────

        struct stat st;
        if (stat(path.c_str(), &st) != 0)  return matches;  // can't stat
        if (S_ISDIR(st.st_mode))           return matches;  // directory
        if (!S_ISREG(st.st_mode))          return matches;  // socket/FIFO/device
        if (st.st_size == 0)               return matches;  // empty

        // Size limit (200 MB)
        const off_t MAX_FILE_SIZE = 200 * 1024 * 1024;
        if (st.st_size > MAX_FILE_SIZE) {
            std::cerr << "⚠️  File too large (" << (st.st_size / 1024 / 1024)
            << " MB), skipping: " << path << std::endl;
            std::lock_guard<std::mutex> sl(stats_mutex_);
            stats_.skipped_too_large++;
            return matches;
        }

        // Self-protection
        if (path.find("/opt/koraav/") == 0 ||
            path == "/usr/bin/koraav"      ||
            path == "/usr/bin/korad") {
            return matches;
            }

            // Extension skip list
            if (IsExtensionSkipped(path)) {
                std::lock_guard<std::mutex> sl(stats_mutex_);
                stats_.skipped_extension++;
                return matches;
            }

            // ── Scan ─────────────────────────────────────────────────────────

            auto t0 = std::chrono::steady_clock::now();

            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!rules_) return matches;

                int result = yr_rules_scan_file(rules_, path.c_str(), 0,
                                                scan_callback, &matches, 0);
                if (result != ERROR_SUCCESS) {
                    const char* error_msg = "Unknown error";
                    switch (result) {
                        case ERROR_INSUFFICIENT_MEMORY:  error_msg = "Insufficient memory"; break;
                        case ERROR_COULD_NOT_OPEN_FILE:  error_msg = "Could not open file";  break;
                        case ERROR_COULD_NOT_MAP_FILE:   error_msg = "Could not map file";   break;
                        case ERROR_SCAN_TIMEOUT:         error_msg = "Scan timeout";         break;
                    }
                    std::cerr << "⚠️  YARA scan failed on " << path
                    << " (code " << result << ": " << error_msg << ")" << std::endl;
                }
            }

            double ms = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - t0).count();
                UpdateStats(/*is_file=*/true, ms, !matches.empty());

                return matches;
    }

    std::vector<std::string> YaraManager::ScanMemory(const void* data, size_t size) {
        std::vector<std::string> matches;

        if (!data || size == 0) return matches;

        auto t0 = std::chrono::steady_clock::now();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!rules_) return matches;

            int result = yr_rules_scan_mem(rules_, (const uint8_t*)data, size,
                                           0, scan_callback, &matches, 0);
            if (result != ERROR_SUCCESS) {
                std::cerr << "YARA scan failed on memory: " << result << std::endl;
            }
        }

        double ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
            UpdateStats(/*is_file=*/false, ms, !matches.empty());

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

    // ── Extension skip list ───────────────────────────────────────────────────

    void YaraManager::SkipExtension(const std::string& ext) {
        std::string lower = ext;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (!lower.empty() && lower[0] != '.') lower = "." + lower;
        std::lock_guard<std::mutex> lk(skip_mutex_);
        skip_extensions_.insert(lower);
    }

    void YaraManager::RemoveSkippedExtension(const std::string& ext) {
        std::string lower = ext;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (!lower.empty() && lower[0] != '.') lower = "." + lower;
        std::lock_guard<std::mutex> lk(skip_mutex_);
        skip_extensions_.erase(lower);
    }

    bool YaraManager::IsExtensionSkipped(const std::string& path) const {
        fs::path p(path);
        std::string ext = p.extension().string();
        if (ext.empty()) return false;
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        std::lock_guard<std::mutex> lk(skip_mutex_);
        return skip_extensions_.count(ext) > 0;
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    void YaraManager::UpdateStats(bool is_file, double scan_ms, bool matched) {
        std::lock_guard<std::mutex> lk(stats_mutex_);
        if (is_file) stats_.files_scanned++;
        else         stats_.memory_scans++;
        if (matched) stats_.malware_detected++;

        // Running average over all scans (file + memory)
        uint64_t total = stats_.files_scanned + stats_.memory_scans;
        if (total == 1) {
            stats_.avg_scan_time_ms = scan_ms;
        } else {
            stats_.avg_scan_time_ms =
            (stats_.avg_scan_time_ms * (total - 1) + scan_ms) / total;
        }
    }

    YaraManager::Statistics YaraManager::GetStatistics() const {
        std::lock_guard<std::mutex> lk(stats_mutex_);
        return stats_;
    }

    void YaraManager::ResetStatistics() {
        std::lock_guard<std::mutex> lk(stats_mutex_);
        stats_ = Statistics{};
    }

} // namespace koraav
