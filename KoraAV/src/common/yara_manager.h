// src/common/yara_manager.h
#ifndef KORAAV_YARA_MANAGER_H
#define KORAAV_YARA_MANAGER_H

#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <unordered_set>
#include <atomic>

// Forward declare YARA types to avoid including yara.h in header
struct YR_RULES;

namespace koraav {

    /**
     * Centralized YARA Rules Manager (Singleton)
     *
     * The single module for all YARA operations in KoraAV.
     * Used by the CLI scanner, the real-time daemon (file writes,
     * process execution), and any future scan path.
     *
     * Rules are loaded from: /opt/koraav/share/signatures/yara-rules/
     *
     * Features:
     * - Runtime loading (no compilation into binary)
     * - Hot-reload support (add rules without restart)
     * - Thread-safe scanning
     * - Recursive directory scanning
     * - Extension skip list (avoids scanning known-safe file types)
     * - Scan statistics (files scanned, detections, avg scan time)
     */
    class YaraManager {
    public:
        // ── Scan statistics ───────────────────────────────────────────────
        struct Statistics {
            uint64_t files_scanned      = 0;
            uint64_t memory_scans       = 0;
            uint64_t malware_detected   = 0;
            uint64_t skipped_extension  = 0;  // hit the extension skip list
            uint64_t skipped_too_large  = 0;  // exceeded max_file_size
            double   avg_scan_time_ms   = 0.0;
        };

        // ── Lifecycle ─────────────────────────────────────────────────────
        static YaraManager& Instance();

        // Initialize YARA library (call once at startup)
        bool Initialize();

        // Load/reload all rules from directory (recursive)
        bool LoadRules(const std::string& rules_dir =
        "/opt/koraav/share/signatures/yara-rules");

        // Reload rules from the previously set directory
        bool Reload();

        // Cleanup
        void Shutdown();

        // ── Scan operations (thread-safe) ─────────────────────────────────
        // Returns a list of matching rule names, empty = clean.
        // Applies the extension skip list and size limit before scanning.
        std::vector<std::string> ScanFile(const std::string& path);
        std::vector<std::string> ScanMemory(const void* data, size_t size);

        // ── Extension skip list ───────────────────────────────────────────
        // Extensions in this set are returned as clean without scanning.
        // Populated with sensible defaults at construction; callers can
        // add more at runtime (e.g. from the exclusion database).
        void SkipExtension(const std::string& ext);   // e.g. ".vmdk"
        void RemoveSkippedExtension(const std::string& ext);
        bool IsExtensionSkipped(const std::string& path) const;

        // ── Status / statistics ───────────────────────────────────────────
        bool        IsReady()          const;
        std::string GetRulesDirectory() const { return rules_dir_; }
        int         GetRuleCount()     const;
        Statistics  GetStatistics()    const;
        void        ResetStatistics();

    private:
        YaraManager();
        ~YaraManager();

        YaraManager(const YaraManager&)            = delete;
        YaraManager& operator=(const YaraManager&) = delete;

        bool LoadRulesInternal(const std::string& dir);
        void UpdateStats(bool is_file, double scan_ms, bool matched);

        // ── State ─────────────────────────────────────────────────────────
        YR_RULES*   rules_       = nullptr;
        std::string rules_dir_;
        bool        initialized_ = false;
        mutable std::mutex mutex_;  // guards rules_, initialized_, rules_dir_

        // Extension skip list (lowercase ".ext" → skip)
        mutable std::mutex             skip_mutex_;
        std::unordered_set<std::string> skip_extensions_;

        // Statistics (atomic so reads don't need the scan lock)
        mutable std::mutex stats_mutex_;
        Statistics         stats_;
    };

} // namespace koraav

#endif // KORAAV_YARA_MANAGER_H
