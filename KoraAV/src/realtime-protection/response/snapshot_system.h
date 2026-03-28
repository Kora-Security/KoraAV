// src/realtime-protection/response/snapshot_system.h
#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <atomic>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <functional>

namespace koraav {
    namespace realtime {

        /**
         * @brief Enterprise-grade snapshot system for ransomware recovery
         *
         * Supports:
         * - Btrfs (native snapshots)
         * - LVM Thin (space-efficient snapshots)
         * - ZFS (native snapshots)
         * - ext4 on LVM (LVM snapshots)
         * - XFS on LVM (XFS on LVM snapshots)
         * - Plain ext4/XFS (rsync-based snapshots)
         *
         * inotify Integration:
         * - Watches critical directories for high-frequency write bursts
         * - Detects mass-rename/delete patterns (classic ransomware IOC)
         * - Triggers emergency snapshot when anomalous activity is detected
         * - Complements the rolling 5-minute snapshots — does NOT replace them
         *   (inotify can miss events under extreme kernel load; rolling snapshots
         *    always guarantee a ≤5 min recovery point)
         */
        class SnapshotSystem {
        public:
            enum class FilesystemType {
                UNKNOWN,
                BTRFS,
                LVM_THIN,
                ZFS,
                EXT4_LVM,
                XFS_LVM,
                EXT4_RSYNC,
                XFS_RSYNC,
                UNSUPPORTED
            };

            struct SnapshotEntry {
                std::string id;
                std::string path;
                std::chrono::system_clock::time_point created;
                bool is_readonly;
                uint64_t size_bytes;
                bool emergency;   // true = triggered by inotify anomaly
            };

            struct Statistics {
                uint64_t snapshots_created;
                uint64_t snapshots_deleted;
                uint64_t rollbacks_performed;
                uint64_t deletion_attempts_blocked;
                uint64_t emergency_snapshots_triggered; // inotify-triggered
                uint64_t inotify_events_processed;
            };

            // ── inotify anomaly thresholds ─────────────────────────────────
            struct InotifyConfig {
                // How many file modification events per window triggers an
                // emergency snapshot.
                uint32_t write_burst_threshold      = 50;

                // How many rename events per window is suspicious.
                uint32_t rename_burst_threshold     = 20;

                // How many delete events per window is suspicious.
                uint32_t delete_burst_threshold     = 20;

                // Sliding window duration (seconds) for all counters above.
                uint32_t window_seconds             = 10;

                // Minimum gap (seconds) between two consecutive emergency
                // snapshots — prevents a burst from triggering dozens of
                // near-identical snapshots.
                uint32_t min_emergency_interval_sec = 30;

                // Whether inotify watching is enabled at all.
                bool     enabled                    = true;
            };

            SnapshotSystem();
            ~SnapshotSystem();

            // Initialize and detect filesystem
            bool Initialize(int max_snapshots,
                            int snapshot_interval_minutes,
                            const std::string& snapshot_dir);

            // ── inotify control ────────────────────────────────────────────
            // Start watching all critical directories.  Called automatically
            // by Initialize() when inotify is enabled.
            bool StartInotifyWatcher();

            // Stop the inotify watcher thread gracefully.
            void StopInotifyWatcher();

            // Override default inotify thresholds before Initialize().
            void SetInotifyConfig(const InotifyConfig& cfg) { inotify_cfg_ = cfg; }
            const InotifyConfig& GetInotifyConfig() const   { return inotify_cfg_; }

            // ── snapshot creation ──────────────────────────────────────────
            // Create a scheduled (rolling) snapshot.
            std::string CreateSnapshot();

            // Create an emergency snapshot (called by inotify watcher).
            std::string CreateEmergencySnapshot(const std::string& reason);

            // Rollback to most recent snapshot
            bool RollbackToLatestSnapshot();

            // List available snapshots
            std::vector<std::string> ListSnapshots() const;

            // Get statistics
            Statistics GetStats() const;

            // Check if command is attempting to delete snapshots (block it)
            bool IsSnapshotDeletionAttempt(const std::string& command) const;

            // Configuration
            void SetMaxSnapshots(int max)           { max_snapshots_ = max; }
            void SetSnapshotInterval(int minutes)   { snapshot_interval_minutes_ = minutes; }

            // Get filesystem info
            FilesystemType GetFilesystemType() const { return fs_type_; }
            std::string    GetFilesystemTypeName() const;

        private:
            // ── filesystem detection ───────────────────────────────────────
            bool DetectFilesystem();

            // ── snapshot creation by filesystem type ───────────────────────
            std::string CreateBtrfsSnapshot();
            std::string CreateLVMSnapshot();
            std::string CreateZFSSnapshot();
            std::string CreateRsyncSnapshot();

            // Internal shared creation path (handles entry tracking)
            std::string CreateSnapshotInternal(bool emergency,
                                               const std::string& reason = "");

            // ── rollback by filesystem type ────────────────────────────────
            bool RollbackBtrfsSnapshot(const std::string& snapshot_id);
            bool RollbackLVMSnapshot(const std::string& snapshot_id);
            bool RollbackZFSSnapshot(const std::string& snapshot_id);
            bool RollbackRsyncSnapshot(const std::string& snapshot_id);

            // ── inotify internals ──────────────────────────────────────────
            // Main loop run in inotify_thread_.
            void InotifyWatchLoop();

            // Add inotify watches for all critical directories (recursive).
            bool AddWatchesForDirectory(int inotify_fd,
                                        const std::string& path,
                                        std::unordered_map<int, std::string>& wd_to_path);

            // Evaluate counters and decide whether to fire emergency snapshot.
            void EvaluateInotifyCounters();

            // Reset the per-window event counters.
            void ResetInotifyCounters();

            // ── helpers ────────────────────────────────────────────────────
            bool        MakeSnapshotImmutable(const std::string& snapshot_path);
            bool        DeleteOldestSnapshot();
            std::string GenerateSnapshotID();
            std::string ExecuteCommand(const std::string& command);
            uint64_t    GetSnapshotSize(const std::string& snapshot_path);

            // Filesystem detection helpers
            bool        IsLVMAvailable();
            bool        IsBtrfsAvailable();
            bool        IsZFSAvailable();
            std::string GetRootVolumeGroup();
            std::string GetRootLogicalVolume();

            // rsync helpers
            std::vector<std::string> GetCriticalDirectories();
            bool CreateSnapshotDirectory(const std::string& snapshot_path);

            // ── state ──────────────────────────────────────────────────────
            FilesystemType fs_type_;
            std::string    root_mount_;
            std::string    snapshot_dir_;

            int max_snapshots_;
            int snapshot_interval_minutes_;

            std::vector<SnapshotEntry> active_snapshots_;
            mutable std::mutex         snapshots_mutex_;

            // inotify
            InotifyConfig inotify_cfg_;
            int           inotify_fd_      = -1;
            std::thread   inotify_thread_;
            std::atomic<bool> inotify_running_{false};

            // Per-window counters (protected by inotify_counters_mutex_)
            std::mutex    inotify_counters_mutex_;
            uint32_t      inotify_writes_  = 0;
            uint32_t      inotify_renames_ = 0;
            uint32_t      inotify_deletes_ = 0;
            std::chrono::steady_clock::time_point window_start_;

            // Rate-limit consecutive emergency snapshots
            std::chrono::steady_clock::time_point last_emergency_snapshot_;

            // Statistics
            struct Stats {
                std::atomic<uint64_t> snapshots_created{0};
                std::atomic<uint64_t> snapshots_deleted{0};
                std::atomic<uint64_t> rollbacks_performed{0};
                std::atomic<uint64_t> deletion_attempts_blocked{0};
                std::atomic<uint64_t> emergency_snapshots_triggered{0};
                std::atomic<uint64_t> inotify_events_processed{0};
            } stats_;
        };

    } // namespace realtime
} // namespace koraav
