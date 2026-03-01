// src/realtime-protection/behavioral-analysis/snapshot_system.h
#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <atomic>

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
         * - XFS on LVM (LVM snapshots)
         * - **NEW: Plain ext4/XFS (rsync-based snapshots)**
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
                EXT4_RSYNC,      // NEW: Plain ext4 with rsync
                XFS_RSYNC,       // NEW: Plain XFS with rsync
                UNSUPPORTED
            };

            struct SnapshotEntry {
                std::string id;
                std::string path;
                std::chrono::system_clock::time_point created;
                bool is_readonly;
                uint64_t size_bytes;
            };

            struct Statistics {
                uint64_t snapshots_created;
                uint64_t snapshots_deleted;
                uint64_t rollbacks_performed;
                uint64_t deletion_attempts_blocked;
            };

            SnapshotSystem();
            ~SnapshotSystem();

            // Initialize and detect filesystem
            bool Initialize();

            // Create new snapshot
            std::string CreateSnapshot();

            // Rollback to most recent snapshot
            bool RollbackToLatestSnapshot();

            // List available snapshots
            std::vector<std::string> ListSnapshots() const;

            // Get statistics
            Statistics GetStats() const;

            // Check if command is attempting to delete snapshots (block it)
            bool IsSnapshotDeletionAttempt(const std::string& command) const;

            // Configuration
            void SetMaxSnapshots(int max) { max_snapshots_ = max; }
            void SetSnapshotInterval(int minutes) { snapshot_interval_minutes_ = minutes; }
            void SetSnapshotRetention(int minutes) { snapshot_retention_minutes_ = minutes; }

            // Get filesystem info
            FilesystemType GetFilesystemType() const { return fs_type_; }
            std::string GetFilesystemTypeName() const;

        private:
            // Detection
            bool DetectFilesystem();

            // Snapshot creation by filesystem type
            std::string CreateBtrfsSnapshot();
            std::string CreateLVMSnapshot();
            std::string CreateZFSSnapshot();
            std::string CreateRsyncSnapshot();  // NEW

            // Rollback by filesystem type
            bool RollbackBtrfsSnapshot(const std::string& snapshot_id);
            bool RollbackLVMSnapshot(const std::string& snapshot_id);
            bool RollbackZFSSnapshot(const std::string& snapshot_id);
            bool RollbackRsyncSnapshot(const std::string& snapshot_id);  // NEW

            // Helpers
            bool MakeSnapshotImmutable(const std::string& snapshot_path);
            bool DeleteOldestSnapshot();
            std::string GenerateSnapshotID();
            std::string ExecuteCommand(const std::string& command);
            uint64_t GetSnapshotSize(const std::string& snapshot_path);

            // Filesystem detection helpers
            bool IsLVMAvailable();
            bool IsBtrfsAvailable();
            bool IsZFSAvailable();
            std::string GetRootVolumeGroup();
            std::string GetRootLogicalVolume();

            // NEW: rsync helpers
            std::vector<std::string> GetCriticalDirectories();
            bool CreateSnapshotDirectory(const std::string& snapshot_path);

            // State
            FilesystemType fs_type_;
            std::string root_mount_;
            std::string snapshot_dir_;

            std::vector<SnapshotEntry> active_snapshots_;
            mutable std::mutex snapshots_mutex_;

            // Configuration
            int max_snapshots_ = 6;
            int snapshot_interval_minutes_ = 5;
            int snapshot_retention_minutes_ = 30;

            // Statistics
            struct Stats {
                std::atomic<uint64_t> snapshots_created{0};
                std::atomic<uint64_t> snapshots_deleted{0};
                std::atomic<uint64_t> rollbacks_performed{0};
                std::atomic<uint64_t> deletion_attempts_blocked{0};
            } stats_;
        };

    } // namespace realtime
} // namespace koraav
