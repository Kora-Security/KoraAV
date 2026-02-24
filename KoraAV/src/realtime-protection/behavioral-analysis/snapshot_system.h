// src/realtime-protection/behavioral-analysis/snapshot_system.h
// Filesystem Snapshot Management for Instant Rollback
#ifndef KORAAV_SNAPSHOT_SYSTEM_H
#define KORAAV_SNAPSHOT_SYSTEM_H

#include <string>
#include <vector>
#include <chrono>
#include <mutex>
#include <atomic>

namespace koraav {
namespace realtime {

/**
 * Snapshot System
 * 
 * Manages filesystem snapshots (Btrfs/LVM/ZFS) for instant rollback.
 * Creates rolling snapshots every 5 minutes (max 5 stored).
 * Protects snapshots from deletion.
 */
class SnapshotSystem {
public:
    SnapshotSystem();
    ~SnapshotSystem();
    
    bool Initialize();
    
    /**
     * Create a new snapshot
     * @return Snapshot ID or empty on failure
     */
    std::string CreateSnapshot();
    
    /**
     * Rollback to most recent snapshot
     */
    bool RollbackToLatestSnapshot();
    
    /**
     * Check if command is trying to delete our snapshots
     */
    bool IsSnapshotDeletionAttempt(const std::string& command) const;
    
    /**
     * List available snapshots
     */
    std::vector<std::string> ListSnapshots() const;
    
    /**
     * Filesystem types
     */
    enum class FilesystemType {
        UNKNOWN,
        BTRFS,
        LVM_THIN,
        ZFS,
        EXT4_LVM,
        XFS_LVM,
        UNSUPPORTED
    };
    
    FilesystemType GetFilesystemType() const { return fs_type_; }
    std::string GetFilesystemTypeName() const;
    
    /**
     * Statistics (non-atomic for return)
     */
    struct Statistics {
        uint64_t snapshots_created;
        uint64_t snapshots_deleted;
        uint64_t rollbacks_performed;
        uint64_t deletion_attempts_blocked;
    };
    
    Statistics GetStats() const;

private:
    struct SnapshotEntry {
        std::string id;
        std::string path;
        std::chrono::system_clock::time_point created;
        bool is_readonly = false;
        uint64_t size_bytes = 0;
    };
    
    // Internal stats with atomics
    struct InternalStats {
        std::atomic<uint64_t> snapshots_created{0};
        std::atomic<uint64_t> snapshots_deleted{0};
        std::atomic<uint64_t> rollbacks_performed{0};
        std::atomic<uint64_t> deletion_attempts_blocked{0};
    };
    
    FilesystemType fs_type_;
    std::string root_mount_;
    std::string snapshot_dir_;
    std::vector<SnapshotEntry> active_snapshots_;
    mutable std::mutex snapshots_mutex_;
    const int max_snapshots_ = 5;
    mutable InternalStats stats_;
    
    // Filesystem operations
    bool DetectFilesystem();
    std::string CreateBtrfsSnapshot();
    std::string CreateLVMSnapshot();
    std::string CreateZFSSnapshot();
    bool RollbackBtrfsSnapshot(const std::string& snapshot_id);
    bool RollbackLVMSnapshot(const std::string& snapshot_id);
    bool RollbackZFSSnapshot(const std::string& snapshot_id);
    bool DeleteOldestSnapshot();
    bool MakeSnapshotReadonly(const std::string& snapshot_id);
    bool MakeSnapshotImmutable(const std::string& snapshot_path);
    
    // Utilities
    std::string GenerateSnapshotID();
    std::string ExecuteCommand(const std::string& command);
    bool IsLVMAvailable();
    bool IsBtrfsAvailable();
    bool IsZFSAvailable();
    std::string GetRootVolumeGroup();
    std::string GetRootLogicalVolume();
    uint64_t GetSnapshotSize(const std::string& snapshot_path);
};

} // namespace realtime
} // namespace koraav

#endif // KORAAV_SNAPSHOT_SYSTEM_H
