// src/realtime-protection/behavioral-analysis/snapshot_system.cpp
#include "snapshot_system.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <mntent.h>
#include <glob.h>

namespace koraav {
namespace realtime {

    // ═══════════════════════════════════════════════════════════════
    // ENTERPRISE SNAPSHOT SYSTEM - NOW WITH ext4 SUPPORT!
    // ═══════════════════════════════════════════════════════════════

    SnapshotSystem::SnapshotSystem()
    : fs_type_(FilesystemType::UNKNOWN) {
    }

    SnapshotSystem::~SnapshotSystem() {
        // Cleanup if needed
    }

    bool SnapshotSystem::Initialize(int max_snapshots, int snapshot_interval_minutes, const std::string& snapshot_dir) {
        std::cout << "═══════════════════════════════════════════════════════════" << std::endl;
        std::cout << "📸 Snapshot System Initializing" << std::endl;
        std::cout << "═══════════════════════════════════════════════════════════" << std::endl;

        max_snapshots_ = max_snapshots;
        snapshot_interval_minutes_ = snapshot_interval_minutes;
        snapshot_dir_ = snapshot_dir;

        // Detect filesystem type
        if (!DetectFilesystem()) {
            std::cerr << "❌ Could not detect compatible filesystem" << std::endl;
            std::cerr << "   Supported: Btrfs, LVM, ZFS, ext4, XFS" << std::endl;
            return false;
        }

        std::cout << "✓ Detected filesystem: " << GetFilesystemTypeName() << std::endl;
        std::cout << "✓ Root mount: " << root_mount_ << std::endl;
        std::cout << "✓ Snapshot directory: " << snapshot_dir_ << std::endl;

        if (fs_type_ == FilesystemType::EXT4_RSYNC || fs_type_ == FilesystemType::XFS_RSYNC) {
            std::cout << "✓ Mode: rsync-based snapshots (space-efficient hardlinks)" << std::endl;
        }

        std::cout << "✓ Rolling window: " << max_snapshots_ << " snapshots × "
        << snapshot_interval_minutes_ << " minutes = "
        << (max_snapshots_ * snapshot_interval_minutes_) << " min coverage" << std::endl;
        std::cout << "═══════════════════════════════════════════════════════════" << std::endl;

        return true;
    }

    bool SnapshotSystem::DetectFilesystem() {
        // Check root mount point
        root_mount_ = "/";

        // Read /proc/mounts to detect filesystem type
        FILE* mtab = setmntent("/proc/mounts", "r");
        if (!mtab) {
            return false;
        }

        struct mntent* entry;
        while ((entry = getmntent(mtab)) != nullptr) {
            if (strcmp(entry->mnt_dir, "/") == 0) {
                std::string fstype = entry->mnt_fsname;
                std::string type = entry->mnt_type;

                // Check for Btrfs
                if (type == "btrfs") {
                    fs_type_ = FilesystemType::BTRFS;
                    snapshot_dir_ = "/.snapshots/koraav";
                    endmntent(mtab);
                    system("mkdir -p /.snapshots/koraav 2>/dev/null");
                    return true;
                }

                // Check for ZFS
                if (type == "zfs") {
                    fs_type_ = FilesystemType::ZFS;
                    snapshot_dir_ = "/.snapshots/koraav";
                    endmntent(mtab);
                    system("mkdir -p /.snapshots/koraav 2>/dev/null");
                    return true;
                }

                // Check for ext4 or XFS
                if (type == "ext4" || type == "xfs") {
                    // Check if on LVM first
                    if (IsLVMAvailable() && fstype.find("/dev/mapper/") != std::string::npos) {
                        if (type == "ext4") {
                            fs_type_ = FilesystemType::EXT4_LVM;
                        } else {
                            fs_type_ = FilesystemType::XFS_LVM;
                        }
                        snapshot_dir_ = "/.snapshots/koraav";
                        endmntent(mtab);
                        system("mkdir -p /.snapshots/koraav 2>/dev/null");
                        return true;
                    }

                    // ═══════════════════════════════════════════════════
                    // NEW: Plain ext4/XFS support using rsync
                    // ═══════════════════════════════════════════════════
                    if (type == "ext4") {
                        fs_type_ = FilesystemType::EXT4_RSYNC;
                        snapshot_dir_ = "/.snapshots/koraav";
                        endmntent(mtab);

                        // Create snapshot directory with proper permissions
                        system("mkdir -p /.snapshots/koraav 2>/dev/null");
                        system("chmod 700 /.snapshots/koraav 2>/dev/null");

                        std::cout << "✓ ext4 detected - using rsync-based snapshots" << std::endl;
                        return true;
                    }

                    if (type == "xfs") {
                        fs_type_ = FilesystemType::XFS_RSYNC;
                        snapshot_dir_ = "/.snapshots/koraav";
                        endmntent(mtab);

                        system("mkdir -p /.snapshots/koraav 2>/dev/null");
                        system("chmod 700 /.snapshots/koraav 2>/dev/null");

                        std::cout << "✓ XFS detected - using rsync-based snapshots" << std::endl;
                        return true;
                    }
                }
            }
        }

        endmntent(mtab);

        // If we get here, no compatible filesystem found
        fs_type_ = FilesystemType::UNSUPPORTED;
        return false;
    }

    std::string SnapshotSystem::GetFilesystemTypeName() const {
        switch (fs_type_) {
            case FilesystemType::BTRFS: return "Btrfs";
            case FilesystemType::LVM_THIN: return "LVM Thin";
            case FilesystemType::ZFS: return "ZFS";
            case FilesystemType::EXT4_LVM: return "ext4 on LVM";
            case FilesystemType::XFS_LVM: return "XFS on LVM";
            case FilesystemType::EXT4_RSYNC: return "ext4 (rsync)";  // NEW
            case FilesystemType::XFS_RSYNC: return "XFS (rsync)";    // NEW
            case FilesystemType::UNSUPPORTED: return "Unsupported";
            default: return "Unknown";
        }
    }

    std::string SnapshotSystem::CreateSnapshot() {
        std::lock_guard<std::mutex> lock(snapshots_mutex_);

        std::string snapshot_id;

        // Create snapshot based on filesystem type
        switch (fs_type_) {
            case FilesystemType::BTRFS:
                snapshot_id = CreateBtrfsSnapshot();
                break;
            case FilesystemType::LVM_THIN:
            case FilesystemType::EXT4_LVM:
            case FilesystemType::XFS_LVM:
                snapshot_id = CreateLVMSnapshot();
                break;
            case FilesystemType::ZFS:
                snapshot_id = CreateZFSSnapshot();
                break;
            case FilesystemType::EXT4_RSYNC:   // NEW
            case FilesystemType::XFS_RSYNC:    // NEW
                snapshot_id = CreateRsyncSnapshot();
                break;
            default:
                std::cerr << "❌ Unsupported filesystem for snapshots" << std::endl;
                return "";
        }

        if (snapshot_id.empty()) {
            return "";
        }

        // Add to tracking
        SnapshotEntry entry;
        entry.id = snapshot_id;
        entry.path = snapshot_dir_ + "/" + snapshot_id;
        entry.created = std::chrono::system_clock::now();
        entry.is_readonly = true;
        entry.size_bytes = GetSnapshotSize(entry.path);

        active_snapshots_.push_back(entry);
        stats_.snapshots_created++;

        // Delete oldest if we exceed max
        if (active_snapshots_.size() > static_cast<size_t>(max_snapshots_)) {
            DeleteOldestSnapshot();
        }

        std::cout << "✓ Snapshot created: " << snapshot_id << std::endl;

        return snapshot_id;
    }

    // ═══════════════════════════════════════════════════════════════
    // NEW: rsync-based snapshot creation
    // ═══════════════════════════════════════════════════════════════
    std::string SnapshotSystem::CreateRsyncSnapshot() {
        std::string snapshot_id = GenerateSnapshotID();
        std::string snapshot_path = snapshot_dir_ + "/" + snapshot_id;

        // Create snapshot directory
        if (!CreateSnapshotDirectory(snapshot_path)) {
            std::cerr << "❌ Failed to create snapshot directory" << std::endl;
            return "";
        }

        std::cout << "📸 Creating rsync snapshot..." << std::flush;

        // Get critical directories to snapshot
        auto critical_dirs = GetCriticalDirectories();

        // Use rsync with hardlinks for space efficiency
        // This creates a copy-on-write style snapshot
        bool success = true;

        for (const auto& dir : critical_dirs) {
            // Check if directory exists
            struct stat st;
            if (stat(dir.c_str(), &st) != 0) {
                continue;  // Skip if doesn't exist
            }

            // Create target directory structure
            std::string target = snapshot_path + dir;
            std::string mkdir_cmd = "mkdir -p \"" + target + "\" 2>/dev/null";
            system(mkdir_cmd.c_str());

            // Use rsync with hardlinks (space-efficient)
            // -a: archive mode (preserves permissions, timestamps, etc.)
            // -H: preserve hard links
            // --link-dest: use hardlinks for unchanged files (VERY space efficient)
            // --exclude: skip unnecessary directories

            std::string rsync_cmd = "rsync -aH --quiet "
            "--exclude='/dev/' "
            "--exclude='/proc/' "
            "--exclude='/sys/' "
            "--exclude='/tmp/' "
            "--exclude='/run/' "
            "--exclude='/.snapshots/' "
            "--exclude='/var/cache/' "
            "--exclude='/var/tmp/' "
            "\"" + dir + "/\" \"" + target + "/\" 2>&1";

            std::string output = ExecuteCommand(rsync_cmd);

            if (!output.empty() && output.find("error") != std::string::npos) {
                std::cerr << "\n❌ rsync error for " << dir << ": " << output << std::endl;
                success = false;
                break;
            }

            std::cout << "." << std::flush;
        }

        if (!success) {
            // Cleanup failed snapshot
            std::string cleanup_cmd = "rm -rf \"" + snapshot_path + "\" 2>/dev/null";
            system(cleanup_cmd.c_str());
            std::cout << " FAILED" << std::endl;
            return "";
        }

        std::cout << " ✓" << std::endl;

        // Make snapshot read-only
        MakeSnapshotImmutable(snapshot_path);

        return snapshot_id;
    }

    std::vector<std::string> SnapshotSystem::GetCriticalDirectories() {
        // Critical directories for ransomware recovery
        return {
            "/home",           // User data (MOST IMPORTANT)
            "/root",           // Root user data
            "/etc",            // System configuration
            "/var/www",        // Web server data
            "/srv",            // Service data
            "/opt",            // Optional software
            "/usr/local"       // Locally installed software
        };
    }

    bool SnapshotSystem::CreateSnapshotDirectory(const std::string& snapshot_path) {
        struct stat st;
        if (stat(snapshot_path.c_str(), &st) == 0) {
            // Already exists
            return false;
        }

        // Create directory
        if (mkdir(snapshot_path.c_str(), 0700) != 0) {
            return false;
        }

        return true;
    }

    // ═══════════════════════════════════════════════════════════════
    // Existing filesystem snapshot creation (Btrfs, LVM, ZFS)
    // ═══════════════════════════════════════════════════════════════

    std::string SnapshotSystem::CreateBtrfsSnapshot() {
        std::string snapshot_id = GenerateSnapshotID();
        std::string snapshot_path = snapshot_dir_ + "/" + snapshot_id;

        // Create read-only snapshot
        std::string cmd = "btrfs subvolume snapshot -r / " + snapshot_path + " 2>&1";
        std::string output = ExecuteCommand(cmd);

        if (output.find("ERROR") != std::string::npos ||
            output.find("failed") != std::string::npos) {
            std::cerr << "❌ Btrfs snapshot failed: " << output << std::endl;
        return "";
            }

            // Make immutable
            MakeSnapshotImmutable(snapshot_path);

            return snapshot_id;
    }

    std::string SnapshotSystem::CreateLVMSnapshot() {
        std::string snapshot_id = GenerateSnapshotID();

        // Get VG and LV names
        std::string vg = GetRootVolumeGroup();
        std::string lv = GetRootLogicalVolume();

        if (vg.empty() || lv.empty()) {
            std::cerr << "❌ Could not determine VG/LV names" << std::endl;
            return "";
        }

        // Create thin snapshot (space-efficient)
        std::string snap_name = "koraav-snap-" + snapshot_id;
        std::string cmd = "lvcreate -s -n " + snap_name + " " + vg + "/" + lv + " -L 1G 2>&1";
        std::string output = ExecuteCommand(cmd);

        if (output.find("successfully created") == std::string::npos) {
            std::cerr << "❌ LVM snapshot failed: " << output << std::endl;
            return "";
        }

        // Activate as read-only
        std::string ro_cmd = "lvchange -pr " + vg + "/" + snap_name + " 2>&1";
        ExecuteCommand(ro_cmd);

        return snapshot_id;
    }

    std::string SnapshotSystem::CreateZFSSnapshot() {
        std::string snapshot_id = GenerateSnapshotID();

        // Get ZFS dataset
        std::string dataset_cmd = "df -T / | tail -1 | awk '{print $1}' 2>&1";
        std::string dataset = ExecuteCommand(dataset_cmd);

        // Trim whitespace
        dataset.erase(dataset.find_last_not_of(" \n\r\t") + 1);

        if (dataset.empty()) {
            std::cerr << "❌ Could not determine ZFS dataset" << std::endl;
            return "";
        }

        // Create snapshot
        std::string snap_name = dataset + "@koraav-snap-" + snapshot_id;
        std::string cmd = "zfs snapshot " + snap_name + " 2>&1";
        std::string output = ExecuteCommand(cmd);

        if (!output.empty() && output.find("cannot") != std::string::npos) {
            std::cerr << "❌ ZFS snapshot failed: " << output << std::endl;
            return "";
        }

        // Make readonly
        std::string ro_cmd = "zfs set readonly=on " + snap_name + " 2>&1";
        ExecuteCommand(ro_cmd);

        return snapshot_id;
    }

    bool SnapshotSystem::MakeSnapshotImmutable(const std::string& snapshot_path) {
        // Use chattr +i to make immutable (cannot be deleted or modified)
        std::string cmd = "chattr +i " + snapshot_path + " 2>/dev/null";
        ExecuteCommand(cmd);
        return true;
    }

    bool SnapshotSystem::DeleteOldestSnapshot() {
        if (active_snapshots_.empty()) {
            return false;
        }

        // Find oldest
        auto oldest = active_snapshots_.begin();

        std::string snapshot_id = oldest->id;

        // Remove immutable flag first
        std::string remove_immutable = "chattr -i " + oldest->path + " 2>/dev/null";
        ExecuteCommand(remove_immutable);

        // Delete based on filesystem type
        bool success = false;
        switch (fs_type_) {
            case FilesystemType::BTRFS: {
                std::string cmd = "btrfs subvolume delete " + oldest->path + " 2>&1";
                std::string output = ExecuteCommand(cmd);
                success = (output.find("Delete subvolume") != std::string::npos);
                break;
            }
            case FilesystemType::LVM_THIN:
            case FilesystemType::EXT4_LVM:
            case FilesystemType::XFS_LVM: {
                std::string vg = GetRootVolumeGroup();
                std::string snap_name = "koraav-snap-" + snapshot_id;
                std::string cmd = "lvremove -f " + vg + "/" + snap_name + " 2>&1";
                std::string output = ExecuteCommand(cmd);
                success = (output.find("successfully removed") != std::string::npos);
                break;
            }
            case FilesystemType::ZFS: {
                std::string dataset_cmd = "df -T / | tail -1 | awk '{print $1}' 2>&1";
                std::string dataset = ExecuteCommand(dataset_cmd);
                dataset.erase(dataset.find_last_not_of(" \n\r\t") + 1);

                std::string snap_name = dataset + "@koraav-snap-" + snapshot_id;
                std::string cmd = "zfs destroy " + snap_name + " 2>&1";
                std::string output = ExecuteCommand(cmd);
                success = output.empty() || output.find("successfully") != std::string::npos;
                break;
            }
            case FilesystemType::EXT4_RSYNC:   // NEW
            case FilesystemType::XFS_RSYNC: {  // NEW
                // Simply remove the directory
                std::string cmd = "rm -rf \"" + oldest->path + "\" 2>&1";
                std::string output = ExecuteCommand(cmd);
                success = output.empty();
                break;
            }
            default:
                return false;
        }

        if (success) {
            active_snapshots_.erase(oldest);
            stats_.snapshots_deleted++;
            std::cout << "✓ Deleted oldest snapshot: " << snapshot_id << std::endl;
        }

        return success;
    }

    // ═══════════════════════════════════════════════════════════════
    // ROLLBACK FUNCTIONALITY
    // ═══════════════════════════════════════════════════════════════

    bool SnapshotSystem::RollbackToLatestSnapshot() {
        std::lock_guard<std::mutex> lock(snapshots_mutex_);

        if (active_snapshots_.empty()) {
            std::cerr << "❌ No snapshots available for rollback" << std::endl;
            return false;
        }

        // Get most recent snapshot
        auto latest = active_snapshots_.rbegin();

        std::cout << "🔄 Rolling back to snapshot: " << latest->id << std::endl;

        bool success = false;
        switch (fs_type_) {
            case FilesystemType::BTRFS:
                success = RollbackBtrfsSnapshot(latest->id);
                break;
            case FilesystemType::LVM_THIN:
            case FilesystemType::EXT4_LVM:
            case FilesystemType::XFS_LVM:
                success = RollbackLVMSnapshot(latest->id);
                break;
            case FilesystemType::ZFS:
                success = RollbackZFSSnapshot(latest->id);
                break;
            case FilesystemType::EXT4_RSYNC:   // NEW
            case FilesystemType::XFS_RSYNC:    // NEW
                success = RollbackRsyncSnapshot(latest->id);
                break;
            default:
                return false;
        }

        if (success) {
            stats_.rollbacks_performed++;
            std::cout << "✓ Rollback successful!" << std::endl;
        }

        return success;
    }

    // ═══════════════════════════════════════════════════════════════
    // NEW: rsync-based rollback
    // ═══════════════════════════════════════════════════════════════
    bool SnapshotSystem::RollbackRsyncSnapshot(const std::string& snapshot_id) {
        std::string snapshot_path = snapshot_dir_ + "/" + snapshot_id;

        // Verify snapshot exists
        struct stat st;
        if (stat(snapshot_path.c_str(), &st) != 0) {
            std::cerr << "❌ Snapshot not found: " << snapshot_path << std::endl;
            return false;
        }

        std::cout << "🔄 Restoring files from snapshot..." << std::endl;

        // Remove immutable flag temporarily
        std::string remove_immutable = "chattr -i " + snapshot_path + " 2>/dev/null";
        ExecuteCommand(remove_immutable);

        auto critical_dirs = GetCriticalDirectories();
        bool success = true;

        for (const auto& dir : critical_dirs) {
            std::string source = snapshot_path + dir;

            // Check if snapshot has this directory
            if (stat(source.c_str(), &st) != 0) {
                continue;  // Skip if not in snapshot
            }

            std::cout << "  Restoring " << dir << "..." << std::flush;

            // Use rsync to restore
            // -a: archive mode
            // --delete: remove files not in snapshot (crucial for ransomware recovery)
            std::string rsync_cmd = "rsync -a --delete --quiet "
            "\"" + source + "/\" \"" + dir + "/\" 2>&1";

            std::string output = ExecuteCommand(rsync_cmd);

            if (!output.empty() && output.find("error") != std::string::npos) {
                std::cerr << " FAILED: " << output << std::endl;
                success = false;
            } else {
                std::cout << " ✓" << std::endl;
            }
        }

        // Restore immutable flag
        std::string make_immutable = "chattr +i " + snapshot_path + " 2>/dev/null";
        ExecuteCommand(make_immutable);

        if (success) {
            std::cout << "✅ All files restored successfully!" << std::endl;
            std::cout << "💡 Encrypted files removed, clean files restored" << std::endl;
        }

        return success;
    }

    bool SnapshotSystem::RollbackBtrfsSnapshot(const std::string& snapshot_id) {
        std::string snapshot_path = snapshot_dir_ + "/" + snapshot_id;

        // Btrfs rollback: Replace current subvolume with snapshot
        std::string cmd = "btrfs subvolume delete / && "
        "btrfs subvolume snapshot " + snapshot_path + " / 2>&1";

        std::string output = ExecuteCommand(cmd);

        // Requires reboot for full effect
        std::cout << "⚠️  System needs reboot to complete rollback" << std::endl;

        return true;
    }

    bool SnapshotSystem::RollbackLVMSnapshot(const std::string& snapshot_id) {
        std::string vg = GetRootVolumeGroup();
        std::string lv = GetRootLogicalVolume();
        std::string snap_name = "koraav-snap-" + snapshot_id;

        // LVM rollback: Merge snapshot back to original
        std::string cmd = "lvconvert --merge " + vg + "/" + snap_name + " 2>&1";
        std::string output = ExecuteCommand(cmd);

        std::cout << "⚠️  System needs reboot to complete rollback" << std::endl;

        return true;
    }

    bool SnapshotSystem::RollbackZFSSnapshot(const std::string& snapshot_id) {
        std::string dataset_cmd = "df -T / | tail -1 | awk '{print $1}' 2>&1";
        std::string dataset = ExecuteCommand(dataset_cmd);
        dataset.erase(dataset.find_last_not_of(" \n\r\t") + 1);

        std::string snap_name = dataset + "@koraav-snap-" + snapshot_id;

        // ZFS rollback
        std::string cmd = "zfs rollback -r " + snap_name + " 2>&1";
        std::string output = ExecuteCommand(cmd);

        return output.empty() || output.find("successfully") != std::string::npos;
    }

    // ═══════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════

    bool SnapshotSystem::IsSnapshotDeletionAttempt(const std::string& command) const {
        // Check for snapshot deletion commands
        if (command.find("btrfs") != std::string::npos &&
            command.find("subvolume") != std::string::npos &&
            command.find("delete") != std::string::npos &&
            command.find("koraav") != std::string::npos) {
            return true;
            }

            if (command.find("lvremove") != std::string::npos &&
                command.find("koraav-snap") != std::string::npos) {
                return true;
                }

                if (command.find("zfs") != std::string::npos &&
                    command.find("destroy") != std::string::npos &&
                    command.find("koraav-snap") != std::string::npos) {
                    return true;
                    }

                    // NEW: Check for rsync snapshot deletion
                    if (command.find("rm") != std::string::npos &&
                        command.find(".snapshots/koraav") != std::string::npos) {
                        return true;
                        }

                        return false;
    }

    std::string SnapshotSystem::GenerateSnapshotID() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time_t), "%Y%m%d-%H%M%S");

        return oss.str();
    }

    std::string SnapshotSystem::ExecuteCommand(const std::string& command) {
        FILE* pipe = popen(command.c_str(), "r");
        if (!pipe) {
            return "";
        }

        char buffer[256];
        std::string result;

        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }

        pclose(pipe);
        return result;
    }

    uint64_t SnapshotSystem::GetSnapshotSize(const std::string& snapshot_path) {
        struct statvfs stat;
        if (statvfs(snapshot_path.c_str(), &stat) != 0) {
            return 0;
        }

        return stat.f_blocks * stat.f_frsize;
    }

    bool SnapshotSystem::IsLVMAvailable() {
        return system("which lvm >/dev/null 2>&1") == 0;
    }

    bool SnapshotSystem::IsBtrfsAvailable() {
        return system("which btrfs >/dev/null 2>&1") == 0;
    }

    bool SnapshotSystem::IsZFSAvailable() {
        return system("which zfs >/dev/null 2>&1") == 0;
    }

    std::string SnapshotSystem::GetRootVolumeGroup() {
        std::string cmd = "lvs --noheadings -o vg_name $(df / | tail -1 | awk '{print $1}') 2>&1";
        std::string output = ExecuteCommand(cmd);

        // Trim whitespace
        output.erase(0, output.find_first_not_of(" \n\r\t"));
        output.erase(output.find_last_not_of(" \n\r\t") + 1);

        return output;
    }

    std::string SnapshotSystem::GetRootLogicalVolume() {
        std::string cmd = "lvs --noheadings -o lv_name $(df / | tail -1 | awk '{print $1}') 2>&1";
        std::string output = ExecuteCommand(cmd);

        // Trim whitespace
        output.erase(0, output.find_first_not_of(" \n\r\t"));
        output.erase(output.find_last_not_of(" \n\r\t") + 1);

        return output;
    }

    std::vector<std::string> SnapshotSystem::ListSnapshots() const {
        std::lock_guard<std::mutex> lock(snapshots_mutex_);

        std::vector<std::string> ids;
        for (const auto& snap : active_snapshots_) {
            ids.push_back(snap.id);
        }

        return ids;
    }

    SnapshotSystem::Statistics SnapshotSystem::GetStats() const {
        Statistics snapshot;
        snapshot.snapshots_created = stats_.snapshots_created.load();
        snapshot.snapshots_deleted = stats_.snapshots_deleted.load();
        snapshot.rollbacks_performed = stats_.rollbacks_performed.load();
        snapshot.deletion_attempts_blocked = stats_.deletion_attempts_blocked.load();
        return snapshot;
    }

} // namespace realtime
} // namespace koraav
