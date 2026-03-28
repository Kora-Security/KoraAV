// src/realtime-protection/response/snapshot_system.cpp
#include "snapshot_system.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/inotify.h>
#include <mntent.h>
#include <glob.h>
#include <poll.h>
#include <errno.h>

namespace koraav {
namespace realtime {

    // ═══════════════════════════════════════════════════════════════
    // ENTERPRISE SNAPSHOT SYSTEM - with inotify enhancements
    // ═══════════════════════════════════════════════════════════════

    SnapshotSystem::SnapshotSystem()
        : fs_type_(FilesystemType::UNKNOWN)
        , max_snapshots_(6)
        , snapshot_interval_minutes_(5)
    {
        window_start_           = std::chrono::steady_clock::now();
        last_emergency_snapshot_ = std::chrono::steady_clock::time_point{};
    }

    SnapshotSystem::~SnapshotSystem() {
        StopInotifyWatcher();
    }

    bool SnapshotSystem::Initialize(int max_snapshots,
                                    int snapshot_interval_minutes,
                                    const std::string& snapshot_dir) {
        std::cout << "═══════════════════════════════════════════════════════════" << std::endl;
        std::cout << "📸 Snapshot System Initializing" << std::endl;
        std::cout << "═══════════════════════════════════════════════════════════" << std::endl;

        max_snapshots_              = max_snapshots;
        snapshot_interval_minutes_  = snapshot_interval_minutes;
        snapshot_dir_               = snapshot_dir;

        // Detect filesystem type
        if (!DetectFilesystem()) {
            std::cerr << "❌ Could not detect compatible filesystem" << std::endl;
            std::cerr << "   Supported: Btrfs, LVM, ZFS, ext4, XFS" << std::endl;
            return false;
        }

        std::cout << "✓ Detected filesystem: " << GetFilesystemTypeName() << std::endl;
        std::cout << "✓ Root mount: "          << root_mount_ << std::endl;
        std::cout << "✓ Snapshot directory: "  << snapshot_dir_ << std::endl;

        if (fs_type_ == FilesystemType::EXT4_RSYNC ||
            fs_type_ == FilesystemType::XFS_RSYNC) {
            std::cout << "✓ Mode: rsync-based snapshots (space-efficient hardlinks)" << std::endl;
        }

        std::cout << "✓ Rolling window: " << max_snapshots_ << " snapshots × "
                  << snapshot_interval_minutes_ << " minutes = "
                  << (max_snapshots_ * snapshot_interval_minutes_)
                  << " min coverage" << std::endl;

        // ── inotify ─────────────────────────────────────────────────
        if (inotify_cfg_.enabled) {
            if (StartInotifyWatcher()) {
                std::cout << "✓ inotify watcher active (burst thresholds: "
                          << inotify_cfg_.write_burst_threshold  << " writes / "
                          << inotify_cfg_.rename_burst_threshold << " renames / "
                          << inotify_cfg_.delete_burst_threshold << " deletes"
                          << " per " << inotify_cfg_.window_seconds << "s window)"
                          << std::endl;
            } else {
                std::cerr << "⚠️  inotify watcher could not start — "
                             "rolling snapshots still active" << std::endl;
            }
        }

        std::cout << "═══════════════════════════════════════════════════════════" << std::endl;
        return true;
    }

    // ═══════════════════════════════════════════════════════════════
    // INOTIFY WATCHER
    // ═══════════════════════════════════════════════════════════════

    bool SnapshotSystem::StartInotifyWatcher() {
        inotify_fd_ = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (inotify_fd_ < 0) {
            std::cerr << "⚠️  inotify_init1 failed: " << strerror(errno) << std::endl;
            return false;
        }

        inotify_running_.store(true);
        inotify_thread_ = std::thread(&SnapshotSystem::InotifyWatchLoop, this);
        return true;
    }

    void SnapshotSystem::StopInotifyWatcher() {
        if (inotify_running_.load()) {
            inotify_running_.store(false);
            if (inotify_fd_ >= 0) {
                close(inotify_fd_);
                inotify_fd_ = -1;
            }
            if (inotify_thread_.joinable()) {
                inotify_thread_.join();
            }
        }
    }

    // Add watches for a directory and all of its subdirectories (recursive).
    // We limit depth to avoid watching enormous trees; user home subdirs are
    // the highest-value targets and rarely exceed 3–4 levels of nesting.
    static void AddWatchesRecursive(int inotify_fd,
                                    const std::string& path,
                                    std::unordered_map<int, std::string>& wd_to_path,
                                    int depth = 0,
                                    int max_depth = 4)
    {
        if (depth > max_depth) return;

        uint32_t mask = IN_CLOSE_WRITE   // file written and closed
                      | IN_MOVED_FROM    // file/dir renamed away (source)
                      | IN_MOVED_TO      // file/dir renamed into (dest)
                      | IN_DELETE        // file deleted
                      | IN_CREATE        // file created (detect new .enc etc.)
                      | IN_DONT_FOLLOW;  // never follow symlinks

        int wd = inotify_add_watch(inotify_fd, path.c_str(), mask);
        if (wd >= 0) {
            wd_to_path[wd] = path;
        }

        // Recurse into subdirectories
        DIR* dir = opendir(path.c_str());
        if (!dir) return;

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name[0] == '.') continue; // skip . and hidden
            if (entry->d_type == DT_DIR) {
                AddWatchesRecursive(inotify_fd,
                                    path + "/" + entry->d_name,
                                    wd_to_path,
                                    depth + 1,
                                    max_depth);
            }
        }
        closedir(dir);
    }

    void SnapshotSystem::InotifyWatchLoop() {
        // Map from inotify watch descriptor → directory path
        std::unordered_map<int, std::string> wd_to_path;

        // Add watches for every critical directory
        auto critical_dirs = GetCriticalDirectories();
        for (const auto& dir : critical_dirs) {
            struct stat st;
            if (stat(dir.c_str(), &st) == 0) {
                AddWatchesRecursive(inotify_fd_, dir, wd_to_path);
            }
        }

        if (wd_to_path.empty()) {
            std::cerr << "⚠️  inotify: no watches registered — "
                         "all critical directories missing?" << std::endl;
            inotify_running_.store(false);
            return;
        }

        std::cout << "✓ inotify: watching " << wd_to_path.size()
                  << " directories" << std::endl;

        // Event buffer — sized for many events per read
        constexpr size_t EVENT_BUF_LEN =
            64 * (sizeof(struct inotify_event) + NAME_MAX + 1);
        char buf[EVENT_BUF_LEN] __attribute__((aligned(alignof(struct inotify_event))));

        struct pollfd pfd = { inotify_fd_, POLLIN, 0 };

        while (inotify_running_.load()) {
            // Use poll() with a short timeout so we can check inotify_running_
            int ret = poll(&pfd, 1, 500 /*ms*/);
            if (ret < 0) {
                if (errno == EINTR) continue;
                break; // fd closed / error → exit thread
            }
            if (ret == 0) {
                // Timeout — evaluate counters (window expiry check)
                EvaluateInotifyCounters();
                continue;
            }

            ssize_t len = read(inotify_fd_, buf, sizeof(buf));
            if (len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                break; // fd closed
            }

            // Process each event in the buffer
            const char* ptr = buf;
            while (ptr < buf + len) {
                const auto* event = reinterpret_cast<const struct inotify_event*>(ptr);
                ptr += sizeof(struct inotify_event) + event->len;

                stats_.inotify_events_processed++;

                // Track a new sub-directory: add a watch for it too
                if ((event->mask & IN_CREATE) && (event->mask & IN_ISDIR) && event->len > 0) {
                    auto it = wd_to_path.find(event->wd);
                    if (it != wd_to_path.end()) {
                        std::string new_dir = it->second + "/" + event->name;
                        AddWatchesRecursive(inotify_fd_, new_dir, wd_to_path, 0, 2);
                    }
                }

                // ── Count anomaly events ─────────────────────────────────
                {
                    std::lock_guard<std::mutex> lk(inotify_counters_mutex_);

                    if (event->mask & IN_CLOSE_WRITE) {
                        inotify_writes_++;
                    }
                    if (event->mask & (IN_MOVED_FROM | IN_MOVED_TO)) {
                        inotify_renames_++;
                    }
                    if (event->mask & IN_DELETE) {
                        inotify_deletes_++;
                    }
                }

                EvaluateInotifyCounters();
            }
        }
    }

    void SnapshotSystem::EvaluateInotifyCounters() {
        using namespace std::chrono;
        auto now = steady_clock::now();

        std::lock_guard<std::mutex> lk(inotify_counters_mutex_);

        auto elapsed = duration_cast<seconds>(now - window_start_).count();

        // If the window has expired, reset counters and start a new window
        if (elapsed >= static_cast<long>(inotify_cfg_.window_seconds)) {
            ResetInotifyCounters();
            window_start_ = now;
            return;
        }

        // ── Anomaly detection ────────────────────────────────────────────
        bool triggered = false;
        std::string reason;

        if (inotify_writes_ >= inotify_cfg_.write_burst_threshold) {
            triggered = true;
            reason    = "write_burst:" + std::to_string(inotify_writes_)
                      + "_in_" + std::to_string(elapsed) + "s";
        } else if (inotify_renames_ >= inotify_cfg_.rename_burst_threshold) {
            triggered = true;
            reason    = "rename_burst:" + std::to_string(inotify_renames_)
                      + "_in_" + std::to_string(elapsed) + "s";
        } else if (inotify_deletes_ >= inotify_cfg_.delete_burst_threshold) {
            triggered = true;
            reason    = "delete_burst:" + std::to_string(inotify_deletes_)
                      + "_in_" + std::to_string(elapsed) + "s";
        }

        if (!triggered) return;

        // ── Rate-limit emergency snapshots ───────────────────────────────
        auto since_last = duration_cast<seconds>(
                              now - last_emergency_snapshot_).count();
        if (since_last < static_cast<long>(inotify_cfg_.min_emergency_interval_sec)
            && last_emergency_snapshot_ != steady_clock::time_point{}) {
            // Too soon — reset counters and wait
            ResetInotifyCounters();
            return;
        }

        // Trigger emergency snapshot (releases the mutex first to avoid deadlock)
        // We unlock before calling CreateEmergencySnapshot because that function
        // acquires snapshots_mutex_.  Counter reset happens before returning.
        ResetInotifyCounters();
        last_emergency_snapshot_ = now;

        // Unlock during the (potentially slow) snapshot operation
        inotify_counters_mutex_.unlock();
        std::cout << "🚨 inotify anomaly detected (" << reason
                  << ") — triggering emergency snapshot" << std::endl;
        CreateEmergencySnapshot(reason);
        inotify_counters_mutex_.lock();  // re-lock for caller's guard
    }

    void SnapshotSystem::ResetInotifyCounters() {
        // Caller must hold inotify_counters_mutex_
        inotify_writes_  = 0;
        inotify_renames_ = 0;
        inotify_deletes_ = 0;
    }

    // ═══════════════════════════════════════════════════════════════
    // SNAPSHOT CREATION
    // ═══════════════════════════════════════════════════════════════

    std::string SnapshotSystem::CreateSnapshot() {
        return CreateSnapshotInternal(/*emergency=*/false);
    }

    std::string SnapshotSystem::CreateEmergencySnapshot(const std::string& reason) {
        stats_.emergency_snapshots_triggered++;
        return CreateSnapshotInternal(/*emergency=*/true, reason);
    }

    std::string SnapshotSystem::CreateSnapshotInternal(bool emergency,
                                                        const std::string& reason) {
        std::lock_guard<std::mutex> lock(snapshots_mutex_);

        std::string snapshot_id;

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
            case FilesystemType::EXT4_RSYNC:
            case FilesystemType::XFS_RSYNC:
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
        entry.id         = snapshot_id;
        entry.path       = snapshot_dir_ + "/" + snapshot_id;
        entry.created    = std::chrono::system_clock::now();
        entry.is_readonly = true;
        entry.size_bytes = GetSnapshotSize(entry.path);
        entry.emergency  = emergency;

        active_snapshots_.push_back(entry);
        stats_.snapshots_created++;

        // Delete oldest if we exceed max
        if (active_snapshots_.size() > static_cast<size_t>(max_snapshots_)) {
            DeleteOldestSnapshot();
        }

        if (emergency) {
            std::cout << "🚨 Emergency snapshot created: " << snapshot_id
                      << " (reason: " << reason << ")" << std::endl;
        } else {
            std::cout << "✓ Snapshot created: " << snapshot_id << std::endl;
        }

        return snapshot_id;
    }

    // ═══════════════════════════════════════════════════════════════
    // FILESYSTEM DETECTION
    // ═══════════════════════════════════════════════════════════════

    bool SnapshotSystem::DetectFilesystem() {
        root_mount_ = "/";

        FILE* mtab = setmntent("/proc/mounts", "r");
        if (!mtab) return false;

        struct mntent* entry;
        while ((entry = getmntent(mtab)) != nullptr) {
            if (strcmp(entry->mnt_dir, "/") == 0) {
                std::string fstype = entry->mnt_fsname;
                std::string type   = entry->mnt_type;

                if (type == "btrfs") {
                    fs_type_      = FilesystemType::BTRFS;
                    snapshot_dir_ = "/.snapshots/koraav";
                    endmntent(mtab);
                    return true;
                }

                if (type == "zfs") {
                    fs_type_      = FilesystemType::ZFS;
                    snapshot_dir_ = "/.snapshots/koraav";
                    endmntent(mtab);
                    return true;
                }

                if (type == "ext4" || type == "xfs") {
                    if (IsLVMAvailable() &&
                        fstype.find("/dev/mapper/") != std::string::npos) {
                        fs_type_ = (type == "ext4") ? FilesystemType::EXT4_LVM
                                                    : FilesystemType::XFS_LVM;
                        snapshot_dir_ = "/.snapshots/koraav";
                        endmntent(mtab);
                        return true;
                    }

                    if (type == "ext4") {
                        fs_type_      = FilesystemType::EXT4_RSYNC;
                        snapshot_dir_ = "/.snapshots/koraav";
                        endmntent(mtab);
                        std::cout << "✓ ext4 detected - using rsync-based snapshots" << std::endl;
                        return true;
                    }

                    if (type == "xfs") {
                        fs_type_      = FilesystemType::XFS_RSYNC;
                        snapshot_dir_ = "/.snapshots/koraav";
                        endmntent(mtab);
                        std::cout << "✓ XFS detected - using rsync-based snapshots" << std::endl;
                        return true;
                    }
                }
            }
        }

        endmntent(mtab);
        fs_type_ = FilesystemType::UNSUPPORTED;
        return false;
    }

    std::string SnapshotSystem::GetFilesystemTypeName() const {
        switch (fs_type_) {
            case FilesystemType::BTRFS:       return "Btrfs";
            case FilesystemType::LVM_THIN:    return "LVM Thin";
            case FilesystemType::ZFS:         return "ZFS";
            case FilesystemType::EXT4_LVM:    return "ext4 on LVM";
            case FilesystemType::XFS_LVM:     return "XFS on LVM";
            case FilesystemType::EXT4_RSYNC:  return "ext4 (rsync)";
            case FilesystemType::XFS_RSYNC:   return "XFS (rsync)";
            case FilesystemType::UNSUPPORTED: return "Unsupported";
            default:                          return "Unknown";
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // rsync-BASED SNAPSHOT
    // ═══════════════════════════════════════════════════════════════

    std::string SnapshotSystem::CreateRsyncSnapshot() {
        std::string snapshot_id   = GenerateSnapshotID();
        std::string snapshot_path = snapshot_dir_ + "/" + snapshot_id;

        if (!CreateSnapshotDirectory(snapshot_path)) {
            std::cerr << "❌ Failed to create snapshot directory" << std::endl;
            return "";
        }

        std::cout << "📸 Creating rsync snapshot..." << std::flush;

        auto critical_dirs = GetCriticalDirectories();
        bool success       = true;

        for (const auto& dir : critical_dirs) {
            struct stat st;
            if (stat(dir.c_str(), &st) != 0) continue;

            std::string target   = snapshot_path + dir;
            std::string mkdir_cmd = "mkdir -p \"" + target + "\" 2>/dev/null";
            system(mkdir_cmd.c_str());

            std::string rsync_cmd = "rsync -aH --quiet "
                "--no-perms --no-owner --no-group "
                "--exclude='/dev/' "
                "--exclude='/proc/' "
                "--exclude='/sys/' "
                "--exclude='/tmp/' "
                "--exclude='/run/' "
                "--exclude='/.snapshots/' "
                "--exclude='/var/cache/' "
                "--exclude='/var/tmp/' "
                "--exclude='/var/log/' "
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
            std::string cleanup_cmd = "rm -rf \"" + snapshot_path + "\" 2>/dev/null";
            system(cleanup_cmd.c_str());
            std::cout << " FAILED" << std::endl;
            return "";
        }

        std::cout << " ✓" << std::endl;
        MakeSnapshotImmutable(snapshot_path);
        return snapshot_id;
    }

    std::vector<std::string> SnapshotSystem::GetCriticalDirectories() {
        return {
            "/home",        // User data (MOST IMPORTANT)
            "/root",        // Root user data
            "/etc",         // System configuration
            "/var/www",     // Web server data
            "/srv",         // Service data
            "/opt",         // Optional software
            "/usr/local"    // Locally installed software
        };
    }

    bool SnapshotSystem::CreateSnapshotDirectory(const std::string& snapshot_path) {
        struct stat st;
        if (stat(snapshot_path.c_str(), &st) == 0) return false; // already exists

        return mkdir(snapshot_path.c_str(), 0700) == 0;
    }

    // ═══════════════════════════════════════════════════════════════
    // Btrfs / LVM / ZFS SNAPSHOT CREATION
    // ═══════════════════════════════════════════════════════════════

    std::string SnapshotSystem::CreateBtrfsSnapshot() {
        std::string snapshot_id   = GenerateSnapshotID();
        std::string snapshot_path = snapshot_dir_ + "/" + snapshot_id;

        std::string cmd    = "btrfs subvolume snapshot -r / " + snapshot_path + " 2>&1";
        std::string output = ExecuteCommand(cmd);

        if (output.find("ERROR") != std::string::npos ||
            output.find("failed") != std::string::npos) {
            std::cerr << "❌ Btrfs snapshot failed: " << output << std::endl;
            return "";
        }

        MakeSnapshotImmutable(snapshot_path);
        return snapshot_id;
    }

    std::string SnapshotSystem::CreateLVMSnapshot() {
        std::string snapshot_id = GenerateSnapshotID();

        std::string vg = GetRootVolumeGroup();
        std::string lv = GetRootLogicalVolume();

        if (vg.empty() || lv.empty()) {
            std::cerr << "❌ Could not determine VG/LV names" << std::endl;
            return "";
        }

        std::string snap_name = "koraav-snap-" + snapshot_id;
        std::string cmd       = "lvcreate -s -n " + snap_name + " " + vg + "/" + lv + " -L 1G 2>&1";
        std::string output    = ExecuteCommand(cmd);

        if (output.find("successfully created") == std::string::npos) {
            std::cerr << "❌ LVM snapshot failed: " << output << std::endl;
            return "";
        }

        std::string ro_cmd = "lvchange -pr " + vg + "/" + snap_name + " 2>&1";
        ExecuteCommand(ro_cmd);

        return snapshot_id;
    }

    std::string SnapshotSystem::CreateZFSSnapshot() {
        std::string snapshot_id = GenerateSnapshotID();

        std::string dataset_cmd = "df -T / | tail -1 | awk '{print $1}' 2>&1";
        std::string dataset     = ExecuteCommand(dataset_cmd);
        dataset.erase(dataset.find_last_not_of(" \n\r\t") + 1);

        if (dataset.empty()) {
            std::cerr << "❌ Could not determine ZFS dataset" << std::endl;
            return "";
        }

        std::string snap_name = dataset + "@koraav-snap-" + snapshot_id;
        std::string cmd       = "zfs snapshot " + snap_name + " 2>&1";
        std::string output    = ExecuteCommand(cmd);

        if (!output.empty() && output.find("cannot") != std::string::npos) {
            std::cerr << "❌ ZFS snapshot failed: " << output << std::endl;
            return "";
        }

        std::string ro_cmd = "zfs set readonly=on " + snap_name + " 2>&1";
        ExecuteCommand(ro_cmd);

        return snapshot_id;
    }

    // ═══════════════════════════════════════════════════════════════
    // ROLLBACK
    // ═══════════════════════════════════════════════════════════════

    bool SnapshotSystem::RollbackToLatestSnapshot() {
        std::lock_guard<std::mutex> lock(snapshots_mutex_);

        if (active_snapshots_.empty()) {
            std::cerr << "❌ No snapshots available for rollback" << std::endl;
            return false;
        }

        auto latest = active_snapshots_.rbegin();
        std::cout << "🔄 Rolling back to snapshot: " << latest->id << std::endl;
        if (latest->emergency) {
            std::cout << "   (emergency snapshot)" << std::endl;
        }

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
            case FilesystemType::EXT4_RSYNC:
            case FilesystemType::XFS_RSYNC:
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

    bool SnapshotSystem::RollbackRsyncSnapshot(const std::string& snapshot_id) {
        std::string snapshot_path = snapshot_dir_ + "/" + snapshot_id;

        struct stat st;
        if (stat(snapshot_path.c_str(), &st) != 0) {
            std::cerr << "❌ Snapshot not found: " << snapshot_path << std::endl;
            return false;
        }

        std::cout << "🔄 Restoring files from snapshot..." << std::endl;

        std::string remove_immutable = "chattr -i " + snapshot_path + " 2>/dev/null";
        ExecuteCommand(remove_immutable);

        auto critical_dirs = GetCriticalDirectories();
        bool success       = true;

        for (const auto& dir : critical_dirs) {
            std::string source = snapshot_path + dir;

            if (stat(source.c_str(), &st) != 0) continue;

            std::cout << "  Restoring " << dir << "..." << std::flush;

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

        std::string cmd = "btrfs subvolume delete / && "
                          "btrfs subvolume snapshot " + snapshot_path + " / 2>&1";
        ExecuteCommand(cmd);

        std::cout << "⚠️  System needs reboot to complete rollback" << std::endl;
        return true;
    }

    bool SnapshotSystem::RollbackLVMSnapshot(const std::string& snapshot_id) {
        std::string vg        = GetRootVolumeGroup();
        std::string snap_name = "koraav-snap-" + snapshot_id;

        std::string cmd = "lvconvert --merge " + vg + "/" + snap_name + " 2>&1";
        ExecuteCommand(cmd);

        std::cout << "⚠️  System needs reboot to complete rollback" << std::endl;
        return true;
    }

    bool SnapshotSystem::RollbackZFSSnapshot(const std::string& snapshot_id) {
        std::string dataset_cmd = "df -T / | tail -1 | awk '{print $1}' 2>&1";
        std::string dataset     = ExecuteCommand(dataset_cmd);
        dataset.erase(dataset.find_last_not_of(" \n\r\t") + 1);

        std::string snap_name = dataset + "@koraav-snap-" + snapshot_id;
        std::string cmd       = "zfs rollback -r " + snap_name + " 2>&1";
        std::string output    = ExecuteCommand(cmd);

        return output.empty() || output.find("successfully") != std::string::npos;
    }

    // ═══════════════════════════════════════════════════════════════
    // HELPERS
    // ═══════════════════════════════════════════════════════════════

    bool SnapshotSystem::MakeSnapshotImmutable(const std::string& snapshot_path) {
        std::string cmd = "chattr +i " + snapshot_path + " 2>/dev/null";
        ExecuteCommand(cmd);
        return true;
    }

    bool SnapshotSystem::DeleteOldestSnapshot() {
        if (active_snapshots_.empty()) return false;

        auto oldest      = active_snapshots_.begin();
        std::string snap_id = oldest->id;

        std::string remove_immutable = "chattr -i " + oldest->path + " 2>/dev/null";
        ExecuteCommand(remove_immutable);

        bool success = false;
        switch (fs_type_) {
            case FilesystemType::BTRFS: {
                std::string cmd    = "btrfs subvolume delete " + oldest->path + " 2>&1";
                std::string output = ExecuteCommand(cmd);
                success = (output.find("Delete subvolume") != std::string::npos);
                break;
            }
            case FilesystemType::LVM_THIN:
            case FilesystemType::EXT4_LVM:
            case FilesystemType::XFS_LVM: {
                std::string vg        = GetRootVolumeGroup();
                std::string snap_name = "koraav-snap-" + snap_id;
                std::string cmd       = "lvremove -f " + vg + "/" + snap_name + " 2>&1";
                std::string output    = ExecuteCommand(cmd);
                success = (output.find("successfully removed") != std::string::npos);
                break;
            }
            case FilesystemType::ZFS: {
                std::string dataset_cmd = "df -T / | tail -1 | awk '{print $1}' 2>&1";
                std::string dataset     = ExecuteCommand(dataset_cmd);
                dataset.erase(dataset.find_last_not_of(" \n\r\t") + 1);

                std::string snap_name = dataset + "@koraav-snap-" + snap_id;
                std::string cmd       = "zfs destroy " + snap_name + " 2>&1";
                std::string output    = ExecuteCommand(cmd);
                success = output.empty() || output.find("successfully") != std::string::npos;
                break;
            }
            case FilesystemType::EXT4_RSYNC:
            case FilesystemType::XFS_RSYNC: {
                std::string cmd    = "rm -rf \"" + oldest->path + "\" 2>&1";
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
            std::cout << "✓ Deleted oldest snapshot: " << snap_id << std::endl;
        }

        return success;
    }

    bool SnapshotSystem::IsSnapshotDeletionAttempt(const std::string& command) const {
        if (command.find("btrfs")      != std::string::npos &&
            command.find("subvolume")  != std::string::npos &&
            command.find("delete")     != std::string::npos &&
            command.find("koraav")     != std::string::npos) return true;

        if (command.find("lvremove")   != std::string::npos &&
            command.find("koraav-snap") != std::string::npos) return true;

        if (command.find("zfs")        != std::string::npos &&
            command.find("destroy")    != std::string::npos &&
            command.find("koraav-snap") != std::string::npos) return true;

        if (command.find("rm")         != std::string::npos &&
            command.find(".snapshots/koraav") != std::string::npos) return true;

        return false;
    }

    std::string SnapshotSystem::GenerateSnapshotID() {
        auto now    = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time_t), "%Y%m%d-%H%M%S");
        return oss.str();
    }

    std::string SnapshotSystem::ExecuteCommand(const std::string& command) {
        FILE* pipe = popen(command.c_str(), "r");
        if (!pipe) return "";

        char        buffer[256];
        std::string result;

        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }

        pclose(pipe);
        return result;
    }

    uint64_t SnapshotSystem::GetSnapshotSize(const std::string& snapshot_path) {
        struct statvfs stat;
        if (statvfs(snapshot_path.c_str(), &stat) != 0) return 0;
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
        std::string cmd    = "lvs --noheadings -o vg_name $(df / | tail -1 | awk '{print $1}') 2>&1";
        std::string output = ExecuteCommand(cmd);
        output.erase(0, output.find_first_not_of(" \n\r\t"));
        output.erase(output.find_last_not_of(" \n\r\t") + 1);
        return output;
    }

    std::string SnapshotSystem::GetRootLogicalVolume() {
        std::string cmd    = "lvs --noheadings -o lv_name $(df / | tail -1 | awk '{print $1}') 2>&1";
        std::string output = ExecuteCommand(cmd);
        output.erase(0, output.find_first_not_of(" \n\r\t"));
        output.erase(output.find_last_not_of(" \n\r\t") + 1);
        return output;
    }

    std::vector<std::string> SnapshotSystem::ListSnapshots() const {
        std::lock_guard<std::mutex> lock(snapshots_mutex_);

        std::vector<std::string> ids;
        for (const auto& snap : active_snapshots_) {
            ids.push_back(snap.id + (snap.emergency ? " [emergency]" : ""));
        }
        return ids;
    }

    SnapshotSystem::Statistics SnapshotSystem::GetStats() const {
        Statistics s;
        s.snapshots_created            = stats_.snapshots_created.load();
        s.snapshots_deleted            = stats_.snapshots_deleted.load();
        s.rollbacks_performed          = stats_.rollbacks_performed.load();
        s.deletion_attempts_blocked    = stats_.deletion_attempts_blocked.load();
        s.emergency_snapshots_triggered = stats_.emergency_snapshots_triggered.load();
        s.inotify_events_processed     = stats_.inotify_events_processed.load();
        return s;
    }

} // namespace realtime
} // namespace koraav
