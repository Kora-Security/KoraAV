// src/realtime-protection/response/exclusion_manager.h
#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <chrono>
#include <sqlite3.h>

namespace koraav {
namespace realtime {

/**
 * @brief SQLite3-backed exclusion (whitelist) manager.
 *
 * Enterprise AV solutions like CrowdStrike Falcon and SentinelOne maintain
 * structured exclusion lists that are checked before ANY detection action:
 * process kill, file quarantine, scan, rollback trigger, etc.
 *
 * Exclusion types
 * ───────────────
 *  PROCESS    - Exclude a process by executable path or name
 *               e.g.  /usr/bin/rsync   OR   rsync
 *  PATH       - Exclude a specific file path (exact match)
 *               e.g.  /home/user/.wine/drive_c/game.exe
 *  FOLDER     - Exclude everything under a directory (prefix match)
 *               e.g.  /home/user/VMs
 *  EXTENSION  - Exclude all files with a given extension
 *               e.g.  .vmdk  .iso  .bak
 *  HASH       - Exclude a file by its SHA-256 hash
 *               e.g.  a3f1... (useful for known-good custom binaries)
 *
 * Security model
 * ──────────────
 * The DB lives at /opt/koraav/var/exclusions.db and is owned by the
 * koraav system user (mode 0600).  The CLI binary (koraav) requires the
 * caller to be root (sudo); it then drops privileges and writes through
 * the ExclusionManager as the koraav user.  The daemon reads the DB at
 * startup and reloads it on SIGHUP or after every CLI mutation.
 *
 * All write methods return false if the caller is not running as the
 * koraav UID or root, making DB manipulation from unprivileged code
 * impossible even if an attacker obtains a shell.
 */
class ExclusionManager {
public:
    // ── Exclusion record ──────────────────────────────────────────────────
    enum class ExclusionType {
        PROCESS,    // exe path or basename
        PATH,       // exact file path
        FOLDER,     // directory prefix
        EXTENSION,  // file extension (e.g. ".vmdk")
        HASH,       // SHA-256 hex string
    };

    struct Exclusion {
        int64_t     id;
        ExclusionType type;
        std::string value;          // the path / name / hash / ext
        std::string comment;        // human-readable reason
        std::string added_by;       // username that added this entry
        std::chrono::system_clock::time_point created_at;
    };

    // ── Lifecycle ─────────────────────────────────────────────────────────
    explicit ExclusionManager(
        const std::string& db_path = "/opt/koraav/var/exclusions.db");
    ~ExclusionManager();

    // Open (or create) the database.  Returns false on failure.
    bool Initialize();

    // Re-read the database into the in-memory cache.
    // Call after CLI mutations so the running daemon picks them up without
    // a full restart.
    bool Reload();

    // ── Write API (require koraav UID or root) ────────────────────────────
    bool AddExclusion(ExclusionType type,
                      const std::string& value,
                      const std::string& comment = "");

    bool RemoveExclusion(int64_t id);
    bool RemoveExclusionByValue(ExclusionType type, const std::string& value);

    // ── Query API (in-memory, lock-free hot path) ─────────────────────────

    // True if the executable path (or its basename) is excluded.
    bool IsProcessExcluded(const std::string& exe_path) const;

    // True if the file path matches an excluded PATH, FOLDER, or EXTENSION.
    bool IsPathExcluded(const std::string& file_path) const;

    // True if the SHA-256 hash is on the exclusion list.
    bool IsHashExcluded(const std::string& sha256_hex) const;

    // Combined check used by the daemon at every detection gate:
    //   IsProcessExcluded(exe_path) || IsPathExcluded(file_path)
    bool ShouldExclude(const std::string& exe_path,
                       const std::string& file_path) const;

    // ── List / inspect ────────────────────────────────────────────────────
    std::vector<Exclusion> ListAll() const;
    std::vector<Exclusion> ListByType(ExclusionType type) const;

    // ── Helpers ───────────────────────────────────────────────────────────
    static std::string TypeToString(ExclusionType t);
    static ExclusionType StringToType(const std::string& s);

private:
    // ── DB helpers ────────────────────────────────────────────────────────
    bool OpenDatabase();
    bool CreateSchema();
    bool LoadCache();

    // Returns true if the current effective UID is allowed to write.
    bool CallerCanWrite() const;

    std::string GetCallerUsername() const;

    // ── State ─────────────────────────────────────────────────────────────
    std::string  db_path_;
    sqlite3*     db_ = nullptr;
    mutable std::mutex mutex_;   // protects db_ and cache

    // In-memory caches for hot-path lookups (rebuilt on every Reload())
    std::unordered_set<std::string> cached_processes_;    // full path + basename
    std::unordered_set<std::string> cached_paths_;        // exact file paths
    std::vector<std::string>        cached_folders_;      // directory prefixes
    std::unordered_set<std::string> cached_extensions_;   // ".ext" lowercase
    std::unordered_set<std::string> cached_hashes_;       // sha256 lowercase

    // UID of the koraav system user (resolved once at Initialize())
    uid_t koraav_uid_ = static_cast<uid_t>(-1);
};

} // namespace realtime
} // namespace koraav
