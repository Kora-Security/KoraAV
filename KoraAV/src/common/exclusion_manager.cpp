// src/common/exclusion_manager.cpp
#include "exclusion_manager.h"
#include <iostream>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>

namespace koraav {

// ════════════════════════════════════════════════════════════════════════════
// Lifecycle
// ════════════════════════════════════════════════════════════════════════════

ExclusionManager::ExclusionManager(const std::string& db_path)
    : db_path_(db_path) {}

ExclusionManager::~ExclusionManager() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool ExclusionManager::Initialize() {
    // Resolve the koraav UID so we can gate writes later
    struct passwd* pw = getpwnam("koraav");
    if (pw) {
        koraav_uid_ = pw->pw_uid;
    } else {
        // Fallback: root only
        koraav_uid_ = 0;
    }

    if (!OpenDatabase()) return false;
    if (!CreateSchema()) return false;
    if (!LoadCache())    return false;

    std::cout << "✓ Exclusion database: " << db_path_
              << " (" << (cached_processes_.size()  +
                          cached_paths_.size()       +
                          cached_folders_.size()     +
                          cached_extensions_.size()  +
                          cached_hashes_.size())
              << " entries loaded)" << std::endl;
    return true;
}

bool ExclusionManager::Reload() {
    std::lock_guard<std::mutex> lk(mutex_);
    return LoadCache();
}

// ════════════════════════════════════════════════════════════════════════════
// Database open / schema
// ════════════════════════════════════════════════════════════════════════════

bool ExclusionManager::OpenDatabase() {
    // Ensure parent directory exists
    std::string dir = db_path_.substr(0, db_path_.rfind('/'));
    mkdir(dir.c_str(), 0700);

    int rc = sqlite3_open(db_path_.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::cerr << "❌ ExclusionManager: cannot open database '"
                  << db_path_ << "': " << sqlite3_errmsg(db_) << std::endl;
        db_ = nullptr;
        return false;
    }

    // Lock the DB file so only koraav user can read/write it
    // (installer should set this; we enforce it here too)
    if (koraav_uid_ != static_cast<uid_t>(-1)) {
        chown(db_path_.c_str(), koraav_uid_, static_cast<gid_t>(-1));
    }
    chmod(db_path_.c_str(), 0600);

    // Enable WAL for better concurrent read performance
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA foreign_keys=ON;",  nullptr, nullptr, nullptr);

    return true;
}

bool ExclusionManager::CreateSchema() {
    const char* sql = R"SQL(
        CREATE TABLE IF NOT EXISTS exclusions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            type        TEXT    NOT NULL
                            CHECK(type IN ('PROCESS','PATH','FOLDER','EXTENSION','HASH')),
            value       TEXT    NOT NULL,
            comment     TEXT    NOT NULL DEFAULT '',
            added_by    TEXT    NOT NULL DEFAULT '',
            created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            UNIQUE(type, value)
        );

        CREATE INDEX IF NOT EXISTS idx_exclusions_type
            ON exclusions(type);
    )SQL";

    char* errmsg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::cerr << "❌ ExclusionManager: schema creation failed: "
                  << (errmsg ? errmsg : "unknown") << std::endl;
        sqlite3_free(errmsg);
        return false;
    }
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// Cache rebuild  (called under mutex_)
// ════════════════════════════════════════════════════════════════════════════

bool ExclusionManager::LoadCache() {
    if (!db_) return false;

    cached_processes_.clear();
    cached_paths_.clear();
    cached_folders_.clear();
    cached_extensions_.clear();
    cached_hashes_.clear();

    const char* sql =
        "SELECT type, value FROM exclusions ORDER BY type;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "❌ ExclusionManager: LoadCache prepare failed: "
                  << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string type  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

        if (type == "PROCESS") {
            // Store both the full path and the basename so callers can match
            // either /usr/bin/rsync  or just  rsync
            cached_processes_.insert(value);
            size_t slash = value.rfind('/');
            if (slash != std::string::npos) {
                cached_processes_.insert(value.substr(slash + 1));
            }
        } else if (type == "PATH") {
            cached_paths_.insert(value);
        } else if (type == "FOLDER") {
            // Normalise: ensure trailing slash so prefix matches are unambiguous
            std::string folder = value;
            if (!folder.empty() && folder.back() != '/') folder += '/';
            cached_folders_.push_back(folder);
        } else if (type == "EXTENSION") {
            // Normalise to lowercase with leading dot
            std::string ext = value;
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (!ext.empty() && ext[0] != '.') ext = "." + ext;
            cached_extensions_.insert(ext);
        } else if (type == "HASH") {
            // Lowercase SHA-256
            std::string hash = value;
            std::transform(hash.begin(), hash.end(), hash.begin(), ::tolower);
            cached_hashes_.insert(hash);
        }
    }

    sqlite3_finalize(stmt);
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// Write API
// ════════════════════════════════════════════════════════════════════════════

bool ExclusionManager::CallerCanWrite() const {
    uid_t euid = geteuid();
    return (euid == 0 || euid == koraav_uid_);
}

std::string ExclusionManager::GetCallerUsername() const {
    uid_t uid = getuid();
    struct passwd* pw = getpwuid(uid);
    return pw ? std::string(pw->pw_name) : std::to_string(uid);
}

bool ExclusionManager::AddExclusion(ExclusionType type,
                                     const std::string& value,
                                     const std::string& comment) {
    if (!CallerCanWrite()) {
        std::cerr << "❌ ExclusionManager: permission denied — "
                     "run with sudo or as koraav user" << std::endl;
        return false;
    }
    if (value.empty()) {
        std::cerr << "❌ ExclusionManager: exclusion value cannot be empty" << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lk(mutex_);

    const char* sql =
        "INSERT OR IGNORE INTO exclusions(type, value, comment, added_by) "
        "VALUES(?, ?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "❌ ExclusionManager: AddExclusion prepare failed" << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, TypeToString(type).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, value.c_str(),              -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, comment.c_str(),            -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, GetCallerUsername().c_str(),-1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        std::cerr << "❌ ExclusionManager: AddExclusion failed: "
                  << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    // Rebuild cache so the daemon picks up the change immediately
    LoadCache();
    return true;
}

bool ExclusionManager::RemoveExclusion(int64_t id) {
    if (!CallerCanWrite()) {
        std::cerr << "❌ ExclusionManager: permission denied" << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lk(mutex_);

    const char* sql = "DELETE FROM exclusions WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return false;
    LoadCache();
    return true;
}

bool ExclusionManager::RemoveExclusionByValue(ExclusionType type,
                                               const std::string& value) {
    if (!CallerCanWrite()) {
        std::cerr << "❌ ExclusionManager: permission denied" << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lk(mutex_);

    const char* sql =
        "DELETE FROM exclusions WHERE type = ? AND value = ?;";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, TypeToString(type).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, value.c_str(),              -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return false;
    LoadCache();
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// Hot-path query API  (in-memory, no DB I/O)
// ════════════════════════════════════════════════════════════════════════════

bool ExclusionManager::IsProcessExcluded(const std::string& exe_path) const {
    // Check full path first
    if (cached_processes_.count(exe_path)) return true;

    // Check basename
    size_t slash = exe_path.rfind('/');
    if (slash != std::string::npos) {
        std::string basename = exe_path.substr(slash + 1);
        if (cached_processes_.count(basename)) return true;
    }
    return false;
}

bool ExclusionManager::IsPathExcluded(const std::string& file_path) const {
    // 1. Exact path match
    if (cached_paths_.count(file_path)) return true;

    // 2. Folder prefix match
    for (const auto& folder : cached_folders_) {
        if (file_path.compare(0, folder.size(), folder) == 0) return true;
    }

    // 3. Extension match
    if (!cached_extensions_.empty()) {
        // Find last '.' after last '/'
        size_t slash = file_path.rfind('/');
        size_t dot   = file_path.rfind('.');
        if (dot != std::string::npos &&
            (slash == std::string::npos || dot > slash)) {
            std::string ext = file_path.substr(dot);
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (cached_extensions_.count(ext)) return true;
        }
    }

    return false;
}

bool ExclusionManager::IsHashExcluded(const std::string& sha256_hex) const {
    std::string lower = sha256_hex;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return cached_hashes_.count(lower) > 0;
}

bool ExclusionManager::ShouldExclude(const std::string& exe_path,
                                      const std::string& file_path) const {
    return IsProcessExcluded(exe_path) || IsPathExcluded(file_path);
}

// ════════════════════════════════════════════════════════════════════════════
// List / inspect
// ════════════════════════════════════════════════════════════════════════════

std::vector<ExclusionManager::Exclusion> ExclusionManager::ListAll() const {
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<Exclusion> result;
    if (!db_) return result;

    const char* sql =
        "SELECT id, type, value, comment, added_by, created_at "
        "FROM exclusions ORDER BY type, value;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return result;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Exclusion ex;
        ex.id         = sqlite3_column_int64(stmt, 0);
        ex.type       = StringToType(
                            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
        ex.value      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        ex.comment    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        ex.added_by   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        int64_t ts    = sqlite3_column_int64(stmt, 5);
        ex.created_at = std::chrono::system_clock::from_time_t(
                            static_cast<time_t>(ts));
        result.push_back(std::move(ex));
    }

    sqlite3_finalize(stmt);
    return result;
}

std::vector<ExclusionManager::Exclusion>
ExclusionManager::ListByType(ExclusionType type) const {
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<Exclusion> result;
    if (!db_) return result;

    const char* sql =
        "SELECT id, type, value, comment, added_by, created_at "
        "FROM exclusions WHERE type = ? ORDER BY value;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return result;

    sqlite3_bind_text(stmt, 1, TypeToString(type).c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Exclusion ex;
        ex.id         = sqlite3_column_int64(stmt, 0);
        ex.type       = type;
        ex.value      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        ex.comment    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        ex.added_by   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        int64_t ts    = sqlite3_column_int64(stmt, 5);
        ex.created_at = std::chrono::system_clock::from_time_t(
                            static_cast<time_t>(ts));
        result.push_back(std::move(ex));
    }

    sqlite3_finalize(stmt);
    return result;
}

// ════════════════════════════════════════════════════════════════════════════
// Type string helpers
// ════════════════════════════════════════════════════════════════════════════

std::string ExclusionManager::TypeToString(ExclusionType t) {
    switch (t) {
        case ExclusionType::PROCESS:   return "PROCESS";
        case ExclusionType::PATH:      return "PATH";
        case ExclusionType::FOLDER:    return "FOLDER";
        case ExclusionType::EXTENSION: return "EXTENSION";
        case ExclusionType::HASH:      return "HASH";
        default:                        return "UNKNOWN";
    }
}

ExclusionManager::ExclusionType
ExclusionManager::StringToType(const std::string& s) {
    if (s == "PROCESS")   return ExclusionType::PROCESS;
    if (s == "PATH")      return ExclusionType::PATH;
    if (s == "FOLDER")    return ExclusionType::FOLDER;
    if (s == "EXTENSION") return ExclusionType::EXTENSION;
    if (s == "HASH")      return ExclusionType::HASH;
    return ExclusionType::PATH; // safe default
}


} // namespace koraav
