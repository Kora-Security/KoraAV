// src/cli/koraav_main.cpp
// Unified KoraAV Command-Line Interface
// Combines scanner, rule manager, database manager, unlock, and exclusion management

#include "../scanner/scanner_engine.h"
#include "../scanner/signatures/hash_db_manager.h"
#include "../common/exclusion_manager.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <string>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <fstream>
#include <unistd.h>
#include <cstdlib>
#include <signal.h>

using namespace koraav;
using namespace koraav::scanner;
using namespace koraav::realtime;

// Progress tracking (could be better looking lol)
struct ProgressTracker {
    uint64_t total_files = 0;
    uint64_t scanned_files = 0;
    uint64_t threats_found = 0;
    std::string current_file;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_update;
    
    ProgressTracker() {
        start_time = std::chrono::steady_clock::now();
        last_update = start_time;
    }
    
    void Update(const std::string& file, uint64_t scanned, uint64_t threats) {
        scanned_files = scanned;
        threats_found = threats;
        current_file = file;
        last_update = std::chrono::steady_clock::now();
        Display();
    }
    
    void Display() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        
        double speed = scanned_files > 0 ? (double)scanned_files / (elapsed + 1) : 0;
        uint64_t remaining = total_files > scanned_files ? total_files - scanned_files : 0;
        uint64_t eta_seconds = speed > 0 ? remaining / speed : 0;
        
        std::cout << "\r\033[K";
        
        int progress_percent = total_files > 0 ? (scanned_files * 100) / total_files : 0;
        int bar_width = 40;
        int filled = (bar_width * progress_percent) / 100;
        
        std::cout << "[";
        for (int i = 0; i < bar_width; i++) {
            if (i < filled) std::cout << "█";
            else if (i == filled) std::cout << "▓";
            else std::cout << "░";
        }
        std::cout << "] " << std::setw(3) << progress_percent << "% │ " << scanned_files;
        if (total_files > 0) std::cout << "/" << total_files;
        std::cout << " files │ ";
        
        if (threats_found > 0) std::cout << "\033[31m" << threats_found << " threats\033[0m │ ";
        else std::cout << "\033[32m0 threats\033[0m │ ";
        
        std::cout << std::fixed << std::setprecision(1) << speed << " f/s │ " << FormatTime(elapsed) << " elapsed";
        
        if (eta_seconds > 0 && eta_seconds < 86400) {
            std::cout << " │ ~" << FormatTime(eta_seconds) << " left";
        }
        
        if (!current_file.empty()) {
            std::cout << "\n\033[2m📄 " << TruncatePath(current_file, 80) << "\033[0m\033[A";
        }
        
        std::cout.flush();
    }
    
    void Finish() { std::cout << "\n"; }
    
private:
    std::string FormatTime(uint64_t seconds) {
        if (seconds < 60) return std::to_string(seconds) + "s";
        else if (seconds < 3600) {
            uint64_t mins = seconds / 60;
            uint64_t secs = seconds % 60;
            return std::to_string(mins) + "m " + std::to_string(secs) + "s";
        } else {
            uint64_t hours = seconds / 3600;
            uint64_t mins = (seconds % 3600) / 60;
            return std::to_string(hours) + "h " + std::to_string(mins) + "m";
        }
    }
    
    std::string TruncatePath(const std::string& path, size_t max_len) {
        if (path.length() <= max_len) return path;
        size_t start_len = max_len / 2 - 2;
        size_t end_len = max_len / 2 - 2;
        return path.substr(0, start_len) + "..." + path.substr(path.length() - end_len);
    }
};

static ProgressTracker g_progress;

void ScanProgressCallback(const std::string& file, uint64_t scanned, uint64_t threats) {
    g_progress.Update(file, scanned, threats);
}

void PrintResults(const ScanResults& results) {
    std::cout << "\n=== Scan Results ===" << std::endl;
    std::cout << "Scan Type: ";
    switch (results.scan_type) {
        case ScanType::FULL_SCAN: std::cout << "Full Scan"; break;
        case ScanType::QUICK_SCAN: std::cout << "Quick Scan"; break;
        case ScanType::MANUAL_SCAN: std::cout << "Manual Scan"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << std::endl;
    
    std::cout << "Status: ";
    switch (results.status) {
        case ScanStatus::COMPLETED: std::cout << "Completed"; break;
        case ScanStatus::CANCELLED: std::cout << "Cancelled"; break;
        case ScanStatus::ERROR: std::cout << "Error"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << std::endl;
    
    std::cout << "Files Scanned: " << results.files_scanned << std::endl;
    std::cout << "Threats Found: " << results.threats_found << std::endl;
    std::cout << "Files Skipped: " << results.files_skipped << std::endl;
    std::cout << "Errors: " << results.errors << std::endl;
    std::cout << "Elapsed Time: " << std::fixed << std::setprecision(2) 
              << results.elapsed_time().count() << " seconds" << std::endl;
    
    if (results.threats_found > 0) {
        std::cout << "\n=== Threats Detected ===" << std::endl;
        for (const auto& threat : results.threats) {
            std::cout << "\nFile: " << threat.path << std::endl;
            std::cout << "Threat Level: ";
            switch (threat.threat_level) {
                case ThreatLevel::SUSPICIOUS: std::cout << "SUSPICIOUS"; break;
                case ThreatLevel::LOW: std::cout << "LOW"; break;
                case ThreatLevel::MEDIUM: std::cout << "MEDIUM"; break;
                case ThreatLevel::HIGH: std::cout << "HIGH"; break;
                case ThreatLevel::CRITICAL: std::cout << "CRITICAL"; break;
                default: std::cout << "UNKNOWN"; break;
            }
            std::cout << std::endl;
            
            std::cout << "SHA256: " << threat.hash_sha256 << std::endl;
            std::cout << "Entropy: " << std::fixed << std::setprecision(2) << threat.entropy << std::endl;
            
            std::cout << "Indicators:" << std::endl;
            for (const auto& indicator : threat.indicators) {
                std::cout << "  - " << indicator << std::endl;
            }
        }
    }
}

// Forward declarations
void ShowHelp(const char* prog);
int HandleScan(int argc, char** argv);
int HandleDatabase(int argc, char** argv);
int HandleRules(int argc, char** argv);
int HandleUnlock(int argc, char** argv);
int HandleExclusion(int argc, char** argv);

int main(int argc, char** argv) {
    if (argc < 2) {
        ShowHelp(argv[0]);
        return 1;
    }
    
    std::string command = argv[1];
    
    // Route to appropriate handler
    if (command == "scan" || command == "quick" || command == "full") {
        return HandleScan(argc, argv);
    }
    else if (command == "db" || command == "database" || command == "hashdb") {
        return HandleDatabase(argc, argv);
    }
    else if (command == "rules" || command == "rule") {
        return HandleRules(argc, argv);
    }
    else if (command == "unlock") {
        return HandleUnlock(argc, argv);
    }
    else if (command == "exclude" || command == "exclusion" || command == "whitelist") {
        return HandleExclusion(argc, argv);
    }
    else if (command == "help" || command == "--help" || command == "-h") {
        ShowHelp(argv[0]);
        return 0;
    }
    else if (command == "version" || command == "--version" || command == "-v") {
        std::cout << "KoraAV v0.1.0" << std::endl;
        std::cout << "A Modern Linux Antivirus" << std::endl;
        return 0;
    }
    else {
        std::cerr << "Unknown command: " << command << std::endl;
        std::cerr << "Run '" << argv[0] << " help' for usage information" << std::endl;
        return 1;
    }
}

void ShowHelp(const char* prog) {
    std::cout << R"(
╔════════════════════════════════════════════════════════════╗
║                      KoraAV v0.1.0                         ║
║           A Modern Antivirus for Linux Systems             ║
╚════════════════════════════════════════════════════════════╝

Usage: )" << prog << R"( <command> [options]

SCANNING COMMANDS:
  scan quick                    Quick scan of common locations
  scan full                     Full system scan
  scan <path> [path...]         Scan specific files/directories

DATABASE COMMANDS:
  db create <file>              Create new malware hash database
  db add <hash> [signature]     Add hash to database
  db remove <hash>              Remove hash from database
  db list                       List all hashes
  db check <hash>               Check if hash exists

RULE MANAGEMENT:
  rules add <file.yar>          Add custom YARA rule
  rules remove <n>              Remove YARA rule
  rules list                    List all active rules
  rules validate <file>         Validate rule syntax
  rules update                  Update rules from online sources
  rules reload                  Reload all rules
  rules info <n>                Show rule details

EXCLUSION MANAGEMENT:  (all write operations require sudo)
  exclude list                  List all exclusions
  exclude list <type>           List by type: process|path|folder|extension|hash
  exclude add process <path>    Exclude a process by exe path or name
  exclude add path <file>       Exclude a specific file path
  exclude add folder <dir>      Exclude all files under a directory
  exclude add extension <ext>   Exclude all files with an extension (.vmdk etc.)
  exclude add hash <sha256>     Exclude a file by SHA-256 hash
  exclude remove <id>           Remove an exclusion by its numeric ID
  exclude remove <type> <val>   Remove by type and value
  exclude reload                Signal daemon to reload exclusions (sends SIGHUP)

SYSTEM UNLOCK:
  unlock --filesystem           Restore filesystem to read-write
  unlock --network              Restore network access
  unlock --all                  Restore everything (full unlock)

OTHER COMMANDS:
  help                          Show this help message
  version                       Show version information

Exclusion types:
  process    Matched against full exe path OR basename.
             Use for apps that legitimately write many files
             (backup tools, VMs, databases, etc.)
  path       Exact single file — only that file is excluded.
  folder     Directory prefix — everything under that path.
  extension  File extension, e.g. .vmdk .iso .bak
  hash       SHA-256 of a specific binary — most precise.

Examples:
  sudo )" << prog << R"( exclude add process /opt/myapp/bin/myapp
  sudo )" << prog << R"( exclude add folder "/home/user/VirtualBox VMs"
  sudo )" << prog << R"( exclude add extension .iso
  sudo )" << prog << R"( exclude list
  sudo )" << prog << R"( exclude remove 3
  sudo )" << prog << R"( exclude reload

  )" << prog << R"( scan quick
  )" << prog << R"( scan /home/user/Downloads
  sudo )" << prog << R"( rules add my-malware.yar
  sudo )" << prog << R"( unlock --all

For more information, visit: https://github.com/Kora-Security/KoraAV
)";
}


int HandleScan(int argc, char** argv) {
    std::string scan_type;
    std::vector<std::string> paths;
    
    if (std::string(argv[1]) == "quick" || std::string(argv[1]) == "full") {
        scan_type = argv[1];
    } else if (std::string(argv[1]) == "scan") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " scan <quick|full|path>" << std::endl;
            return 1;
        }
        scan_type = argv[2];
        
        // If scan_type is not quick/full, assume it's a path
        if (scan_type != "quick" && scan_type != "full") {
            scan_type = "manual";
            for (int i = 2; i < argc; i++) {
                paths.push_back(argv[i]);
            }
        }
    }
    
    // Create scanner
    ScannerEngine scanner;
    ScanConfig config;
    
    config.thread_count = 4;
    config.max_file_size = 100 * 1024 * 1024;  // 100MB
    config.exclude_paths = {"/proc", "/sys", "/dev"};
    
    scanner.Initialize(config);
    
    // Run scan
    ScanResults results;
    
    if (scan_type == "quick") {
        std::cout << "\n🔍 Starting quick scan...\n" << std::endl;
        results = scanner.QuickScan(ScanProgressCallback);
        g_progress.Finish();
    }
    else if (scan_type == "full") {
        std::cout << "\n🔍 Starting full system scan...\n" << std::endl;
        results = scanner.FullScan(ScanProgressCallback);
        g_progress.Finish();
    }
    else if (scan_type == "manual") {
        std::cout << "\n🔍 Starting manual scan...\n" << std::endl;
        results = scanner.ManualScan(paths, ScanProgressCallback);
        g_progress.Finish();
    }
    else {
        std::cerr << "Invalid scan type: " << scan_type << std::endl;
        return 1;
    }
    
    PrintResults(results);
    return results.threats_found > 0 ? 1 : 0;
}

int HandleDatabase(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " db <create|add|remove|list|check> [args]" << std::endl;
        return 1;
    }
    
    std::string cmd = argv[2];
    
    if (cmd == "create" && argc >= 4) {
        std::string db_path = argv[3];
        HashDatabaseManager db_mgr;
        
        if (!db_mgr.CreateDatabase(db_path)) {
            std::cerr << "Failed to create database" << std::endl;
            return 1;
        }
        
        std::cout << "✓ Database created: " << db_path << std::endl;
        std::cout << "  Add hashes with: " << argv[0] << " db add <hash> [signature]" << std::endl;
        return 0;
    }
    else if (cmd == "list") {
        // TODO: Implement list and other commands
        std::cout << "Database listing not yet implemented" << std::endl;
        return 1;
    }
    else {
        std::cerr << "Unknown database command: " << cmd << std::endl;
        return 1;
    }
}

int HandleRules(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " rules <add|remove|list|validate|update|reload|info> [args]" << std::endl;
        return 1;
    }
    
    std::string cmd = argv[2];
    
    if (cmd == "list") {
        // Simple list implementation
        std::cout << "=== Active YARA Rules ===" << std::endl;
        std::cout << "\nSystem Rules (/opt/koraav/share/signatures/yara-rules/):" << std::endl;
        system("ls -1 /opt/koraav/share/signatures/yara-rules/*.yar 2>/dev/null | xargs -n1 basename");
        std::cout << "\nUser Rules (/opt/koraav/share/signatures/yara-rules/custom/):" << std::endl;
        system("ls -1 /opt/koraav/share/signatures/yara-rules/custom/*.yar 2>/dev/null | xargs -n1 basename || echo '  No user rules'");
        return 0;
    }
    else if (cmd == "update") {
        std::cout << "Updating YARA rules from online sources..." << std::endl;
        std::cout << "Rule updates not yet implemented" << std::endl;
        return 1;
    }
    else {
        std::cerr << "Unknown rules command: " << cmd << std::endl;
        std::cerr << "Run: " << argv[0] << " help" << std::endl;
        return 1;
    }
}

int HandleUnlock(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " unlock <--filesystem|--network|--all>" << std::endl;
        return 1;
    }
    
    std::string option = argv[2];
    
    std::cout << "KoraAV System Unlock Utility" << std::endl;
    std::cout << "=============================" << std::endl;
    
    if (getuid() != 0) {
        std::cerr << "\n✗ Error: This command requires root privileges" << std::endl;
        std::cerr << "Run: sudo " << argv[0] << " unlock " << option << std::endl;
        return 1;
    }
    
    if (option == "--filesystem") {
        std::cout << "\n🔓 Restoring filesystem to read-write..." << std::endl;
        system("mount -o remount,rw / 2>/dev/null");
        std::cout << "✓ Filesystem restored" << std::endl;
        return 0;
    }
    else if (option == "--network") {
        std::cout << "\n🔓 Restoring network access..." << std::endl;
        system("nft flush ruleset 2>/dev/null || iptables -F 2>/dev/null");
        std::cout << "✓ Network restored" << std::endl;
        return 0;
    }
    else if (option == "--all") {
        std::cout << "\n🔓 FULL SYSTEM UNLOCK" << std::endl;
        std::cout << "Restoring filesystem..." << std::endl;
        system("mount -o remount,rw / 2>/dev/null");
        std::cout << "Restoring network..." << std::endl;
        system("nft flush ruleset 2>/dev/null || iptables -F 2>/dev/null");
        std::cout << "\n✓ System fully unlocked" << std::endl;
        return 0;
    }
    else {
        std::cerr << "Unknown unlock option: " << option << std::endl;
        return 1;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// EXCLUSION MANAGEMENT COMMAND
// All write subcommands (add / remove / reload) require root (sudo).
// 'list' is readable by anyone so admins can audit without privilege.
// ════════════════════════════════════════════════════════════════════════════

static const std::string EXCLUSION_DB = "/opt/koraav/var/exclusions.db";

// Pretty-print a timestamp
static std::string FormatTimestamp(
    const std::chrono::system_clock::time_point& tp) {
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", std::localtime(&t));
    return buf;
}

// Column-aligned table printer
static void PrintExclusionTable(
    const std::vector<ExclusionManager::Exclusion>& items) {
    if (items.empty()) {
        std::cout << "  (no entries)" << std::endl;
        return;
    }
    std::cout << std::left
              << std::setw(6)  << "ID"
              << std::setw(12) << "TYPE"
              << std::setw(42) << "VALUE"
              << std::setw(18) << "ADDED BY"
              << std::setw(18) << "DATE"
              << "COMMENT" << std::endl;
    std::cout << std::string(110, '-') << std::endl;
    for (const auto& ex : items) {
        std::string val = ex.value;
        if (val.size() > 40) val = val.substr(0, 37) + "...";
        std::cout << std::left
                  << std::setw(6)  << ex.id
                  << std::setw(12) << ExclusionManager::TypeToString(ex.type)
                  << std::setw(42) << val
                  << std::setw(18) << ex.added_by
                  << std::setw(18) << FormatTimestamp(ex.created_at)
                  << ex.comment << std::endl;
    }
    std::cout << std::string(110, '-') << std::endl;
    std::cout << items.size() << " exclusion(s)" << std::endl;
}

int HandleExclusion(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0]
                  << " exclude <list|add|remove|reload> [args]\n"
                  << "Run '" << argv[0] << " help' for full usage." << std::endl;
        return 1;
    }

    std::string sub = argv[2];

    // ── list ──────────────────────────────────────────────────────────────
    // Readable without root — anyone can see what's excluded.
    if (sub == "list") {
        ExclusionManager mgr(EXCLUSION_DB);
        if (!mgr.Initialize()) {
            std::cerr << "❌ Could not open exclusion database." << std::endl;
            return 1;
        }

        if (argc >= 4) {
            // Filter by type
            std::string type_str = argv[3];
            // Uppercase it
            std::transform(type_str.begin(), type_str.end(),
                           type_str.begin(), ::toupper);
            try {
                auto type = ExclusionManager::StringToType(type_str);
                auto items = mgr.ListByType(type);
                std::cout << "\n=== Exclusions: " << type_str << " ===" << std::endl;
                PrintExclusionTable(items);
            } catch (...) {
                std::cerr << "Unknown type '" << argv[3]
                          << "'. Valid: process path folder extension hash"
                          << std::endl;
                return 1;
            }
        } else {
            auto items = mgr.ListAll();
            std::cout << "\n=== All Exclusions ===" << std::endl;
            PrintExclusionTable(items);
        }
        return 0;
    }

    // ── All write operations require root ─────────────────────────────────
    if (sub == "add" || sub == "remove" || sub == "reload") {
        if (getuid() != 0) {
            std::cerr << "❌ '" << sub << "' requires root privileges.\n"
                      << "   Run: sudo " << argv[0]
                      << " exclude " << sub << std::endl;
            return 1;
        }
    }

    // ── add ───────────────────────────────────────────────────────────────
    if (sub == "add") {
        if (argc < 5) {
            std::cerr << "Usage: sudo " << argv[0]
                      << " exclude add <type> <value> [--comment \"...\"]"
                      << std::endl;
            return 1;
        }

        std::string type_str = argv[3];
        std::transform(type_str.begin(), type_str.end(),
                       type_str.begin(), ::toupper);

        std::string value = argv[4];

        // Optional --comment flag
        std::string comment;
        for (int i = 5; i < argc - 1; i++) {
            if (std::string(argv[i]) == "--comment") {
                comment = argv[i + 1];
                break;
            }
        }

        ExclusionManager::ExclusionType type;
        try {
            type = ExclusionManager::StringToType(type_str);
        } catch (...) {
            std::cerr << "❌ Unknown exclusion type '" << argv[3] << "'.\n"
                      << "   Valid types: process  path  folder  extension  hash"
                      << std::endl;
            return 1;
        }

        // Validate extension format
        if (type == ExclusionManager::ExclusionType::EXTENSION) {
            if (value[0] != '.') value = "." + value;
        }

        ExclusionManager mgr(EXCLUSION_DB);
        if (!mgr.Initialize()) {
            std::cerr << "❌ Could not open exclusion database." << std::endl;
            return 1;
        }

        if (!mgr.AddExclusion(type, value, comment)) {
            std::cerr << "❌ Failed to add exclusion (may already exist)." << std::endl;
            return 1;
        }

        std::cout << "✓ Exclusion added: ["
                  << ExclusionManager::TypeToString(type) << "] " << value;
        if (!comment.empty()) std::cout << "  (" << comment << ")";
        std::cout << std::endl;
        std::cout << "  Run 'sudo " << argv[0]
                  << " exclude reload' to apply immediately." << std::endl;
        return 0;
    }

    // ── remove ────────────────────────────────────────────────────────────
    if (sub == "remove") {
        if (argc < 4) {
            std::cerr << "Usage: sudo " << argv[0]
                      << " exclude remove <id>\n"
                      << "   OR: sudo " << argv[0]
                      << " exclude remove <type> <value>" << std::endl;
            return 1;
        }

        ExclusionManager mgr(EXCLUSION_DB);
        if (!mgr.Initialize()) {
            std::cerr << "❌ Could not open exclusion database." << std::endl;
            return 1;
        }

        // Numeric ID or type+value?
        bool is_numeric = true;
        for (char c : std::string(argv[3])) {
            if (!std::isdigit(c)) { is_numeric = false; break; }
        }

        if (is_numeric) {
            int64_t id = std::stoll(argv[3]);
            if (!mgr.RemoveExclusion(id)) {
                std::cerr << "❌ No exclusion with ID " << id << std::endl;
                return 1;
            }
            std::cout << "✓ Exclusion #" << id << " removed." << std::endl;
        } else {
            if (argc < 5) {
                std::cerr << "Usage: sudo " << argv[0]
                          << " exclude remove <type> <value>" << std::endl;
                return 1;
            }
            std::string type_str = argv[3];
            std::transform(type_str.begin(), type_str.end(),
                           type_str.begin(), ::toupper);
            std::string value = argv[4];
            auto type = ExclusionManager::StringToType(type_str);
            if (!mgr.RemoveExclusionByValue(type, value)) {
                std::cerr << "❌ Entry not found: ["
                          << type_str << "] " << value << std::endl;
                return 1;
            }
            std::cout << "✓ Removed [" << type_str << "] " << value << std::endl;
        }

        std::cout << "  Run 'sudo " << argv[0]
                  << " exclude reload' to apply immediately." << std::endl;
        return 0;
    }

    // ── reload ────────────────────────────────────────────────────────────
    // Sends SIGHUP to the running korad daemon so it reloads the exclusion
    // DB without a full restart.
    if (sub == "reload") {
        // Find korad PID via /var/run/koraav/korad.pid or pidof
        pid_t daemon_pid = 0;

        // Try pidfile first
        std::ifstream pidfile("/var/run/koraav/korad.pid");
        if (pidfile) {
            pidfile >> daemon_pid;
        }

        // Fall back to pidof
        if (daemon_pid <= 0) {
            FILE* pipe = popen("pidof korad 2>/dev/null", "r");
            if (pipe) {
                fscanf(pipe, "%d", &daemon_pid);
                pclose(pipe);
            }
        }

        if (daemon_pid <= 0) {
            std::cerr << "⚠️  korad daemon does not appear to be running.\n"
                      << "   Exclusions will be loaded on next daemon start."
                      << std::endl;
            return 0;
        }

        if (kill(daemon_pid, SIGHUP) == 0) {
            std::cout << "✓ Sent SIGHUP to korad (PID " << daemon_pid
                      << ") — exclusion database will reload momentarily."
                      << std::endl;
        } else {
            std::cerr << "❌ Could not signal korad (PID " << daemon_pid
                      << "): " << strerror(errno) << std::endl;
            return 1;
        }
        return 0;
    }

    std::cerr << "Unknown exclude subcommand: " << sub << "\n"
              << "Valid: list  add  remove  reload" << std::endl;
    return 1;
}
