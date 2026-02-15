// src/cli/koraav_main.cpp
// Unified KoraAV Command-Line Interface
// Combines scanner, rule manager, database manager, and unlock into one binary

#include "../scanner/scanner_engine.h"
#include "../scanner/signatures/hash_db_manager.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <cstdlib>

using namespace koraav;
using namespace koraav::scanner;

// Progress tracking (can be better lol)
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
║               A Modern Antivirus for Linux                 ║
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
  rules remove <name>           Remove YARA rule
  rules list                    List all active rules
  rules validate <file>         Validate rule syntax
  rules update                  Update rules from online sources
  rules reload                  Reload all rules
  rules info <name>             Show rule details
  
SYSTEM UNLOCK:
  unlock --filesystem           Restore filesystem to read-write
  unlock --network              Restore network access
  unlock --all                  Restore everything (full unlock)
  
OTHER COMMANDS:
  help                          Show this help message
  version                       Show version information

Examples:
  # Quick scan
  )" << prog << R"( scan quick
  
  # Scan a directory
  )" << prog << R"( scan /home/user/Downloads
  
  # Add custom YARA rule
  sudo )" << prog << R"( rules add my-malware.yar
  
  # Create hash database
  sudo )" << prog << R"( db create /opt/koraav/var/db/hashes.db
  
  # Emergency system unlock
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
        std::cout << "\nUser Rules (/opt/koraav/share/signatures/yara-rules/user/):" << std::endl;
        system("ls -1 /opt/koraav/share/signatures/yara-rules/user/*.yar 2>/dev/null | xargs -n1 basename || echo '  No user rules'");
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
