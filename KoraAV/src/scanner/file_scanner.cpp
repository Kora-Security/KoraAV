// src/scanner/file_scanner.cpp
#include "file_scanner.h"
#include "archive_scanner.h"
#include "signatures/hash_scanner.h"
#include "signatures/yara_scanner.h"
#include "heuristics/entropy_analyzer.h"
#include "static-analysis/elf_analyzer.h"
#include "static-analysis/script_analyzer.h"

#include <fstream>
#include <filesystem>
#include <iostream>
#include <openssl/evp.h>

namespace fs = std::filesystem;

namespace koraav {
namespace scanner {

FileScanner::FileScanner() {
    // Allocate detection engines
    hash_scanner_ = std::make_unique<HashScanner>();
    yara_scanner_ = std::make_unique<YaraScanner>();
    entropy_analyzer_ = std::make_unique<EntropyAnalyzer>();
    elf_analyzer_ = std::make_unique<ELFAnalyzer>();
    script_analyzer_ = std::make_unique<ScriptAnalyzer>();
}

FileScanner::~FileScanner() = default;

bool FileScanner::Initialize(const ScanConfig& config) {
    config_ = config;
    
    // Initialize sub-scanners
    if (config_.use_hash_db) {
        if (!hash_scanner_->LoadDatabase("/opt/koraav/data/signatures/hashes.db")) {
            std::cerr << "Warning: Failed to load hash database" << std::endl;
        }
    }
    
    if (config_.use_yara) {
        if (!yara_scanner_->LoadRules("/opt/koraav/data/signatures/yara-rules/")) {
            std::cerr << "Warning: Failed to load YARA rules" << std::endl;
        }
    }
    
    return true;
}

FileScanResult FileScanner::ScanFile(const std::string& path) {
    FileScanResult result;
    result.path = path;
    result.threat_level = ThreatLevel::CLEAN;
    result.scan_time = std::chrono::system_clock::now();
    
    try {
        // Get file info
        if (!fs::exists(path)) {
            result.threat_level = ThreatLevel::CLEAN;
            return result;
        }
        
        result.file_size = fs::file_size(path);
        
        // Check if we should skip this file
        if (!ShouldScanFile(path, result.file_size)) {
            return result;
        }
        
        // Detect file type
        result.file_type = DetectFileType(path);
        
        // Handle archives if enabled
        if (config_.scan_archives && ArchiveScanner::IsArchive(path)) {
            auto archive_threats = ArchiveScanner::ScanArchive(path, *this);
            if (!archive_threats.empty()) {
                result.threat_level = ThreatLevel::HIGH;
                result.detection_methods.push_back(DetectionMethod::STATIC_ANALYSIS);
                for (const auto& threat : archive_threats) {
                    for (const auto& indicator : threat.indicators) {
                        result.indicators.push_back("In archive: " + indicator);
                    }
                }
            }
            // Continue with archive file itself
        }
        
        // Calculate hashes
        result.hash_md5 = CalculateMD5(path);
        result.hash_sha256 = CalculateSHA256(path);
        
        // Check hash database first (fastest)
        if (config_.use_hash_db) {
            if (CheckHashDatabase(result.hash_sha256, result)) {
                return result; // Known malware, don't need further analysis
            }
        }
        
        // YARA rules - use file-based scan when possible (more efficient)
        if (config_.use_yara && yara_scanner_->IsInitialized()) {
            CheckYaraRulesFile(path, result);
        }
        
        // Read file data for heuristic analysis
        std::vector<char> file_data = ReadFile(path, config_.max_file_size);
        
        // Heuristic analysis
        if (config_.use_heuristics && !file_data.empty()) {
            CheckHeuristics(file_data, result);
        }
        
        // Static analysis for executables and scripts
        if (config_.use_static_analysis) {
            CheckStaticAnalysis(path, result.file_type, result);
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error scanning " << path << ": " << e.what() << std::endl;
    }
    
    return result;
}

bool FileScanner::ShouldScanFile(const std::string& path, size_t size) const {
    // Skip if too large
    if (size > config_.max_file_size) {
        return false;
    }
    
    // Skip if in exclude list
    for (const auto& exclude : config_.exclude_paths) {
        if (path.find(exclude) == 0) {
            return false;
        }
    }
    
    // Skip symlinks if configured
    if (!config_.follow_symlinks && fs::is_symlink(path)) {
        return false;
    }
    
    // Skip hidden files if configured
    if (!config_.scan_hidden_files) {
        fs::path p(path);
        if (!p.filename().empty() && p.filename().string()[0] == '.') {
            return false;
        }
    }
    
    return true;
}

FileType FileScanner::DetectFileType(const std::string& path) {
    // Read first few bytes (magic numbers)
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return FileType::UNKNOWN;
    }
    
    char magic[4];
    file.read(magic, 4);
    
    // ELF binary (Linux executable)
    if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
        return FileType::ELF_EXECUTABLE;
    }
    
    // PE binary (Windows executable) - for future windows port
    if (magic[0] == 'M' && magic[1] == 'Z') {
        return FileType::PE_EXECUTABLE;
    }
    
    // Check extension for scripts
    fs::path p(path);
    std::string ext = p.extension().string();
    
    if (ext == ".sh" || ext == ".bash") {
        return FileType::SCRIPT_BASH;
    } else if (ext == ".py") {
        return FileType::SCRIPT_PYTHON;
    } else if (ext == ".pl") {
        return FileType::SCRIPT_PERL;
    } else if (ext == ".zip" || ext == ".tar" || ext == ".gz" || ext == ".bz2") {
        return FileType::ARCHIVE;
    } else if (ext == ".so" || ext == ".dll") {
        return FileType::LIBRARY;
    }
    
    return FileType::UNKNOWN;
}

std::string FileScanner::CalculateMD5(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return "";
    }
    
    // Create EVP context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return "";
    }
    
    // Initialize MD5
    if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    // Read and hash file
    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(ctx);
            return "";
        }
    }
    
    // Finalize hash
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Convert to hex string
    char hex[EVP_MAX_MD_SIZE * 2 + 1];
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(hex + i * 2, "%02x", hash[i]);
    }
    hex[hash_len * 2] = '\0';
    
    return std::string(hex);
}

std::string FileScanner::CalculateSHA256(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return "";
    }
    
    // Create EVP context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return "";
    }
    
    // Initialize SHA256
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    // Read and hash file
    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(ctx);
            return "";
        }
    }
    
    // Finalize hash
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Convert to hex string
    char hex[EVP_MAX_MD_SIZE * 2 + 1];
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(hex + i * 2, "%02x", hash[i]);
    }
    hex[hash_len * 2] = '\0';
    
    return std::string(hex);
}

std::vector<char> FileScanner::ReadFile(const std::string& path, size_t max_size) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return {};
    }
    
    size_t size = file.tellg();
    if (max_size > 0 && size > max_size) {
        size = max_size;
    }
    
    std::vector<char> data(size);
    file.seekg(0);
    file.read(data.data(), size);
    
    return data;
}

bool FileScanner::CheckHashDatabase(const std::string& hash, FileScanResult& result) {
    if (hash_scanner_->IsKnownMalware(hash)) {
        result.threat_level = ThreatLevel::CRITICAL;
        result.detection_methods.push_back(DetectionMethod::HASH_MATCH);
        result.indicators.push_back("Known malware hash: " + hash);
        return true;
    }
    return false;
}

bool FileScanner::CheckYaraRules(const std::vector<char>& data, FileScanResult& result) {
    auto matches = yara_scanner_->ScanData(data);
    
    if (!matches.empty()) {
        result.threat_level = ThreatLevel::HIGH;
        result.detection_methods.push_back(DetectionMethod::YARA_RULE);
        
        for (const auto& match : matches) {
            result.indicators.push_back("YARA rule match: " + match);
        }
        return true;
    }
    
    return false;
}

bool FileScanner::CheckYaraRulesFile(const std::string& path, FileScanResult& result) {
    auto matches = yara_scanner_->ScanFile(path);
    
    if (!matches.empty()) {
        result.threat_level = ThreatLevel::HIGH;
        result.detection_methods.push_back(DetectionMethod::YARA_RULE);
        
        for (const auto& match : matches) {
            result.indicators.push_back("YARA rule match: " + match);
        }
        return true;
    }
    
    return false;
}

bool FileScanner::CheckHeuristics(const std::vector<char>& data, FileScanResult& result) {
    bool threat_found = false;
    
    result.entropy = entropy_analyzer_->Calculate(data);
    
    // High entropy indicates encryption/packing
    if (result.entropy > 7.5) {
        result.threat_level = std::max(result.threat_level, ThreatLevel::MEDIUM);
        result.detection_methods.push_back(DetectionMethod::HIGH_ENTROPY);
        result.indicators.push_back("High entropy: " + std::to_string(result.entropy));
        result.is_packed = true;
        threat_found = true;
    }
    
    // Check for suspicious strings
    auto suspicious_strings = entropy_analyzer_->FindSuspiciousStrings(data);
    if (!suspicious_strings.empty()) {
        result.threat_level = std::max(result.threat_level, ThreatLevel::SUSPICIOUS);
        result.detection_methods.push_back(DetectionMethod::SUSPICIOUS_STRINGS);
        
        for (const auto& str : suspicious_strings) {
            result.indicators.push_back("Suspicious string: " + str);
        }
        threat_found = true;
    }
    
    return threat_found;
}

bool FileScanner::CheckStaticAnalysis(const std::string& path, FileType type, 
                                      FileScanResult& result) {
    bool threat_found = false;
    
    switch (type) {
        case FileType::ELF_EXECUTABLE:
        case FileType::LIBRARY: {
            auto elf_threats = elf_analyzer_->Analyze(path);
            if (!elf_threats.empty()) {
                result.threat_level = std::max(result.threat_level, ThreatLevel::MEDIUM);
                result.detection_methods.push_back(DetectionMethod::STATIC_ANALYSIS);
                
                for (const auto& threat : elf_threats) {
                    result.indicators.push_back("ELF analysis: " + threat);
                }
                threat_found = true;
            }
            break;
        }
        
        case FileType::SCRIPT_BASH:
        case FileType::SCRIPT_PYTHON:
        case FileType::SCRIPT_PERL: {
            auto script_threats = script_analyzer_->Analyze(path, type);
            if (!script_threats.empty()) {
                result.threat_level = std::max(result.threat_level, ThreatLevel::MEDIUM);
                result.detection_methods.push_back(DetectionMethod::STATIC_ANALYSIS);
                
                for (const auto& threat : script_threats) {
                    result.indicators.push_back("Script analysis: " + threat);
                }
                threat_found = true;
            }
            break;
        }
        
        default:
            break;
    }
    
    return threat_found;
}

} // namespace scanner
} // namespace koraav
