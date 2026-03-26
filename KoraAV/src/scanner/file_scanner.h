// src/scanner/file_scanner.h
#ifndef KORAAV_FILE_SCANNER_H
#define KORAAV_FILE_SCANNER_H

#include <koraav/types.h>
#include <string>
#include <memory>

namespace koraav {
namespace scanner {

// Forward declarations
class SignatureDatabase;
class HashScanner;
class YaraScanner;
class EntropyAnalyzer;
class ELFAnalyzer;
class ScriptAnalyzer;

/**
 * Scans individual files for threats
 * Uses multiple detection methods: hash matching, signatures, heuristics, static analysis
 */
class FileScanner {
public:
    FileScanner();
    ~FileScanner();
    
    /**
     * Initialize scanner with configuration
     */
    bool Initialize(const ScanConfig& config);
    
    /**
     * Scan a single file
     * @param path Path to file to scan
     * @return Scan result with threat info
     */
    FileScanResult ScanFile(const std::string& path);
    
    /**
     * Quick check if file should be scanned
     * @param path File path
     * @param size File size
     * @return true if should scan, false if should skip
     */
    bool ShouldScanFile(const std::string& path, size_t size) const;
    
    /**
     * Get current configuration
     */
    const ScanConfig& GetConfig() const { return config_; }

private:
    // Helper methods
    FileType DetectFileType(const std::string& path);
    std::string CalculateMD5(const std::string& path);
    std::string CalculateSHA256(const std::string& path);
    std::vector<char> ReadFile(const std::string& path, size_t max_size = 0);
    
    // Detection methods
    bool CheckHashDatabase(const std::string& hash, FileScanResult& result);
    bool CheckYaraRules(const std::vector<char>& data, FileScanResult& result);
    bool CheckYaraRulesFile(const std::string& path, FileScanResult& result);
    bool CheckHeuristics(const std::vector<char>& data, FileScanResult& result);
    bool CheckStaticAnalysis(const std::string& path, FileType type, FileScanResult& result);
    
    ScanConfig config_;
    
    // Detection engines (owned)
    std::unique_ptr<HashScanner> hash_scanner_;
    std::unique_ptr<YaraScanner> yara_scanner_;
    std::unique_ptr<EntropyAnalyzer> entropy_analyzer_;
    std::unique_ptr<ELFAnalyzer> elf_analyzer_;
    std::unique_ptr<ScriptAnalyzer> script_analyzer_;
};

} // namespace scanner
} // namespace koraav

#endif // KORAAV_FILE_SCANNER_H
