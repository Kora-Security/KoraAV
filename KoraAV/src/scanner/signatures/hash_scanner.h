// src/scanner/signatures/hash_scanner.h
#ifndef KORAAV_HASH_SCANNER_H
#define KORAAV_HASH_SCANNER_H

#include <string>
#include <unordered_set>

namespace koraav {
namespace scanner {

/**
 * Hash-based malware detection
 * Checks file hashes against known malware database
 */
class HashScanner {
public:
    HashScanner() = default;
    ~HashScanner() = default;
    
    /**
     * Load hash database from file
     * Database format: one SHA256 hash per line
     */
    bool LoadDatabase(const std::string& db_path);
    
    /**
     * Check if hash matches known malware
     */
    bool IsKnownMalware(const std::string& hash) const;
    
    /**
     * Add hash to database
     */
    void AddHash(const std::string& hash);
    
    /**
     * Get database size
     */
    size_t GetDatabaseSize() const { return malware_hashes_.size(); }

private:
    std::unordered_set<std::string> malware_hashes_;
};

} // namespace scanner
} // namespace koraav

#endif // KORAAV_HASH_SCANNER_H
