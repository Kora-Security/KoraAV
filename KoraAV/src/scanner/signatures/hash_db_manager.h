// src/scanner/signatures/hash_db_manager.h
#ifndef KORAAV_HASH_DB_MANAGER_H
#define KORAAV_HASH_DB_MANAGER_H

#include <string>
#include <vector>

namespace koraav {
namespace scanner {

/**
 * Manages the malware hash database
 * Provides utilities to create, update, and maintain the hash database
 */
class HashDatabaseManager {
public:
    /**
     * Create initial hash database with known malware samples
     */
    static bool CreateDatabase(const std::string& db_path);
    
    /**
     * Add hash to database
     */
    static bool AddHash(const std::string& db_path, const std::string& hash, 
                       const std::string& description = "");
    
    /**
     * Add multiple hashes from a file (one per line)
     */
    static bool ImportHashes(const std::string& db_path, const std::string& import_file);
    
    /**
     * Update database from online threat feed
     */
    static bool UpdateFromFeed(const std::string& db_path, const std::string& feed_url);
    
    /**
     * Get database statistics
     */
    struct DatabaseStats {
        size_t hash_count;
        std::string last_updated;
    };
    static DatabaseStats GetStats(const std::string& db_path);
    
private:
    // Get list of known malware hashes to seed database
    static std::vector<std::pair<std::string, std::string>> GetKnownMalwareHashes();
};

} // namespace scanner
} // namespace koraav

#endif // KORAAV_HASH_DB_MANAGER_H
