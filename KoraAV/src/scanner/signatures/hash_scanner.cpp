// src/scanner/signatures/hash_scanner.cpp
#include "hash_scanner.h"
#include <fstream>
#include <iostream>
#include <algorithm>

namespace koraav {
namespace scanner {

bool HashScanner::LoadDatabase(const std::string& db_path) {
    std::ifstream file(db_path);
    if (!file) {
        std::cerr << "Could not open hash database: " << db_path << std::endl;
        return false;
    }
    
    std::string line;
    size_t count = 0;
    
    while (std::getline(file, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // Convert to lowercase for case-insensitive matching
        std::transform(line.begin(), line.end(), line.begin(), ::tolower);
        
        malware_hashes_.insert(line);
        count++;
    }
    
    std::cout << "Loaded " << count << " malware hashes" << std::endl;
    return true;
}

bool HashScanner::IsKnownMalware(const std::string& hash) const {
    // Convert to lowercase for matching
    std::string hash_lower = hash;
    std::transform(hash_lower.begin(), hash_lower.end(), hash_lower.begin(), ::tolower);
    
    return malware_hashes_.find(hash_lower) != malware_hashes_.end();
}

void HashScanner::AddHash(const std::string& hash) {
    std::string hash_lower = hash;
    std::transform(hash_lower.begin(), hash_lower.end(), hash_lower.begin(), ::tolower);
    malware_hashes_.insert(hash_lower);
}

} // namespace scanner
} // namespace koraav
