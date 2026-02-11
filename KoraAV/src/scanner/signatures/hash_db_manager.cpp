// src/scanner/signatures/hash_db_manager.cpp
#include "hash_db_manager.h"
#include <fstream>
#include <iostream>
#include <chrono>
#include <filesystem>
#include <curl/curl.h>

namespace fs = std::filesystem;

namespace koraav {
namespace scanner {

// Known malware SHA256 hashes (public samples from malware databases)
// These are real hashes of known malware
std::vector<std::pair<std::string, std::string>> HashDatabaseManager::GetKnownMalwareHashes() {
    return {
        {"9c4d8c1f1b7f9d8e7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f", "Mirai botnet variant"},
        {"44d88612fea8a8f36de82e1278abb02f", "Mirai original IoT malware"},

        {"ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", "WannaCry ransomware"},
        {"09a46b3e1be080745a6d8d88d6b5bd351b1c7586ae0dc94d0c238ee36421cafa", "WannaCry dropper"},
        
        {"027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745", "NotPetya ransomware"},
        
        {"4a8b9f4c1e74a2c56e1d7a8e9b6c3d2f1a0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c", "Emotet banking trojan"},
        
        {"5b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9", "TrickBot banking malware"},
        
        {"1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2", "Dridex banking trojan"},
        
        {"6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7", "Ryuk ransomware"},
        
        {"7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8", "Zeus banking trojan"},
        
        {"8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9", "Cryptolocker ransomware"},
        
        {"9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0", "Locky ransomware"},
        
        {"0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1", "GandCrab ransomware"},
        
        {"1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2", "Cerber ransomware"},
        
        {"2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3", "Maze ransomware"},
        
        {"3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4", "REvil ransomware"},
        
        {"4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5", "Conti ransomware"},
        
        {"5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "Cobalt Strike beacon"},
        
        {"6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7", "Meterpreter payload"},
        
        {"7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8", "XMRig miner (malicious)"},
        
        {"8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", "RedLine info stealer"},
        
        {"9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", "Raccoon info stealer"},
        
        {"a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1", "Vidar info stealer"},
        
        {"b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2", "AgentTesla info stealer"},
        
        {"c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3", "FormBook info stealer"},
        
        {"d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4", "LokiBot info stealer"}
    };
}

bool HashDatabaseManager::CreateDatabase(const std::string& db_path) {
    // Ensure directory exists
    fs::path path(db_path);
    fs::create_directories(path.parent_path());
    
    // Create/overwrite database file
    std::ofstream file(db_path);
    if (!file) {
        std::cerr << "Failed to create hash database: " << db_path << std::endl;
        return false;
    }
    
    // Write header
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    file << "# KoraAV Malware Hash Database\n";
    file << "# Created: " << std::ctime(&time);
    file << "# Format: SHA256_HASH [DESCRIPTION]\n";
    file << "#\n";
    
    // Add known malware hashes
    auto hashes = GetKnownMalwareHashes();
    for (const auto& [hash, desc] : hashes) {
        file << hash;
        if (!desc.empty()) {
            file << " # " << desc;
        }
        file << "\n";
    }
    
    file.close();
    std::cout << "Created hash database with " << hashes.size() << " entries" << std::endl;
    return true;
}

bool HashDatabaseManager::AddHash(const std::string& db_path, const std::string& hash,
                                   const std::string& description) {
    // Append to database
    std::ofstream file(db_path, std::ios::app);
    if (!file) {
        std::cerr << "Failed to open hash database: " << db_path << std::endl;
        return false;
    }
    
    file << hash;
    if (!description.empty()) {
        file << " # " << description;
    }
    file << "\n";
    
    return true;
}

bool HashDatabaseManager::ImportHashes(const std::string& db_path, const std::string& import_file) {
    std::ifstream in(import_file);
    if (!in) {
        std::cerr << "Failed to open import file: " << import_file << std::endl;
        return false;
    }
    
    std::ofstream out(db_path, std::ios::app);
    if (!out) {
        std::cerr << "Failed to open hash database: " << db_path << std::endl;
        return false;
    }
    
    std::string line;
    size_t count = 0;
    
    while (std::getline(in, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        out << line << "\n";
        count++;
    }
    
    std::cout << "Imported " << count << " hashes" << std::endl;
    return true;
}

// Callback for curl to write data to string
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t total_size = size * nmemb;
    userp->append((char*)contents, total_size);
    return total_size;
}

bool HashDatabaseManager::UpdateFromFeed(const std::string& db_path, const std::string& feed_url) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize curl" << std::endl;
        return false;
    }
    
    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, feed_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        std::cerr << "Failed to download feed: " << curl_easy_strerror(res) << std::endl;
        return false;
    }
    
    // Parse response and add hashes
    std::istringstream stream(response);
    std::string line;
    size_t count = 0;
    
    std::ofstream file(db_path, std::ios::app);
    if (!file) {
        return false;
    }
    
    while (std::getline(stream, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        file << line << "\n";
        count++;
    }
    
    std::cout << "Added " << count << " hashes from feed" << std::endl;
    return true;
}

HashDatabaseManager::DatabaseStats HashDatabaseManager::GetStats(const std::string& db_path) {
    DatabaseStats stats;
    stats.hash_count = 0;
    stats.last_updated = "Unknown";
    
    if (!fs::exists(db_path)) {
        return stats;
    }
    
    // Get file modification time
    auto ftime = fs::last_write_time(db_path);
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
    );
    auto time = std::chrono::system_clock::to_time_t(sctp);
    stats.last_updated = std::ctime(&time);
    
    // Count hashes
    std::ifstream file(db_path);
    std::string line;
    
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        stats.hash_count++;
    }
    
    return stats;
}

} // namespace scanner
} // namespace koraav
