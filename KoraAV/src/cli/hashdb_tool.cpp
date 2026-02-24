// src/cli/hashdb_tool.cpp
// Utility to manage the malware hash database

#include "../scanner/signatures/hash_db_manager.h"
#include <iostream>
#include <string>

using namespace koraav::scanner;

void print_usage(const char* prog) {
    std::cout << "KoraAV Hash Database Manager\n";
    std::cout << "Usage:\n";
    std::cout << "  " << prog << " create <db_path>              - Create new database\n";
    std::cout << "  " << prog << " add <db_path> <hash> [desc]   - Add hash to database\n";
    std::cout << "  " << prog << " import <db_path> <file>       - Import hashes from file\n";
    std::cout << "  " << prog << " stats <db_path>               - Show database statistics\n";
    std::cout << "  " << prog << " update <db_path> <feed_url>   - Update from threat feed\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << prog << " create /opt/koraav/data/signatures/hashes.db\n";
    std::cout << "  " << prog << " add /opt/koraav/data/signatures/hashes.db abc123... \"Malware X\"\n";
}

int main(int argc, char** argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    std::string command = argv[1];
    std::string db_path = argv[2];
    
    if (command == "create") {
        std::cout << "Creating hash database: " << db_path << std::endl;
        if (HashDatabaseManager::CreateDatabase(db_path)) {
            std::cout << "Database created successfully" << std::endl;
            return 0;
        } else {
            std::cerr << "Failed to create database" << std::endl;
            return 1;
        }
    }
    else if (command == "add") {
        if (argc < 4) {
            std::cerr << "Error: Missing hash argument" << std::endl;
            print_usage(argv[0]);
            return 1;
        }
        
        std::string hash = argv[3];
        std::string desc = argc > 4 ? argv[4] : "";
        
        if (HashDatabaseManager::AddHash(db_path, hash, desc)) {
            std::cout << "Hash added successfully" << std::endl;
            return 0;
        } else {
            std::cerr << "Failed to add hash" << std::endl;
            return 1;
        }
    }
    else if (command == "import") {
        if (argc < 4) {
            std::cerr << "Error: Missing import file argument" << std::endl;
            print_usage(argv[0]);
            return 1;
        }
        
        std::string import_file = argv[3];
        
        if (HashDatabaseManager::ImportHashes(db_path, import_file)) {
            std::cout << "Hashes imported successfully" << std::endl;
            return 0;
        } else {
            std::cerr << "Failed to import hashes" << std::endl;
            return 1;
        }
    }
    else if (command == "stats") {
        auto stats = HashDatabaseManager::GetStats(db_path);
        
        std::cout << "Database Statistics:\n";
        std::cout << "  Path: " << db_path << "\n";
        std::cout << "  Total Hashes: " << stats.hash_count << "\n";
        std::cout << "  Last Updated: " << stats.last_updated;
        
        return 0;
    }
    else if (command == "update") {
        if (argc < 4) {
            std::cerr << "Error: Missing feed URL argument" << std::endl;
            print_usage(argv[0]);
            return 1;
        }
        
        std::string feed_url = argv[3];
        
        std::cout << "Updating from feed: " << feed_url << std::endl;
        if (HashDatabaseManager::UpdateFromFeed(db_path, feed_url)) {
            std::cout << "Database updated successfully" << std::endl;
            return 0;
        } else {
            std::cerr << "Failed to update database" << std::endl;
            return 1;
        }
    }
    else {
        std::cerr << "Unknown command: " << command << std::endl;
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}
