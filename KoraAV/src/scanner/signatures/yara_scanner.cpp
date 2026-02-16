// src/scanner/signatures/yara_scanner.cpp
#include "yara_scanner.h"
#include <yara.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>

namespace fs = std::filesystem;

namespace koraav {
    namespace scanner {

        /*
         * YARA Compiler Error Callback
         **/
        static void yara_compiler_callback(
            int error_level,
            const char* file_name,
            int line_number,
            #if YR_MAJOR_VERSION >= 4
            const YR_RULE* /* rule */,
            #endif
            const char* message,
            void* /* user_data */)
        {
            const char* level = (error_level == YARA_ERROR_LEVEL_ERROR) ? "Error" : "Warning";

            std::cerr << "[YARA " << level << "] "
            << (file_name ? file_name : "unknown")
            << ":" << line_number
            << ": "
            << (message ? message : "unknown error")
            << std::endl;
        }

        /*
         * YARA Scan Callback
         **/
        static int yara_scan_callback(
            YR_SCAN_CONTEXT* /* context */,
            int message,
            void* message_data,
            void* user_data)
        {
            if (message == CALLBACK_MSG_RULE_MATCHING) {
                YR_RULE* rule = static_cast<YR_RULE*>(message_data);
                auto* matches = static_cast<std::vector<std::string>*>(user_data);
                matches->push_back(rule->identifier);
            }

            return CALLBACK_CONTINUE;
        }

        /*
         * Constructor / Destructor
         **/
        YaraScanner::YaraScanner()
        : rules_(nullptr),
        yara_initialized_(false)
        {
            if (yr_initialize() == ERROR_SUCCESS) {
                yara_initialized_ = true;
            } else {
                std::cerr << "Failed to initialize YARA library" << std::endl;
            }
        }

        YaraScanner::~YaraScanner()
        {
            if (rules_) {
                yr_rules_destroy(rules_);
                rules_ = nullptr;
            }

            if (yara_initialized_) {
                yr_finalize();
            }
        }

        /*
         * Load Rules From Directory
         **/
        bool YaraScanner::LoadRules(const std::string& rules_dir)
        {
            if (!yara_initialized_) {
                std::cerr << "YARA not initialized" << std::endl;
                return false;
            }

            if (!fs::exists(rules_dir) || !fs::is_directory(rules_dir)) {
                std::cerr << "YARA rules directory not found: " << rules_dir << std::endl;
                return false;
            }

            if (rules_) {
                yr_rules_destroy(rules_);
                rules_ = nullptr;
            }

            YR_COMPILER* compiler = nullptr;

            if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
                std::cerr << "Failed to create YARA compiler" << std::endl;
                return false;
            }

            // Set error callback to capture compilation errors
            yr_compiler_set_callback(compiler, yara_compiler_callback, nullptr);

            int rule_count = 0;
            int failed_count = 0;
            std::vector<std::string> failed_files;

            for (const auto& entry : fs::recursive_directory_iterator(rules_dir)) {
                if (!entry.is_regular_file())
                    continue;

                std::string ext = entry.path().extension().string();
                if (ext != ".yar" && ext != ".yara")
                    continue;

                std::string path = entry.path().string();

                FILE* rule_file = fopen(path.c_str(), "r");
                if (!rule_file) {
                    std::cerr << "Could not open " << path << std::endl;
                    failed_count++;
                    failed_files.push_back(entry.path().filename().string());
                    continue;
                }

                // CRITICAL FIX: Check for errors instead of asserting!
                int errors = yr_compiler_add_file(compiler, rule_file, nullptr, path.c_str());
                fclose(rule_file);

                if (errors > 0) {
                    // Compilation failed - skip this file and continue
                    std::cerr << "⚠️  Skipping file with " << errors << " error(s): "
                    << entry.path().filename().string() << std::endl;
                    failed_count++;
                    failed_files.push_back(entry.path().filename().string());
                    continue;  // DON'T CRASH - just skip bad file
                }

                rule_count++;
                std::cout << "  ✓ Loaded: " << entry.path().filename().string() << std::endl;
            }

            if (rule_count == 0) {
                std::cerr << "❌ No YARA rules successfully loaded from " << rules_dir << std::endl;
                std::cerr << "YARA scanning will be disabled." << std::endl;
                yr_compiler_destroy(compiler);
                return false;
            }

            // Get the compiled rules
            if (yr_compiler_get_rules(compiler, &rules_) != ERROR_SUCCESS) {
                std::cerr << "Failed to get compiled YARA rules" << std::endl;
                yr_compiler_destroy(compiler);
                return false;
            }

            yr_compiler_destroy(compiler);

            std::cout << "\nYARA Rules Summary:" << std::endl;
            std::cout << "  Successfully loaded: " << rule_count << " files" << std::endl;

            if (failed_count > 0) {
                std::cout << "  Failed to load: " << failed_count << " files" << std::endl;
                std::cout << "  Failed files:" << std::endl;
                for (const auto& file : failed_files) {
                    std::cout << "    • " << file << std::endl;
                }
            }

            std::cout << "✓ YARA scanner ready with " << rule_count << " rule file(s)\n" << std::endl;

            return true;
        }

        /*
         * Load Single Rule File
         **/
        bool YaraScanner::LoadRuleFile(const std::string& rule_path)
        {
            if (!yara_initialized_)
                return false;

            if (rules_) {
                yr_rules_destroy(rules_);
                rules_ = nullptr;
            }

            YR_COMPILER* compiler = nullptr;

            if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
                return false;

            yr_compiler_set_callback(compiler, yara_compiler_callback, nullptr);

            FILE* rule_file = fopen(rule_path.c_str(), "r");
            if (!rule_file) {
                std::cerr << "Failed to open " << rule_path << std::endl;
                yr_compiler_destroy(compiler);
                return false;
            }

            // CRITICAL FIX: Check for errors
            int errors = yr_compiler_add_file(compiler, rule_file, nullptr, rule_path.c_str());
            fclose(rule_file);

            if (errors > 0) {
                std::cerr << "Compilation failed: " << rule_path << " (" << errors << " errors)" << std::endl;
                yr_compiler_destroy(compiler);
                return false;
            }

            if (yr_compiler_get_rules(compiler, &rules_) != ERROR_SUCCESS) {
                yr_compiler_destroy(compiler);
                return false;
            }

            yr_compiler_destroy(compiler);
            return true;
        }

        /*
         * Scan Memory
         **/
        std::vector<std::string> YaraScanner::ScanData(const std::vector<char>& data)
        {
            std::vector<std::string> matches;

            if (!rules_ || data.empty())
                return matches;

            int result = yr_rules_scan_mem(
                rules_,
                reinterpret_cast<const uint8_t*>(data.data()),
                                           data.size(),
                                           0,
                                           yara_scan_callback,
                                           &matches,
                                           0
            );

            if (result != ERROR_SUCCESS) {
                std::cerr << "YARA scan error: " << result << std::endl;
            }

            return matches;
        }

        /*
         * Scan File
         **/
        std::vector<std::string> YaraScanner::ScanFile(const std::string& path)
        {
            std::vector<std::string> matches;

            if (!rules_)
                return matches;

            int result = yr_rules_scan_file(
                rules_,
                path.c_str(),
                                            0,
                                            yara_scan_callback,
                                            &matches,
                                            0
            );

            if (result != ERROR_SUCCESS) {
                std::cerr << "YARA scan error on " << path << ": " << result << std::endl;
            }

            return matches;
        }

    } // namespace scanner
} // namespace koraav
