// src/scanner/heuristics/entropy_analyzer.cpp
#include "entropy_analyzer.h"
#include <cmath>
#include <map>
#include <regex>

namespace koraav {
namespace scanner {

double EntropyAnalyzer::Calculate(const std::vector<char>& data) {
    if (data.empty()) {
        return 0.0;
    }
    
    // Count byte frequencies
    std::map<unsigned char, size_t> freq;
    for (char c : data) {
        freq[static_cast<unsigned char>(c)]++;
    }
    
    // Calculate Shannon entropy
    double entropy = 0.0;
    size_t size = data.size();
    
    for (const auto& [byte, count] : freq) {
        double probability = static_cast<double>(count) / size;
        entropy -= probability * std::log2(probability);
    }
    
    return entropy;
}

std::vector<std::string> EntropyAnalyzer::FindSuspiciousStrings(const std::vector<char>& data) {
    std::vector<std::string> suspicious;
    
    // Convert data to string for regex searching
    std::string str(data.begin(), data.end());
    
    // Look for URLs
    std::regex url_regex(R"((https?://[^\s]+))");
    std::smatch match;
    std::string::const_iterator search_start(str.cbegin());
    
    while (std::regex_search(search_start, str.cend(), match, url_regex)) {
        suspicious.push_back("URL: " + match[1].str());
        search_start = match.suffix().first;
        if (suspicious.size() > 10) break;  // Limit results
    }
    
    // Look for IP addresses
    std::regex ip_regex(R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)");
    search_start = str.cbegin();
    
    while (std::regex_search(search_start, str.cend(), match, ip_regex)) {
        suspicious.push_back("IP: " + match[0].str());
        search_start = match.suffix().first;
        if (suspicious.size() > 20) break;
    }
    
    // Look for crypto-related strings
    std::vector<std::string> crypto_keywords = {
        "bitcoin", "wallet", "private_key", "seed_phrase",
        "metamask", "coinbase", "exodus"
    };
    
    for (const auto& keyword : crypto_keywords) {
        if (str.find(keyword) != std::string::npos) {
            suspicious.push_back("Crypto keyword: " + keyword);
        }
    }
    
    return suspicious;
}

} // namespace scanner
} // namespace koraav
