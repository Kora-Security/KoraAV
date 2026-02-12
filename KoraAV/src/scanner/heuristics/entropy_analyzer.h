// src/scanner/heuristics/entropy_analyzer.h
#ifndef KORAAV_ENTROPY_ANALYZER_H
#define KORAAV_ENTROPY_ANALYZER_H

#include <vector>
#include <string>

namespace koraav {
namespace scanner {

class EntropyAnalyzer {
public:
    /**
     * Calculate Shannon entropy of data
     * Returns value 0-8, where >7.5 usually indicates encryption/packing
     */
    double Calculate(const std::vector<char>& data);
    
    /**
     * Find suspicious strings in data
     * Looks for URLs, IP addresses, crypto-related strings, etc.
     */
    std::vector<std::string> FindSuspiciousStrings(const std::vector<char>& data);
};

} // namespace scanner
} // namespace koraav

#endif
