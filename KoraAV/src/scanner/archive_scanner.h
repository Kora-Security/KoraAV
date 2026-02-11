// src/scanner/archive_scanner.h
#ifndef KORAAV_ARCHIVE_SCANNER_H
#define KORAAV_ARCHIVE_SCANNER_H

#include <koraav/types.h>
#include <string>
#include <vector>

namespace koraav {
namespace scanner {

// Forward declaration
class FileScanner;

/**
 * Scans archive files (zip, tar, tar.gz, tar.bz2, etc.)
 * Extracts to temp directory and scans contents
 */
class ArchiveScanner {
public:
    /**
     * Check if file is an archive we can scan
     */
    static bool IsArchive(const std::string& path);
    
    /**
     * Scan archive contents
     * @param path Path to archive file
     * @param scanner FileScanner to use for extracted files
     * @param results Accumulator for scan results
     * @return List of threats found in archive
     */
    static std::vector<FileScanResult> ScanArchive(
        const std::string& path,
        FileScanner& scanner,
        size_t max_depth = 3  // Prevent archive bombs
    );

private:
    // Extract archive to temporary directory
    static std::string ExtractArchive(const std::string& path);
    
    // Cleanup extracted files
    static void CleanupExtraction(const std::string& temp_dir);
    
    // Detect archive type from extension
    enum class ArchiveType {
        ZIP,
        TAR,
        TAR_GZ,
        TAR_BZ2,
        TAR_XZ,
        SEVEN_ZIP,
        RAR,
        UNKNOWN
    };
    
    static ArchiveType DetectArchiveType(const std::string& path);
};

} // namespace scanner
} // namespace koraav

#endif // KORAAV_ARCHIVE_SCANNER_H
