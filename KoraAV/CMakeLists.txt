cmake_minimum_required(VERSION 3.16)
project(KoraAV VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pthread")

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)

# Find libcap (Linux capabilities)
find_library(CAP_LIBRARY cap)
if(NOT CAP_LIBRARY)
    message(FATAL_ERROR "libcap not found - install libcap-dev (Debian/Ubuntu) or libcap (Arch)")
endif()
message(STATUS "libcap: ${CAP_LIBRARY}")

# Find YARA (optional but recommended)
pkg_check_modules(YARA yara)

if(YARA_FOUND)
    add_definitions(-DHAVE_YARA)
    include_directories(${YARA_INCLUDE_DIRS})
    link_directories(${YARA_LIBRARY_DIRS})
    message(STATUS "YARA found: ${YARA_VERSION}")
else()
    message(WARNING "YARA not found - YARA scanning will be disabled")
endif()

# Common library (capabilities, etc.)
add_library(koraav_common STATIC
    src/common/capabilities_manager.cpp
)

target_link_libraries(koraav_common
    ${CAP_LIBRARY}
)

# Scanner library
add_library(koraav_scanner STATIC
    # Main scanner files
    src/scanner/scanner_engine.cpp
    src/scanner/file_scanner.cpp
    src/scanner/archive_scanner.cpp
    
    # Signature scanners
    src/scanner/signatures/hash_scanner.cpp
    src/scanner/signatures/yara_scanner.cpp
    src/scanner/signatures/hash_db_manager.cpp
    
    # Heuristics
    src/scanner/heuristics/entropy_analyzer.cpp
    
    # Static analysis
    src/scanner/static-analysis/elf_analyzer.cpp
    src/scanner/static-analysis/script_analyzer.cpp
)

target_link_libraries(koraav_scanner
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    pthread
)

if(YARA_FOUND)
    target_link_libraries(koraav_scanner ${YARA_LIBRARIES})
endif()

# Real-time protection library
add_library(koraav_realtime STATIC
    # Behavioral analysis
    src/realtime-protection/behavioral-analysis/infostealer_detector.cpp
    src/realtime-protection/behavioral-analysis/ransomware_detector.cpp
    src/realtime-protection/behavioral-analysis/clickfix_detector.cpp
    
    # Response
    src/realtime-protection/response/lockdown_manager.cpp
    src/realtime-protection/response/firewall_manager.cpp
    
    # Daemon
    src/daemon/secure_ipc.cpp
)

target_link_libraries(koraav_realtime
    koraav_common
    ${CAP_LIBRARY}
)

# Daemon library
add_library(koraav_daemon STATIC
    src/daemon/koraav_daemon.cpp
    src/daemon/secure_ipc.cpp
)

target_link_libraries(koraav_daemon
    koraav_realtime
    koraav_common
    ${CAP_LIBRARY}
)

# Unified CLI (replaces koraav, koraav-hashdb, koraav-unlock, koraav-rules)
add_executable(koraav
    src/cli/koraav_main.cpp
)

target_link_libraries(koraav
    koraav_scanner
    koraav_common
)

# Daemon executable
add_executable(korad
    src/cli/daemon_main.cpp
)

target_link_libraries(korad
    koraav_daemon
    koraav_realtime
    koraav_common
    ${CAP_LIBRARY}
)

# Install targets
install(TARGETS koraav korad
    RUNTIME DESTINATION bin
)

# Install data files
install(DIRECTORY data/signatures/
    DESTINATION share/koraav/signatures
    FILES_MATCHING PATTERN "*.yar"
)

# Print build configuration
message(STATUS "=== KoraAV Build Configuration ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "CURL: Found")
message(STATUS "libcap: Found")
message(STATUS "YARA: ${YARA_FOUND}")
message(STATUS "==================================")
message(STATUS "Executables:")
message(STATUS "  - koraav (unified CLI: scan/db/rules/unlock)")
message(STATUS "  - korad (real-time protection daemon)")
message(STATUS "==================================")

