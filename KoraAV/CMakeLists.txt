cmake_minimum_required(VERSION 3.16)
project(KoraAV VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pthread")

# Build type
# if(NOT CMAKE_BUILD_TYPE)
#     set(CMAKE_BUILD_TYPE Release)
# endif()

set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# BPF output directory
set(BPF_OUTPUT_DIR ${CMAKE_BINARY_DIR}/lib/bpf)
file(MAKE_DIRECTORY ${BPF_OUTPUT_DIR})

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)


# Find systemd (for Type=notify support)
pkg_check_modules(SYSTEMD libsystemd)
if(SYSTEMD_FOUND)
    message(STATUS "libsystemd found")
else()
    message(FATAL_ERROR "libsystemd not found - install libsystemd-dev for notifications")
endif()



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

# Common library (capabilities, quarantine, notifications, YARA manager, etc.)
# NOTE: YaraManager is now in common library - it's a singleton shared by all scanners
add_library(koraav_common STATIC
    src/common/capabilities_manager.cpp
    src/common/quarantine_manager.cpp
    src/common/notification_manager.cpp
    src/common/yara_manager.cpp          # Centralized YARA rules manager
)

target_link_libraries(koraav_common
    ${CAP_LIBRARY}
)

# Link YARA to common library (since yara_manager lives here now)
if(YARA_FOUND)
    target_link_libraries(koraav_common ${YARA_LIBRARIES})
endif()

# Scanner library
# NOTE: yara_scanner.cpp is now just a wrapper around YaraManager
add_library(koraav_scanner STATIC
    # Main scanner files
    src/scanner/scanner_engine.cpp
    src/scanner/file_scanner.cpp
    src/scanner/archive_scanner.cpp

    # Signature scanners
    src/scanner/signatures/hash_scanner.cpp
    src/scanner/signatures/yara_scanner.cpp      # Wrapper for YaraManager
    src/scanner/signatures/hash_db_manager.cpp

    # Heuristics
    src/scanner/heuristics/entropy_analyzer.cpp

    # Static analysis
    src/scanner/static-analysis/elf_analyzer.cpp
    src/scanner/static-analysis/script_analyzer.cpp
)

target_link_libraries(koraav_scanner
    koraav_common  # Links YaraManager
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    pthread
)

# Note: YARA is already linked via koraav_common, no need to link again

# Real-time protection library
# NOTE: realtime_yara_scanner.cpp also uses YaraManager (no duplicate rules)
add_library(koraav_realtime STATIC
    # Behavioral analysis
    src/realtime-protection/behavioral-analysis/infostealer_detector.cpp
    src/realtime-protection/behavioral-analysis/ransomware_detector.cpp
    src/realtime-protection/behavioral-analysis/clickfix_detector.cpp
    src/realtime-protection/behavioral-analysis/c2_detector.cpp
    src/realtime-protection/behavioral-analysis/canary_file_system.cpp

    # YARA real-time scanning (uses YaraManager)
    src/realtime-protection/yara-realtime/realtime_yara_scanner.cpp

    # Response
    src/realtime-protection/response/lockdown_manager.cpp
    src/realtime-protection/response/firewall_manager.cpp

    # Daemon
    src/daemon/secure_ipc.cpp

    # File Restore Util
    src/realtime-protection/behavioral-analysis/snapshot_system.cpp
)

target_link_libraries(koraav_realtime
    koraav_common   # Provides YaraManager
    koraav_scanner  # For backwards compatibility
    ${CAP_LIBRARY}
    stdc++fs        # C++17 filesystem support (required for ransomware detector)
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
    bpf  # libbpf for eBPF functionality
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
    bpf  # libbpf for eBPF functionality
    ${SYSTEMD_LIBRARIES}
)

target_include_directories(korad PRIVATE ${SYSTEMD_INCLUDE_DIRS})

# eBPF programs compilation
add_custom_target(bpf_programs ALL
    COMMAND ${CMAKE_COMMAND} -E echo "Building eBPF programs..."
    COMMAND make -C ${CMAKE_SOURCE_DIR}/bpf OUTPUT=${BPF_OUTPUT_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/bpf
    COMMENT "Compiling eBPF monitoring programs"
    VERBATIM
)

# Make binaries depend on eBPF programs
add_dependencies(korad bpf_programs)

# Install targets
install(TARGETS koraav korad
    RUNTIME DESTINATION bin
)

# Install eBPF programs
install(DIRECTORY ${BPF_OUTPUT_DIR}/
    DESTINATION lib/bpf
    FILES_MATCHING PATTERN "*.bpf.o"
)

# Install YARA rules (loaded at runtime, NOT compiled into binary)
# Users can add custom .yar files to this directory and reload
install(DIRECTORY data/signatures/
    DESTINATION share/koraav/signatures
    FILES_MATCHING PATTERN "*.yar"
    PATTERN "*.yara"
)

# Print build configuration
message(STATUS "=== KoraAV Build Configuration ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "CURL: Found")
message(STATUS "libcap: Found")
message(STATUS "YARA: ${YARA_FOUND}")
if(YARA_FOUND)
    message(STATUS "YARA Version: ${YARA_VERSION}")
    message(STATUS "YARA Architecture: Centralized (YaraManager singleton)")
endif()
message(STATUS "==================================")
message(STATUS "Executables:")
message(STATUS "  - koraav (unified CLI: scan/db/rules/unlock)")
message(STATUS "  - korad (real-time protection daemon)")
message(STATUS "eBPF Programs:")
message(STATUS "  - file_monitor.bpf.o (file access monitoring)")
message(STATUS "  - process_monitor.bpf.o (process execution monitoring)")
message(STATUS "  - network_monitor.bpf.o (network connection monitoring)")
message(STATUS "YARA Rules:")
message(STATUS "  - Loaded at runtime from /opt/koraav/share/signatures/yara-rules/")
message(STATUS "  - Users can add custom .yar files and reload")
message(STATUS "  - CLI and daemon use SAME rules (YaraManager)")
message(STATUS "==================================")
