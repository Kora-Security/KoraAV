#!/bin/bash
# KoraAV Linux Installer
# Downloads latest release from GitHub and installs KoraAV

set -e  # Exit on error

# Configuration
GITHUB_REPO="kora-security/koraav"
GITHUB_API="https://api.github.com/repos/$GITHUB_REPO"
KORAAV_VERSION="latest"  # or specific version like "0.1.0"
MIN_KERNEL_VERSION="5.15"
INSTALL_DIR="/opt/koraav"
CONFIG_DIR="/etc/koraav"
SERVICE_FILE="/etc/systemd/system/korad.service"
BIN_LINK="/usr/local/bin/koraav"
LOG_FILE="/tmp/koraav-install.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Functions
print_header() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                      KoraAV Installer                      ║"
    echo "║                 Modern Antivirus for Linux                 ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    log "SUCCESS: $1"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    log "ERROR: $1"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
    log "WARNING: $1"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
    log "INFO: $1"
}

print_step() {
    echo ""
    echo -e "${CYAN}▶ $1${NC}"
    log "STEP: $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This installer must be run as root"
        echo ""
        echo "Please run: sudo ./install.sh"
        echo ""
        exit 1
    fi
    print_success "Running as root"
}

check_internet() {
    print_info "Checking internet connection..."

    if ! ping -c 1 github.com >/dev/null 2>&1; then
        print_error "No internet connection"
        print_error "This installer requires internet to download KoraAV files from GitHub"
        exit 1
    fi

    print_success "Internet connection available"
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
        DISTRO_NAME=$NAME
    else
        print_error "Cannot detect distribution"
        exit 1
    fi

    print_info "Detected: $DISTRO_NAME ($DISTRO $DISTRO_VERSION)"

    # Check if supported
    case "$DISTRO" in
        debian|ubuntu|linuxmint|pop)
            DISTRO_FAMILY="debian"
            print_success "Debian-based distribution detected"
            ;;
        arch|manjaro|endeavouros)
            DISTRO_FAMILY="arch"
            print_success "Arch-based distribution detected"
            ;;
        *)
            print_error "Unsupported distribution: $DISTRO"
            echo ""
            echo "Supported distributions:"
            echo "  • Debian 13+"
            echo "  • Ubuntu 22.04+"
            echo "  • Arch Linux (current)"
            echo "  • Manjaro (current)"
            echo ""
            exit 1
            ;;
    esac
}

check_kernel_version() {
    CURRENT_KERNEL=$(uname -r | cut -d'-' -f1)

    print_info "Kernel version: $CURRENT_KERNEL (minimum: $MIN_KERNEL_VERSION)"

    if [ "$(printf '%s\n' "$MIN_KERNEL_VERSION" "$CURRENT_KERNEL" | sort -V | head -n1)" != "$MIN_KERNEL_VERSION" ]; then
        print_error "Kernel version $CURRENT_KERNEL is too old"
        print_error "KoraAV requires kernel $MIN_KERNEL_VERSION or newer for eBPF support"
        echo ""
        exit 1
    fi

    print_success "Kernel version check passed"
}

check_btf_support() {
    print_info "Checking BTF (BPF Type Format) support..."

    if [ -f /sys/kernel/btf/vmlinux ]; then
        print_success "BTF is supported"
    else
        print_warning "BTF not found at /sys/kernel/btf/vmlinux"
        print_warning "Some eBPF CO-RE features may not work and it is reccomended that you have them supported"
        echo ""
        echo -n "Continue anyway? [y/N] "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

check_dependencies_tools() {
    print_info "Checking for required tools..."

    MISSING_TOOLS=()

    for tool in curl tar cmake gcc g++ make git; do
        if ! command -v $tool >/dev/null 2>&1; then
            MISSING_TOOLS+=($tool)
        fi
    done

    if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
        print_warning "Missing tools: ${MISSING_TOOLS[*]}"
        print_info "These will be installed with dependencies"
    else
        print_success "All required tools available"
    fi
}

get_latest_release() {
    print_step "Finding Latest Release"
    print_info "Querying GitHub API..."

    if [ "$KORAAV_VERSION" = "latest" ]; then
        RELEASE_JSON=$(curl -s "$GITHUB_API/releases/latest")
        RELEASE_TAG=$(echo "$RELEASE_JSON" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        # Get specific version
        RELEASE_TAG="v$KORAAV_VERSION"
        RELEASE_JSON=$(curl -s "$GITHUB_API/releases/tags/$RELEASE_TAG")
    fi

    if [ -z "$RELEASE_TAG" ]; then
        print_error "Could not find release information"
        print_error "The gitHub API may be rate limited or the repo is currently not accessible"
        exit 1
    fi

    DOWNLOAD_URL="https://github.com/$GITHUB_REPO/archive/refs/tags/$RELEASE_TAG.tar.gz"
    print_success "Found release: $RELEASE_TAG"
    print_info "Download URL: $DOWNLOAD_URL"
}

download_source() {
    print_step "Downloading KoraAV Source Code"

    # Create temp directory
    TEMP_DIR=$(mktemp -d -t koraav-download-XXXXXX)
    TARBALL="$TEMP_DIR/koraav-$RELEASE_TAG.tar.gz"

    print_info "Downloading to: $TARBALL"
    if command -v wget >/dev/null 2>&1; then
        wget -q --show-progress -O "$TARBALL" "$DOWNLOAD_URL" || {
            print_error "Download failed"
            rm -rf "$TEMP_DIR"
            exit 1
        }
    else
        curl -L --progress-bar -o "$TARBALL" "$DOWNLOAD_URL" || {
            print_error "Download failed"
            rm -rf "$TEMP_DIR"
            exit 1
        }
    fi

    print_success "Download complete ($(du -h "$TARBALL" | cut -f1))"
    print_info "Extracting source code..."
    BUILD_DIR="$TEMP_DIR/koraav-build"
    mkdir -p "$BUILD_DIR"
    tar -xzf "$TARBALL" -C "$BUILD_DIR" --strip-components=1

    print_success "Source code extracted"

    # Make BUILD_DIR available globally
    export BUILD_DIR
}

install_dependencies_debian() {
    print_step "Installing Dependencies (Debian/Ubuntu)"
    print_info "Updating package lists..."
    apt-get update -qq

    print_info "Installing build tools..."
    apt-get install -y -qq \
        build-essential \
        cmake \
        git \
        pkg-config \
        wget \
        curl

    print_info "Installing libraries..."
    apt-get install -y -qq \
        libssl-dev \
        libcurl4-openssl-dev \
        libelf-dev \
        zlib1g-dev \
        libsqlite3-dev \
        libcap-dev \
        libcap2-bin \
        libnotify-bin \
        libsystemd-dev

    print_info "Installing eBPF tools..."
    # Try to install bpftool from linux-tools
    if apt-cache search linux-tools-$(uname -r) | grep -q linux-tools; then
        apt-get install -y -qq \
            libbpf-dev \
            linux-headers-$(uname -r) \
            linux-perf \
            linux-tools-$(uname -r) \
            clang \
            llvm
    else
        # Fallback for systems without kernel-specific linux-tools
        apt-get install -y -qq \
            libbpf-dev \
            linux-headers-$(uname -r) \
            linux-perf \
            clang \
            llvm

        # Try to install bpftool separately if available
        apt-get install -y -qq bpftool 2>/dev/null || print_warning "bpftool not available in repositories"
    fi

    print_info "Installing desktop notification support..."
    apt-get install -y -qq \
        libnotify-bin \
        notification-daemon 2>/dev/null || \
        apt-get install -y -qq libnotify-bin || \
        print_warning "Desktop notifications may not work currently.."


    print_info "Installing YARA (optional)..."
    if apt-cache show libyara-dev >/dev/null 2>&1; then
        apt-get install -y -qq libyara-dev yara
        print_success "YARA installed"
    else
        print_warning "YARA not available in repositories"
    fi

    print_info "Installing firewall tools..."
    apt-get install -y -qq nftables iptables

    print_info "Installing archive tools..."
    apt-get install -y -qq \
        unzip \
        tar \
        p7zip-full

    # unrar is in non-free
    apt-get install -y -qq unrar 2>/dev/null || print_warning "unrar not available (non-free)"

    print_success "All dependencies installed"
}


# Untested
install_dependencies_arch() {
    print_step "Installing Dependencies (Arch Linux)"

    print_info "Updating package database..."
    pacman -Sy --noconfirm

    print_info "Installing packages..."
    pacman -S --noconfirm --needed \
        base-devel \
        cmake \
        git \
        pkgconf \
        wget \
        curl \
        openssl \
        libcurl-compat \
        libelf \
        zlib \
        sqlite \
        libcap \
        libbpf \
        linux-headers \
        libnotify \
        clang \
        llvm \
        yara \
        nftables \
        iptables \
        unzip \
        tar \
        p7zip \
        unrar

    print_success "All dependencies installed"
}

install_dependencies() {
    case "$DISTRO_FAMILY" in
        debian)
            install_dependencies_debian
            ;;
        arch)
            install_dependencies_arch
            ;;
    esac
}

build_koraav() {
    print_step "Building KoraAV"

    cd "$BUILD_DIR/KoraAV"

    print_info "Configuring build system..."
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | tee -a "$LOG_FILE" | grep -v "^--" | grep -v "^$" || true

    print_info "Compiling (this may take a few minutes)..."
    echo -n "Progress: "
    make -j$(nproc) 2>&1 | tee -a "$LOG_FILE" | \
        grep -E "^\[" | \
        while read line; do
            echo -n "."
        done || true
    echo " done"

    if [ ! -f bin/koraav ]; then
        print_error "Build failed - koraav binary not found in bin"
        print_error "Check log at: $LOG_FILE"
        exit 1
    fi

    print_success "Build completed successfully!"
}

install_files() {
    print_step "Installing KoraAV Files"

    # Create dedicated user for the daemon (if doesn't exist)
    print_info "Creating koraav system user..."
    if ! id -u koraav >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin \
                --comment "KoraAV Security Daemon" koraav
        print_success "User 'koraav' created"
    else
        print_info "User 'koraav' already exists"
    fi

    print_info "Creating directory structure..."
    mkdir -p "$INSTALL_DIR"/{bin,lib/bpf,etc/rules,var/{db,logs,quarantine,run},share/doc}
    mkdir -p "$CONFIG_DIR"
    mkdir -p /var/log/koraav

    # Set ownership to koraav user for data directories
    print_info "Setting directory permissions..."
    chown -R koraav:koraav "$INSTALL_DIR/var"
    chown -R koraav:koraav /var/log/koraav
    chown koraav:koraav "$CONFIG_DIR"
    chmod 700 "$INSTALL_DIR/var/quarantine"
    chmod 755 "$INSTALL_DIR/var/run"
    chmod 755 /var/log/koraav

    print_info "Installing binaries..."
    cp "$BUILD_DIR/KoraAV/build/bin/"* "$INSTALL_DIR/bin/"
    chmod 755 "$INSTALL_DIR/bin/"*

    print_info "Installing BPF programs..."
    if ls "$BUILD_DIR/KoraAV/build/lib/bpf/"*.bpf.o >/dev/null 2>&1; then
        cp "$BUILD_DIR/KoraAV/build/lib/bpf/"*.bpf.o "$INSTALL_DIR/lib/bpf/" 2>/dev/null || true
    fi

    print_info "Installing YARA rules (runtime loaded, not compiled)..."
    if [ -d "$BUILD_DIR/KoraAV/data/signatures/yara-rules" ]; then
        mkdir -p "$INSTALL_DIR/share/signatures/yara-rules"
        mkdir -p "$INSTALL_DIR/share/signatures/yara-rules/custom"  # For user-added rules
        
        # Copy all .yar files (recursively, to support subdirectories)
        if ls "$BUILD_DIR/KoraAV/data/signatures/yara-rules/"*.yar >/dev/null 2>&1; then
            cp -r "$BUILD_DIR/KoraAV/data/signatures/yara-rules/"*.yar "$INSTALL_DIR/share/signatures/yara-rules/" 2>/dev/null || true
            print_success "YARA rules installed"
            
            # Count rules
            RULE_COUNT=$(find "$INSTALL_DIR/share/signatures/yara-rules/" -name "*.yar" -o -name "*.yara" | wc -l)
            print_info "Installed $RULE_COUNT YARA rule files"
        else
            print_warning "No YARA rules found in source directory"
        fi
        
        # Set permissions (readable by koraav user)
        chmod 755 "$INSTALL_DIR/share/signatures/yara-rules"
        chmod 755 "$INSTALL_DIR/share/signatures/yara-rules/custom"
        find "$INSTALL_DIR/share/signatures/yara-rules" -type f -name "*.yar*" -exec chmod 644 {} \;
        
        print_info "Users can add custom rules to: $INSTALL_DIR/share/signatures/yara-rules/custom/"
    else
        print_warning "YARA rules directory not found - YARA scanning will be limited"
    fi

    print_info "Setting permissions..."
    chown -R root:root "$INSTALL_DIR"
    chown -R koraav:koraav "$INSTALL_DIR/var"
    chown -R koraav:koraav /var/log/koraav
    chmod 700 "$INSTALL_DIR/var/quarantine"
    chmod 755 "$INSTALL_DIR/var/run"

    print_info "Creating symlinks..."
    ln -sf "$INSTALL_DIR/bin/koraav" "/usr/local/bin/koraav"
    ln -sf "$INSTALL_DIR/bin/korad" "/usr/local/bin/korad"

    print_success "Files installed to $INSTALL_DIR"
}


create_hash_database() {
    print_step "Creating Malware Hash Database"

    mkdir -p "$INSTALL_DIR/var/db"

    if [ -f "$INSTALL_DIR/bin/koraav" ]; then
        print_info "Generating database with a handful of known malware signatures..."
        "$INSTALL_DIR/bin/koraav" db create "$INSTALL_DIR/var/db/hashes.db" 2>&1 | \
            grep -v "^#" | tee -a "$LOG_FILE" || true
        print_success "Hash database created"
    else
        print_warning "koraav not found, skipping database creation - (please manually create it using koraav)"
    fi
}

create_config() {
    print_step "Creating KoraAV Configuration File"

    cat > "$CONFIG_DIR/koraav.conf" << 'EOF'
# KoraAV Config

[scanning]
enable_hash_scan = true
enable_yara_scan = true
enable_heuristic_scan = true
enable_static_analysis = true
enable_archive_scan = true
max_file_size = 104857600  # 100MB
max_scan_depth = 32
thread_count = 4

[realtime]
# Real-time protection
enable_file_monitor = true
enable_process_monitor = true
enable_network_monitor = true
enable_behavioral_analysis = true

# Behavioral detection
detect_infostealer = true
detect_ransomware = true
detect_clickfix = true

[paths]
exclude_paths = /proc,/sys,/dev,/tmp/.X11-unix
sensitive_paths = /home/*/.ssh,/home/*/.gnupg,/home/*/.mozilla,/home/*/.config/google-chrome,/home/*/Documents,/home/*/Downloads,/root/.ssh,/root/.gnupg

[thresholds]
alert_threshold = 61
block_threshold = 81
lockdown_threshold = 96

[response]
auto_kill = true
auto_block_network = true
auto_lockdown = false  # Require manual confirmation if false

[logging]
log_level = INFO
log_path = /opt/koraav/var/logs
max_log_size = 104857600
max_log_files = 10

[database]
hash_db_path = /opt/koraav/var/db/hashes.db
yara_rules_path = /opt/koraav/share/signatures/yara-rules
EOF

    chmod 644 "$CONFIG_DIR/koraav.conf"
    print_success "Configuration created"
}

create_systemd_service() {
    print_step "Creating Korad Systemd Service"

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=KoraAV Security Daemon
Documentation=https://github.com/$GITHUB_REPO
After=network.target local-fs.target
Before=multi-user.target
Wants=network.target
Requires=local-fs.target
Conflicts=sleep.target suspend.target hibernate.target hybrid-sleep.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=notify
NotifyAccess=main
ExecStart=$INSTALL_DIR/bin/korad
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStartSec=60s
TimeoutStopSec=30s
WatchdogSec=30s
KillMode=control-group
KillSignal=SIGTERM

# Working Directory
WorkingDirectory=$INSTALL_DIR

# User & Capabilities (Non-root with explicit privileges)
User=koraav
Group=koraav
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_KILL CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_IPC_LOCK
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_KILL CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_IPC_LOCK
NoNewPrivileges=true

# Filesystem Access (eBPF requires /sys access)
ProtectSystem=no
ProtectHome=no
ReadWritePaths=$INSTALL_DIR/var /var/log/koraav /sys/fs/bpf /sys/kernel/debug
PrivateTmp=no
UMask=0077

# Devices (Restrict to minimum needed)
PrivateDevices=no
DevicePolicy=closed
DeviceAllow=/dev/null rw
DeviceAllow=/dev/zero rw
DeviceAllow=/dev/urandom r
DeviceAllow=/dev/random r

# Kernel Access (Protect where possible)
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectControlGroups=yes
ProtectHostname=yes

# Process Visibility (Hide other processes)
ProtectProc=default
ProcSubset=all

# Network (C2 detection needs network monitoring)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
PrivateNetwork=no

# System Calls - Restrict to native architecture
SystemCallArchitectures=native

# Memory Protection
MemoryDenyWriteExecute=no
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes

# Namespaces - MUST BE DISABLED for eBPF
RestrictNamespaces=no
PrivateUsers=no

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=koraav
SyslogLevel=info
SyslogFacility=daemon
LogLevelMax=info
LogRateLimitIntervalSec=30s
LogRateLimitBurst=1000

# Resource Limits
LimitNOFILE=65536
LimitNPROC=1024
LimitMEMLOCK=infinity
LimitCORE=0
LimitAS=4G
LimitDATA=2G
LimitSTACK=8M
LimitRTPRIO=0
LimitNICE=0
TasksMax=1024
CPUQuota=80%
MemoryMax=2G
MemoryHigh=1.5G
OOMScoreAdjust=-900

# Environment
Environment="PATH=/usr/local/bin:/usr/bin:/bin"

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$SERVICE_FILE"
    systemctl daemon-reload

    print_success "Hardened systemd service created"
}

enable_service() {
    print_info "Enabling KoraAV service..."
    systemctl enable korad.service
    print_success "Service enabled (will start on boot)"
}

create_uninstaller() {
    print_step "Creating Uninstaller"

    cat > "$INSTALL_DIR/uninstall.sh" << 'UNINSTALL_SCRIPT'
#!/bin/bash
# KoraAV Uninstaller - Auto-generated

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Uninstaller must be run as root${NC}"
    exit 1
fi

echo -e "${YELLOW}KoraAV Uninstaller${NC}"
echo "This will completely remove KoraAV from your system"
echo ""
echo -n "Continue? Type 'yes' to confirm: "
read -r response

if [ "$response" != "yes" ]; then
    echo "Cancelled"
    exit 0
fi

echo "Uninstalling KoraAV..."
systemctl stop korad.service 2>/dev/null || true
systemctl disable korad.service 2>/dev/null || true
rm -f /etc/systemd/system/korad.service
systemctl daemon-reload
rm -f /usr/local/bin/koraav
rm -f /usr/local/bin/korad
rm -rf /etc/koraav
rm -rf /opt/koraav
rm -rf /var/log/koraav

# Remove koraav user
if id -u koraav >/dev/null 2>&1; then
    userdel koraav 2>/dev/null || true
    echo "✓ Removed koraav user"
fi

echo -e "${GREEN}✓ KoraAV has been removed${NC}"
UNINSTALL_SCRIPT

    chmod 755 "$INSTALL_DIR/uninstall.sh"
    print_success "Uninstaller created at $INSTALL_DIR/uninstall.sh"
}

cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        print_info "Cleaning up temp files..."
        rm -rf "$TEMP_DIR"
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                  Installation Successful!                  ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Installation Summary:${NC}"
    echo "  Version: $RELEASE_TAG"
    echo "  Location: $INSTALL_DIR"
    echo "  Config: $CONFIG_DIR/koraav.conf"
    echo "  YARA Rules: $INSTALL_DIR/share/signatures/yara-rules/"
    echo "  Commands:"
    echo "    • koraav --help"
    echo "    • (daemon) | korad --help"
    echo ""
    echo -e "${CYAN}Quick Start:${NC}"
    echo "  Run a scan:      sudo koraav scan quick"
    echo "  Start daemon:    sudo systemctl start korad"
    echo "  View logs:       sudo journalctl -u korad -f"
    echo "  Edit config:     sudo nano $CONFIG_DIR/koraav.conf"
    echo ""
    echo -e "${CYAN}YARA Rules (NEW Architecture):${NC}"
    echo "  • Rules loaded at RUNTIME (not compiled into binary)"
    echo "  • Add custom rules: $INSTALL_DIR/share/signatures/yara-rules/custom/"
    echo "  • Reload rules:     sudo koraav rules reload"
    echo "  • CLI and daemon use SAME rules (no duplication)"
    echo ""
    echo -e "${CYAN}Uninstall:${NC}"
    echo "  sudo $INSTALL_DIR/uninstall.sh"
    echo ""
    echo "Installation log: $LOG_FILE"
    echo ""
}

# Main installation
main() {
    print_header

    print_step "Pre-Installation Checks"
    check_root
    check_internet
    detect_distro
    check_kernel_version
    check_btf_support
    check_dependencies_tools

    get_latest_release
    download_source
    install_dependencies
    build_koraav
    install_files
    create_hash_database
    create_config
    create_systemd_service
    enable_service
    create_uninstaller

    cleanup

    print_summary
}

# Trap errors
trap 'print_error "Installation failed at line $LINENO. Check $LOG_FILE for details."; cleanup; exit 1' ERR

# Run
main "$@"
