#!/bin/bash
# KoraAV Standalone Installer
# Downloads latest release from GitHub and installs KoraAV

set -e  # Exit on error

# Configuration
GITHUB_REPO="kora-security/KoraAV"
GITHUB_API="https://api.github.com/repos/$GITHUB_REPO"
KORAAV_VERSION="latest"
MIN_KERNEL_VERSION="5.15"
INSTALL_DIR="/opt/koraav"
CONFIG_DIR="/etc/koraav"
SERVICE_FILE="/etc/systemd/system/koraav.service"
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
    echo "║                   KoraAV Installer                         ║"
    echo "║              Modern Antivirus for Linux                    ║"
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
        print_warning "Some eBPF CO-RE features may not work"
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
    
    print_info "Querying GitHub API for latest release..."
    
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
        print_error "GitHub API response may be rate limited or repo not accessible"
        exit 1
    fi
    
    # Get download URL for source tarball
    DOWNLOAD_URL="https://github.com/$GITHUB_REPO/archive/refs/tags/$RELEASE_TAG.tar.gz"
    
    print_success "Found release: $RELEASE_TAG"
    print_info "Download URL: $DOWNLOAD_URL"
}

download_source() {
    print_step "Downloading KoraAV Source Code"
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d -t koraav-download-XXXXXX)
    TARBALL="$TEMP_DIR/koraav-$RELEASE_TAG.tar.gz"
    
    print_info "Downloading to: $TARBALL"
    
    # Download with progress
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
    
    # Extract
    print_info "Extracting source code..."
    BUILD_DIR="$TEMP_DIR/koraav-build/"
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
        libcap2-bin
    
    print_info "Installing eBPF tools..."
    apt-get install -y -qq \
        libbpf-dev \
        linux-headers-$(uname -r) \
        linux-perf \
        bpftool \
        clang \
        llvm
    
    print_info "Installing YARA"
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
    
    cd "$BUILD_DIR/KoraAV/"
    
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
        print_error "Build failed - binary not found"
        print_error "Check log at: $LOG_FILE"
        exit 1
    fi
    
    print_success "Build completed successfully"
}

install_files() {
    print_step "Installing KoraAV Files"
    
    print_info "Creating directory structure..."
    mkdir -p "$INSTALL_DIR"/{bin,lib/bpf,etc/rules,var/{db,logs,quarantine,run},share/doc}
    mkdir -p "$CONFIG_DIR"
    
    print_info "Installing binaries..."
    cp "$BUILD_DIR/KoraAV/build/bin/"* "$INSTALL_DIR/bin/"
    chmod 755 "$INSTALL_DIR/bin/"*
    
    print_info "Installing BPF programs..."
    if ls "$BUILD_DIR/KoraAV/build/lib/bpf/"*.bpf.o >/dev/null 2>&1; then
        cp "$BUILD_DIR/KoraAV/build/lib/bpf/"*.bpf.o "$INSTALL_DIR/lib/bpf/" 2>/dev/null || true
    fi
    
    print_info "Installing YARA rules..."
    if [ -d "$BUILD_DIR/KoraAV/data/signatures/yara-rules" ]; then
        mkdir -p "$INSTALL_DIR/share/signatures/yara-rules"
        cp "$BUILD_DIR/KoraAV/data/signatures/yara-rules/"*.yar "$INSTALL_DIR/share/signatures/yara-rules/" 2>/dev/null || true
    fi
    
    print_info "Setting permissions..."
    chown -R root:root "$INSTALL_DIR"
    chmod 700 "$INSTALL_DIR/var/quarantine"
    chmod 755 "$INSTALL_DIR/var/run"
    
    print_info "Creating symlinks..."
    ln -sf "$INSTALL_DIR/bin/koraav" "/usr/local/bin/koraav"
    ln -sf "$INSTALL_DIR/bin/koraav-hashdb" "/usr/local/bin/koraav-hashdb"
    ln -sf "$INSTALL_DIR/bin/koraav-unlock" "/usr/local/bin/koraav-unlock"
    ln -sf "$INSTALL_DIR/bin/koraav-rules" "/usr/local/bin/koraav-rules"
    
    print_success "Files installed to $INSTALL_DIR"
}

set_capabilities() {
    print_step "Setting Linux Capabilities"
    
    print_info "Setting capabilities on koraav daemon..."
    
    # Set capabilities instead of setuid root
    setcap \
        cap_sys_admin,cap_net_admin,cap_kill,cap_dac_read_search,cap_sys_ptrace,cap_bpf,cap_perfmon=eip \
        "$INSTALL_DIR/bin/koraav-daemon" 2>&1 | tee -a "$LOG_FILE"
    
    if [ $? -eq 0 ]; then
        print_success "Capabilities set successfully"
    else
        print_warning "Failed to set capabilities on daemon"
        print_warning "Trying legacy capabilities (kernel < 5.8)..."
        
        # Fallback for older kernels without CAP_BPF/CAP_PERFMON
        setcap \
            cap_sys_admin,cap_net_admin,cap_kill,cap_dac_read_search,cap_sys_ptrace=eip \
            "$INSTALL_DIR/bin/koraav-daemon" 2>&1 | tee -a "$LOG_FILE"
        
        if [ $? -eq 0 ]; then
            print_success "Legacy capabilities set (CAP_BPF/CAP_PERFMON not available)"
        else
            print_error "Failed to set capabilities"
            print_error "Daemon will require root to run"
        fi
    fi
    
    # Set capabilities on unlock utility
    print_info "Setting capabilities on unlock utility..."
    setcap cap_sys_admin,cap_net_admin=eip "$INSTALL_DIR/bin/koraav-unlock" 2>&1 | tee -a "$LOG_FILE"
    
    # Verify capabilities
    print_info "Verifying capabilities..."
    getcap "$INSTALL_DIR/bin/koraav-daemon"
    getcap "$INSTALL_DIR/bin/koraav-unlock"
    
    print_success "Capabilities configured"
}

create_hash_database() {
    print_step "Creating Malware Hash Database"
    
    mkdir -p "$INSTALL_DIR/var/db"
    
    if [ -f "$INSTALL_DIR/bin/koraav-hashdb" ]; then
        print_info "Generating database with known malware signatures..."
        "$INSTALL_DIR/bin/koraav-hashdb" create "$INSTALL_DIR/var/db/hashes.db" 2>&1 | \
            grep -v "^#" | tee -a "$LOG_FILE"
        print_success "Hash database created"
    else
        print_warning "koraav-hashdb not found, skipping database creation"
    fi
}

create_config() {
    print_step "Creating Configuration"
    
    cat > "$CONFIG_DIR/koraav.conf" << 'EOF'
# KoraAV Config File

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
sensitive_paths = ~/.ssh,~/.gnupg,~/.mozilla,~/.config/google-chrome,~/Documents,~/Downloads

[thresholds]
alert_threshold = 61
block_threshold = 81
lockdown_threshold = 96

[response]
auto_kill = true
auto_block_network = true
auto_lockdown = false  # Require manual confirmation when false

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


# TODO: Harden and make even more secure.
create_systemd_service() {
    print_step "Creating KoraAV Systemd Service"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=KoraAV Service Daemon
Documentation=https://github.com/$GITHUB_REPO
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/bin/koraav-daemon
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=false
ReadWritePaths=$INSTALL_DIR/var

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=koraav

[Install]
WantedBy=multi-user.target
EOF
    
    chmod 644 "$SERVICE_FILE"
    systemctl daemon-reload
    
    print_success "Systemd service created"
}

enable_service() {
    print_info "Enabling KoraAV service..."
    systemctl enable koraav.service
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
    echo -e "${RED}Error: Must run as root${NC}"
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
systemctl stop koraav.service 2>/dev/null || true
systemctl disable koraav.service 2>/dev/null || true

rm -f /etc/systemd/system/koraav.service
systemctl daemon-reload
rm -f /usr/local/bin/koraav
rm -rf /etc/koraav
rm -rf /opt/koraav

echo -e "${GREEN}KoraAV has been removed${NC}"
UNINSTALL_SCRIPT
    
    chmod 755 "$INSTALL_DIR/uninstall.sh"
    print_success "Uninstaller created at $INSTALL_DIR/uninstall.sh"
}

cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        print_info "Cleaning up temporary files..."
        rm -rf "$TEMP_DIR"
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                  Installation Successfull!                 ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Installation Summary:${NC}"
    echo "  Version: $RELEASE_TAG"
    echo "  Location: $INSTALL_DIR"
    echo "  Config: $CONFIG_DIR/koraav.conf"
    echo "  Commands:"
    echo "    • koraav (main binary/scanner)"
    echo "    • koraav-hashdb (database manager)"
    echo "    • koraav-unlock (system unlock)"
    echo ""
    echo -e "${CYAN}Quick Start:${NC}"
    echo "  Run a scan:      sudo koraav quick"
    echo "  Start service:   sudo systemctl start koraav"
    echo "  View logs:       sudo journalctl -u koraav -f"
    echo "  Edit config:     sudo nano $CONFIG_DIR/koraav.conf"
    echo ""
    echo -e "${CYAN}Uninstall:${NC}"
    echo "  sudo $INSTALL_DIR/uninstall.sh"
    echo ""
    echo "Full log: $LOG_FILE"
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
    set_capabilities
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
