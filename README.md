Copyright (C) 2026 therealOri

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, version 3. 
Do make sure to give credit where credit is due.
__ __

<br>

<div align="center">

![KoraAV Logo](https://github.com/user-attachments/assets/9a13b31e-7ca6-4d57-aa23-dbdb1242cb2a)


# KoraAV

**Modern, Real-Time Antivirus & Behavioral Protection for Linux**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)
[![Kernel: 5.15+](https://img.shields.io/badge/Kernel-5.15+-green.svg)](https://kernel.org)
[![eBPF](https://img.shields.io/badge/Powered%20by-eBPF-orange.svg)](https://ebpf.io)
[![C++: 17](https://img.shields.io/badge/C++-17-00599C.svg)](https://isocpp.org)

Peer Reviews: 0/0 | • | Audit Reviews: 0/0

⚠️ Please note that until this code/av is peer-reviewed and audited, I can't in good faith reccomend you use this product over what you'd currently use now until then. This product/project is a WIP and is not meant for serious use yet and I'll let you know when/if it gets to a point I like where I'd be okay with others using it. If you wish to ignore this note, let it be known that you are using this product with the understanding of the risks that come with using a WIP anti-virus and that you will be using a likely not very good product that could make your security worse. ⚠️

</div>

__ __

> Peer review reports and audit review reports are WIP currently.

> This README.md file is currently a WIP.

<br>

## ToDo
> Placeholders

- [ ] Make and add default yara files & work on yara system to handle crashing on error.
- [ ] Optimize and make faster when scanning.
- [ ] Make progress bar look fancier and actually good looking when scanning.
- [ ] Work on having less false positives and improve scanning detection.
- [ ] RootKit detection.
- [ ] An update system for when a new release is available.
__ __

<br>

## About

KoraAV is a modern antivirus solution designed specifically for Linux systems. Unlike traditional signature-based antivirus software, that uses **eBPF (Extended Berkeley Packet Filter)** for kernel-level monitoring and **behavioral analysis** to detect and stop threats in real-time. Even specific types of zero-day attacks that haven't been seen before.

### Why KoraAV?

- **Real-Time Protection** - eBPF-powered monitoring catches threats before they execute
- **Behavioral Analysis** - Detects ransomware, infostealers, and advanced threats by behavior patterns
- **Lightning Fast** - Minimal system overhead with kernel-level efficiency
- **Maximum Security** - Systemd hardening, capabilities-based permissions, no root privilege escalation
- **Pre-Encryption Detection** - Stops ransomware before your files are encrypted
- **Zero-Day Protection** - Catches unknown malware through heuristics and behavioral patterns
__ __

<br>


## Features

### On-Demand Scanning
- **Hash-based detection** - MD5/SHA256 signatures against known malware
- **YARA rules** - Custom pattern matching and malware family detection
- **Entropy analysis** - Identify packed/encrypted malware
- **Static analysis** - ELF binary inspection, script analysis
- **Archive scanning** - Deep inspection of ZIP, TAR, RAR, 7Z archives
- **Multi-threaded** - Parallel scanning for maximum speed


### Real-Time Protection (eBPF-Powered)
- **File monitoring** - Watch file opens, reads, writes, and modifications
- **Process monitoring** - Track process execution, forks, and termination
- **Network monitoring** - Detect suspicious connections and data exfiltration

### Behavioral detection engines:
- **Ransomware Detector** - Pre-encryption interception, mass file operation tracking
- **InfoStealer Detector** - Monitors what's accessing browser data, credentials, cryptocurrency wallets, etc.
- **ClickFix Detector** - Detects clipboard hijacking and social engineering attacks by looking at what you paste into terminals.
- **C2 Detector** - Looks for and monitors a basic implementation of C2 behaviors.


### Threat Response
- **Automatic threat neutralization** - Kill malicious processes instantly
- **Network isolation** - Block network access for suspicious processes - (Prevent data exfiltration)
- **System lockdown** - Read-only filesystem + network block for critical threats - (prevent data encryption if all else fails)
- **Detailed logging** - Complete audit trail of all threats and actions


### Security Hardening
- **Capabilities-based** - No setuid binaries, minimal privileges
- **Systemd isolation** - Strict filesystem, network, and syscall filtering
- **Protected configuration** - Config files should not be able to be edited by malware without sudo.
- **Memory protections** - W^X enforcement, ASLR, personality locking
__ __

<br>

## Requirements

### Minimum System Requirements
- **Kernel:** Linux 5.15+ (eBPF CO-RE support)
- **Architecture:** x86_64, ARM64
- **RAM:** 256 MB minimum (2 GB recommended for real-time protection)
- **Disk:** 100 MB for installation

### Required Features
- BTF (BPF Type Format) support - `/sys/kernel/btf/vmlinux` must exist
- Systemd for daemon management
- Root or `CAP_SYS_ADMIN` for eBPF loading

### Supported Distributions
| Distribution | Version | Status |
|-------------|---------|--------|
| Debian | 13+ (Trixie) | Fully Supported |
| Ubuntu | 22.04+ (Jammy) | UNTESTED |
| Arch Linux | Rolling | UNTESTED |
| Manjaro | Current | UNTESTED |
| Fedora | 38+ | Experimental & UNTESTED |
| Other | - | No Idea lol & UNTESTED |
__ __

<br>

## Installation

Download and run the standalone installer:

```bash
# Make executable
chmod +x install.sh

# Run installer (requires root)
sudo ./install.sh
```

The installer will:
1. ✅ Check system requirements (kernel version, BTF support)
2. ✅ Install all dependencies
3. ✅ Download and compile KoraAV from source found here/latest release
4. ✅ Set up systemd service with hardening
5. ✅ Configure YARA rules and hash database
6. ✅ Enable real-time protection
__ __

<br>

## Quick Start

```bash
# Quick scan (common locations)
sudo koraav scan quick

# Full system scan
sudo koraav scan full

# Scan specific directories
sudo koraav scan /home/user/Downloads
```

### Start Real-Time Protection
> if it isn't automatically started on install

```bash
sudo systemctl start korad

# Enable on boot/start up
sudo systemctl enable korad

# Check status
sudo systemctl status korad

# View live logs
sudo journalctl -u korad -f
```

### Manage Rules

```bash
# List active YARA rules
koraav rules list

# Add custom rule
sudo koraav rules add new-malware.yar

# Update rules from online sources
sudo koraav rules update
```

### Manage Hash Database

```bash
# Create database
sudo koraav db create /opt/koraav/var/db/hashes.db

# Add known malware hash
sudo koraav db add <sha256-hash> "Malware.Generic"

# Check if hash exists
koraav db check <sha256-hash>
```

### Emergency Unlock

If the system is locked down:

```bash
# Unlock filesystem (remount as read-write)
sudo koraav unlock --filesystem

# Restore network access
sudo koraav unlock --network

# Full system unlock that will do both at once
sudo koraav unlock --all
```
__ __

<br>

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         User Space                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  koraav (CLI)              korad (Daemon)                   │
│  ├── Scan Engine           ├── eBPF Manager                 │
│  ├── YARA Scanner          ├── Event Processors (3 threads) │
│  ├── Hash Checker          │   ├── File Events              │
│  ├── Entropy Analysis      │   ├── Process Events           │
│  ├── Static Analysis       │   └── Network Events           │
│  └── Archive Unpacker      ├── Detection Engines            │
│                            │   ├── Ransomware Detector      │
│                            │   ├── InfoStealer Detector     │
│                            │   └── ClickFix Detector        │
│                            └── Threat Response              │
│                                ├── Kill Process             │
│                                ├── Block Network            │
│                                └── System Lockdown          │
└─────────────────────────────────────────────────────────────┘
                               ↕ eBPF Maps
┌─────────────────────────────────────────────────────────────┐
│                        Kernel Space                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  eBPF Programs (attached to kernel hooks)                   │
│  ├── file_monitor.bpf.o    → Tracepoints: open, read, etc   │
│  ├── process_monitor.bpf.o → Tracepoints: exec, fork, exit  │
│  └── network_monitor.bpf.o → Tracepoints: connect, send     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```
__ __

<br>

## Configuration

KoraAV's config file is stored at `/etc/koraav/koraav.conf`:

```ini
[scanning]
enable_yara_scan = true
enable_heuristic_scan = true
max_file_size = 104857600  # 100MB
thread_count = 4

[realtime]
detect_ransomware = true
detect_infostealer = true
detect_clickfix = true

[thresholds]
alert_threshold = 61   # When to be alerted
block_threshold = 81   # Kill process + block network
lockdown_threshold = 96  # System lockdown

[response]
auto_kill = true
auto_block_network = true
auto_lockdown = false  # Require manual confirmation if false
```

After editing, reload the daemon:
```bash
sudo systemctl reload korad
```
__ __

<br>

## Contributing

I happily welcome contributions! Here's how you can help:

### Reporting Issues
- **Bug Reports** - Use GitHub Issues with the `bug` label
- **Feature Requests** - Use GitHub Issues with the `enhancement` label
- **Security Issues** - Email therealori@duck.com (Will maybe make a real kora-security domain at some point lol)

### Contributing Code
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-patch`)
3. Write tests for your changes
4. Commit with clear messages (`git commit -m 'I added a smiley face :p'`)
5. Push to your fork (`git push origin feature/your-patch`)
6. Open a Pull Request

### Code Style
- C++17 standard - (planning on moving towards C++23 eventually)
- Follow existing code formatting
- Add comments to help let me know what's happening.
- Write unit tests for testing out the new features
__ __

<br>

## Support

- **Documentation:** [WIP]()
- **Discord:** [Maybe/TBD]()
- **Email:** therealori@duck.com
__ __
