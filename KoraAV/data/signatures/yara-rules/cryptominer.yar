/*
   YARA Rules - Linux Cryptominer Detection
   Compatible with: YARA v4.x
   Target: Linux ELF binaries and shell scripts
   Focus: Detecting MALICIOUS mining (stealth/persistence)
   Note: Legitimate mining is NOT flagged
   Last Updated: 2026-03-21
*/

import "elf"

rule Linux_XMRig_Miner {
    meta:
        description = "Detects XMRig miner on Linux"
        severity = "medium"
        confidence = "high"
        category = "cryptominer"
        family = "XMRig"
        platform = "linux"
        note = "Could be legitimate if intentionally installed"
        
    strings:
        $xmrig1 = "xmrig" fullword nocase
        $xmrig2 = "XMRig" nocase
        $donate = "donate-level" nocase
        $randomx = "randomx" nocase
        $stratum = "stratum+tcp://" nocase
        
        // Linux process hiding (MALICIOUS indicator)
        $hide1 = "unlink" fullword
        $hide2 = "/proc/self/exe" nocase
        $nice = "nice" fullword and "-n" nocase
        
    condition:
        (elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN) and
        ((2 of ($xmrig*)) or
         ($xmrig1 and $stratum) or
         ($randomx and $stratum and 1 of ($hide*)))
}

rule Linux_Cryptominer_Stealth {
    meta:
        description = "Detects stealthy Linux cryptominer (MALICIOUS)"
        severity = "high"
        confidence = "high"
        category = "cryptominer"
        platform = "linux"
        
    strings:
        // Mining pool
        $pool1 = "stratum+tcp://" nocase
        $pool2 = "stratum+ssl://" nocase
        $pool3 = /[a-z0-9\-\.]+\.pool\.[a-z0-9]+:[0-9]{4,5}/ nocase
        
        // Monero mining
        $xmr = "monero" nocase or "XMR" fullword or "randomx" nocase
        
        // Linux stealth techniques (KEY MALICIOUS INDICATORS)
        $hide1 = "unlink(\"/proc/self/exe\")" nocase
        $hide2 = "rm -f" fullword and "$0" nocase  // Self-delete
        $hide3 = ">/dev/null 2>&1" nocase
        $cron_hide = "crontab" fullword and "@reboot" nocase
        
        // Process name spoofing
        $spoof1 = "prctl(PR_SET_NAME" nocase
        $spoof2 = "argv[0]" nocase and "=" nocase
        
    condition:
        (elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN) and
        (1 of ($pool*)) and
        $xmr and
        (2 of ($hide*, $cron_hide, $spoof*))
}

rule Linux_Cryptominer_Persistence {
    meta:
        description = "Detects cryptominer with persistence mechanism (MALICIOUS)"
        severity = "high"
        confidence = "high"
        category = "cryptominer"
        platform = "linux"
        
    strings:
        // Mining
        $pool = "stratum" nocase
        $mining = "hashrate" nocase or "difficulty" nocase
        
        // Linux persistence (MALICIOUS indicator)
        $cron1 = "crontab -l" nocase
        $cron2 = "crontab -e" nocase
        $systemd1 = "/etc/systemd/system/" nocase
        $systemd2 = ".service" nocase and "[Service]" nocase
        $autostart = "/.config/autostart/" nocase
        $rc_local = "/etc/rc.local" nocase
        
    condition:
        $pool and $mining and
        (2 of ($cron*, $systemd*, $autostart, $rc_local))
}

rule Linux_Cryptominer_Process_Injection {
    meta:
        description = "Detects cryptominer injecting into processes (MALICIOUS)"
        severity = "critical"
        confidence = "high"
        category = "cryptominer"
        platform = "linux"
        
    strings:
        // Mining
        $pool = "stratum+tcp://" nocase
        $xmr = "randomx" nocase or "cryptonight" nocase
        
        // Process injection (MALICIOUS)
        $ptrace = "ptrace" fullword
        $proc_mem = "/proc/" nocase and "/mem" nocase
        $ld_preload = "LD_PRELOAD" nocase
        
    condition:
        (elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN) and
        $pool and $xmr and
        (1 of ($ptrace, $proc_mem, $ld_preload))
}
