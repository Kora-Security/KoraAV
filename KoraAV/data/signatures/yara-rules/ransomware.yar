/*
   YARA Rules - Linux Ransomware Detection
   Compatible with: YARA v4.x
   Target: Linux ELF binaries and shell scripts
   Focus: Minimal false positives
   Last Updated: 2026-03-21
*/

import "elf"
import "math"

rule Linux_Ransomware_Generic {
    meta:
        description = "Detects Linux ransomware behavior"
        severity = "critical"
        confidence = "high"
        category = "ransomware"
        platform = "linux"
        
    strings:
        // Ransom notes (platform-agnostic)
        $note1 = "Your files have been encrypted" nocase
        $note2 = "To decrypt your files" nocase
        $note3 = "Bitcoin address" nocase
        $note4 = "payment" nocase and "decrypt" nocase
        
        // File encryption extensions
        $ext1 = ".encrypted"
        $ext2 = ".locked"
        $ext3 = ".enc"
        
        // Linux-specific file operations
        $openssl = "openssl enc" nocase
        $gpg = "gpg --encrypt" nocase
        
        // Mass file operation
        $find_exec = "find" nocase and "-exec" nocase
        
    condition:
        (elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN) and
        ((3 of ($note*)) or
         (2 of ($note*) and 1 of ($ext*)) or
         (1 of ($note*) and 1 of ($openssl, $gpg) and $find_exec))
}

rule Linux_DarkRadiation_Ransomware {
    meta:
        description = "Detects DarkRadiation Linux ransomware"
        severity = "critical"
        confidence = "high"
        category = "ransomware"
        family = "DarkRadiation"
        platform = "linux"
        
    strings:
        $dark1 = "DarkRadiation" nocase
        $dark2 = "darkside" nocase
        $ransom_note = "README_FOR_DECRYPT" nocase
        $telegram = "t.me/" nocase
        
    condition:
        2 of them
}

rule Linux_RansomEXX_Defray {
    meta:
        description = "Detects RansomEXX/Defray for Linux"
        severity = "critical"
        confidence = "high"
        category = "ransomware"
        family = "RansomEXX"
        platform = "linux"
        
    strings:
        $ransom1 = "RansomEXX" nocase
        $ransom2 = "Defray" nocase
        $note = "ransom" nocase and ".txt" nocase
        $ext = ".exx" or ".defray"
        
    condition:
        2 of them
}

rule Linux_ESXi_Ransomware {
    meta:
        description = "Detects ESXi-targeting ransomware (common on Linux servers)"
        severity = "critical"
        confidence = "high"
        category = "ransomware"
        platform = "linux"
        
    strings:
        // ESXi specific paths
        $esxi1 = "/vmfs/volumes/" nocase
        $esxi2 = ".vmdk" nocase
        $esxi3 = "esxcli" fullword
        
        // Ransomware indicators
        $ransom = "encrypted" nocase or "locked" nocase
        $bitcoin = "bitcoin" nocase or "BTC" fullword
        
    condition:
        (elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN) and
        (2 of ($esxi*)) and
        ($ransom and $bitcoin)
}
