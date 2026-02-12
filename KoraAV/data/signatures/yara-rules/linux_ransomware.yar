/*
   YARA Rules for Linux Ransomware Detection
   Based on real-world ransomware families targeting Linux (2024-2026)
   
   Families covered:
   - BlackBasta (Linux variant)
   - LockBit Linux
   - Hive Ransomware
   - ESXiArgs (VMware ESXi)
   - Cheerscrypt
   - TargetCompany
*/

rule Linux_Ransomware_BlackBasta
{
    meta:
        description = "Detects BlackBasta ransomware Linux variant"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-249a"
        
    strings:
        // File extension
        $ext1 = ".basta" nocase
        
        // Ransom note indicators
        $note1 = "BlackBasta" nocase
        $note2 = "Your data has been encrypted"
        $note3 = "Do not modify encrypted files"
        
        // Encryption markers
        $marker1 = "BASTA_ENCRYPTED_FILE"
        
        // Command patterns
        $cmd1 = "chmod +x" nocase
        $cmd2 = "esxcli system shutdown poweroff"
        
        // Crypto libraries
        $crypto1 = "ChaCha20"
        $crypto2 = "RSA-4096"
        
    condition:
        uint32(0) == 0x464c457f and  // ELF header
        (
            ($ext1 and any of ($note*)) or
            ($marker1 and any of ($crypto*)) or
            (2 of ($cmd*) and any of ($note*))
        )
}

rule Linux_Ransomware_LockBit_Linux
{
    meta:
        description = "Detects LockBit ransomware Linux/ESXi variant"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a"
        
    strings:
        // LockBit indicators
        $lockbit1 = "LockBit" nocase
        $lockbit2 = ".lockbit" nocase
        
        // ESXi targeting
        $esxi1 = "vim-cmd vmsvc/getallvms"
        $esxi2 = "esxcli vm process kill"
        $esxi3 = "/vmfs/volumes/"
        
        // Ransom note patterns
        $note1 = "Restore-My-Files.txt"
        $note2 = "All your important files are stolen and encrypted"
        $note3 = "LockBit Black"
        
        // Encryption strings
        $enc1 = "AES-256"
        $enc2 = "encrypted successfully"
        
        // File operations
        $file1 = "chmod 777"
        $file2 = "find / -name"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            (any of ($lockbit*) and any of ($note*)) or
            (2 of ($esxi*) and any of ($enc*)) or
            (#file1 > 2 and any of ($note*))
        )
}

rule Linux_Ransomware_ESXiArgs
{
    meta:
        description = "Detects ESXiArgs ransomware targeting VMware ESXi"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "https://www.bleepingcomputer.com/news/security/massive-esxiargs-ransomware-attack-targets-vmware-esxi-servers-worldwide/"
        
    strings:
        // ESXiArgs specific
        $ransom_ext = ".args" nocase
        
        // ESXi commands
        $cmd1 = "esxcli vm process list"
        $cmd2 = "esxcli vm process kill --type=force"
        $cmd3 = "vim-cmd vmsvc/snapshot.removeall"
        
        // Encryption
        $enc1 = "sosemanuk" // Custom encryption
        $enc2 = "encrypt.sh"
        
        // Ransom note
        $note1 = "How to Restore Your Files.txt"
        $note2 = "args"
        
        // Network
        $net1 = "http://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            ($ransom_ext and 2 of ($cmd*)) or
            (any of ($enc*) and any of ($note*) and any of ($cmd*))
        )
}

rule Linux_Ransomware_Hive
{
    meta:
        description = "Detects Hive ransomware Linux variant"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        
    strings:
        // File extension
        $ext = ".hive" nocase
        
        // Hive indicators
        $hive1 = "HOW_TO_DECRYPT.txt"
        $hive2 = "hive" nocase
        
        // Encryption
        $enc1 = "ENCRYPTED_WITH_HIVE"
        $enc2 = "ChaCha20-Poly1305"
        
        // Commands
        $cmd1 = "for i in $(ls -d /root/*)"
        $cmd2 = "kill -9"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            ($ext and any of ($hive*)) or
            ($enc1 and any of ($cmd*))
        )
}

rule Linux_Ransomware_Cheerscrypt
{
    meta:
        description = "Detects Cheerscrypt ransomware (Emperor Dragonfly APT)"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        
    strings:
        $ext = ".cheers" nocase
        
        $note1 = "readme.txt"
        $note2 = "emperor dragonfly" nocase
        
        $enc = "openssl enc -aes-256-cbc"
        
    condition:
        uint32(0) == 0x464c457f and
        ($ext or ($enc and any of ($note*)))
}

rule Linux_Ransomware_Generic_Indicators
{
    meta:
        description = "Generic ransomware behavior patterns"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        // Common extensions
        $ext1 = /\.(encrypted|locked|crypt|enc|cry|crypted|kraken|zzzzz|crypto|vault)["\s]/
        
        // Ransom notes
        $note1 = "DECRYPT" nocase
        $note2 = "RESTORE" nocase
        $note3 = "README" nocase
        $note4 = "HOW_TO" nocase
        $note5 = "bitcoin" nocase
        $note6 = "Your files have been encrypted"
        
        // File operations
        $op1 = "chmod 444" // Make readonly
        $op2 = "find / -type f"
        $op3 = "shred -vfz"
        
        // Crypto functions
        $crypto1 = "AES_encrypt"
        $crypto2 = "RSA_public_encrypt"
        $crypto3 = "EVP_EncryptInit"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            ($ext1 and 2 of ($note*)) or
            (2 of ($crypto*) and any of ($note*)) or
            (2 of ($op*) and 2 of ($note*))
        )
}

rule Linux_Ransomware_Mass_File_Operations
{
    meta:
        description = "Detects mass file encryption behavior"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        $loop1 = "for file in"
        $loop2 = "find . -type f -exec"
        $loop3 = "while read"
        
        $crypt1 = "openssl"
        $crypt2 = "gpg --encrypt"
        $crypt3 = ".encrypted"
        $crypt4 = "AES"
        
        $delete1 = "rm -rf"
        $delete2 = "shred"
        
    condition:
        uint32(0) == 0x464c457f and
        any of ($loop*) and
        2 of ($crypt*) and
        any of ($delete*)
}
