/*
   YARA Rules - Linux InfoStealer Detection
   Compatible with: YARA v4.x
   Target: Linux ELF binaries and shell scripts
   Focus: Minimal false positives
   Last Updated: 2026-03-21
*/

import "elf"

rule Linux_Browser_Credential_Theft {
    meta:
        description = "Detects browser credential theft on Linux"
        severity = "high"
        confidence = "high"
        category = "infostealer"
        platform = "linux"
        
    strings:
        // Linux browser paths (full paths, not fragments)
        $chrome1 = "/.config/google-chrome/Default/Login Data" nocase
        $chrome2 = "/.config/google-chrome/Default/Cookies" nocase
        $firefox1 = "/.mozilla/firefox/" nocase and "logins.json" nocase
        $firefox2 = "/.mozilla/firefox/" nocase and "key4.db" nocase
        
        // Browser databases
        $sqlite_chrome = "Login Data" and "logins"
        $sqlite_firefox = "moz_logins"
        
        // Exfiltration (Linux network tools)
        $curl = "curl" fullword and "-d" nocase
        $wget = "wget" fullword and "--post" nocase
        $nc = "nc" fullword
        
    condition:
        (elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN or
         uint16(0) == 0x2123) and // #! shebang for scripts
        ((2 of ($chrome*) or 2 of ($firefox*)) and
         (1 of ($sqlite_*)) and
         (1 of ($curl, $wget, $nc)))
}

rule Linux_SSH_Key_Theft {
    meta:
        description = "Detects SSH key and credential theft"
        severity = "critical"
        confidence = "high"
        category = "infostealer"
        platform = "linux"
        
    strings:
        // SSH key locations (full paths)
        $ssh1 = "/.ssh/id_rsa" nocase
        $ssh2 = "/.ssh/id_ed25519" nocase
        $ssh3 = "/.ssh/authorized_keys" nocase
        $ssh4 = "/.ssh/known_hosts" nocase
        
        // AWS credentials
        $aws1 = "/.aws/credentials" nocase
        $aws2 = "AWS_ACCESS_KEY_ID" nocase
        $aws3 = "AWS_SECRET_ACCESS_KEY" nocase
        
        // Copy/exfiltration commands
        $copy = "cp" fullword or "cat" fullword
        $exfil = "curl" fullword or "wget" fullword or "scp" fullword
        
    condition:
        ((3 of ($ssh*)) or (2 of ($aws*))) and
        $copy and $exfil
}

rule Linux_Crypto_Wallet_Theft {
    meta:
        description = "Detects cryptocurrency wallet theft on Linux"
        severity = "critical"
        confidence = "high"
        category = "infostealer"
        platform = "linux"
        
    strings:
        // Linux wallet paths (full paths)
        $wallet1 = "/.bitcoin/wallet.dat" nocase
        $wallet2 = "/.ethereum/keystore/" nocase
        $wallet3 = "/.electrum/wallets/" nocase
        $wallet4 = "/.monero/" nocase
        
        // Wallet file operations
        $find_wallet = "find" nocase and "wallet" nocase
        $grep_wallet = "grep" nocase and "private" nocase
        
        // Archive and exfiltration
        $tar = "tar" fullword and "-czf" nocase
        $exfil = "curl" fullword or "nc" fullword
        
    condition:
        (3 of ($wallet*)) and
        (1 of ($find_wallet, $grep_wallet)) and
        ($tar or $exfil)
}

rule Linux_Environment_Variable_Theft {
    meta:
        description = "Detects environment variable credential theft"
        severity = "high"
        confidence = "high"
        category = "infostealer"
        platform = "linux"
        
    strings:
        // Sensitive environment variables
        $env1 = "AWS_ACCESS_KEY_ID" nocase
        $env2 = "AWS_SECRET_ACCESS_KEY" nocase
        $env3 = "GITHUB_TOKEN" nocase
        $env4 = "DOCKER_PASSWORD" nocase
        $env5 = "DATABASE_URL" nocase
        
        // Environment access
        $getenv = "getenv" fullword or "os.environ" nocase or "$" and "export" fullword
        
        // Exfiltration
        $exfil = "curl" fullword or "wget" fullword or "nc" fullword
        
    condition:
        (3 of ($env*)) and
        $getenv and
        $exfil
}
