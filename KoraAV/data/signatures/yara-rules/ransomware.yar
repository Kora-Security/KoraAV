/*
   YARA Rules - Ransomware Detection
   Compatible with: YARA v4.x
   Author: KoraAV Project Default
   Description: Detects common ransomware families and behaviors
   Last Updated: 2025-02-23
*/

import "pe"
import "math"

rule Ransomware_Generic_Strings {
    meta:
        description = "Generic ransomware indicators"
        severity = "high"
        confidence = "medium"
        category = "ransomware"
        
    strings:
        // Ransom note indicators
        $ransom1 = "your files have been encrypted" nocase
        $ransom2 = "pay the ransom" nocase
        $ransom3 = "bitcoin address" nocase
        $ransom4 = "decryption key" nocase
        $ransom5 = "all your files" nocase
        $ransom6 = "READ_ME" nocase
        $ransom7 = "DECRYPT_INSTRUCTION" nocase
        $ransom8 = "HOW_TO_DECRYPT" nocase
        
        // Crypto APIs
        $crypto1 = "CryptAcquireContext" nocase
        $crypto2 = "CryptEncrypt" nocase
        $crypto3 = "CryptGenKey" nocase
        $crypto4 = "AES" nocase
        $crypto5 = "RSA" nocase
        
        // File extensions
        $ext1 = ".encrypted"
        $ext2 = ".locked"
        $ext3 = ".crypto"
        $ext4 = ".crypt"
        $ext5 = ".enc"
        
    condition:
        (3 of ($ransom*)) or
        (2 of ($crypto*) and 1 of ($ext*)) or
        (4 of ($crypto*))
}

rule WannaCry_Ransomware {
    meta:
        description = "Detects WannaCry ransomware"
        severity = "critical"
        confidence = "high"
        category = "ransomware"
        family = "WannaCry"
        reference = "CVE-2017-0144 (EternalBlue)"
        
    strings:
        $str1 = "tasksche.exe" nocase
        $str2 = "mssecsvc.exe" nocase
        $str3 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" nocase
        $str4 = "taskdl.exe" nocase
        $str5 = "WNcry@2ol7" nocase
        $str6 = "@WanaDecryptor@" nocase
        $str7 = "www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
        
        $wannacry1 = "!WannaDecryptor!" nocase
        $wannacry2 = "WANACRY!" nocase
        
    condition:
        3 of them
}

rule LockBit_Ransomware {
    meta:
        description = "Detects LockBit ransomware"
        severity = "critical"
        confidence = "high"
        category = "ransomware"
        family = "LockBit"
        
    strings:
        $str1 = "LockBit" nocase
        $str2 = "Restore-My-Files.txt" nocase
        $str3 = "lockbit" nocase
        $str4 = ".lockbit"
        $str5 = "Your data is stolen and encrypted" nocase
        
        // LockBit 3.0 (Black)
        $lb3_1 = "LockBit 3.0" nocase
        $lb3_2 = "LockBit Black" nocase
        
    condition:
        2 of them
}

rule Ryuk_Ransomware {
    meta:
        description = "Detects Ryuk ransomware"
        severity = "critical"
        confidence = "high"
        category = "ransomware"
        family = "Ryuk"
        
    strings:
        $str1 = "RyukReadMe.txt" nocase
        $str2 = "UNIQUE_ID_DO_NOT_REMOVE" nocase
        $str3 = "HERMES" nocase
        $str4 = "Ryuk" nocase
        $str5 = "No system is safe" nocase
        
        // Mutex
        $mutex = "Global\\{8761ABBD-7F85-42EE-B272-A76179687C63}"
        
    condition:
        2 of them
}

rule REvil_Sodinokibi_Ransomware {
    meta:
        description = "Detects REvil/Sodinokibi ransomware"
        severity = "critical"
        confidence = "high"
        category = "ransomware"
        family = "REvil"
        
    strings:
        $str1 = "REvil" nocase
        $str2 = "Sodinokibi" nocase
        $str3 = "readme.txt" nocase
        $str4 = "expand 32-byte k" // Salsa20
        $str5 = "{EXT}" 
        $str6 = "stat-extension"
        $str7 = "pk_key"
        
    condition:
        2 of them
}

rule Maze_Ransomware {
    meta:
        description = "Detects Maze ransomware"
        severity = "critical"
        confidence = "high"
        category = "ransomware"
        family = "Maze"
        
    strings:
        $str1 = "DECRYPT-FILES.txt" nocase
        $str2 = "DECRYPT-FILES.html" nocase
        $str3 = "maze" nocase
        $str4 = "Your company network has been penetrated" nocase
        $str5 = "All files have been encrypted" nocase
        
    condition:
        2 of them
}

rule Conti_Ransomware {
    meta:
        description = "Detects Conti ransomware"
        severity = "critical"
        confidence = "high"
        category = "ransomware"
        family = "Conti"
        
    strings:
        $str1 = "CONTI" nocase
        $str2 = "readme.txt" nocase
        $str3 = "All of your files are currently encrypted" nocase
        $str4 = ".CONTI"
        $str5 = "conti_log" nocase
        
    condition:
        2 of them
}

rule DarkSide_Ransomware {
    meta:
        description = "Detects DarkSide ransomware"
        severity = "critical"
        confidence = "high"
        category = "ransomware"
        family = "DarkSide"
        
    strings:
        $str1 = "README" nocase
        $str2 = "DarkSide" nocase
        $str3 = "Welcome to DarkSide" nocase
        $str4 = "Your files are encrypted" nocase
        $str5 = "darkside"
        
    condition:
        2 of them
}

rule BlackCat_ALPHV_Ransomware {
    meta:
        description = "Detects BlackCat/ALPHV ransomware"
        severity = "critical"
        confidence = "high"
        category = "ransomware"
        family = "BlackCat"
        
    strings:
        $str1 = "BlackCat" nocase
        $str2 = "ALPHV" nocase
        $str3 = "RECOVER-" nocase
        $str4 = "-FILES.txt" nocase
        $str5 = "Your data is stolen and encrypted" nocase
        
        // Rust indicators (BlackCat written in Rust)
        $rust1 = "rust_panic" nocase
        $rust2 = "rustc" nocase
        
    condition:
        2 of ($str*) or (1 of ($str*) and 1 of ($rust*))
}

rule Ransomware_High_Entropy_Executable {
    meta:
        description = "Detects potentially packed/encrypted ransomware"
        severity = "medium"
        confidence = "low"
        category = "ransomware"
        
    condition:
        uint16(0) == 0x5A4D and // MZ header
        math.entropy(0, filesize) > 7.2 and // High entropy (packed/encrypted)
        filesize < 5MB
}

rule Ransomware_File_Extension_Changer {
    meta:
        description = "Detects tools that mass-rename files"
        severity = "high"
        confidence = "medium"
        category = "ransomware"
        
    strings:
        $api1 = "MoveFileEx" nocase
        $api2 = "CopyFile" nocase
        $api3 = "FindFirstFile" nocase
        $api4 = "FindNextFile" nocase
        $api5 = "SetFileAttributes" nocase
        
        $ext1 = ".encrypted"
        $ext2 = ".locked"
        $ext3 = ".crypto"
        
    condition:
        4 of ($api*) and 1 of ($ext*)
}

rule Ransomware_VSS_Deletion {
    meta:
        description = "Detects shadow copy deletion (common ransomware behavior)"
        severity = "high"
        confidence = "medium"
        category = "ransomware"
        
    strings:
        $cmd1 = "vssadmin delete shadows" nocase
        $cmd2 = "wmic shadowcopy delete" nocase
        $cmd3 = "bcdedit /set {default} recoveryenabled no" nocase
        $cmd4 = "wbadmin delete catalog" nocase
        $cmd5 = "Delete Shadows" nocase
        
    condition:
        1 of them
}

