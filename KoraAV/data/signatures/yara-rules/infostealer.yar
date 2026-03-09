/*
   YARA Rules - InfoStealer Detection
   Compatible with: YARA v4.x
   Author: KoraAV Project Default
   Description: Detects credential stealers and data exfiltration malware
   Last Updated: 2025-02-23
*/

import "pe"

rule InfoStealer_Generic {
    meta:
        description = "Generic infostealer indicators"
        severity = "high"
        confidence = "medium"
        category = "infostealer"
        
    strings:
        // Browser data paths
        $path1 = "\\Google\\Chrome\\User Data" nocase
        $path2 = "\\Mozilla\\Firefox\\Profiles" nocase
        $path3 = "\\Opera\\Opera" nocase
        $path4 = "\\BraveSoftware\\Brave" nocase
        $path5 = "Login Data" nocase
        $path6 = "Cookies" nocase
        
        // Crypto wallet paths
        $crypto1 = "\\Ethereum\\keystore" nocase
        $crypto2 = "\\Bitcoin\\wallet.dat" nocase
        $crypto3 = "\\Electrum\\wallets" nocase
        $crypto4 = "\\Exodus\\exodus.wallet" nocase
        
        // Sensitive data keywords
        $keyword1 = "password" nocase
        $keyword2 = "credential" nocase
        $keyword3 = "cookie" nocase
        $keyword4 = "autofill" nocase
        $keyword5 = "wallet" nocase
        
    condition:
        (3 of ($path*)) or
        (2 of ($crypto*)) or
        (2 of ($path*) and 2 of ($keyword*))
}

rule RedLine_Stealer {
    meta:
        description = "Detects RedLine stealer"
        severity = "critical"
        confidence = "high"
        category = "infostealer"
        family = "RedLine"
        
    strings:
        $str1 = "RedLine" nocase
        $str2 = "\\Browsers\\" nocase
        $str3 = "\\Wallets\\" nocase
        $str4 = "\\Discord\\" nocase
        $str5 = "SystemInfo" nocase
        $str6 = "Hardware" nocase
        $str7 = "ScanData" nocase
        
    condition:
        3 of them
}

rule Raccoon_Stealer {
    meta:
        description = "Detects Raccoon stealer"
        severity = "critical"
        confidence = "high"
        category = "infostealer"
        family = "Raccoon"
        
    strings:
        $str1 = "RC4" nocase
        $str2 = "machineId" nocase
        $str3 = "file_" nocase
        $str4 = "screenshot_" nocase
        $str5 = "/gate" nocase
        $str6 = "Raccoon" nocase
        
        $api1 = "sqlite3_" nocase
        
    condition:
        3 of ($str*) or (2 of ($str*) and $api1)
}

rule Vidar_Stealer {
    meta:
        description = "Detects Vidar stealer"
        severity = "critical"
        confidence = "high"
        category = "infostealer"
        family = "Vidar"
        
    strings:
        $str1 = "Vidar" nocase
        $str2 = "profile" nocase
        $str3 = "autofill" nocase
        $str4 = "CC_" nocase
        $str5 = "History_" nocase
        $str6 = "*.txt" nocase
        
    condition:
        3 of them
}

rule AgentTesla_Stealer {
    meta:
        description = "Detects Agent Tesla keylogger/stealer"
        severity = "critical"
        confidence = "high"
        category = "infostealer"
        family = "AgentTesla"
        
    strings:
        $str1 = "Agent Tesla" nocase
        $str2 = "get_OSFullName" nocase
        $str3 = "get_Clipboard" nocase
        $str4 = "GetAsyncKeyState" nocase
        $str5 = "MailAddress" nocase
        
        // .NET indicators
        $net1 = "System.Windows.Forms" nocase
        $net2 = "System.Net.Mail" nocase
        
    condition:
        3 of ($str*) or (2 of ($str*) and 1 of ($net*))
}

rule LokiBot_Stealer {
    meta:
        description = "Detects Loki Bot stealer"
        severity = "critical"
        confidence = "high"
        category = "infostealer"
        family = "LokiBot"
        
    strings:
        $str1 = "sqlite3_" nocase
        $str2 = "Login Data" nocase
        $str3 = "Cookies" nocase
        $str4 = "Web Data" nocase
        $str5 = "logins.json" nocase
        $str6 = "key3.db" nocase
        
        $mutex = "3749282D-C0E6-4255-9105" nocase
        
    condition:
        4 of ($str*) or $mutex
}

rule Formbook_Stealer {
    meta:
        description = "Detects Formbook infostealer"
        severity = "critical"
        confidence = "high"
        category = "infostealer"
        family = "Formbook"
        
    strings:
        $str1 = "sqlite3_open" nocase
        $str2 = "GetClipboardData" nocase
        $str3 = "HttpSendRequest" nocase
        $str4 = "GetKeyState" nocase
        $str5 = "SetWindowsHook" nocase
        
    condition:
        4 of them
}

rule AZORult_Stealer {
    meta:
        description = "Detects AZORult stealer"
        severity = "critical"
        confidence = "high"
        category = "infostealer"
        family = "AZORult"
        
    strings:
        $str1 = "AZORult" nocase
        $str2 = "information.txt" nocase
        $str3 = "1.txt" nocase
        $str4 = "passwords.txt" nocase
        $str5 = "cookies.txt" nocase
        
    condition:
        2 of them
}

rule MetaStealer {
    meta:
        description = "Detects Meta Stealer"
        severity = "critical"
        confidence = "high"
        category = "infostealer"
        family = "MetaStealer"
        
    strings:
        $str1 = "Meta Stealer" nocase
        $str2 = "Passwords_" nocase
        $str3 = "Cookies_" nocase
        $str4 = "Wallets_" nocase
        $str5 = "Screenshot_" nocase
        
    condition:
        3 of them
}

rule Generic_Keylogger {
    meta:
        description = "Generic keylogger detection"
        severity = "high"
        confidence = "medium"
        category = "infostealer"
        
    strings:
        $api1 = "GetAsyncKeyState" nocase
        $api2 = "GetKeyState" nocase
        $api3 = "SetWindowsHookEx" nocase
        $api4 = "GetForegroundWindow" nocase
        $api5 = "GetWindowText" nocase
        
        $keyword1 = "keylog" nocase
        $keyword2 = "keystroke" nocase
        
    condition:
        (3 of ($api*)) or
        (2 of ($api*) and 1 of ($keyword*))
}

rule Browser_Data_Exfiltration {
    meta:
        description = "Detects browser data exfiltration attempts"
        severity = "high"
        confidence = "medium"
        category = "infostealer"
        
    strings:
        // SQLite operations (browser databases)
        $sqlite1 = "sqlite3_open" nocase
        $sqlite2 = "sqlite3_prepare" nocase
        $sqlite3 = "sqlite3_step" nocase
        
        // Browser database files
        $db1 = "Login Data"
        $db2 = "Cookies"
        $db3 = "Web Data"
        $db4 = "logins.json"
        
        // Network exfiltration
        $net1 = "InternetOpenUrl" nocase
        $net2 = "HttpSendRequest" nocase
        $net3 = "send" nocase
        
    condition:
        (2 of ($sqlite*) and 1 of ($db*)) or
        (1 of ($db*) and 1 of ($net*))
}

