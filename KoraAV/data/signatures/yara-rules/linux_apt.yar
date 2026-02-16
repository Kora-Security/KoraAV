/*
   YARA Rules for APT Groups Targeting Linux
   Based on real-world APT campaigns (2024-2026)
   
   APT Groups covered:
   - APT28 (Fancy Bear) - Russia
   - APT29 (Cozy Bear) - Russia
   - Lazarus Group - North Korea
   - Volt Typhoon - China
   - Turla - Russia
   - Equation Group tools
*/

rule APT_Lazarus_MATA_Framework
{
    meta:
        description = "Detects Lazarus Group MATA malware framework"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "North Korean APT targeting cryptocurrency and defense"
        
    strings:
        // MATA indicators
        $mata1 = "MATA" nocase
        $mata2 = "MataNet"
        
        // C2 communication
        $c2_1 = "DispatchCommand"
        $c2_2 = "ExecuteCommand"
        $c2_3 = "SendResult"
        
        // Plugin system
        $plugin1 = "LoadPlugin"
        $plugin2 = "PluginInterface"
        
        // Crypto targeting
        $crypto1 = "wallet.dat"
        $crypto2 = "bitcoin"
        $crypto3 = "ethereum"
        
        // Network
        $net1 = "443"
        $net2 = "8080"
        $net3 = "SSL_connect"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            any of ($mata*) or
            (2 of ($c2_*) and any of ($plugin*)) or
            (any of ($c2_*) and 2 of ($crypto*))
        )
}

rule APT_VoltTyphoon_Infrastructure
{
    meta:
        description = "Detects Volt Typhoon APT infrastructure targeting"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "Chinese APT targeting critical infrastructure"
        
    strings:
        // Living off the land
        $lolbin1 = "ntpd"
        $lolbin2 = "systemd-resolve"
        $lolbin3 = "certutil"
        
        // Network scanning
        $scan1 = "nmap"
        $scan2 = "masscan"
        $scan3 = "/24"
        
        // Credential harvesting
        $cred1 = "/etc/shadow"
        $cred2 = "/etc/passwd"
        $cred3 = "mimipenguin"
        
        // Lateral movement
        $lateral1 = "ssh-keyscan"
        $lateral2 = "authorized_keys"
        $lateral3 = "id_rsa"
        
        // Persistence
        $persist1 = "/etc/rc.local"
        $persist2 = "systemd"
        $persist3 = "cron"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            (2 of ($lolbin*) and any of ($scan*)) or
            (any of ($cred*) and any of ($lateral*)) or
            (2 of ($lateral*) and any of ($persist*))
        )
}

rule APT_Turla_Penquin
{
    meta:
        description = "Detects Turla Penquin Linux backdoor"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "Russian APT Turla's Linux implant"
        
    strings:
        // Turla indicators
        $turla1 = "penquin" nocase
        $turla2 = "turla" nocase
        
        // Backdoor functions
        $bd1 = "execute_command"
        $bd2 = "upload_file"
        $bd3 = "download_file"
        $bd4 = "list_directory"
        
        // C2
        $c2_1 = "beacon_interval"
        $c2_2 = "sleep_time"
        $c2_3 = "jitter"
        
        // Encryption
        $enc1 = "AES-256"
        $enc2 = "encrypt_data"
        $enc3 = "decrypt_data"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            any of ($turla*) or
            (3 of ($bd*) and any of ($c2_*))
        )
}

rule APT_APT28_Zebrocy
{
    meta:
        description = "Detects APT28 Zebrocy malware"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "Russian APT28 (Fancy Bear)"
        
    strings:
        // Zebrocy indicators
        $zebro1 = "zebrocy" nocase
        $zebro2 = "sofacy" nocase
        
        // Information gathering
        $info1 = "systeminfo"
        $info2 = "uname -a"
        $info3 = "ifconfig"
        $info4 = "ps aux"
        
        // Screenshot
        $screen1 = "screenshot"
        $screen2 = "xwd"
        $screen3 = "scrot"
        
        // Exfiltration
        $exfil1 = "upload"
        $exfil2 = "POST"
        $exfil3 = "multipart/form-data"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            any of ($zebro*) or
            (3 of ($info*) and any of ($exfil*))
        )
}

rule APT_APT29_WellMess
{
    meta:
        description = "Detects APT29 WellMess malware"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "Russian APT29 (Cozy Bear) targeting COVID-19 research"
        
    strings:
        // WellMess indicators
        $wm1 = "WellMess" nocase
        $wm2 = "wellmess" nocase
        
        // Cookie-based C2
        $c2_1 = "Cookie:"
        $c2_2 = "Set-Cookie:"
        $c2_3 = "session_id"
        
        // Commands
        $cmd1 = "cmd_"
        $cmd2 = "execute"
        $cmd3 = "result"
        
        // RC4 encryption
        $enc1 = "rc4"
        $enc2 = "RC4"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            any of ($wm*) or
            (2 of ($c2_*) and any of ($enc*))
        )
}

rule APT_HiddenWasp
{
    meta:
        description = "Detects HiddenWasp Linux malware"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "Advanced Linux trojan with rootkit"
        
    strings:
        // HiddenWasp components
        $hw1 = "deployment.sh"
        $hw2 = "sftp"
        $hw3 = "autorun.sh"
        
        // Rootkit
        $rk1 = "ld.so.preload"
        $rk2 = "libselinux.so"
        
        // Trojan
        $trojan1 = "socket()"
        $trojan2 = "connect()"
        $trojan3 = "recv()"
        
        // Init script
        $init = "/etc/init.d"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            2 of ($hw*) or
            (any of ($rk*) and 2 of ($trojan*))
        )
}

rule APT_EquationGroup_BvpSpell
{
    meta:
        description = "Detects Equation Group BvpSpell implant"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "NSA Equation Group Linux implant"
        
    strings:
        // Module names
        $mod1 = "bvp47"
        $mod2 = "BvpSpell"
        
        // Encryption
        $enc1 = "TeaEncrypt"
        $enc2 = "RC6"
        
        // Network
        $net1 = "0x28561002" // Magic value
        $net2 = "trigger packet"
        
    condition:
        uint32(0) == 0x464c457f and
        (any of ($mod*) or (any of ($enc*) and any of ($net*)))
}

rule APT_Chinese_APT_Webshell
{
    meta:
        description = "Detects Chinese APT web shell patterns"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        // Chinese comments (common in Chinese APT webshells)
        
        // Common webshell functions
        $ws1 = "eval("
        $ws2 = "assert("
        $ws3 = "system("
        
        // Obfuscation
        $obf1 = "base64_decode"
        $obf2 = "gzinflate"
        $obf3 = "str_rot13"
        
        // File operations
        $file1 = "file_put_contents"
        $file2 = "fwrite"
        
    condition:
        (
            ($cn1 and 2 of ($ws*)) or
            (2 of ($obf*) and any of ($ws*))
        )
}

rule APT_Generic_RAT_Indicators
{
    meta:
        description = "Generic Remote Access Trojan indicators"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        // RAT functionality
        $rat1 = "keylogger"
        $rat2 = "screenshot"
        $rat3 = "webcam"
        $rat4 = "microphone"
        $rat5 = "download_execute"
        $rat6 = "update_binary"
        
        // C2 communication
        $c2_1 = "beacon"
        $c2_2 = "checkin"
        $c2_3 = "heartbeat"
        
        // Persistence
        $persist1 = "install_service"
        $persist2 = "add_startup"
        $persist3 = "cron"
        
    condition:
        uint32(0) == 0x464c457f and
        (
            3 of ($rat*) or
            (2 of ($rat*) and any of ($c2_*) and any of ($persist*))
        )
}

rule APT_Supply_Chain_Attack
{
    meta:
        description = "Detects supply chain attack patterns"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        
    strings:
        // Package managers
        $pkg1 = "pip install"
        $pkg2 = "npm install"
        $pkg3 = "gem install"
        $pkg4 = "apt-get install"
        
        // Backdoor in setup
        $setup1 = "setup.py"
        $setup2 = "post-install"
        $setup3 = "__init__.py"
        
        // Network activity in setup
        $net1 = "urllib.request"
        $net2 = "requests.get"
        $net3 = "wget"
        $net4 = "curl"
        
        // Suspicious execution
        $exec1 = "eval("
        $exec2 = "exec("
        $exec3 = "os.system("
        
    condition:
        (
            any of ($pkg*) and
            any of ($setup*) and
            any of ($net*) and
            any of ($exec*)
        )
}
