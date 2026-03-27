/*
   YARA Rules - Linux Backdoor/RAT Detection
   Compatible with: YARA v4.x
   Target: Linux ELF binaries, shell scripts, webshells
   Focus: Minimal false positives
   Last Updated: 2026-03-21
*/

import "elf"

rule Linux_Metasploit_Meterpreter {
    meta:
        description = "Detects Metasploit Meterpreter for Linux"
        severity = "critical"
        confidence = "high"
        category = "backdoor"
        family = "Meterpreter"
        platform = "linux"
        note = "Legitimate penetration testing tool"
        
    strings:
        $meterpreter1 = "meterpreter" nocase
        $metsrv = "metsrv" nocase
        $stdapi = "stdapi_" nocase
        $channel = "core_channel_" nocase
        
    condition:
        (elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN) and
        3 of them
}

rule Linux_Reverse_Shell_Generic {
    meta:
        description = "Detects generic reverse shell patterns"
        severity = "high"
        confidence = "medium"
        category = "backdoor"
        platform = "linux"
        
    strings:
        // Shell spawning
        $shell1 = "/bin/sh" fullword
        $shell2 = "/bin/bash" fullword
        $shell3 = "sh -i" nocase
        $shell4 = "bash -i" nocase
        
        // Network connection (for compiled binaries)
        $socket1 = "socket(AF_INET" nocase
        $connect = "connect(" fullword
        
        // I/O redirection
        $dup1 = "dup2(" fullword
        $dup2 = ">&" nocase and "/dev/tcp/" nocase
        
        // Common reverse shell patterns (scripts)
        $perl_rev = "perl -e" nocase and "socket" nocase and "connect" nocase
        $python_rev = "python -c" nocase and "socket" nocase and "connect" nocase
        $nc_rev = "nc" fullword and "-e" nocase and "/bin/" nocase
        $bash_tcp = "/dev/tcp/" nocase and "/bin/bash" nocase
        
    condition:
        (1 of ($shell*)) and
        (($socket1 and $connect and $dup1) or
         1 of ($perl_rev, $python_rev, $nc_rev, $bash_tcp))
}

rule Linux_SSH_Backdoor {
    meta:
        description = "Detects SSH backdoor/persistence"
        severity = "critical"
        confidence = "high"
        category = "backdoor"
        platform = "linux"
        
    strings:
        // Malicious SSH key injection
        $auth_keys = "/.ssh/authorized_keys" nocase
        $ssh_rsa = "ssh-rsa" nocase or "ssh-ed25519" nocase
        $append = ">>" nocase
        
        // SSH config tampering
        $sshd_config = "/etc/ssh/sshd_config" nocase
        $permit_root = "PermitRootLogin yes" nocase
        $no_password = "PasswordAuthentication no" nocase
        
        // SSH service restart
        $restart1 = "systemctl restart sshd" nocase
        $restart2 = "service sshd restart" nocase
        
    condition:
        ($auth_keys and $ssh_rsa and $append) or
        ($sshd_config and 1 of ($permit_root, $no_password) and 1 of ($restart*))
}

rule Linux_Rootkit_Behavior {
    meta:
        description = "Detects rootkit-like behavior"
        severity = "critical"
        confidence = "high"
        category = "backdoor"
        platform = "linux"
        
    strings:
        // LD_PRELOAD hooking
        $ld_preload = "LD_PRELOAD" nocase
        $so_file = ".so" nocase
        
        // Kernel module
        $insmod = "insmod" fullword
        $modprobe = "modprobe" fullword
        $ko_file = ".ko" nocase
        
        // Process hiding
        $proc_hide = "/proc/" nocase and "hide" nocase
        $ps_hide = "ps" fullword and "grep" fullword and "-v" nocase
        
        // File hiding
        $ls_hide = "ls" fullword and "grep" fullword and "-v" nocase
        
    condition:
        (elf.type == elf.ET_EXEC or elf.type == elf.ET_DYN) and
        (($ld_preload and $so_file) or
         (1 of ($insmod, $modprobe) and $ko_file) or
         (2 of ($proc_hide, $ps_hide, $ls_hide)))
}

rule Linux_PHP_Webshell {
    meta:
        description = "Detects PHP webshells"
        severity = "critical"
        confidence = "high"
        category = "backdoor"
        platform = "linux"
        
    strings:
        // PHP execution functions
        $exec1 = "exec(" nocase
        $exec2 = "shell_exec(" nocase
        $exec3 = "system(" nocase
        $exec4 = "passthru(" nocase
        $eval = "eval(" nocase
        
        // Common webshell obfuscation
        $base64 = "base64_decode(" nocase
        $gzinflate = "gzinflate(" nocase
        $assert = "assert(" nocase
        
        // POST data
        $post1 = "$_POST[" nocase
        $request = "$_REQUEST[" nocase
        
    condition:
        uint32(0) == 0x3C3F7068 and // <?ph (PHP file)
        (3 of ($exec*) or $eval) and
        (1 of ($base64, $gzinflate, $assert)) and
        (1 of ($post1, $request))
}

rule Linux_Backdoor_Persistence_Cron {
    meta:
        description = "Detects backdoor using cron for persistence"
        severity = "high"
        confidence = "high"
        category = "backdoor"
        platform = "linux"
        
    strings:
        // Reverse shell indicators
        $shell = "/bin/sh" or "/bin/bash"
        $nc = "nc" fullword
        $curl = "curl" fullword
        
        // Cron persistence
        $cron1 = "crontab -l" nocase
        $cron2 = "echo" nocase and "crontab" nocase
        $cron3 = "@reboot" nocase
        $cron4 = "* * * * *" // Every minute
        
    condition:
        (1 of ($shell, $nc, $curl)) and
        (2 of ($cron*))
}

rule Linux_Backdoor_Systemd_Persistence {
    meta:
        description = "Detects backdoor using systemd for persistence"
        severity = "high"
        confidence = "high"
        category = "backdoor"
        platform = "linux"
        
    strings:
        // Reverse shell indicators
        $shell = "/bin/sh" or "/bin/bash"
        $nc = "nc" fullword
        $python_socket = "python" nocase and "socket" nocase
        
        // Systemd persistence
        $systemd1 = "/etc/systemd/system/" nocase
        $systemd2 = "/.config/systemd/user/" nocase
        $service = "[Service]" nocase
        $exec_start = "ExecStart=" nocase
        
    condition:
        (1 of ($shell, $nc, $python_socket)) and
        (1 of ($systemd*)) and
        $service and $exec_start
}
