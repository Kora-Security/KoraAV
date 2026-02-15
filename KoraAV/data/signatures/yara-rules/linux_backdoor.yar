/*
   YARA Rules for Linux Backdoors and Reverse Shells
   Based on real-world backdoors and C2 implants (2024-2026)
   
   Families covered:
   - China Chopper web shells
   - Reverse shells (bash, python, perl, etc.)
   - Bind shells
   - Web shells (PHP, CGI, etc.)
   - SSH backdoors
*/

rule Linux_Backdoor_ChinaChopper
{
    meta:
        description = "Detects China Chopper web shell"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        reference = "Popular APT web shell"
        
    strings:
        // PHP variant
        $php1 = "eval($_POST"
        $php2 = "assert($_POST"
        $php3 = "base64_decode($_POST"
        
        // Perl/CGI variant
        $perl1 = "eval($cgi->param"
        
        // Compact signatures
        $compact1 = /<\?=eval\(\$_POST/
        $compact2 = /<\?php @eval\(\$_POST/
        
        // Function calls
        $func1 = "system("
        $func2 = "exec("
        $func3 = "passthru("
        $func4 = "shell_exec("
        
    condition:
        (
            (any of ($php*) and any of ($func*)) or
            any of ($compact*) or
            $perl1
        )
}

rule Linux_ReverseShell_Bash_DevTcp
{
    meta:
        description = "Detects bash reverse shell using /dev/tcp"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        $dev_tcp = "/dev/tcp/"
        
        $redirect1 = "0>&1"
        $redirect2 = ">&"
        $redirect3 = "2>&1"
        
        $bash1 = "/bin/bash"
        $bash2 = "/bin/sh"
        $bash3 = "bash -i"
        
        $ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{2,5}/
        
    condition:
        $dev_tcp and
        (
            any of ($redirect*) or
            any of ($bash*) or
            $ip
        )
}

rule Linux_ReverseShell_Netcat
{
    meta:
        description = "Detects netcat reverse shell"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        $nc1 = "nc " nocase
        $nc2 = "ncat " nocase
        $nc3 = "netcat " nocase
        
        $exec1 = "-e /bin/bash"
        $exec2 = "-e /bin/sh"
        $exec3 = "-c /bin/bash"
        $exec4 = "-c /bin/sh"
        
        $pipe1 = "| /bin/bash"
        $pipe2 = "| /bin/sh"
        $pipe3 = "| bash"
        
        $listen = "-l" // Bind shell
        
    condition:
        any of ($nc*) and
        (any of ($exec*) or any of ($pipe*))
}

rule Linux_ReverseShell_Python
{
    meta:
        description = "Detects Python reverse shell"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        $python = "python" nocase
        
        // Socket creation
        $sock1 = "socket.socket"
        $sock2 = "socket.AF_INET"
        $sock3 = "socket.SOCK_STREAM"
        
        // Connection
        $connect1 = ".connect(("
        $connect2 = "socket.connect"
        
        // Shell execution
        $exec1 = "subprocess.call"
        $exec2 = "os.system"
        $exec3 = "pty.spawn"
        $exec4 = "/bin/bash"
        
        // Redirection
        $redir1 = "os.dup2"
        $redir2 = "subprocess.PIPE"
        
    condition:
        (
            (any of ($sock*) and any of ($connect*) and any of ($exec*)) or
            (2 of ($sock*) and $redir1)
        )
}

rule Linux_ReverseShell_Perl
{
    meta:
        description = "Detects Perl reverse shell"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        $perl = "perl" nocase
        
        // Socket
        $sock1 = "use Socket"
        $sock2 = "socket(S"
        $sock3 = "IO::Socket::INET"
        
        // Connection
        $conn1 = "connect(S"
        $conn2 = "->new("
        
        // Execution
        $exec1 = "open(STDIN"
        $exec2 = "open(STDOUT"
        $exec3 = "open(STDERR"
        $exec4 = "exec("
        
    condition:
        (
            (any of ($sock*) and any of ($conn*) and any of ($exec*))
        )
}

rule Linux_ReverseShell_Ruby
{
    meta:
        description = "Detects Ruby reverse shell"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        $ruby = "ruby" nocase
        
        $sock1 = "TCPSocket.new"
        $sock2 = "Socket.tcp"
        
        $exec1 = "exec("
        $exec2 = "system("
        
        $redir = "STDIN.reopen"
        
    condition:
        (any of ($sock*) and (any of ($exec*) or $redir))
}

rule Linux_ReverseShell_PHP
{
    meta:
        description = "Detects PHP reverse shell"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        $php = "<?php"
        
        $sock1 = "fsockopen"
        $sock2 = "socket_create"
        $sock3 = "stream_socket_client"
        
        $exec1 = "system("
        $exec2 = "exec("
        $exec3 = "passthru("
        $exec4 = "shell_exec("
        $exec5 = "proc_open"
        
        $desc = "descriptorspec"
        
    condition:
        $php and
        (
            (any of ($sock*) and any of ($exec*)) or
            $desc
        )
}

rule Linux_WebShell_Generic
{
    meta:
        description = "Generic web shell detection"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        // Command execution
        $cmd1 = "system($_"
        $cmd2 = "exec($_"
        $cmd3 = "passthru($_"
        $cmd4 = "shell_exec($_"
        $cmd5 = "popen("
        
        // Eval
        $eval1 = "eval($_"
        $eval2 = "assert($_"
        
        // File operations
        $file1 = "file_get_contents($_"
        $file2 = "file_put_contents($_"
        $file3 = "fwrite("
        
        // Obfuscation
        $obf1 = "base64_decode"
        $obf2 = "gzinflate"
        $obf3 = "str_rot13"
        
    condition:
        3 of them
}

rule Linux_Backdoor_SSH_Authorized_Keys
{
    meta:
        description = "Detects SSH backdoor via authorized_keys"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        
    strings:
        $path = ".ssh/authorized_keys"
        
        // Suspicious key additions
        $add1 = "echo " // Adding key
        $add2 = "cat >" // Overwriting
        $add3 = ">>"  // Appending
        
        // Public key format
        $key1 = "ssh-rsa"
        $key2 = "ssh-ed25519"
        $key3 = "ssh-dss"
        
    condition:
        $path and
        (any of ($add*) and any of ($key*))
}

rule Linux_Backdoor_Cron_Persistence
{
    meta:
        description = "Detects backdoor persistence via cron"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        // Cron paths
        $cron1 = "/etc/cron"
        $cron2 = "/var/spool/cron"
        $cron3 = "crontab"
        
        // Suspicious activities
        $sus1 = "curl " // Download
        $sus2 = "wget "
        $sus3 = "nc "  // Netcat
        $sus4 = "/dev/tcp"
        
        // Pipe to shell
        $pipe1 = "| bash"
        $pipe2 = "| sh"
        $pipe3 = "| python"
        
    condition:
        any of ($cron*) and
        (any of ($sus*) or any of ($pipe*))
}

rule Linux_Backdoor_SUID_Binary
{
    meta:
        description = "Detects suspicious SUID binary creation"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        
    strings:
        $suid1 = "chmod 4755"
        $suid2 = "chmod +s"
        $suid3 = "chmod u+s"
        
        $backdoor1 = "/tmp/."
        $backdoor2 = "cp /bin/bash"
        $backdoor3 = "setuid(0)"
        $backdoor4 = "setgid(0)"
        
    condition:
        any of ($suid*) and any of ($backdoor*)
}

rule Linux_Backdoor_Library_Injection
{
    meta:
        description = "Detects library injection backdoor"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "high"
        
    strings:
        $ld1 = "LD_PRELOAD"
        $ld2 = "LD_LIBRARY_PATH"
        $ld3 = "/etc/ld.so.preload"
        
        $lib1 = ".so"
        
        $backdoor1 = "/tmp/."
        $backdoor2 = "libprocesshider"
        $backdoor3 = "__constructor__"
        
    condition:
        any of ($ld*) and
        (any of ($backdoor*) or $lib1)
}

rule Linux_C2_Beacon
{
    meta:
        description = "Detects C2 beacon behavior"
        author = "KoraAV Default"
        date = "2026-02-11"
        severity = "critical"
        
    strings:
        // HTTP beaconing
        $http1 = "User-Agent:"
        $http2 = "POST /"
        $http3 = "GET /"
        
        // Periodic execution
        $sleep1 = "sleep("
        $sleep2 = "usleep("
        $sleep3 = "while true"
        $sleep4 = "for(;;)"
        
        // Network
        $net1 = "curl "
        $net2 = "wget "
        $net3 = "socket("
        
        // Encoding
        $enc1 = "base64"
        $enc2 = "AES"
        $enc3 = "RC4"
        
    condition:
        (
            (any of ($http*) and any of ($sleep*)) or
            (any of ($net*) and any of ($sleep*) and any of ($enc*))
        )
}
