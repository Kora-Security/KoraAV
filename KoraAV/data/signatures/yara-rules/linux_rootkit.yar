/*
 *   YARA Rules for Linux Rootkit Detection
 *   Based on real-world rootkits (2024-2026)
 */

rule Linux_Rootkit_eBPF_Based
{
    meta:
    description = "Detects eBPF-based rootkits"
    author = "KoraAV Default"
    date = "2026-02-11"
    severity = "critical"
    reference = "Modern rootkits using eBPF for stealth"

    strings:
    $ebpf1 = "bpf_probe_read"
    $ebpf2 = "bpf_override_return"
    $ebpf3 = "BPF_PROG_TYPE_KPROBE"
    $ebpf4 = "bpf_get_current_comm"

    $hide1 = "hide_pid"
    $hide2 = "hide_file"
    $hide3 = "hide_port"
    $hide4 = "hide_module"

    $hook1 = "sys_getdents"
    $hook2 = "sys_read"
    $hook3 = "tcp4_seq_show"
    $hook4 = "proc_readdir"

    $name1 = "bdoor" nocase
    $name2 = "pamspy" nocase
    $name3 = "boopkit" nocase

    condition:
    uint32(0) == 0x464c457f and
    (
        (2 of ($ebpf*) and any of ($hide*)) or
        (any of ($name*) and any of ($hook*)) or
        (3 of ($hook*) and any of ($hide*))
    )
}

rule Linux_Rootkit_Diamorphine
{
    meta:
    description = "Detects Diamorphine LKM rootkit"
    author = "KoraAV Default"
    date = "2026-02-11"
    severity = "critical"
    reference = "Popular open-source LKM rootkit"

    strings:
    $name = "diamorphine" nocase
    $sig1 = "kill -63"
    $sig2 = "SIGISR"
    $hide1 = "module_hide"
    $hide2 = "module_show"
    $hide3 = "is_invisible"
    $hook1 = "getdents"
    $hook2 = "getdents64"
    $hook3 = "sys_call_table"
    $str1 = "/proc/modules"
    $str2 = "/sys/module"

    condition:
    ($name) or ((any of ($sig*) and any of ($hide*)) or (2 of ($hook*) and any of ($str*)))
}

rule Linux_Rootkit_Reptile
{
    meta:
    description = "Detects Reptile LKM rootkit"
    author = "KoraAV Default"
    date = "2026-02-11"
    severity = "critical"
    reference = "Advanced LKM rootkit with reverse shell"

    strings:
    $name = "reptile" nocase
    $magic1 = "MAGIC_PACKET"
    $magic2 = "SHELL_PACKET"
    $shell1 = "reverse_shell"
    $shell2 = "connect_shell"
    $hide1 = "hide_proc"
    $hide2 = "hide_tcp"
    $hide3 = "hide_udp"
    $cfg = "/reptile"

    condition:
    $name or ((any of ($magic*) and any of ($shell*)) or (2 of ($hide*) and $cfg))
}

rule Linux_Rootkit_Suterusu
{
    meta:
    description = "Detects Suterusu LKM rootkit"
    author = "KoraAV Default"
    date = "2026-02-11"
    severity = "critical"

    strings:
    $name = "suterusu" nocase
    $hide1 = "suterusu_hide"
    $hide2 = "suterusu_unhide"
    $hook = "sys_call_table"

    condition:
    $name or (any of ($hide*) and $hook)
}

rule Linux_Rootkit_Kovid
{
    meta:
    description = "Detects Kovid LKM rootkit"
    author = "KoraAV Default"
    date = "2026-02-11"
    severity = "critical"

    strings:
    $name = "kovid" nocase
    $magic = { 4D 56 4F 4B } // "KOVM" magic value
    $hide1 = "kovid_hide"
    $hide2 = "tty_write"

    condition:
    $name or ($magic and any of ($hide*))
}

rule Linux_Rootkit_LKM_Generic
{
    meta:
    description = "Generic LKM rootkit indicators"
    author = "KoraAV Default"
    date = "2026-02-11"
    severity = "high"

    strings:
    $lkm1 = "init_module"
    $lkm2 = "cleanup_module"
    $lkm3 = "module_init"
    $lkm4 = "module_exit"
    $lkm5 = "MODULE_LICENSE"
    $syscall1 = "sys_call_table"
    $syscall2 = "ia32_sys_call_table"
    $syscall3 = "syscall_table"
    $hook1 = "orig_getdents"
    $hook2 = "orig_read"
    $hook3 = "orig_write"
    $hook4 = "orig_open"
    $hide1 = "hide_"
    $hide2 = "unhide_"
    $hide3 = "invisible"
    $hide4 = "magic_"

    condition:
    ((2 of ($lkm*) and any of ($syscall*) and any of ($hook*)) or
    (any of ($syscall*) and 2 of ($hide*)) or
    (2 of ($hook*) and 2 of ($hide*)))
}

rule Linux_Rootkit_LD_PRELOAD
{
    meta:
    description = "Detects LD_PRELOAD based user-land rootkits"
    author = "KoraAV Default"
    date = "2026-02-11"
    severity = "high"

    strings:
    $ld1 = "LD_PRELOAD"
    $ld2 = "/etc/ld.so.preload"
    $ld3 = "ld-linux"
    $hook1 = "__libc_readdir"
    $hook2 = "__libc_readdir64"
    $hook3 = "__libc_open"
    $hook4 = "fopen"
    $hook5 = "stat"
    $hook6 = "lstat"
    $lib1 = "dlsym"
    $lib2 = "RTLD_NEXT"
    $hide1 = "hide_process"
    $hide2 = "hide_file"
    $hide3 = "is_invisible"

    condition:
    ((any of ($ld*) and 2 of ($hook*)) or
    (2 of ($lib*) and any of ($hide*)) or
    (3 of ($hook*) and any of ($hide*)))
}

rule Linux_Rootkit_PAM_Backdoor
{
    meta:
    description = "Detects PAM backdoor modules"
    author = "KoraAV Default"
    date = "2026-02-11"
    severity = "critical"

    strings:
    $pam1 = "pam_sm_authenticate"
    $pam2 = "pam_sm_setcred"
    $pam3 = "pam_get_authtok"
    $backdoor1 = "magic_password" nocase
    $backdoor2 = "backdoor_pass" nocase
    $backdoor3 = "strcmp(password"
    $log1 = "password_log"
    $log2 = "/tmp/."
    $log3 = "captured_passwords"

    condition:
    2 of ($pam*) and (any of ($backdoor*) or any of ($log*))
}

rule Linux_Rootkit_Network_Hiding
{
    meta:
    description = "Detects network connection hiding"
    author = "KoraAV Default"
    date = "2026-02-11"
    severity = "high"

    strings:
    $hide1 = "hide_tcp"
    $hide2 = "hide_udp"
    $hide3 = "hide_port"
    $hide4 = "hide_socket"
    $proc1 = "/proc/net/tcp"
    $proc2 = "/proc/net/udp"
    $proc3 = "/proc/net/tcp6"
    $hook1 = "tcp4_seq_show"
    $hook2 = "tcp6_seq_show"
    $hook3 = "udp4_seq_show"

    condition:
    ((2 of ($hide*) and any of ($proc*)) or (any of ($hide*) and any of ($hook*)))
}

rule Linux_Rootkit_Privilege_Escalation
{
    meta:
    description = "Detects privilege escalation in rootkits"
    author = "KoraAV Default"
    date = "2026-02-11"
    severity = "critical"

    strings:
    $priv1 = "commit_creds"
    $priv2 = "prepare_kernel_cred"
    $priv3 = "uid = 0"
    $priv4 = "gid = 0"
    $cap1 = "CAP_SYS_ADMIN"
    $cap2 = "capable(CAP"
    $proc1 = "task_struct"
    $proc2 = "cred_struct"

    condition:
    ((2 of ($priv*) and any of ($proc*)) or (any of ($cap*) and any of ($proc*)))
}
