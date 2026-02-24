// bpf/monitors/network_monitor.bpf.c
// Attempted enterprise-grade real-time network connection monitoring
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Endianness helpers (if not in vmlinux.h)
#ifndef __bpf_ntohs
#define __bpf_ntohs(x) __builtin_bswap16(x)
#endif

#ifndef __bpf_ntohl  
#define __bpf_ntohl(x) __builtin_bswap32(x)
#endif

// Socket family constants (if not in vmlinux.h)
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#define MAX_COMM_LEN 16
#define RATE_LIMIT_NS 200000000  // 200ms between events per PID

struct network_event {
    __u64 timestamp;
    __u32 tgid;
    __u32 uid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    char comm[MAX_COMM_LEN];
};

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} network_events SEC(".maps");

// Rate limiting map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10000);
} net_rate_limit_map SEC(".maps");

// Helper: Check if string starts with prefix
static __always_inline bool starts_with(const char *str, const char *prefix, int max_len) {
    for (int i = 0; i < max_len && prefix[i] != '\0'; i++) {
        if (str[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}

// Helper: Check if IP is localhost/private (less interesting)
static __always_inline bool is_localhost(__u32 ip) {
    // 127.0.0.0/8 (localhost)
    __u8 first_octet = ip & 0xFF;
    if (first_octet == 127) {
        return true;
    }
    
    // 0.0.0.0
    if (ip == 0) {
        return true;
    }
    
    return false;
}

// Helper: Check if IP is private network (less suspicious)
static __always_inline bool is_private_ip(__u32 ip) {
    __u8 first = ip & 0xFF;
    __u8 second = (ip >> 8) & 0xFF;
    
    // 10.0.0.0/8
    if (first == 10) {
        return true;
    }
    
    // 172.16.0.0/12
    if (first == 172 && second >= 16 && second <= 31) {
        return true;
    }
    
    // 192.168.0.0/16
    if (first == 192 && second == 168) {
        return true;
    }
    
    return false;
}

// Helper: Check if port is suspicious
static __always_inline bool is_suspicious_port(__u16 port) {
    // Common C2/backdoor ports
    if (port == 4444 ||   // Metasploit default
        port == 31337 ||  // Elite/leet
        port == 1337 ||
        port == 6667 ||   // IRC
        port == 6666 ||
        port == 8888 ||
        port == 9999 ||
        port == 12345 ||
        port == 54321) {
        return true;
    }
    
    return false;
}

// Helper: Check if process should be monitored
static __always_inline bool should_monitor_process(const char *comm) {
    // Always monitor suspicious binaries
    if (starts_with(comm, "nc", 2) ||
        starts_with(comm, "ncat", 4) ||
        starts_with(comm, "socat", 5) ||
        starts_with(comm, "telnet", 6) ||
        starts_with(comm, "wget", 4) ||
        starts_with(comm, "curl", 4) ||
        starts_with(comm, "python", 6) ||
        starts_with(comm, "perl", 4) ||
        starts_with(comm, "ruby", 4) ||
        starts_with(comm, "node", 4) ||
        starts_with(comm, "bash", 4) ||
        starts_with(comm, "sh", 2)) {
        return true;
    }
    
    return false;
}

// Helper: Should ignore process (browsers, system services)
static __always_inline bool should_ignore_process(const char *comm) {
    // Browsers (generate too many connections)
    if (starts_with(comm, "firefox", 7) ||
        starts_with(comm, "chrome", 6) ||
        starts_with(comm, "chromium", 8) ||
        starts_with(comm, "brave", 5)) {
        return true;
    }
    
    // System services
    if (starts_with(comm, "systemd", 7) ||
        starts_with(comm, "dbus-daemon", 11) ||
        starts_with(comm, "korad", 5) ||
        starts_with(comm, "koraav", 6) ||
        starts_with(comm, "rsyslogd", 8) ||
        starts_with(comm, "NetworkManager", 14) ||
        starts_with(comm, "dhclient", 8)) {
        return true;
    }
    
    return false;
}

// Helper: Rate limit check
static __always_inline bool check_rate_limit(__u32 tgid) {
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_time = bpf_map_lookup_elem(&net_rate_limit_map, &tgid);
    
    if (last_time) {
        if (now - *last_time < RATE_LIMIT_NS) {
            return false;
        }
    }
    
    bpf_map_update_elem(&net_rate_limit_map, &tgid, &now, BPF_ANY);
    return true;
}

SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    // __u64 pid_tgid = bpf_get_current_pid_tgid();
    // __u32 pid = pid_tgid >> 32;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // FILTER #1: Skip kernel threads
    if (tgid == 0) {
        return 0;
    }
    
    // FILTER #2: Get and check process name
    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    
    if (should_ignore_process(comm)) {
        return 0;
    }
    
    // FILTER #3: Get socket and read connection details
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) {
        return 0;
    }
    
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    
    BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    
    dport = __builtin_bswap16(dport);
    
    // FILTER #4: Skip localhost connections (less interesting)
    if (is_localhost(daddr)) {
        return 0;
    }
    
    // FILTER #5: Prioritize based on destination
    bool is_suspicious = false;
    
    // Always send if suspicious port
    if (is_suspicious_port(dport)) {
        is_suspicious = true;
    }
    
    // Always send if suspicious process
    if (should_monitor_process(comm)) {
        is_suspicious = true;
    }
    
    // Always send if connecting to external IP (not private)
    if (!is_private_ip(daddr)) {
        is_suspicious = true;
    }
    
    // FILTER #6: For non-suspicious connections, heavy sampling
    if (!is_suspicious) {
        // Only send 5% of boring connections
        if ((bpf_get_prandom_u32() % 20) != 0) {
            return 0;
        }
    }
    
    // FILTER #7: Rate limiting per PID
    if (!check_rate_limit(tgid)) {
        return 0;
    }
    
    // FILTER #8: Skip common legitimate ports for non-suspicious processes
    if (!is_suspicious) {
        if (dport == 80 ||    // HTTP
            dport == 443 ||   // HTTPS
            dport == 53 ||    // DNS
            dport == 22 ||    // SSH (legitimate)
            dport == 25 ||    // SMTP
            dport == 587 ||   // SMTP submission
            dport == 993 ||   // IMAPS
            dport == 995) {   // POP3S
            // Sample only 1% of these
            if ((bpf_get_prandom_u32() % 100) != 0) {
                return 0;
            }
        }
    }
    
    // ✅ All filters passed - send event
    struct network_event *event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->uid = uid;
    event->saddr = saddr;
    event->daddr = daddr;
    event->sport = sport;
    event->dport = dport;
    
    __builtin_memcpy(event->comm, comm, MAX_COMM_LEN);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
