// network_monitor.bpf.c - PERMISSIVE VERSION FOR TESTING

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct network_event {
    u64 timestamp;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} network_events SEC(".maps");

static __always_inline bool starts_with(const char *str, const char *prefix, int prefix_len) {
    for (int i = 0; i < prefix_len && i < 16; i++) {
        if (str[i] != prefix[i]) return false;
        if (str[i] == '\0') return (prefix[i] == '\0');
    }
    return true;
}

static __always_inline bool should_ignore(const char *comm) {
    if (starts_with(comm, "korad", 5)) return true;
    return false;
}

SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();
    
    if (pid == 0) return 0;
    
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    
    if (should_ignore(comm)) return 0;
    
    // Get socket from first argument
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;
    
    // Read socket info
    u16 family;
    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;
    
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    
    if (family == AF_INET) {
        BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
        BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
        
        // dport is in network byte order, convert
        dport = __bpf_ntohs(dport);
    }
    
    struct network_event *e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (!e) return 0;
    
    e->timestamp = bpf_ktime_get_ns();
    e->pid = pid;
    e->uid = uid;
    e->saddr = saddr;
    e->daddr = daddr;
    e->sport = sport;
    e->dport = dport;
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
