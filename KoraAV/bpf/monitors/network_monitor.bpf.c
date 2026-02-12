// bpf/monitors/network_monitor.bpf.c
// Real-time network connection monitoring for C2 detection
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMM_LEN 16

// Network event
struct network_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u32 saddr;  // Source IP
    __u32 daddr;  // Destination IP
    __u16 sport;  // Source port
    __u16 dport;  // Destination port
    __u8  protocol;  // TCP, UDP, etc.
    char comm[MAX_COMM_LEN];
};

// Ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} network_events SEC(".maps");

// Per-process connection counter
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} connection_counts SEC(".maps");

// Config
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

// Hook: tcp_connect (TCP connection attempts)
SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect, struct sock *sk) {
    __u32 key = 0;
    __u32 *enabled = bpf_map_lookup_elem(&config, &key);
    if (!enabled || *enabled == 0)
        return 0;
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Reserve event
    struct network_event *event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->uid = bpf_get_current_uid_gid();
    event->protocol = 6;  // TCP
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Read socket information
    struct sock_common *sk_common = &sk->__sk_common;
    bpf_probe_read_kernel(&event->saddr, sizeof(event->saddr), &sk_common->skc_rcv_saddr);
    bpf_probe_read_kernel(&event->daddr, sizeof(event->daddr), &sk_common->skc_daddr);
    
    __u16 sport = 0, dport = 0;
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk_common->skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk_common->skc_dport);
    
    event->sport = sport;
    event->dport = __builtin_bswap16(dport);  // Convert from network byte order
    
    bpf_ringbuf_submit(event, 0);
    
    // Update connection counter
    __u64 *count = bpf_map_lookup_elem(&connection_counts, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&connection_counts, &pid, &initial, BPF_ANY);
    }
    
    return 0;
}

// Hook: udp_sendmsg (UDP traffic)
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk) {
    __u32 key = 0;
    __u32 *enabled = bpf_map_lookup_elem(&config, &key);
    if (!enabled || *enabled == 0)
        return 0;
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct network_event *event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->uid = bpf_get_current_uid_gid();
    event->protocol = 17;  // UDP
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    struct sock_common *sk_common = &sk->__sk_common;
    bpf_probe_read_kernel(&event->saddr, sizeof(event->saddr), &sk_common->skc_rcv_saddr);
    bpf_probe_read_kernel(&event->daddr, sizeof(event->daddr), &sk_common->skc_daddr);
    
    __u16 sport = 0, dport = 0;
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk_common->skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk_common->skc_dport);
    
    event->sport = sport;
    event->dport = __builtin_bswap16(dport);
    
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
