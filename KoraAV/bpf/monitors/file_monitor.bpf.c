// bpf/monitors/file_monitor.bpf.c
// Real-time file access monitoring
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16

struct file_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char comm[MAX_COMM_LEN];
    char filename[MAX_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->uid = bpf_get_current_uid_gid();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename_ptr);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
