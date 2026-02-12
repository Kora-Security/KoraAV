// bpf/monitors/file_monitor.bpf.c
// Real-time file access monitoring for info stealer detection
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16

// Event types
#define EVENT_FILE_OPEN 1
#define EVENT_FILE_READ 2
#define EVENT_FILE_WRITE 3

// File event sent to userspace
struct file_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 event_type;
    char comm[MAX_COMM_LEN];
    char filename[MAX_PATH_LEN];
};

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

// Per-process file access counter
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} access_counts SEC(".maps");

// Monitoring enabled flag
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

// Helper: Check if path is sensitive
static __always_inline int is_sensitive_path(const char *path) {
    // Check for common sensitive directories
    // Note: this should be configurable from userspace, but for now we'll just keep it here.
    
    // .ssh directory
    if (bpf_strstr(path, "/.ssh/") != NULL)
        return 1;
    
    // .gnupg directory
    if (bpf_strstr(path, "/.gnupg/") != NULL)
        return 1;
    
    // Browser profiles
    if (bpf_strstr(path, "/.mozilla/") != NULL)
        return 1;
    if (bpf_strstr(path, "/google-chrome/") != NULL)
        return 1;
    if (bpf_strstr(path, "/chromium/") != NULL)
        return 1;
    if (bpf_strstr(path, "/BraveSoftware/") != NULL)
        return 1;
    
    // Crypto wallets
    if (bpf_strstr(path, "/.electrum/") != NULL)
        return 1;
    if (bpf_strstr(path, "/.exodus/") != NULL)
        return 1;
    if (bpf_strstr(path, "/wallet") != NULL)
        return 1;
    
    // Documents and Downloads
    if (bpf_strstr(path, "/Documents/") != NULL)
        return 1;
    if (bpf_strstr(path, "/Downloads/") != NULL)
        return 1;
    
    // AWS credentials
    if (bpf_strstr(path, "/.aws/") != NULL)
        return 1;
    
    // Docker configs
    if (bpf_strstr(path, "/.docker/") != NULL)
        return 1;
    
    return 0;
}

// Tracepoint: sys_enter_openat
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    __u32 *enabled = bpf_map_lookup_elem(&config, &key);
    if (!enabled || *enabled == 0)
        return 0;
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Read filename from syscall arguments
    char filename[MAX_PATH_LEN];
    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&filename, sizeof(filename), filename_ptr);
    
    // Filter: only sensitive paths
    if (!is_sensitive_path(filename))
        return 0;
    
    // Increment access counter for this process
    __u64 *count = bpf_map_lookup_elem(&access_counts, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&access_counts, &pid, &initial, BPF_ANY);
    }
    
    // Send event to userspace
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = (__u32)pid_tgid;
    event->uid = bpf_get_current_uid_gid();
    event->event_type = EVENT_FILE_OPEN;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->filename, filename, sizeof(filename));
    
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
