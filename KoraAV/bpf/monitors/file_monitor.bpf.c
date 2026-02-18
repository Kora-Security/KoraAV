// file_monitor.bpf.c - PERMISSIVE VERSION FOR TESTING
// This version sends MANY more events to userspace for debugging

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Event structure matching daemon
struct file_event {
    u64 timestamp;
    u32 pid;
    u32 uid;
    u32 flags;
    u32 mode;
    char comm[16];
    char filename[256];
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

// Simple helper to check if path starts with prefix
static __always_inline bool starts_with(const char *str, const char *prefix, int prefix_len) {
    for (int i = 0; i < prefix_len && i < 256; i++) {
        if (str[i] != prefix[i]) return false;
        if (str[i] == '\0') return (prefix[i] == '\0');
    }
    return true;
}

// Check if this is a path we want to monitor
// PERMISSIVE: Only filter out obvious system noise
static __always_inline bool should_monitor_path(const char *path) {
    // Skip /proc, /sys, /dev (kernel/system virtual filesystems)
    if (starts_with(path, "/proc/", 6)) return false;
    if (starts_with(path, "/sys/", 5)) return false;
    if (starts_with(path, "/dev/", 5)) return false;
    
    // Skip temporary/cache that creates massive noise
    if (starts_with(path, "/tmp/.X", 7)) return false;
    if (starts_with(path, "/var/cache/", 11)) return false;
    if (starts_with(path, "/var/tmp/", 9)) return false;
    
    // Monitor everything else (including /home, /root, /etc)
    return true;
}

// Check if process should be ignored (reduce noise)
static __always_inline bool should_ignore_process(const char *comm) {
    // Ignore korad itself to prevent self-monitoring loops
    if (starts_with(comm, "korad", 5)) return true;
    
    // Ignore X11/desktop compositors (massive file access noise)
    if (starts_with(comm, "Xorg", 4)) return true;
    if (starts_with(comm, "gnome-shell", 11)) return true;
    if (starts_with(comm, "plasmashell", 11)) return true;
    if (starts_with(comm, "kwin", 4)) return true;
    
    // Monitor everything else
    return false;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter* ctx) {
    // Get PID and UID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();
    
    // Skip kernel threads (PID 0)
    if (pid == 0) return 0;
    
    // Get process name
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Filter out noisy processes
    if (should_ignore_process(comm)) return 0;
    
    // Get filename from syscall args
    char filename[256] = {};
    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&filename, sizeof(filename), filename_ptr);
    
    // Filter by path
    if (!should_monitor_path(filename)) return 0;
    
    // Get flags and mode
    u32 flags = (u32)ctx->args[2];
    u32 mode = (u32)ctx->args[3];
    
    // Reserve space in ring buffer
    struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e) return 0;
    
    // Fill event
    e->timestamp = bpf_ktime_get_ns();
    e->pid = pid;
    e->uid = uid;
    e->flags = flags;
    e->mode = mode;
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    __builtin_memcpy(e->filename, filename, sizeof(filename));
    
    // Submit to userspace
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}
