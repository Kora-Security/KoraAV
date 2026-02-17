// bpf/monitors/file_monitor.bpf.c
// real-time file access monitoring
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16
#define RATE_LIMIT_NS 100000000  // 100ms between events per PID

struct file_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u32 flags;
    __u32 mode;
    char comm[MAX_COMM_LEN];
    char filename[MAX_PATH_LEN];
};

// Ring buffer for events (reduced size for efficiency)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

// Rate limiting map: PID -> last_event_timestamp
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    // PID
    __type(value, __u64);  // timestamp
    __uint(max_entries, 10000);
} rate_limit_map SEC(".maps");

// Configuration map (userspace can update)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} config_map SEC(".maps");

// Helper: Check if string starts with prefix
static __always_inline bool starts_with(const char *str, const char *prefix, int max_len) {
    for (int i = 0; i < max_len && prefix[i] != '\0'; i++) {
        if (str[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}

// Helper: Check if path is sensitive (worth monitoring)
static __always_inline bool is_sensitive_path(const char *path) {
    // High-priority paths (always monitor)
    if (starts_with(path, "/home/", 7)) {
        // Check for sensitive subdirectories
        if (starts_with(path, ".ssh/", 5) ||
            starts_with(path, ".gnupg/", 7) ||
            starts_with(path, ".aws/", 5) ||
            starts_with(path, ".mozilla/", 9) ||
            starts_with(path, ".config/google-chrome/", 22) ||
            starts_with(path, "Documents/", 10) ||
            starts_with(path, "Downloads/", 10) ||
            starts_with(path, ".password-store/", 16)) {
            return true;
        }
    }
    
    // Root user sensitive files
    if (starts_with(path, "/root/.ssh/", 11) ||
        starts_with(path, "/root/.gnupg/", 13) ||
        starts_with(path, "/root/.aws/", 11)) {
        return true;
    }
    
    // System credentials
    if (starts_with(path, "/etc/passwd", 11) ||
        starts_with(path, "/etc/shadow", 11) ||
        starts_with(path, "/etc/sudoers", 12) ||
        starts_with(path, "/etc/ssh/", 9)) {
        return true;
    }
    
    return false;
}

// Helper: Check if process should be ignored
static __always_inline bool should_ignore_process(const char *comm) {
    // Ignore system daemons that access files legitimately
    if (starts_with(comm, "systemd", 7) ||
        starts_with(comm, "dbus-daemon", 11) ||
        starts_with(comm, "korad", 5) ||          // Don't monitor ourselves!
        starts_with(comm, "koraav", 6) ||
        starts_with(comm, "rsyslogd", 8) ||
        starts_with(comm, "pulseaudio", 10) ||
        starts_with(comm, "Xorg", 4) ||
        starts_with(comm, "gnome-shell", 11)) {
        return true;
    }
    return false;
}

// Helper: Rate limit check
static __always_inline bool check_rate_limit(__u32 pid) {
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_time = bpf_map_lookup_elem(&rate_limit_map, &pid);
    
    if (last_time) {
        // Only send event if enough time has passed
        if (now - *last_time < RATE_LIMIT_NS) {
            return false;  // Too soon, rate limited
        }
    }
    
    // Update last event time
    bpf_map_update_elem(&rate_limit_map, &pid, &now, BPF_ANY);
    return true;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // FILTER #1: Skip kernel threads (PID 0)
    if (pid == 0) {
        return 0;
    }
    
    // FILTER #2: Get and check process name early
    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    
    if (should_ignore_process(comm)) {
        return 0;
    }
    
    // FILTER #3: Read filename and check if sensitive
    char filename[MAX_PATH_LEN] = {};
    const char *filename_ptr = (const char *)ctx->args[1];
    long ret = bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);
    
    if (ret <= 0) {
        return 0;  // Failed to read filename
    }
    
    // Skip empty filenames
    if (filename[0] == '\0') {
        return 0;
    }
    
    // CRITICAL: Only monitor sensitive paths
    if (!is_sensitive_path(filename)) {
        return 0;
    }
    
    // FILTER #4: Rate limiting per PID
    if (!check_rate_limit(pid)) {
        return 0;
    }
    
    // FILTER #5: Skip if file descriptor is < 0 (error case)
    int dfd = (int)ctx->args[0];
    if (dfd < -100) {  // AT_FDCWD is -100
        return 0;
    }
    
    // ✅ All filters passed - send event to userspace
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        return 0;  // Ring buffer full, drop event
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->uid = uid;
    event->flags = (int)ctx->args[2];  // open flags
    event->mode = (int)ctx->args[3];   // mode
    
    __builtin_memcpy(event->comm, comm, MAX_COMM_LEN);
    __builtin_memcpy(event->filename, filename, MAX_PATH_LEN);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
