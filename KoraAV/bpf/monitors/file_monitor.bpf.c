// bpf/monitors/file_monitor.bpf.c
// Attempted enterprise-grade real-time file access monitoring
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

// Helper: Check if path contains substring (simple implementation)
static __always_inline bool contains(const char *str, const char *substr, int max_len) {
    for (int i = 0; i < max_len && str[i] != '\0'; i++) {
        bool match = true;
        for (int j = 0; substr[j] != '\0' && (i + j) < max_len; j++) {
            if (str[i + j] != substr[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// Helper: Check if path is sensitive (worth monitoring)
static __always_inline bool is_sensitive_path(const char *path) {
    // Check for sensitive patterns ANYWHERE in the path
    // This works because if path is /home/you/.ssh/id_rsa,
    // it will contain "/.ssh/" which is what we want to detect
    
    if (contains(path, "/.ssh/", 256) ||
        contains(path, "/.gnupg/", 256) ||
        contains(path, "/.aws/", 256) ||
        contains(path, "/.mozilla/", 256) ||
        contains(path, "/google-chrome/", 256) ||
        contains(path, "/Documents/", 256) ||
        contains(path, "/Downloads/", 256) ||
        contains(path, "/.password-store/", 256) ||
        contains(path, "/etc/passwd", 256) ||
        contains(path, "/etc/shadow", 256) ||
        contains(path, "/etc/sudoers", 256) ||
        contains(path, "/etc/ssh/", 256)) {
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
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
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
