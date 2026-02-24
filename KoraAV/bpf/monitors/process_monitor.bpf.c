// bpf/monitors/process_monitor.bpf.c
// Attempted enterprise-grade real-time process execution monitoring
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMM_LEN 16
#define MAX_CMDLINE_LEN 256
#define RATE_LIMIT_NS 50000000  // 50ms between events per PID

struct process_event {
    __u64 timestamp;
    __u32 tgid;
    __u32 ptgid;
    __u32 uid;
    char comm[MAX_COMM_LEN];
    char cmdline[MAX_CMDLINE_LEN];
};

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} process_events SEC(".maps");

// Rate limiting map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10000);
} proc_rate_limit_map SEC(".maps");

// Helper: Check if string starts with prefix
static __always_inline bool starts_with(const char *str, const char *prefix, int max_len) {
    for (int i = 0; i < max_len && prefix[i] != '\0'; i++) {
        if (str[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}

// Helper: Check if command is attempting snapshot deletion
static __always_inline bool is_snapshot_deletion_attempt(const char *comm) {
    // Check for snapshot management tools
    if (starts_with(comm, "btrfs", 5) ||
        starts_with(comm, "lvremove", 8) ||
        starts_with(comm, "lvchange", 8) ||
        starts_with(comm, "zfs", 3)) {
        return true;
    }
    return false;
}

// Helper: Check if process is interesting (shell, terminal, or suspicious)
static __always_inline bool is_interesting_process(const char *comm) {
    // Shells (high priority - ClickFix detection)
    if (starts_with(comm, "bash", 4) ||
        starts_with(comm, "sh", 2) ||
        starts_with(comm, "zsh", 3) ||
        starts_with(comm, "fish", 4) ||
        starts_with(comm, "dash", 4)) {
        return true;
    }
    
    // Terminals (medium priority)
    if (starts_with(comm, "konsole", 7) ||
        starts_with(comm, "gnome-terminal", 14) ||
        starts_with(comm, "xterm", 5) ||
        starts_with(comm, "alacritty", 9)) {
        return true;
    }
    
    // Scripting languages (medium priority - could be malicious scripts)
    if (starts_with(comm, "python", 6) ||
        starts_with(comm, "perl", 4) ||
        starts_with(comm, "ruby", 4) ||
        starts_with(comm, "node", 4)) {
        return true;
    }
    
    // Suspicious executables
    if (starts_with(comm, "nc", 2) ||           // netcat
        starts_with(comm, "ncat", 4) ||
        starts_with(comm, "socat", 5) ||
        starts_with(comm, "wget", 4) ||
        starts_with(comm, "curl", 4) ||
        starts_with(comm, "base64", 6) ||
        starts_with(comm, "openssl", 7)) {
        return true;
    }
    
    return false;
}

// Helper: Should ignore process (system processes we don't care about)
static __always_inline bool should_ignore_process(const char *comm) {
    // System services
    if (starts_with(comm, "systemd", 7) ||
        starts_with(comm, "dbus-daemon", 11) ||
        starts_with(comm, "korad", 5) ||
        starts_with(comm, "koraav", 6) ||
        starts_with(comm, "rsyslogd", 8) ||
        starts_with(comm, "cron", 4) ||
        starts_with(comm, "atd", 3)) {
        return true;
    }
    
    // Desktop environment (too noisy)
    if (starts_with(comm, "gnome-", 6) ||
        starts_with(comm, "kde", 3) ||
        starts_with(comm, "plasma", 6) ||
        starts_with(comm, "Xorg", 4) ||
        starts_with(comm, "pulseaudio", 10)) {
        return true;
    }
    
    return false;
}

// Helper: Rate limit check
static __always_inline bool check_rate_limit(__u32 tgid) {
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_time = bpf_map_lookup_elem(&proc_rate_limit_map, &tgid);
    
    if (last_time) {
        if (now - *last_time < RATE_LIMIT_NS) {
            return false;
        }
    }
    
    bpf_map_update_elem(&proc_rate_limit_map, &tgid, &now, BPF_ANY);
    return true;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
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
    
    // Skip ignored processes
    if (should_ignore_process(comm)) {
        return 0;
    }
    
    // Only send event if process is interesting OR we're sampling
    bool is_interesting = is_interesting_process(comm);
    bool is_snapshot_cmd = is_snapshot_deletion_attempt(comm);
    
    // ALWAYS send snapshot deletion attempts regardless of filters
    if (is_snapshot_cmd) {
        // Skip rate limiting for snapshot commands - send immediately
        struct process_event *event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
        if (!event) {
            return 0;
        }
        
        event->timestamp = bpf_ktime_get_ns();
        event->tgid = tgid;
        event->uid = uid;
        
        __builtin_memcpy(event->comm, comm, MAX_COMM_LEN);
        
        // Get parent PID
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct task_struct *parent;
        BPF_CORE_READ_INTO(&parent, task, real_parent);
        BPF_CORE_READ_INTO(&event->ptgid, parent, tgid);
        
        // Get full command line
        const char **argv_ptr = (const char **)ctx->args[1];
        const char *first_arg = NULL;
        bpf_probe_read_user(&first_arg, sizeof(first_arg), argv_ptr);
        
        if (first_arg) {
            bpf_probe_read_user_str(event->cmdline, MAX_CMDLINE_LEN, first_arg);
        } else {
            event->cmdline[0] = '\0';
        }
        
        bpf_ringbuf_submit(event, 0);
        return 0;
    }
    
    // FILTER #3: If not interesting, use heavy sampling (1% of events)
    if (!is_interesting) {
        // Simple sampling: only send 1 out of 100 uninteresting events
        if ((bpf_get_prandom_u32() % 100) != 0) {
            return 0;
        }
    }
    
    // FILTER #4: Rate limiting
    if (!check_rate_limit(tgid)) {
        return 0;
    }
    
    // ✅ All filters passed - send event
    struct process_event *event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->tgid = tgid;
    event->uid = uid;
    
    __builtin_memcpy(event->comm, comm, MAX_COMM_LEN);
    
    // Get parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    BPF_CORE_READ_INTO(&parent, task, real_parent);
    BPF_CORE_READ_INTO(&event->ptgid, parent, tgid);
    
    // Try to read command line (first argument to execve)
    const char **argv_ptr = (const char **)ctx->args[1];
    const char *first_arg = NULL;
    
    // Read pointer to first argument
    bpf_probe_read_user(&first_arg, sizeof(first_arg), argv_ptr);
    
    if (first_arg) {
        // Read the actual command line string
        bpf_probe_read_user_str(event->cmdline, MAX_CMDLINE_LEN, first_arg);
    } else {
        event->cmdline[0] = '\0';
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
