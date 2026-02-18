// process_monitor.bpf.c - PERMISSIVE VERSION FOR TESTING

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct process_event {
    u64 timestamp;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char cmdline[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} process_events SEC(".maps");

static __always_inline bool starts_with(const char *str, const char *prefix, int prefix_len) {
    for (int i = 0; i < prefix_len && i < 16; i++) {
        if (str[i] != prefix[i]) return false;
        if (str[i] == '\0') return (prefix[i] == '\0');
    }
    return true;
}

static __always_inline bool should_ignore(const char *comm) {
    // Only ignore korad itself
    if (starts_with(comm, "korad", 5)) return true;
    
    // Monitor everything else (bash, python, etc.)
    return false;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();
    
    if (pid == 0) return 0;
    
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    
    if (should_ignore(comm)) return 0;
    
    struct process_event *e = bpf_ringbuf_reserve(&process_events, sizeof(*e), 0);
    if (!e) return 0;
    
    e->timestamp = bpf_ktime_get_ns();
    e->pid = pid;
    e->ppid = 0;  // Will be filled by userspace if needed
    e->uid = uid;
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    
    // Get command line from args
    const char **argv = (const char **)ctx->args[1];
    char cmdline[256] = {};
    
    // Read first argument (the command)
    const char *arg0;
    bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]);
    if (arg0) {
        bpf_probe_read_user_str(cmdline, sizeof(cmdline), arg0);
    }
    
    __builtin_memcpy(e->cmdline, cmdline, sizeof(cmdline));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
