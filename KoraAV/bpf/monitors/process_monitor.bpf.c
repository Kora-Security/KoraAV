// bpf/monitors/process_monitor.bpf.c
// Real-time process execution monitoring for malicious command detection
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_CMDLINE_LEN 512
#define MAX_COMM_LEN 16

// Event types
#define EVENT_PROCESS_EXEC 1
#define EVENT_PROCESS_EXIT 2

// Process event
struct process_event {
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 event_type;
    char comm[MAX_COMM_LEN];
    char cmdline[MAX_CMDLINE_LEN];
};

// Ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} process_events SEC(".maps");

// Process tree tracking
struct process_info {
    __u32 ppid;
    __u64 start_time;
    char comm[MAX_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, struct process_info);
} process_tree SEC(".maps");

// Config
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

// Helper: Read command line arguments
static __always_inline void read_cmdline(struct trace_event_raw_sys_enter *ctx, char *cmdline) {
    const char **argv = (const char **)ctx->args[1];
    __u32 pos = 0;
    
    #pragma unroll
    for (int i = 0; i < 16 && pos < MAX_CMDLINE_LEN - 1; i++) {
        const char *arg;
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) != 0)
            break;
        if (!arg)
            break;
        
        // Add space between args
        if (pos > 0 && pos < MAX_CMDLINE_LEN - 1) {
            cmdline[pos++] = ' ';
        }
        
        // Read argument
        int len = bpf_probe_read_user_str(cmdline + pos, MAX_CMDLINE_LEN - pos, arg);
        if (len <= 0)
            break;
        
        pos += len - 1;  // -1 for null terminator
    }
    
    cmdline[pos] = '\0';
}

// Tracepoint: sys_enter_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    __u32 *enabled = bpf_map_lookup_elem(&config, &key);
    if (!enabled || *enabled == 0)
        return 0;
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Reserve ring buffer
    struct process_event *event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->uid = bpf_get_current_uid_gid();
    event->event_type = EVENT_PROCESS_EXEC;
    
    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Get parent PID from task struct
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&event->ppid, sizeof(event->ppid), &parent->tgid);
    
    // Read command line
    __builtin_memset(event->cmdline, 0, sizeof(event->cmdline));
    read_cmdline(ctx, event->cmdline);
    
    bpf_ringbuf_submit(event, 0);
    
    // Update process tree
    struct process_info info = {
        .ppid = event->ppid,
        .start_time = event->timestamp,
    };
    __builtin_memcpy(info.comm, event->comm, sizeof(info.comm));
    bpf_map_update_elem(&process_tree, &pid, &info, BPF_ANY);
    
    return 0;
}

// Tracepoint: sched_process_exit
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 pid = ctx->pid;
    
    // Send exit event
    struct process_event *event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (event) {
        event->timestamp = bpf_ktime_get_ns();
        event->pid = pid;
        event->event_type = EVENT_PROCESS_EXIT;
        bpf_ringbuf_submit(event, 0);
    }
    
    // Clean up process tree
    bpf_map_delete_elem(&process_tree, &pid);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
