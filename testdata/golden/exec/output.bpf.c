#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

static __always_inline __u32 hzn_current_pid(void) {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline __u32 hzn_current_ppid(void) {
    return 0;
}

static __always_inline __u32 hzn_current_uid(void) {
    return (__u32)bpf_get_current_uid_gid();
}

static __always_inline long hzn_current_comm(void *dst, __u32 size) {
    return bpf_get_current_comm(dst, size);
}

struct ExecEvent {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8 comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ExecEvents SEC(".maps");

static __always_inline struct ExecEvent *ExecEvents_reserve(void) {
    return bpf_ringbuf_reserve(&ExecEvents, sizeof(struct ExecEvent), 0);
}

static __always_inline void ExecEvents_submit(struct ExecEvent *value) {
    bpf_ringbuf_submit(value, 0);
}

SEC("tracepoint/sched/sched_process_exec")
int OnExec(struct trace_event_raw_sched_process_exec *ctx) {
    (void)ctx;
    struct ExecEvent *event = ExecEvents_reserve();
    if (event == 0) {
        return 0;
    }
    event->pid = hzn_current_pid();
    event->ppid = hzn_current_ppid();
    event->uid = hzn_current_uid();
    hzn_current_comm(&event->comm, sizeof(event->comm));
    ExecEvents_submit(event);
    return 0;
}
