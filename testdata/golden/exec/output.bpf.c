#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

_Static_assert(sizeof(__u8) == 1, "horizon: __u8 width mismatch");
_Static_assert(sizeof(__u16) == 2, "horizon: __u16 width mismatch");
_Static_assert(sizeof(__u32) == 4, "horizon: __u32 width mismatch");
_Static_assert(sizeof(__u64) == 8, "horizon: __u64 width mismatch");
_Static_assert(sizeof(__s8) == 1, "horizon: __s8 width mismatch");
_Static_assert(sizeof(__s16) == 2, "horizon: __s16 width mismatch");
_Static_assert(sizeof(__s32) == 4, "horizon: __s32 width mismatch");
_Static_assert(sizeof(__s64) == 8, "horizon: __s64 width mismatch");

static __always_inline __u32 hzn_current_pid(void) {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline __u32 hzn_current_ppid(void) {
    return 0;
}

static __always_inline __u32 hzn_current_uid(void) {
    return (__u32)bpf_get_current_uid_gid();
}

static __always_inline __u64 hzn_ktime_get_ns(void) {
    return bpf_ktime_get_ns();
}

static __always_inline long hzn_current_comm(void *dst, __u32 size) {
    return bpf_get_current_comm(dst, size);
}

struct hzn_type_ExecEvent {
    __u64 ts_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8 comm[16];
};
_Static_assert(sizeof(struct hzn_type_ExecEvent) == 40, "horizon: struct ExecEvent size mismatch");
_Static_assert(__builtin_offsetof(struct hzn_type_ExecEvent, ts_ns) == 0, "horizon: struct ExecEvent.ts_ns offset mismatch");
_Static_assert(__builtin_offsetof(struct hzn_type_ExecEvent, pid) == 8, "horizon: struct ExecEvent.pid offset mismatch");
_Static_assert(__builtin_offsetof(struct hzn_type_ExecEvent, ppid) == 12, "horizon: struct ExecEvent.ppid offset mismatch");
_Static_assert(__builtin_offsetof(struct hzn_type_ExecEvent, uid) == 16, "horizon: struct ExecEvent.uid offset mismatch");
_Static_assert(__builtin_offsetof(struct hzn_type_ExecEvent, comm) == 20, "horizon: struct ExecEvent.comm offset mismatch");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ExecEvents SEC(".maps");

static __always_inline struct hzn_type_ExecEvent *ExecEvents_reserve(void) {
    return bpf_ringbuf_reserve(&ExecEvents, sizeof(struct hzn_type_ExecEvent), 0);
}

static __always_inline void ExecEvents_submit(struct hzn_type_ExecEvent *value) {
    bpf_ringbuf_submit(value, 0);
}

SEC("tracepoint/sched/sched_process_exec")
int OnExec(struct trace_event_raw_sched_process_exec *ctx) {
    (void)ctx;
    struct hzn_type_ExecEvent *event = ExecEvents_reserve();
    if (event == 0) {
        return 0;
    }
    event->ts_ns = hzn_ktime_get_ns();
    event->pid = hzn_current_pid();
    event->ppid = hzn_current_ppid();
    event->uid = hzn_current_uid();
    hzn_current_comm(&event->comm, sizeof(event->comm));
    ExecEvents_submit(event);
    return 0;
}
