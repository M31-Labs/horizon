/* scripts/ci/vmlinux-stub.h
 *
 * Minimal stand-in for a BTF-generated vmlinux.h, used by CI jobs that build
 * example .bpf.o on runners without /sys/kernel/btf/vmlinux. Shared by
 * test.yml, release.yml, and kernel-matrix.yml so the definitions cannot
 * drift apart (they previously did, as inline printf blocks).
 *
 * IMPORTANT — BPF context structs must match the kernel UAPI layout exactly.
 * Direct field reads on a program's context (struct bpf_sock_addr, struct
 * xdp_md, ...) are NOT CO-RE-relocated: the verifier checks the literal byte
 * offset in the load instruction against the program type's allowed context
 * layout. A made-up layout compiles fine but is rejected at load with
 * "invalid bpf_context access". (This is exactly how the kernel-matrix caught
 * a wrong bpf_sock_addr layout: protocol was placed at offset 8 instead of
 * its real UAPI offset 36, so cgroupconnect failed the verifier on every
 * kernel.) CO-RE structs (e.g. task_struct, marked preserve_access_index) are
 * relocated at load and need only field-name accuracy.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

enum bpf_map_type {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_RINGBUF = 27,
};
enum { BPF_ANY = 0 };

struct __sk_buff;

struct pt_regs {
    __u64 di; __u64 si; __u64 dx; __u64 cx; __u64 r8; __u64 r9;
    __u64 sp; __u64 bp; __u64 ax; __u64 ip;
};

struct task_struct {
    struct task_struct *real_parent;
    __u32 tgid;
} __attribute__((preserve_access_index));

/* Real UAPI layout (include/uapi/linux/bpf.h). Field order — hence byte
 * offsets — is load-bearing for context access; do not reorder. */
struct bpf_sock_addr {
    __u32 user_family;    /* off 0  */
    __u32 user_ip4;       /* off 4  */
    __u32 user_ip6[4];    /* off 8  */
    __u32 user_port;      /* off 24 */
    __u32 family;         /* off 28 */
    __u32 type;           /* off 32 */
    __u32 protocol;       /* off 36 */
    __u32 msg_src_ip4;    /* off 40 */
    __u32 msg_src_ip6[4]; /* off 44 */
};

struct xdp_md { __u32 data; __u32 data_end; };

struct trace_event_raw_sched_process_exec {};

/* struct_ops stub for tcp_congestion_ops (v0.4 Track A A2). The generated
 * SEC(".struct_ops") ops-struct instance assigns the bound program function
 * to the ops field via a (void *) cast, so the stub only needs the referenced
 * field(s) to exist as void-pointer-compatible members. Unlike the context
 * structs above, a struct_ops ops instance is NOT a verifier context-access
 * struct — its field layout is CO-RE-resolved from the kernel's real
 * tcp_congestion_ops BTF at load time, so this minimal stub is sufficient for
 * clang to compile the generated C on runners without a BTF vmlinux.h. */
struct tcp_congestion_ops {
    void *init;
};

#endif /* __VMLINUX_H__ */
