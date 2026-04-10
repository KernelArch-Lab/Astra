/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * vmlinux.h — portable stub for local / CI builds
 *
 * The real vmlinux.h is generated from the running kernel's BTF data via:
 *   sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 *
 * This stub provides the complete set of type definitions and struct
 * forward-declarations required by bpf_helpers.h and bpf_helper_defs.h so
 * that task_spawn.bpf.c compiles without a live kernel BTF file.
 *
 * Rules for maintaining this stub:
 *   - Add typedefs / struct forward-decls; do NOT add real struct bodies
 *     (the BPF verifier does CO-RE relocation at load time anyway).
 *   - Keep the signed/unsigned/BE/LE family complete — bpf_helper_defs.h
 *     uses all of them.
 *   - Keep BPF_MAP_TYPE_* complete so map-type constants resolve.
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/* -------------------------------------------------------------------------
 * Basic unsigned integer types
 * ---------------------------------------------------------------------- */
typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;

/* -------------------------------------------------------------------------
 * Basic signed integer types
 * ---------------------------------------------------------------------- */
typedef signed char         __s8;
typedef signed short        __s16;
typedef signed int          __s32;
typedef signed long long    __s64;

/* -------------------------------------------------------------------------
 * Network byte-order aliases (same width — different semantic intent).
 * bpf_helper_defs.h uses __be16 / __be32 / __wsum extensively.
 * ---------------------------------------------------------------------- */
typedef __u16  __be16;
typedef __u32  __be32;
typedef __u64  __be64;
typedef __u16  __le16;
typedef __u32  __le32;
typedef __u64  __le64;
typedef __u32  __wsum;      /* TCP/IP checksum accumulator */
typedef __u16  __sum16;

/* -------------------------------------------------------------------------
 * Non-prefixed aliases used inside BPF programs (e.g. (u32)pid)
 * ---------------------------------------------------------------------- */
typedef __u8   u8;
typedef __u16  u16;
typedef __u32  u32;
typedef __u64  u64;
typedef __s8   s8;
typedef __s16  s16;
typedef __s32  s32;
typedef __s64  s64;

/* -------------------------------------------------------------------------
 * Misc kernel scalar types
 * ---------------------------------------------------------------------- */
typedef int          __kernel_pid_t;
typedef unsigned int __kernel_uid32_t;
typedef unsigned int __kernel_gid32_t;
typedef long         __kernel_long_t;
typedef unsigned long __kernel_ulong_t;
typedef long long    __kernel_loff_t;
typedef unsigned int __kernel_size_t;
typedef int          __kernel_ssize_t;
typedef int          bool;   /* BPF C is not C++ */

/* -------------------------------------------------------------------------
 * BPF map type enumeration.
 * Must be kept in sync with include/uapi/linux/bpf.h.
 * We list the full enum so BPF_MAP_TYPE_RINGBUF and friends resolve.
 * ---------------------------------------------------------------------- */
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC                 =  0,
    BPF_MAP_TYPE_HASH                   =  1,
    BPF_MAP_TYPE_ARRAY                  =  2,
    BPF_MAP_TYPE_PROG_ARRAY             =  3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY       =  4,
    BPF_MAP_TYPE_PERCPU_HASH            =  5,
    BPF_MAP_TYPE_PERCPU_ARRAY           =  6,
    BPF_MAP_TYPE_STACK_TRACE            =  7,
    BPF_MAP_TYPE_CGROUP_ARRAY           =  8,
    BPF_MAP_TYPE_LRU_HASH               =  9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH        = 10,
    BPF_MAP_TYPE_LPM_TRIE               = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS          = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS           = 13,
    BPF_MAP_TYPE_DEVMAP                 = 14,
    BPF_MAP_TYPE_SOCKMAP                = 15,
    BPF_MAP_TYPE_CPUMAP                 = 16,
    BPF_MAP_TYPE_XSKMAP                 = 17,
    BPF_MAP_TYPE_SOCKHASH               = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE         = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY    = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE  = 21,
    BPF_MAP_TYPE_QUEUE                  = 22,
    BPF_MAP_TYPE_STACK                  = 23,
    BPF_MAP_TYPE_SK_STORAGE             = 24,
    BPF_MAP_TYPE_DEVMAP_HASH            = 25,
    BPF_MAP_TYPE_STRUCT_OPS             = 26,
    BPF_MAP_TYPE_RINGBUF                = 27,
    BPF_MAP_TYPE_INODE_STORAGE          = 28,
    BPF_MAP_TYPE_TASK_STORAGE           = 29,
    BPF_MAP_TYPE_BLOOM_FILTER           = 30,
    BPF_MAP_TYPE_USER_RINGBUF           = 31,
    BPF_MAP_TYPE_CGRP_STORAGE           = 32,
};

/* -------------------------------------------------------------------------
 * Forward declarations for every kernel struct referenced by
 * bpf_helper_defs.h.  We use empty struct bodies so the compiler accepts
 * pointer parameters without needing the real definitions.
 * ---------------------------------------------------------------------- */
struct task_struct          { int __opaque; };
struct file                 { int __opaque; };
struct inode                { int __opaque; };
struct mm_struct            { int __opaque; };
struct bpf_map              { int __opaque; };
struct bpf_spin_lock        { int __opaque; };
struct bpf_timer            { int __opaque; };
struct bpf_dynptr           { __u64 __opaque[2]; };
struct bpf_list_head        { __u64 __opaque[2]; };
struct bpf_list_node        { __u64 __opaque[3]; };
struct bpf_rb_root          { __u64 __opaque[2]; };
struct bpf_rb_node          { __u64 __opaque[4]; };
struct bpf_refcount         { int __opaque; };
/* x86_64 pt_regs layout — must match arch/x86/include/asm/ptrace.h.
 * The PT_REGS_PARM1..6 macros in bpf_tracing.h expand to the field names
 * below (di, si, dx, cx, r8, r9), so they must be present verbatim. */
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

/* Networking structs used by socket/skb helpers */
struct __sk_buff            { __u32 __opaque[32]; };
struct sk_msg_md            { __u32 __opaque[16]; };
struct xdp_md               { __u32 __opaque[8]; };
struct sk_reuseport_md      { __u64 __opaque[8]; };
struct sockaddr             { __u16 sa_family; char sa_data[14]; };
struct bpf_sock             { int __opaque; };
struct bpf_tcp_sock         { int __opaque; };
struct bpf_sock_tuple       { int __opaque; };
struct bpf_sock_ops         { __u32 __opaque[32]; };
struct bpf_sock_addr        { __u32 __opaque[16]; };
struct tcp_sock             { int __opaque; };
struct udp6_sock            { int __opaque; };
struct socket               { int __opaque; };

/* L3/L4 protocol headers — used by syncookie helpers */
struct tcphdr {
    __be16  source;
    __be16  dest;
    __be32  seq;
    __be32  ack_seq;
    __u16   doff_flags;
    __be16  window;
    __sum16 check;
    __be16  urg_ptr;
};
struct iphdr {
    __u8    ihl_version;
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __sum16 check;
    __be32  saddr;
    __be32  daddr;
};
struct ipv6hdr {
    __u8    priority_version;
    __u8    flow_lbl[3];
    __be16  payload_len;
    __u8    nexthdr;
    __u8    hop_limit;
    __u8    saddr[16];
    __u8    daddr[16];
};

/* Misc helpers */
struct bpf_raw_tracepoint_args { __u64 args[0]; };
struct btf_ptr              { void *ptr; __u32 type_id; __u32 flags; };
struct fib_lookup_arg       { int __opaque; };
struct path                 { int __opaque; };
struct seq_file             { int __opaque; };
struct user_namespace       { int __opaque; };
struct cgroup               { int __opaque; };
struct linux_binprm         { int __opaque; };
struct iov_iter             { int __opaque; };
struct xfrm_state           { int __opaque; };
struct nf_conn              { int __opaque; };
struct nfgenmsg             { int __opaque; };
struct bpf_func_info_min    { int __opaque; };
struct bpf_line_info_min    { int __opaque; };
struct bpf_iter_num         { int __opaque; };
struct bpf_iter_task        { int __opaque; };
struct bpf_iter_task_vma    { int __opaque; };
struct bpf_iter_task_file   { int __opaque; };
struct bpf_iter_css_task    { int __opaque; };
struct bpf_iter_css         { int __opaque; };
struct bpf_iter_bpf_map     { int __opaque; };
struct bpf_iter_bpf_sk      { int __opaque; };
struct bpf_iter_unix        { int __opaque; };
struct bpf_iter_bpf_map_elem { int __opaque; };
struct bpf_iter_bpf_prog    { int __opaque; };
struct bpf_iter_bpf_link    { int __opaque; };
struct bpf_iter_sockmap     { int __opaque; };

#endif /* __VMLINUX_H__ */
