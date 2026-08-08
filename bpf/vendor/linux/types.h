/* Minimal linux/types.h shim for compiling eBPF programs with clang -target bpf
 * without the host kernel UAPI tree. Only the types used by libbpf's
 * bpf_helpers.h / bpf_helper_defs.h and our BPF sources are defined. */
#ifndef ZQFW_LINUX_TYPES_H
#define ZQFW_LINUX_TYPES_H

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
typedef __u64 __be64;

typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;

/* checksum type used by bpf_csum_diff etc. */
typedef __u32 __wsum;

typedef __u16 __sum16;
typedef __u32 __sum;

/* aligned 64-bit type used throughout the BPF UAPI */
typedef __u64 __aligned_u64 __attribute__((aligned(8)));

#endif /* ZQFW_LINUX_TYPES_H */
