/* SPDX-License-Identifier: GPL-2.0-only */
/* Experimental ABI v1: no raw physical addresses, install/load is not automatic. */
#ifndef OBMM_PMEM_UAPI_H
#define OBMM_PMEM_UAPI_H
#include <linux/types.h>
#include <linux/ioctl.h>

#define OBMM_PMEM_ABI 1
#define OBMM_PMEM_MAX_SEGMENTS 32
struct obmm_pmem_segment {
	__s32 fd;
	__u32 reserved;
	__u64 offset;
	__u64 bytes;
};
struct obmm_pmem_create {
	__u32 version;
	__u32 count;
	__u8 uuid[16];
	struct obmm_pmem_segment segments[OBMM_PMEM_MAX_SEGMENTS];
};
struct obmm_pmem_status {
	__u32 version;
	__u32 reserved;
	__u8 uuid[16];
	__u32 id;
	__u32 state;
	__u32 major;
	__u32 minor;
	__u64 bytes;
	__u64 openers;
	__u64 active_io;
	__u64 block_reads;
	__u64 block_bytes;
	__u64 dax_accesses;
	__u64 dax_span_bytes;
};
#define OBMM_PMEM_CREATE _IOW(0xb8, 0, struct obmm_pmem_create)
#define OBMM_PMEM_STATUS _IOWR(0xb8, 1, struct obmm_pmem_status)
#define OBMM_PMEM_DESTROY _IOW(0xb8, 2, struct obmm_pmem_status)

/* Separate commands preserve the full-mode ABI. No implicit allocation. */
#define OBMM_PMEM_DEMAND_BYTES (4ULL << 30)
#define OBMM_PMEM_LOAD_BYTES (256ULL << 10)
struct obmm_pmem_sparse_create {
	__u32 version;
	__u32 reserved;
	__u8 uuid[16];
	__u64 logical_bytes;
	__u64 image_bytes;
};
struct obmm_pmem_install {
	__u32 version;
	__u32 reserved;
	__u8 uuid[16];
	__u64 logical_offset;
	struct obmm_pmem_segment segment;
};
/* Query one logical unit after an INSTALL reply is lost. READY is local
 * mapping state only, never an attestation of global UB provenance. */
struct obmm_pmem_range_status {
	__u32 version;
	__u32 state; /* input 0; output 0 absent, 1 mapped, 2 pending, 3 claimed, 4 failed */
	__u8 uuid[16];
	__u64 logical_offset;
	__u64 mapped_offset;
	__u64 mapped_bytes;
};
/* GET_MISS is nonblocking: EAGAIN means no new pending unit. A claimed
 * miss is never implicitly requeued after a lost response. */
struct obmm_pmem_miss {
	__u32 version;
	__u32 reserved;
	__u8 uuid[16];
	__u64 logical_offset;
	__u64 bytes;
};
#define OBMM_PMEM_SPARSE_CREATE _IOW(0xb8, 3, struct obmm_pmem_sparse_create)
#define OBMM_PMEM_INSTALL _IOW(0xb8, 4, struct obmm_pmem_install)
#define OBMM_PMEM_RANGE_STATUS _IOWR(0xb8, 5, struct obmm_pmem_range_status)
#define OBMM_PMEM_GET_MISS _IOWR(0xb8, 6, struct obmm_pmem_miss)
#define OBMM_PMEM_FAIL_MISS _IOW(0xb8, 7, struct obmm_pmem_miss)

/* Controlled arena: all ordinary writable mappings are closed before attach.
 * writer=1 requires the separate disabled-by-default module write gate.
 * No general writable mmap or physical address is exposed.
 */
struct obmm_pmem_pool_create {
	__u32 version;
	__u32 writer;
	__u8 uuid[16];
	struct obmm_pmem_segment segment;
};
struct obmm_pmem_pool_fill {
	__u32 version;
	__u32 bytes;
	__u8 uuid[16];
	__u64 slot_offset;
	__u64 user_data;
	__u8 sha256[32];
};
struct obmm_pmem_pool_slot {
	__u32 version;
	__u32 state; /* input 0; output 0 empty, 1 filling, 2 ready, 3 poisoned */
	__u8 uuid[16];
	__u64 slot_offset;
	__u32 bytes;
	__u32 reserved;
	__u8 sha256[32];
};
struct obmm_pmem_pool_bind {
	__u32 version;
	__u32 reserved;
	__u8 uuid[16]; /* logical volume */
	__u8 pool_uuid[16];
	__u64 slot_offset;
	__u64 logical_offset;
	__u8 sha256[32]; /* expected digest of this immutable logical unit */
};
#define OBMM_PMEM_POOL_CREATE _IOW(0xb8, 8, struct obmm_pmem_pool_create)
#define OBMM_PMEM_POOL_FILL _IOW(0xb8, 9, struct obmm_pmem_pool_fill)
#define OBMM_PMEM_POOL_ACCEPT _IOW(0xb8, 10, struct obmm_pmem_pool_fill)
#define OBMM_PMEM_POOL_SLOT _IOWR(0xb8, 11, struct obmm_pmem_pool_slot)
#define OBMM_PMEM_POOL_BIND _IOW(0xb8, 12, struct obmm_pmem_pool_bind)
#define OBMM_PMEM_POOL_DESTROY _IOW(0xb8, 13, struct obmm_pmem_pool_slot)
#endif
