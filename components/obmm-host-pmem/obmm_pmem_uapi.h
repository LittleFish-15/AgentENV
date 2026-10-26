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
#endif
