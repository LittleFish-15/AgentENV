/* Compile against the exact target headers; no kernel/UB operations. */
#include "../obmm_pmem_uapi.h"
#include <uapi/linux/fs.h>
#include <uapi/linux/fiemap.h>

_Static_assert(sizeof(struct obmm_pmem_segment) == 24, "segment size");
_Static_assert(sizeof(struct obmm_pmem_create) == 792, "create size");
_Static_assert(sizeof(struct obmm_pmem_status) == 96, "status size");
_Static_assert(__builtin_offsetof(struct obmm_pmem_create, segments) == 24, "segments offset");
_Static_assert(__builtin_offsetof(struct obmm_pmem_status, id) == 24, "id offset");
_Static_assert(__builtin_offsetof(struct obmm_pmem_status, bytes) == 40, "length offset");
_Static_assert(__builtin_offsetof(struct obmm_pmem_status, dax_span_bytes) == 88, "last counter");
_Static_assert(OBMM_PMEM_CREATE == 0x4318b800UL, "create ioctl");
_Static_assert(OBMM_PMEM_STATUS == 0xc060b801UL, "status ioctl");
_Static_assert(OBMM_PMEM_DESTROY == 0x4060b802UL, "destroy ioctl");
_Static_assert(sizeof(struct obmm_pmem_sparse_create) == 40, "sparse create size");
_Static_assert(sizeof(struct obmm_pmem_install) == 56, "install size");
_Static_assert(OBMM_PMEM_SPARSE_CREATE == 0x4028b803UL, "sparse create ioctl");
_Static_assert(OBMM_PMEM_INSTALL == 0x4038b804UL, "install ioctl");
_Static_assert(sizeof(struct obmm_pmem_range_status) == 48, "range status size");
_Static_assert(OBMM_PMEM_RANGE_STATUS == 0xc030b805UL, "range status ioctl");
_Static_assert(sizeof(struct obmm_pmem_miss) == 40, "miss size");
_Static_assert(OBMM_PMEM_GET_MISS == 0xc028b806UL, "get miss ioctl");
_Static_assert(OBMM_PMEM_FAIL_MISS == 0x4028b807UL, "fail miss ioctl");
_Static_assert(sizeof(struct obmm_pmem_pool_create) == 48, "pool create size");
_Static_assert(sizeof(struct obmm_pmem_pool_fill) == 72, "pool fill size");
_Static_assert(sizeof(struct obmm_pmem_pool_slot) == 72, "pool slot size");
_Static_assert(sizeof(struct obmm_pmem_pool_bind) == 88, "pool bind size");
_Static_assert(OBMM_PMEM_POOL_CREATE == 0x4030b808UL, "pool create ioctl");
_Static_assert(OBMM_PMEM_POOL_FILL == 0x4048b809UL, "pool fill ioctl");
_Static_assert(OBMM_PMEM_POOL_ACCEPT == 0x4048b80aUL, "pool accept ioctl");
_Static_assert(OBMM_PMEM_POOL_SLOT == 0xc048b80bUL, "pool slot ioctl");
_Static_assert(OBMM_PMEM_POOL_BIND == 0x4058b80cUL, "pool bind ioctl");
_Static_assert(OBMM_PMEM_POOL_DESTROY == 0x4048b80dUL, "pool destroy ioctl");
_Static_assert(sizeof(struct fiemap) == 32, "fiemap header size");
_Static_assert(sizeof(struct fiemap_extent) == 56, "fiemap extent size");
_Static_assert(FS_IOC_FIEMAP == 0xc020660bUL, "fiemap ioctl");
_Static_assert(BLKRASET == 0x1262UL, "set readahead ioctl");
_Static_assert(BLKRAGET == 0x1263UL, "get readahead ioctl");
_Static_assert(BLKGETSIZE64 == 0x80081272UL, "block size ioctl");
