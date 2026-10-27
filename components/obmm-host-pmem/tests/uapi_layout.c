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
_Static_assert(sizeof(struct fiemap) == 32, "fiemap header size");
_Static_assert(sizeof(struct fiemap_extent) == 56, "fiemap extent size");
_Static_assert(FS_IOC_FIEMAP == 0xc020660bUL, "fiemap ioctl");
_Static_assert(BLKRASET == 0x1262UL, "set readahead ioctl");
_Static_assert(BLKRAGET == 0x1263UL, "get readahead ioctl");
_Static_assert(BLKGETSIZE64 == 0x80081272UL, "block size ioctl");
