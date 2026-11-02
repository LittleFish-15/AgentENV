/* SPDX-License-Identifier: GPL-2.0-only */
/* Host harness around extracted production read methods, not a kernel test. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#define OBMM_PMEM_LOAD_BYTES (256ULL << 10)
#define smp_load_acquire(p) (*(p))
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;
typedef uint64_t pgoff_t;
typedef uint64_t pfn_t;
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define msecs_to_jiffies(x) (x)
#define spin_lock_irqsave(lock, flags) ((void)(lock), (flags)=0)
#define spin_unlock_irqrestore(lock, flags) ((void)(lock), (void)(flags))
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
enum dax_access_mode { DAX_ACCESS, DAX_RECOVERY_WRITE };
struct pmem_extent { u64 offset, bytes; void *address; bool is_vmap; };
struct pmem_volume {
    u64 bytes;
    u64 image_bytes, logical_offset;
    struct pmem_volume **units;
    struct pmem_volume *pool_parent;
    u64 pool_offset;
    bool controlled_writer;
    struct pmem_slot *slots;
    u8 *miss_states;
    int lock, miss_wait;
    struct pmem_extent *extents;
    u32 nr_extents;
    bool dying;
    uint64_t dax_accesses, dax_span_bytes;
};
/* Deterministic wake injection exercises production wait state transitions;
 * this does not simulate Linux scheduling, locking or DAX SRCU behavior. */
static void (*wait_hook)(void);
#define wait_event_interruptible_timeout(q, cond, timeout) \
    ((void)(q), (cond) ? (timeout) : \
     ((wait_hook ? (wait_hook(), 0) : 0), (cond) ? (timeout) : 0))
struct dax_device { struct pmem_volume *private; };
static void *dax_get_private(struct dax_device *dev) { return dev->private; }
static void atomic64_inc(uint64_t *value) { (*value)++; }
static void atomic64_add(uint64_t add, uint64_t *value) { *value += add; }
static bool fail_copy;
static int copy_mc_to_kernel(void *to, const void *from, size_t bytes)
{
    if (fail_copy) return 1;
    memcpy(to, from, bytes);
    return 0;
}
/* Generated verbatim from obmm_pmem_ro.c by the local test runner. */
#include "read_methods.inc"

static void sparse_reads(void)
{
    unsigned char *a = malloc(OBMM_PMEM_LOAD_BYTES), *b = malloc(PAGE_SIZE), out[32];
    struct pmem_volume **units = calloc(16384, sizeof(*units));
    u8 *states = calloc(16384, 1);
    assert(a && b && units && states);
    memset(a, 0x33, OBMM_PMEM_LOAD_BYTES); memset(b, 0x55, PAGE_SIZE);
    struct pmem_extent ea = {0, OBMM_PMEM_LOAD_BYTES, a, true};
    struct pmem_extent eb = {0, PAGE_SIZE, b, false};
    struct pmem_volume ba = {.bytes=OBMM_PMEM_LOAD_BYTES,.extents=&ea,.nr_extents=1};
    struct pmem_volume bb = {.bytes=PAGE_SIZE,.extents=&eb,.nr_extents=1,.logical_offset=OBMM_PMEM_LOAD_BYTES};
    struct pmem_volume v = {.bytes=4ULL<<30,.image_bytes=OBMM_PMEM_LOAD_BYTES+PAGE_SIZE,.units=units,.miss_states=states};
    struct dax_device dax = {.private=&v};
    void *address = NULL;
    assert(read_bytes(&v,out,0,4)==-EIO); /* Missing never returns zeros. */
    assert(wait_range(&v,0,4)==-ETIMEDOUT);
    assert(states[0]==1);
    states[0]=2; /* Claimed miss remains claimed across a waiting reader timeout. */
    assert(wait_range(&v,0,4)==-ETIMEDOUT && states[0]==2);
    states[0]=3;
    assert(wait_range(&v,0,4)==-EIO);
    units[0]=&ba;
    assert(wait_range(&v,0,4)==0); /* Actual mapping, not stale request state, is authoritative. */
    assert(read_bytes(&v,out,OBMM_PMEM_LOAD_BYTES-8,16)==-EIO);
    units[1]=&bb;
    assert(read_bytes(&v,out,OBMM_PMEM_LOAD_BYTES-8,16)==0);
    for(int i=0;i<16;i++) assert(out[i]==(i<8?0x33:0x55));
    assert(pmem_direct_access(&dax,OBMM_PMEM_LOAD_BYTES/PAGE_SIZE,2,DAX_ACCESS,&address,NULL)==1);
    assert(address==b);
    assert(read_bytes(&v,out,v.image_bytes,1)==-EIO);
    assert(pmem_direct_access(&dax,v.image_bytes/PAGE_SIZE,1,DAX_ACCESS,&address,NULL)==-EIO);
    assert(read_bytes(&v,out,v.bytes-1,1)==-EIO);
    free(states); free(units); free(a); free(b);
}

static void arena_slot_reads(void)
{
    unsigned char *data=malloc(2*OBMM_PMEM_LOAD_BYTES);
    struct pmem_volume **units=calloc(16384,sizeof(*units));
    u8 *states=calloc(16384,1);
    assert(data && units && states);
    memset(data,0x11,OBMM_PMEM_LOAD_BYTES);memset(data+OBMM_PMEM_LOAD_BYTES,0x22,OBMM_PMEM_LOAD_BYTES);
    struct pmem_extent e={0,2*OBMM_PMEM_LOAD_BYTES,data,true};
    struct pmem_volume pool={.bytes=2*OBMM_PMEM_LOAD_BYTES,.extents=&e,.nr_extents=1};
    struct pmem_volume binding={.bytes=OBMM_PMEM_LOAD_BYTES,.pool_parent=&pool,.pool_offset=OBMM_PMEM_LOAD_BYTES};
    struct pmem_volume v={.bytes=4ULL<<30,.image_bytes=2*OBMM_PMEM_LOAD_BYTES,.units=units,.miss_states=states};
    struct dax_device dax={.private=&v};
    void *address=NULL;unsigned char out[16];
    units[0]=&binding;
    assert(read_bytes(&v,out,0,sizeof(out))==0);
    for(unsigned i=0;i<sizeof(out);i++)assert(out[i]==0x22);
    assert(pmem_direct_access(&dax,0,1024,DAX_ACCESS,&address,NULL)==OBMM_PMEM_LOAD_BYTES/PAGE_SIZE);
    assert(address==data+OBMM_PMEM_LOAD_BYTES);
    assert(read_bytes(&v,out,OBMM_PMEM_LOAD_BYTES,1)==-EIO);
    free(states);free(units);free(data);
}

int main(void)
{
    sparse_reads();
    arena_slot_reads();
    unsigned char a[PAGE_SIZE], b[PAGE_SIZE], output[32];
    struct pmem_extent extents[] = {{0, PAGE_SIZE, a, true}, {PAGE_SIZE, PAGE_SIZE, b, false}};
    struct pmem_volume v = {.bytes = 2 * PAGE_SIZE, .extents = extents, .nr_extents = 2};
    struct dax_device dax = {.private = &v};
    pfn_t pfn = 0;
    void *address = NULL;
    memset(a, 0x31, sizeof(a)); memset(b, 0x72, sizeof(b));
    assert(find_extent(&v, 0) == &extents[0]);
    assert(find_extent(&v, PAGE_SIZE) == &extents[1]);
    assert(find_extent(&v, v.bytes) == NULL);
    assert(read_bytes(&v, output, PAGE_SIZE - 10, 20) == 0);
    for (int i = 0; i < 20; i++) assert(output[i] == (i < 10 ? 0x31 : 0x72));
    assert(read_bytes(&v, output, v.bytes - 1, 2) == -EINVAL);
    assert(read_bytes(&v, output, UINT64_MAX, 2) == -EINVAL);
    assert(read_bytes(&v, output, v.bytes, 0) == 0);
    fail_copy = true;
    assert(read_bytes(&v, output, 0, 1) == -EIO);
    fail_copy = false;
    assert(pmem_direct_access(&dax, 0, 2, DAX_ACCESS, &address, NULL) == 1);
    assert(address == a && v.dax_span_bytes == PAGE_SIZE && v.dax_accesses == 1);
    assert(pmem_direct_access(&dax, 1, 2, DAX_ACCESS, &address, NULL) == 1 && address == b);
    assert(pmem_direct_access(&dax, 2, 1, DAX_ACCESS, &address, NULL) == -EINVAL);
    assert(pmem_direct_access(&dax, UINT64_MAX, 1, DAX_ACCESS, &address, NULL) == -EINVAL);
    assert(pmem_direct_access(&dax, 0, 0, DAX_ACCESS, &address, NULL) == -EINVAL);
    assert(pmem_direct_access(&dax, 0, -1, DAX_ACCESS, &address, NULL) == -EINVAL);
    assert(pmem_direct_access(&dax, 0, 1, DAX_ACCESS, &address, &pfn) == -EOPNOTSUPP);
    assert(pmem_direct_access(&dax, 0, 1, DAX_ACCESS, NULL, NULL) == -EOPNOTSUPP);
    assert(pmem_direct_access(&dax, 0, 1, DAX_RECOVERY_WRITE, &address, NULL) == -EOPNOTSUPP);
    v.dying = true;
    assert(pmem_direct_access(&dax, 0, 1, DAX_ACCESS, &address, NULL) == -ENXIO);
    puts("PRODUCTION_READ_METHODS_PASS_NO_KERNEL_OR_HARDWARE_ACCEPTANCE");
    return 0;
}
