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
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint64_t pgoff_t;
typedef uint64_t pfn_t;
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096
#define READ_ONCE(x) (x)
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
enum dax_access_mode { DAX_ACCESS, DAX_RECOVERY_WRITE };
struct pmem_extent { u64 offset, bytes; void *address; bool is_vmap; };
struct pmem_volume {
    u64 bytes;
    struct pmem_extent *extents;
    u32 nr_extents;
    bool dying;
    uint64_t dax_accesses, dax_span_bytes;
};
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

int main(void)
{
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
