// SPDX-License-Identifier: GPL-2.0-only
/* Experimental OBMM-owned readonly block/DAX read_iter frontend.
 * Compiled inside obmm.ko against the pinned baseline, disabled by default.
 * No System RAM registration, dev_pagemap, writable DAX or PFN handoff.
 */
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/capability.h>
#include <linux/dax.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/idr.h>
#include <linux/io.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <crypto/sha2.h>
#include "obmm_core.h"
#include "obmm_pmem_ro.h"
#include "obmm_pmem_uapi.h"

extern const struct file_operations obmm_shm_fops;
#define PMEM_MAX_EXTENTS 1024
#define PMEM_MAX_BYTES (16ULL << 30)
static_assert(sizeof(struct obmm_pmem_segment) == 24);
static_assert(sizeof(struct obmm_pmem_create) == 792);
static_assert(sizeof(struct obmm_pmem_status) == 96);
static_assert(sizeof(struct obmm_pmem_sparse_create) == 40);
static_assert(sizeof(struct obmm_pmem_install) == 56);
static_assert(sizeof(struct obmm_pmem_range_status) == 48);
static_assert(sizeof(struct obmm_pmem_miss) == 40);
static_assert(sizeof(struct obmm_pmem_pool_create) == 48);
static_assert(sizeof(struct obmm_pmem_pool_fill) == 72);
static_assert(sizeof(struct obmm_pmem_pool_slot) == 72);
static_assert(sizeof(struct obmm_pmem_pool_bind) == 88);

struct pmem_slot {
	u32 bytes;
	u8 state;
	u8 sha256[SHA256_DIGEST_SIZE];
};

struct pmem_extent {
	u64 offset, bytes;
	void *address;
	bool is_vmap;
};
struct pmem_volume {
	struct list_head node;
	u8 uuid[16];
	int id;
	u64 bytes;
	/* Sparse parent owns immutable backing children until device destruction.
	 * Fixed 4 GiB / 256 KiB indexing costs 128 KiB on a 64-bit host, not 4 GiB.
	 * Published pointers are never replaced or freed while readers can exist.
	 */
	u64 image_bytes, logical_offset;
	struct pmem_volume **units;
	/* 0 absent, 1 pending, 2 claimed, 3 terminal failure. READY is units[i]. */
	u8 *miss_states;
	wait_queue_head_t miss_wait;
	struct list_head backings;
	/* Pool children borrow backing; volumes_lock serializes pool references. */
	struct pmem_volume *pool_parent;
	u64 pool_offset, pool_refs;
	bool controlled_writer;
	struct pmem_slot *slots;
	struct obmm_region *regions[OBMM_PMEM_MAX_SEGMENTS];
	u32 nr_regions, nr_sealed, nr_extents, extent_capacity;
	struct pmem_extent *extents;
	struct gendisk *disk;
	struct dax_device *dax;
	spinlock_t lock;
	bool dying;
	u64 openers;
	atomic_t active_io;
	wait_queue_head_t idle;
	atomic64_t block_reads, block_bytes, dax_accesses, dax_span_bytes;
};

static bool pmem_ro_enable;
static bool pmem_demand_write_enable;
module_param(pmem_ro_enable, bool, 0444);
module_param(pmem_demand_write_enable, bool, 0444);
MODULE_PARM_DESC(pmem_demand_write_enable, "Allow root-controlled one-time demand pool writes (default off)");
MODULE_PARM_DESC(pmem_ro_enable, "Enable experimental readonly OBMM block/DAX frontend (default off)");
static DEFINE_MUTEX(volumes_lock);
static LIST_HEAD(volumes);
static LIST_HEAD(pools);
static DEFINE_IDA(volume_ids);

static struct pmem_extent *find_extent(struct pmem_volume *v, u64 offset)
{
	u32 i;
	for (i = 0; i < v->nr_extents; i++) {
		struct pmem_extent *e = &v->extents[i];
		if (offset >= e->offset && offset - e->offset < e->bytes)
			return e;
	}
	return NULL;
}

static struct pmem_extent *resolve_extent(struct pmem_volume *v, u64 offset,
					 u64 *within)
{
	struct pmem_extent *e;
	if (v->units) {
		struct pmem_volume *backing;
		if (offset >= v->image_bytes)
			return NULL;
		backing = smp_load_acquire(&v->units[offset / OBMM_PMEM_LOAD_BYTES]);
		if (!backing)
			return NULL; /* Missing is an error until the miss service is connected. */
		offset -= backing->logical_offset;
		if (backing->pool_parent) {
			offset += backing->pool_offset;
			v = backing->pool_parent;
		} else {
			v = backing;
		}
	}
	e = find_extent(v, offset);
	if (e)
		*within = offset - e->offset;
	return e;
}

/* Only called in process context: DAX read_iter or the sparse bio worker.
 * It never holds volumes_lock while waiting for the userspace loader.
 * The immutable backing survives until the existing DAX/bio teardown barrier.
 */
static int wait_range(struct pmem_volume *v, u64 offset, u64 bytes)
{
	u64 i, last;
	unsigned long flags;
	long remaining = msecs_to_jiffies(30000);
	if (!v->units)
		return 0;
	if (offset > v->image_bytes || bytes > v->image_bytes - offset)
		return -EIO;
	if (!bytes)
		return 0;
	last = (offset + bytes - 1) / OBMM_PMEM_LOAD_BYTES;
	for (i = offset / OBMM_PMEM_LOAD_BYTES; i <= last; i++) {
		if (smp_load_acquire(&v->units[i]))
			continue;
		spin_lock_irqsave(&v->lock, flags);
		if (!v->miss_states[i])
			WRITE_ONCE(v->miss_states[i], 1);
		spin_unlock_irqrestore(&v->lock, flags);
		remaining = wait_event_interruptible_timeout(v->miss_wait,
			READ_ONCE(v->dying) || smp_load_acquire(&v->units[i]) ||
			READ_ONCE(v->miss_states[i]) == 3, remaining);
		if (READ_ONCE(v->dying))
			return -ENXIO;
		if (remaining < 0)
			return (int)remaining;
		if (!remaining)
			return -ETIMEDOUT;
		if (READ_ONCE(v->miss_states[i]) == 3)
			return -EIO;
	}
	return 0;
}

static int read_bytes(struct pmem_volume *v, void *destination, u64 offset, size_t bytes)
{
	if (offset > v->bytes || bytes > v->bytes - offset)
		return -EINVAL;
	while (bytes) {
		u64 within;
		struct pmem_extent *e = resolve_extent(v, offset, &within);
		size_t count;
		if (!e)
			return -EIO;
		count = min_t(u64, bytes, e->bytes - within);
		if (v->units)
			count = min_t(u64, count, OBMM_PMEM_LOAD_BYTES - offset % OBMM_PMEM_LOAD_BYTES);
		if (v->units)
			count = min_t(u64, count, v->image_bytes - offset);
		if (copy_mc_to_kernel(destination, e->address + within, count))
			return -EIO;
		destination += count;
		offset += count;
		bytes -= count;
	}
	return 0;
}

static void pmem_run_bio(struct bio *bio)
{
	struct pmem_volume *v = bio->bi_bdev->bd_disk->private_data;
	struct bio_vec bv;
	struct bvec_iter iter;
	u64 sector = (u64)bio->bi_iter.bi_sector;
	u64 offset = sector << SECTOR_SHIFT;
	u32 bytes = bio->bi_iter.bi_size;
	int ret = 0;

	if (bio_op(bio) != REQ_OP_READ || sector > (v->bytes >> SECTOR_SHIFT) ||
	    offset > v->bytes || bytes > v->bytes - offset) {
		ret = -EIO;
		goto done;
	}
	/* Must wait before kmap_local_page or copying any partial bio payload. */
	ret = wait_range(v, offset, bytes);
	if (ret)
		goto done;
	bio_for_each_segment(bv, bio, iter) {
		struct page *page = bv.bv_page;
		unsigned int left = bv.bv_len, page_offset = bv.bv_offset;
		while (left) {
			unsigned int count = min_t(unsigned int, left, PAGE_SIZE - page_offset);
			void *destination = kmap_local_page(page);
			ret = read_bytes(v, destination + page_offset, offset, count);
			kunmap_local(destination);
			if (ret)
				goto done;
			flush_dcache_page(page);
			offset += count;
			left -= count;
			page_offset = 0;
			page++;
		}
	}
	atomic64_inc(&v->block_reads);
	atomic64_add(bytes, &v->block_bytes);
done:
	if (ret)
		bio->bi_status = BLK_STS_IOERR;
	bio_endio(bio);
	if (atomic_dec_and_test(&v->active_io))
		wake_up_all(&v->idle);
}

struct pmem_bio_work {
	struct work_struct work;
	struct bio *bio;
};

static void pmem_bio_worker(struct work_struct *work)
{
	struct pmem_bio_work *item = container_of(work, struct pmem_bio_work, work);
	pmem_run_bio(item->bio);
	kfree(item);
}

static void pmem_submit_bio(struct bio *bio)
{
	struct pmem_volume *v = bio->bi_bdev->bd_disk->private_data;
	struct pmem_bio_work *item;
	unsigned long flags;
	spin_lock_irqsave(&v->lock, flags);
	if (v->dying) {
		spin_unlock_irqrestore(&v->lock, flags);
		bio_io_error(bio);
		return;
	}
	atomic_inc(&v->active_io); /* Pins v before the work can be scheduled. */
	spin_unlock_irqrestore(&v->lock, flags);
	if (!v->units) {
		pmem_run_bio(bio);
		return;
	}
	item = kmalloc(sizeof(*item), GFP_ATOMIC);
	if (!item) {
		bio_io_error(bio);
		if (atomic_dec_and_test(&v->active_io))
			wake_up_all(&v->idle);
		return;
	}
	item->bio = bio;
	INIT_WORK(&item->work, pmem_bio_worker);
	queue_work(system_unbound_wq, &item->work);
}

static int pmem_open(struct gendisk *disk, blk_mode_t mode)
{
	struct pmem_volume *v = disk->private_data;
	unsigned long flags;
	int ret = 0;
	spin_lock_irqsave(&v->lock, flags);
	if (v->dying)
		ret = -ENXIO;
	else if (mode & BLK_OPEN_WRITE)
		ret = -EROFS;
	else
		v->openers++;
	spin_unlock_irqrestore(&v->lock, flags);
	return ret;
}

static void pmem_release(struct gendisk *disk)
{
	struct pmem_volume *v = disk->private_data;
	unsigned long flags;
	spin_lock_irqsave(&v->lock, flags);
	if (!WARN_ON(!v->openers))
		v->openers--;
	spin_unlock_irqrestore(&v->lock, flags);
}

static const struct block_device_operations pmem_fops = {
	.owner = THIS_MODULE, .open = pmem_open, .release = pmem_release,
	.submit_bio = pmem_submit_bio,
};

static long pmem_direct_access(struct dax_device *dax, pgoff_t pgoff,
		long pages, enum dax_access_mode mode, void **kaddr, pfn_t *pfn)
{
	struct pmem_volume *v = dax_get_private(dax);
	struct pmem_extent *e;
	u64 offset, within;
	long available;
	int ret;
	/* read_iter asks for kaddr without a PFN. Never invent devmap pages. */
	if (pfn || !kaddr || mode != DAX_ACCESS)
		return -EOPNOTSUPP;
	if (READ_ONCE(v->dying))
		return -ENXIO;
	if (pages <= 0 || (u64)pgoff >= (v->bytes >> PAGE_SHIFT))
		return -EINVAL;
	offset = (u64)pgoff << PAGE_SHIFT;
	ret = wait_range(v, offset, PAGE_SIZE);
	if (ret)
		return ret;
	e = resolve_extent(v, offset, &within);
	if (!e)
		return -EIO;
	available = min_t(u64, pages, (e->bytes - within) >> PAGE_SHIFT);
	if (v->units)
		available = min_t(u64, available,
			(OBMM_PMEM_LOAD_BYTES - offset % OBMM_PMEM_LOAD_BYTES) >> PAGE_SHIFT);
	if (v->units)
		available = min_t(u64, available, (v->image_bytes - offset) >> PAGE_SHIFT);
	*kaddr = e->address + within;
	atomic64_inc(&v->dax_accesses);
	/* Accessible spans, not bytes proven consumed by userspace or residency. */
	atomic64_add((u64)available << PAGE_SHIFT, &v->dax_span_bytes);
	return available;
}

static int pmem_zero(struct dax_device *dax, pgoff_t offset, size_t pages)
{
	return -EROFS;
}

static const struct dax_operations pmem_dax_ops = {
	.direct_access = pmem_direct_access, .zero_page_range = pmem_zero,
};

static void release_backing(struct pmem_volume *v)
{
	struct pmem_volume *backing, *next;
	u32 i;
	if (v->pool_parent) {
		WARN_ON(!v->pool_parent->pool_refs);
		v->pool_parent->pool_refs--;
		kfree(v);
		return;
	}
	list_for_each_entry_safe(backing, next, &v->backings, node) {
		list_del(&backing->node);
		release_backing(backing);
	}
	kfree(v->units);
	kfree(v->miss_states);
	kvfree(v->slots);
	for (i = v->nr_extents; i; i--) {
		struct pmem_extent *e = &v->extents[i - 1];
		if (e->is_vmap)
			vunmap(e->address);
		else
			iounmap((void __iomem *)e->address);
	}
	for (i = 0; i < v->nr_sealed; i++) {
		struct obmm_region *r = v->regions[i];
		mutex_lock(&r->state_mutex);
		r->pmem_views--;
		if (!r->pmem_views && !atomic_read(&r->mmap_count))
			r->mmap_mode = OBMM_MMAP_INIT;
		/* A seal is irreversible for this region lifetime, including failure. */
		mutex_unlock(&r->state_mutex);
	}
	for (i = 0; i < v->nr_regions; i++)
		put_obmm_region(v->regions[i]);
	kfree(v->extents);
	kfree(v);
}

static int add_extent(struct pmem_volume *v, phys_addr_t pa, u64 bytes, bool exporter)
{
	struct pmem_extent *e;
	pgprot_t prot = pgprot_writecombine(v->controlled_writer ? PAGE_KERNEL : PAGE_KERNEL_RO);
	unsigned long count = bytes >> PAGE_SHIFT, i;
	struct page **pages;
	void *address;
	phys_addr_t end;
	if (!bytes || !IS_ALIGNED(pa, PAGE_SIZE) || !IS_ALIGNED(bytes, PAGE_SIZE) ||
	    v->nr_extents == PMEM_MAX_EXTENTS || bytes > PMEM_MAX_BYTES - v->bytes ||
	    check_add_overflow(pa, (phys_addr_t)bytes, &end))
		return -EINVAL;
	/* A small installed range must not allocate the full 1024-extent table.
	 * This table is built before publication and never resized by readers.
	 */
	if (v->nr_extents == v->extent_capacity) {
		u32 capacity = min_t(u32, PMEM_MAX_EXTENTS,
				    v->extent_capacity ? v->extent_capacity * 2 : 4);
		struct pmem_extent *grown = krealloc_array(v->extents, capacity,
							 sizeof(*grown), GFP_KERNEL);
		if (!grown)
			return -ENOMEM;
		v->extents = grown;
		v->extent_capacity = capacity;
	}
	if (exporter) {
		pages = kvmalloc_array(count, sizeof(*pages), GFP_KERNEL);
		if (!pages)
			return -ENOMEM;
		for (i = 0; i < count; i++) {
			unsigned long pfn = PHYS_PFN(pa) + i;
			if (!pfn_valid(pfn)) {
				kvfree(pages);
				return -EINVAL;
			}
			pages[i] = pfn_to_page(pfn);
		}
		address = vmap(pages, count, VM_MAP, prot);
		kvfree(pages);
	} else {
		address = (__force void *)ioremap_prot(pa, bytes, pgprot_val(prot));
	}
	if (!address)
		return -ENOMEM;
	e = &v->extents[v->nr_extents++];
	e->offset = v->bytes;
	e->bytes = bytes;
	e->address = address;
	e->is_vmap = exporter;
	v->bytes += bytes;
	return 0;
}

static int map_region(struct pmem_volume *v, struct obmm_region *r, u64 offset, u64 bytes)
{
	struct scatterlist *sg;
	u32 i;
	int ret;
	if (r->type == OBMM_IMPORT_REGION) {
		struct obmm_import_region *import = container_of(r, struct obmm_import_region, region);
		return add_extent(v, import->pa + offset, bytes, false);
	}
	for_each_sgtable_sg(&container_of(r, struct obmm_export_region, region)->sgt, sg, i) {
		u64 count;
		if (offset >= sg->length) {
			offset -= sg->length;
			continue;
		}
		count = min_t(u64, bytes, sg->length - offset);
		ret = add_extent(v, sg_phys(sg) + offset, count, true);
		if (ret)
			return ret;
		bytes -= count;
		offset = 0;
		if (!bytes)
			return 0;
	}
	return -EINVAL;
}

static struct pmem_volume *lookup_volume(const u8 uuid[16])
{
	struct pmem_volume *v;
	list_for_each_entry(v, &volumes, node)
		if (!memcmp(uuid, v->uuid, 16))
			return v;
	return NULL;
}

static struct pmem_volume *prepare_backing(const struct obmm_pmem_create *request, bool writer)
{
	struct pmem_volume *v;
	u32 i, j;
	u64 total = 0;
	int ret = -EINVAL;
	if (request->version != OBMM_PMEM_ABI || !request->count ||
	    request->count > OBMM_PMEM_MAX_SEGMENTS || !memchr_inv(request->uuid, 0, 16))
		return ERR_PTR(-EINVAL);
	v = kzalloc(sizeof(*v), GFP_KERNEL);
	if (!v)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&v->backings);
	v->controlled_writer = writer;
	memcpy(v->uuid, request->uuid, 16);
	spin_lock_init(&v->lock);
	init_waitqueue_head(&v->idle);
	atomic_set(&v->active_io, 0);
	for (i = 0; i < request->count; i++) {
		const struct obmm_pmem_segment *s = &request->segments[i];
		struct obmm_region *r;
		struct file *file;
		if (s->reserved || !s->bytes || !IS_ALIGNED(s->offset, PAGE_SIZE) ||
		    !IS_ALIGNED(s->bytes, PAGE_SIZE) || s->bytes > PMEM_MAX_BYTES - total)
			goto fail;
		file = fget(s->fd);
		if (!file)
			goto fail;
		if (file->f_op != &obmm_shm_fops || !(file->f_mode & FMODE_READ) ||
		    (file->f_mode & FMODE_WRITE) || (file->f_flags & O_SYNC) != O_SYNC) {
			fput(file);
			goto fail;
		}
		r = try_get_obmm_region(file->private_data);
		fput(file);
		if (!r)
			goto fail;
		v->regions[v->nr_regions++] = r;
		if (region_numa_remote(r) || region_memory_from_user(r) ||
		    !(r->mem_cap & OBMM_MEM_ALLOW_NONCACHEABLE_MMAP) ||
		    s->offset > r->mem_size || s->bytes > r->mem_size - s->offset)
			goto fail;
		for (j = 0; j < i; j++)
			if (v->regions[j] == r)
				goto fail;
		total += s->bytes;
	}
	/* Serialize against mmap. Existing readonly NC SDK anchors may remain. */
	for (i = 0; i < v->nr_regions; i++) {
		struct obmm_region *r = v->regions[i];
		mutex_lock(&r->state_mutex);
		if (r->pmem_views || atomic_read(&r->pmem_nc_writers) ||
		    r->mmap_mode == OBMM_MMAP_NORMAL || (writer && r->pmem_sealed)) {
			mutex_unlock(&r->state_mutex);
			ret = -EBUSY;
			goto fail;
		}
		r->pmem_sealed = true;
		r->pmem_views++;
		r->mmap_mode = OBMM_MMAP_OSYNC;
		v->nr_sealed++;
		mutex_unlock(&r->state_mutex);
	}
	for (i = 0; i < v->nr_regions; i++) {
		ret = map_region(v, v->regions[i], request->segments[i].offset, request->segments[i].bytes);
		if (ret)
			goto fail;
	}
	return v;
fail:
	release_backing(v);
	return ERR_PTR(ret);
}

static int register_volume(struct pmem_volume *v)
{
	int ret;
	v->id = ida_alloc(&volume_ids, GFP_KERNEL);
	if (v->id < 0) {
		ret = v->id;
		goto fail;
	}
	v->disk = blk_alloc_disk(NUMA_NO_NODE);
	if (!v->disk) {
		ret = -ENOMEM;
		goto free_id;
	}
	v->disk->fops = &pmem_fops;
	v->disk->private_data = v;
	v->disk->flags |= GENHD_FL_NO_PART;
	snprintf(v->disk->disk_name, DISK_NAME_LEN, "ubpmem_ro%d", v->id);
	set_capacity(v->disk, v->bytes >> SECTOR_SHIFT);
	set_disk_ro(v->disk, true);
	blk_queue_logical_block_size(v->disk->queue, PAGE_SIZE);
	blk_queue_physical_block_size(v->disk->queue, PAGE_SIZE);
	blk_queue_flag_set(QUEUE_FLAG_DAX, v->disk->queue);
	blk_queue_flag_set(QUEUE_FLAG_SYNCHRONOUS, v->disk->queue);
	v->dax = alloc_dax(v, &pmem_dax_ops);
	if (IS_ERR(v->dax)) {
		ret = PTR_ERR(v->dax);
		goto put_disk;
	}
	set_dax_nomc(v->dax);
	ret = dax_add_host(v->dax, v->disk);
	if (ret)
		goto put_dax;
	ret = add_disk(v->disk);
	if (ret)
		goto remove_host;
	/* A persistent device, not its creating process, owns this reference. */
	__module_get(THIS_MODULE);
	list_add_tail(&v->node, &volumes);
	return 0;
remove_host:
	dax_remove_host(v->disk);
put_dax:
	kill_dax(v->dax);
	put_dax(v->dax);
put_disk:
	put_disk(v->disk);
free_id:
	ida_free(&volume_ids, v->id);
fail:
	release_backing(v);
	return ret;
}

static int create_volume(const struct obmm_pmem_create *request)
{
	struct pmem_volume *v;
	if (lookup_volume(request->uuid))
		return -EEXIST;
	v = prepare_backing(request, false);
	return IS_ERR(v) ? PTR_ERR(v) : register_volume(v);
}

static int create_sparse_volume(const struct obmm_pmem_sparse_create *request)
{
	struct pmem_volume *v;
	if (request->version != OBMM_PMEM_ABI || request->reserved ||
	    !memchr_inv(request->uuid, 0, 16) ||
	    request->logical_bytes != OBMM_PMEM_DEMAND_BYTES ||
	    !request->image_bytes || request->image_bytes > request->logical_bytes ||
	    !IS_ALIGNED(request->image_bytes, PAGE_SIZE) ||
	    OBMM_PMEM_LOAD_BYTES % PAGE_SIZE)
		return -EINVAL;
	if (lookup_volume(request->uuid))
		return -EEXIST;
	v = kzalloc(sizeof(*v), GFP_KERNEL);
	if (!v)
		return -ENOMEM;
	INIT_LIST_HEAD(&v->backings);
	v->units = kcalloc(OBMM_PMEM_DEMAND_BYTES / OBMM_PMEM_LOAD_BYTES,
			   sizeof(*v->units), GFP_KERNEL);
	if (!v->units) {
		kfree(v);
		return -ENOMEM;
	}
	v->miss_states = kcalloc(OBMM_PMEM_DEMAND_BYTES / OBMM_PMEM_LOAD_BYTES, 1, GFP_KERNEL);
	if (!v->miss_states) {
		release_backing(v);
		return -ENOMEM;
	}
	init_waitqueue_head(&v->miss_wait);
	memcpy(v->uuid, request->uuid, 16);
	v->bytes = request->logical_bytes;
	v->image_bytes = request->image_bytes;
	spin_lock_init(&v->lock);
	init_waitqueue_head(&v->idle);
	atomic_set(&v->active_io, 0);
	return register_volume(v);
}

/* Called with volumes_lock. No replacement/eviction in the first revision. */
static int install_backing(const struct obmm_pmem_install *request)
{
	struct obmm_pmem_create *create;
	struct pmem_volume *v, *backing;
	u64 end, first, last, i;
	if (request->version != OBMM_PMEM_ABI || request->reserved ||
	    !request->segment.bytes || !IS_ALIGNED(request->logical_offset, OBMM_PMEM_LOAD_BYTES) ||
	    check_add_overflow(request->logical_offset, request->segment.bytes, &end))
		return -EINVAL;
	v = lookup_volume(request->uuid);
	if (!v || !v->units || READ_ONCE(v->dying))
		return -ENODEV;
	if (end > v->image_bytes || (!IS_ALIGNED(end, OBMM_PMEM_LOAD_BYTES) && end != v->image_bytes))
		return -EINVAL;
	first = request->logical_offset / OBMM_PMEM_LOAD_BYTES;
	last = DIV_ROUND_UP_ULL(end, OBMM_PMEM_LOAD_BYTES);
	for (i = first; i < last; i++)
		if (v->units[i] || READ_ONCE(v->miss_states[i]) == 3)
			return -EEXIST; /* Never reinterpret an occupied range after a lost reply. */
	create = kzalloc(sizeof(*create), GFP_KERNEL);
	if (!create)
		return -ENOMEM;
	create->version = OBMM_PMEM_ABI;
	create->count = 1;
	memcpy(create->uuid, request->uuid, 16);
	create->segments[0] = request->segment;
	backing = prepare_backing(create, false);
	kfree(create);
	if (IS_ERR(backing))
		return PTR_ERR(backing);
	backing->logical_offset = request->logical_offset;
	list_add_tail(&backing->node, &v->backings);
	/* No fallible operations after publication. Each visible span is complete.
	 * Backing stays immutable until kill_dax and active bio drain at destroy.
	 */
	for (i = first; i < last; i++)
		smp_store_release(&v->units[i], backing);
	wake_up_all(&v->miss_wait);
	return 0;
}

/* All arena control operations hold volumes_lock. A pool is not a disk,
 * mount or new allocation: it owns an existing OBMM region and its seal.
 */
static struct pmem_volume *lookup_pool(const u8 uuid[16])
{
	struct pmem_volume *pool;
	list_for_each_entry(pool, &pools, node)
		if (!memcmp(pool->uuid, uuid, 16))
			return pool;
	return NULL;
}

static int create_pool(const struct obmm_pmem_pool_create *request)
{
	struct obmm_pmem_create *create;
	struct pmem_volume *pool;
	if (request->version != OBMM_PMEM_ABI || request->writer > 1 ||
	    (request->writer && !pmem_demand_write_enable) ||
	    !request->segment.bytes || request->segment.bytes > OBMM_PMEM_DEMAND_BYTES ||
	    !IS_ALIGNED(request->segment.bytes, OBMM_PMEM_LOAD_BYTES) ||
	    !IS_ALIGNED(request->segment.offset, OBMM_PMEM_LOAD_BYTES))
		return -EINVAL;
	if (lookup_pool(request->uuid))
		return -EEXIST;
	create = kzalloc(sizeof(*create), GFP_KERNEL);
	if (!create)
		return -ENOMEM;
	create->version = OBMM_PMEM_ABI;
	create->count = 1;
	memcpy(create->uuid, request->uuid, 16);
	create->segments[0] = request->segment;
	pool = prepare_backing(create, request->writer != 0);
	kfree(create);
	if (IS_ERR(pool))
		return PTR_ERR(pool);
	pool->slots = kvcalloc(pool->bytes / OBMM_PMEM_LOAD_BYTES, sizeof(*pool->slots), GFP_KERNEL);
	if (!pool->slots) {
		release_backing(pool);
		return -ENOMEM;
	}
	__module_get(THIS_MODULE);
	list_add_tail(&pool->node, &pools);
	return 0;
}

static int fill_pool(const struct obmm_pmem_pool_fill *request, bool write, const u8 *payload)
{
	struct pmem_volume *pool = lookup_pool(request->uuid);
	struct pmem_slot *slot;
	u8 *data, *observed;
	u8 digest[SHA256_DIGEST_SIZE];
	u64 at, left;
	int ret = 0;
	if (request->version != OBMM_PMEM_ABI || !pool ||
	    write != pool->controlled_writer || (write && !pmem_demand_write_enable) ||
	    !IS_ALIGNED(request->slot_offset, OBMM_PMEM_LOAD_BYTES) ||
	    request->slot_offset >= pool->bytes || !request->bytes ||
	    request->bytes > OBMM_PMEM_LOAD_BYTES || !IS_ALIGNED(request->bytes, PAGE_SIZE) ||
	    (write ? !request->user_data : request->user_data != 0))
		return -EINVAL;
	slot = &pool->slots[request->slot_offset / OBMM_PMEM_LOAD_BYTES];
	if (slot->state)
		return -EEXIST; /* Query state/hash; never overwrite, including after a lost ACK. */
	data = kvzalloc(OBMM_PMEM_LOAD_BYTES, GFP_KERNEL);
	observed = kvmalloc(request->bytes, GFP_KERNEL);
	if (!data || !observed) {
		ret = -ENOMEM;
		goto out;
	}
	if (write) {
		memcpy(data, payload, request->bytes);
		sha256(data, request->bytes, digest);
		if (memcmp(digest, request->sha256, sizeof(digest))) {
			ret = -EBADMSG;
			goto out;
		}
	}
	slot->state = 1;
	slot->bytes = request->bytes;
	memcpy(slot->sha256, request->sha256, sizeof(slot->sha256));
	if (write) {
		at = request->slot_offset;
		left = OBMM_PMEM_LOAD_BYTES;
		while (left) {
			struct pmem_extent *e = find_extent(pool, at);
			u64 n;
			if (!e) {
				ret = -EIO;
				goto poisoned;
			}
			n = min_t(u64, left, e->bytes - (at - e->offset));
			/* Same NC attribute as the SDK/readonly views; no WB alias. */
			memcpy_toio((void __iomem *)(e->address + at - e->offset),
				    data + at - request->slot_offset, n);
			at += n;
			left -= n;
		}
		wmb();
	}
	/* Owner write/readback and importer acceptance both verify the requested
	 * digest before READY. This is not a claim of hardware persistence or a
	 * substitute for the peer's own acceptance and global publication record.
	 */
	ret = read_bytes(pool, observed, request->slot_offset, request->bytes);
	if (ret)
		goto poisoned;
	sha256(observed, request->bytes, digest);
	if (memcmp(digest, request->sha256, sizeof(digest))) {
		ret = -EBADMSG;
		goto poisoned;
	}
	slot->state = 2;
	goto out;
poisoned:
	slot->state = 3;
out:
	kvfree(observed);
	kvfree(data);
	return ret;
}

static int bind_pool(const struct obmm_pmem_pool_bind *request)
{
	struct pmem_volume *v = lookup_volume(request->uuid);
	struct pmem_volume *pool = lookup_pool(request->pool_uuid);
	struct pmem_volume *backing;
	struct pmem_slot *slot;
	u64 index, bytes;
	if (request->version != OBMM_PMEM_ABI || request->reserved ||
	    !v || !v->units || !pool || READ_ONCE(v->dying) ||
	    !IS_ALIGNED(request->logical_offset, OBMM_PMEM_LOAD_BYTES) ||
	    request->logical_offset >= v->image_bytes ||
	    !IS_ALIGNED(request->slot_offset, OBMM_PMEM_LOAD_BYTES) || request->slot_offset >= pool->bytes)
		return -EINVAL;
	index = request->logical_offset / OBMM_PMEM_LOAD_BYTES;
	if (v->units[index] || READ_ONCE(v->miss_states[index]) == 3)
		return -EEXIST;
	slot = &pool->slots[request->slot_offset / OBMM_PMEM_LOAD_BYTES];
	bytes = min_t(u64, OBMM_PMEM_LOAD_BYTES, v->image_bytes - request->logical_offset);
	if (slot->state != 2 || slot->bytes != bytes ||
	    memcmp(slot->sha256, request->sha256, sizeof(slot->sha256)))
		return -ENODATA;
	backing = kzalloc(sizeof(*backing), GFP_KERNEL);
	if (!backing)
		return -ENOMEM;
	backing->pool_parent = pool;
	backing->pool_offset = request->slot_offset;
	backing->logical_offset = request->logical_offset;
	backing->bytes = bytes;
	pool->pool_refs++;
	list_add_tail(&backing->node, &v->backings);
	smp_store_release(&v->units[index], backing);
	wake_up_all(&v->miss_wait);
	return 0;
}

static int destroy_volume(struct pmem_volume *v)
{
	unsigned long flags;
	spin_lock_irqsave(&v->lock, flags);
	if (v->openers) {
		spin_unlock_irqrestore(&v->lock, flags);
		return -EBUSY; /* Do not kill a mounted/used volume to force teardown. */
	}
	v->dying = true;
	spin_unlock_irqrestore(&v->lock, flags);
	if (v->units)
		wake_up_all(&v->miss_wait);
	del_gendisk(v->disk);
	dax_remove_host(v->disk);
	kill_dax(v->dax); /* Waits for DAX SRCU readers, not ordinary bio requests. */
	wait_event(v->idle, !atomic_read(&v->active_io));
	put_dax(v->dax);
	put_disk(v->disk);
	list_del(&v->node);
	ida_free(&volume_ids, v->id);
	release_backing(v);
	module_put(THIS_MODULE);
	return 0;
}

static long pmem_ioctl(struct file *file, unsigned int command, unsigned long argument)
{
	struct obmm_pmem_status status;
	struct obmm_pmem_create create;
	struct obmm_pmem_sparse_create sparse;
	struct obmm_pmem_install install;
	struct obmm_pmem_range_status range;
	struct obmm_pmem_miss miss;
	union {
		struct obmm_pmem_pool_create create;
		struct obmm_pmem_pool_fill fill;
		struct obmm_pmem_pool_slot slot;
		struct obmm_pmem_pool_bind bind;
	} pool_request;
	struct pmem_volume *v;
	u8 *pool_payload = NULL;
	unsigned long flags;
	void __user *user = (void __user *)argument;
	long ret;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (command == OBMM_PMEM_POOL_CREATE || command == OBMM_PMEM_POOL_FILL ||
	    command == OBMM_PMEM_POOL_ACCEPT || command == OBMM_PMEM_POOL_SLOT ||
	    command == OBMM_PMEM_POOL_BIND || command == OBMM_PMEM_POOL_DESTROY) {
		size_t size = command == OBMM_PMEM_POOL_CREATE ? sizeof(pool_request.create) :
			command == OBMM_PMEM_POOL_BIND ? sizeof(pool_request.bind) : sizeof(pool_request.fill);
		if (copy_from_user(&pool_request, user, size))
			return -EFAULT;
		/* Fault user pages before volumes_lock: a caller's source buffer must
		 * not block all mapping installs while waiting on a userspace fault.
		 */
		if (command == OBMM_PMEM_POOL_FILL) {
			if (!pool_request.fill.bytes || pool_request.fill.bytes > OBMM_PMEM_LOAD_BYTES)
				return -EINVAL;
			pool_payload = kvmalloc(pool_request.fill.bytes, GFP_KERNEL);
			if (!pool_payload)
				return -ENOMEM;
			if (copy_from_user(pool_payload, u64_to_user_ptr(pool_request.fill.user_data), pool_request.fill.bytes)) {
				kvfree(pool_payload);
				return -EFAULT;
			}
		}
		mutex_lock(&volumes_lock);
		if (command == OBMM_PMEM_POOL_CREATE) {
			ret = create_pool(&pool_request.create);
		} else if (command == OBMM_PMEM_POOL_FILL || command == OBMM_PMEM_POOL_ACCEPT) {
			ret = fill_pool(&pool_request.fill, command == OBMM_PMEM_POOL_FILL, pool_payload);
		} else if (command == OBMM_PMEM_POOL_BIND) {
			ret = bind_pool(&pool_request.bind);
		} else {
			struct obmm_pmem_pool_slot *q = &pool_request.slot;
			struct pmem_volume *pool = lookup_pool(q->uuid);
			struct pmem_slot *slot;
			if (!pool) {
				ret = -ENOENT;
				goto unlock;
			}
			if (q->version != OBMM_PMEM_ABI || q->state || q->bytes || q->reserved ||
			    memchr_inv(q->sha256, 0, sizeof(q->sha256)) || !pool ||
			    !IS_ALIGNED(q->slot_offset, OBMM_PMEM_LOAD_BYTES) || q->slot_offset >= pool->bytes) {
				ret = -EINVAL;
				goto unlock;
			}
			if (command == OBMM_PMEM_POOL_DESTROY) {
				if (q->slot_offset || pool->pool_refs) {
					ret = -EBUSY;
					goto unlock;
				}
				list_del(&pool->node);
				release_backing(pool);
				module_put(THIS_MODULE);
				ret = 0;
			} else {
				slot = &pool->slots[q->slot_offset / OBMM_PMEM_LOAD_BYTES];
				q->state = slot->state;
				q->bytes = slot->bytes;
				memcpy(q->sha256, slot->sha256, sizeof(q->sha256));
				ret = copy_to_user(user, q, sizeof(*q)) ? -EFAULT : 0;
			}
		}
		goto unlock;
	}
	if (command == OBMM_PMEM_GET_MISS || command == OBMM_PMEM_FAIL_MISS) {
		u64 i, units;
		if (copy_from_user(&miss, user, sizeof(miss)))
			return -EFAULT;
		if (miss.version != OBMM_PMEM_ABI || miss.reserved)
			return -EINVAL;
		mutex_lock(&volumes_lock);
		v = lookup_volume(miss.uuid);
		if (!v || !v->units || READ_ONCE(v->dying)) {
			ret = -ENODEV;
			goto unlock;
		}
		units = DIV_ROUND_UP_ULL(v->image_bytes, OBMM_PMEM_LOAD_BYTES);
		if (command == OBMM_PMEM_FAIL_MISS) {
			if (!IS_ALIGNED(miss.logical_offset, OBMM_PMEM_LOAD_BYTES) ||
			    miss.logical_offset >= v->image_bytes ||
			    miss.bytes != min_t(u64, OBMM_PMEM_LOAD_BYTES, v->image_bytes - miss.logical_offset)) {
				ret = -EINVAL;
				goto unlock;
			}
			i = miss.logical_offset / OBMM_PMEM_LOAD_BYTES;
			spin_lock_irqsave(&v->lock, flags);
			if (v->units[i] || v->miss_states[i] != 2) {
				ret = -EINVAL;
			} else {
				WRITE_ONCE(v->miss_states[i], 3);
				ret = 0;
			}
			spin_unlock_irqrestore(&v->lock, flags);
			wake_up_all(&v->miss_wait);
			goto unlock;
		}
		if (miss.logical_offset || miss.bytes) {
			ret = -EINVAL;
			goto unlock;
		}
		spin_lock_irqsave(&v->lock, flags);
		for (i = 0; i < units; i++)
			if (!v->units[i] && v->miss_states[i] == 1) {
				WRITE_ONCE(v->miss_states[i], 2);
				break;
			}
		spin_unlock_irqrestore(&v->lock, flags);
		if (i == units) {
			ret = -EAGAIN;
			goto unlock;
		}
		miss.logical_offset = i * OBMM_PMEM_LOAD_BYTES;
		miss.bytes = min_t(u64, OBMM_PMEM_LOAD_BYTES, v->image_bytes - miss.logical_offset);
		ret = copy_to_user(user, &miss, sizeof(miss)) ? -EFAULT : 0;
		goto unlock;
	}
	if (command == OBMM_PMEM_RANGE_STATUS) {
		struct pmem_volume *backing;
		if (copy_from_user(&range, user, sizeof(range)))
			return -EFAULT;
		if (range.version != OBMM_PMEM_ABI || range.state ||
		    range.mapped_offset || range.mapped_bytes ||
		    !IS_ALIGNED(range.logical_offset, OBMM_PMEM_LOAD_BYTES))
			return -EINVAL;
		mutex_lock(&volumes_lock);
		v = lookup_volume(range.uuid);
		if (!v || !v->units || range.logical_offset >= v->image_bytes) {
			ret = -EINVAL;
			goto unlock;
		}
		backing = v->units[range.logical_offset / OBMM_PMEM_LOAD_BYTES];
		if (backing) {
			range.state = 1;
			range.mapped_offset = backing->logical_offset;
			range.mapped_bytes = backing->bytes;
		} else {
			u8 state = READ_ONCE(v->miss_states[range.logical_offset / OBMM_PMEM_LOAD_BYTES]);
			range.state = state ? state + 1 : 0;
		}
		ret = copy_to_user(user, &range, sizeof(range)) ? -EFAULT : 0;
		goto unlock;
	}
	if (command == OBMM_PMEM_SPARSE_CREATE || command == OBMM_PMEM_INSTALL) {
		if (command == OBMM_PMEM_SPARSE_CREATE) {
			if (copy_from_user(&sparse, user, sizeof(sparse)))
				return -EFAULT;
		} else if (copy_from_user(&install, user, sizeof(install))) {
			return -EFAULT;
		}
		mutex_lock(&volumes_lock);
		ret = command == OBMM_PMEM_SPARSE_CREATE ? create_sparse_volume(&sparse) : install_backing(&install);
		mutex_unlock(&volumes_lock);
		return ret;
	}
	if (command == OBMM_PMEM_CREATE) {
		if (copy_from_user(&create, user, sizeof(create)))
			return -EFAULT;
		mutex_lock(&volumes_lock);
		ret = create_volume(&create);
		mutex_unlock(&volumes_lock);
		return ret;
	}
	if (command != OBMM_PMEM_STATUS && command != OBMM_PMEM_DESTROY)
		return -ENOTTY;
	if (copy_from_user(&status, user, sizeof(status)))
		return -EFAULT;
	if (status.version != OBMM_PMEM_ABI || status.reserved || !memchr_inv(status.uuid, 0, 16))
		return -EINVAL;
	mutex_lock(&volumes_lock);
	v = lookup_volume(status.uuid);
	if (!v) {
		ret = -ENOENT;
		goto unlock;
	}
	if (command == OBMM_PMEM_DESTROY) {
		ret = status.id == v->id ? destroy_volume(v) : -ESTALE;
		goto unlock;
	}
	memset(&status, 0, sizeof(status));
	status.version = OBMM_PMEM_ABI;
	memcpy(status.uuid, v->uuid, 16);
	status.id = v->id;
	status.state = v->units ? 2 : 1; /* Sparse != full; no peer/savings claim. */
	status.major = MAJOR(disk_devt(v->disk));
	status.minor = MINOR(disk_devt(v->disk));
	status.bytes = v->bytes;
	spin_lock_irqsave(&v->lock, flags);
	status.openers = v->openers;
	spin_unlock_irqrestore(&v->lock, flags);
	status.active_io = atomic_read(&v->active_io);
	status.block_reads = atomic64_read(&v->block_reads);
	status.block_bytes = atomic64_read(&v->block_bytes);
	status.dax_accesses = atomic64_read(&v->dax_accesses);
	status.dax_span_bytes = atomic64_read(&v->dax_span_bytes);
	ret = copy_to_user(user, &status, sizeof(status)) ? -EFAULT : 0;
unlock:
	mutex_unlock(&volumes_lock);
	kvfree(pool_payload);
	return ret;
}

static const struct file_operations pmem_control_fops = {
	.owner = THIS_MODULE, .unlocked_ioctl = pmem_ioctl, .llseek = no_llseek,
};
static struct miscdevice pmem_control = {
	.minor = MISC_DYNAMIC_MINOR, .name = "obmm_pmem",
	.fops = &pmem_control_fops, .mode = 0600,
};

int obmm_pmem_init(void)
{
	return pmem_ro_enable ? misc_register(&pmem_control) : 0;
}

void obmm_pmem_exit(void)
{
	/* Every volume pins THIS_MODULE; force unloading is unsupported. */
	WARN_ON(!list_empty(&volumes) || !list_empty(&pools));
	if (pmem_ro_enable)
		misc_deregister(&pmem_control);
	ida_destroy(&volume_ids);
}
