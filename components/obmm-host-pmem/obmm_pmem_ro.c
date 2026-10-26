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
#include "obmm_core.h"
#include "obmm_pmem_ro.h"
#include "obmm_pmem_uapi.h"

extern const struct file_operations obmm_shm_fops;
#define PMEM_MAX_EXTENTS 1024
#define PMEM_MAX_BYTES (16ULL << 30)
static_assert(sizeof(struct obmm_pmem_segment) == 24);
static_assert(sizeof(struct obmm_pmem_create) == 792);
static_assert(sizeof(struct obmm_pmem_status) == 96);

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
	struct obmm_region *regions[OBMM_PMEM_MAX_SEGMENTS];
	u32 nr_regions, nr_sealed, nr_extents;
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
module_param(pmem_ro_enable, bool, 0444);
MODULE_PARM_DESC(pmem_ro_enable, "Enable experimental readonly OBMM block/DAX frontend (default off)");
static DEFINE_MUTEX(volumes_lock);
static LIST_HEAD(volumes);
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

static int read_bytes(struct pmem_volume *v, void *destination, u64 offset, size_t bytes)
{
	if (offset > v->bytes || bytes > v->bytes - offset)
		return -EINVAL;
	while (bytes) {
		struct pmem_extent *e = find_extent(v, offset);
		size_t count;
		if (!e)
			return -EIO;
		count = min_t(u64, bytes, e->bytes - (offset - e->offset));
		if (copy_mc_to_kernel(destination, e->address + offset - e->offset, count))
			return -EIO;
		destination += count;
		offset += count;
		bytes -= count;
	}
	return 0;
}

static void pmem_submit_bio(struct bio *bio)
{
	struct pmem_volume *v = bio->bi_bdev->bd_disk->private_data;
	struct bio_vec bv;
	struct bvec_iter iter;
	unsigned long flags;
	u64 sector = (u64)bio->bi_iter.bi_sector;
	u64 offset = sector << SECTOR_SHIFT;
	u32 bytes = bio->bi_iter.bi_size;
	int ret = 0;

	spin_lock_irqsave(&v->lock, flags);
	if (v->dying) {
		spin_unlock_irqrestore(&v->lock, flags);
		bio_io_error(bio);
		return;
	}
	atomic_inc(&v->active_io);
	spin_unlock_irqrestore(&v->lock, flags);
	if (bio_op(bio) != REQ_OP_READ || sector > (v->bytes >> SECTOR_SHIFT) ||
	    offset > v->bytes || bytes > v->bytes - offset) {
		ret = -EIO;
		goto done;
	}
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
	u64 offset;
	long available;
	/* read_iter asks for kaddr without a PFN. Never invent devmap pages. */
	if (pfn || !kaddr || mode != DAX_ACCESS)
		return -EOPNOTSUPP;
	if (READ_ONCE(v->dying))
		return -ENXIO;
	if (pages <= 0 || (u64)pgoff >= (v->bytes >> PAGE_SHIFT))
		return -EINVAL;
	offset = (u64)pgoff << PAGE_SHIFT;
	e = find_extent(v, offset);
	if (!e)
		return -EIO;
	available = min_t(u64, pages, (e->bytes - (offset - e->offset)) >> PAGE_SHIFT);
	*kaddr = e->address + offset - e->offset;
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
	u32 i;
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
	pgprot_t prot = pgprot_writecombine(PAGE_KERNEL_RO);
	unsigned long count = bytes >> PAGE_SHIFT, i;
	struct page **pages;
	void *address;
	phys_addr_t end;
	if (!bytes || !IS_ALIGNED(pa, PAGE_SIZE) || !IS_ALIGNED(bytes, PAGE_SIZE) ||
	    v->nr_extents == PMEM_MAX_EXTENTS || bytes > PMEM_MAX_BYTES - v->bytes ||
	    check_add_overflow(pa, (phys_addr_t)bytes, &end))
		return -EINVAL;
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

static int create_volume(const struct obmm_pmem_create *request)
{
	struct pmem_volume *v;
	u32 i, j;
	u64 total = 0;
	int ret = -EINVAL;
	if (request->version != OBMM_PMEM_ABI || !request->count ||
	    request->count > OBMM_PMEM_MAX_SEGMENTS || !memchr_inv(request->uuid, 0, 16))
		return -EINVAL;
	if (lookup_volume(request->uuid))
		return -EEXIST; /* Lost CREATE reply: query this UUID, never retry allocation. */
	v = kzalloc(sizeof(*v), GFP_KERNEL);
	if (!v)
		return -ENOMEM;
	v->extents = kcalloc(PMEM_MAX_EXTENTS, sizeof(*v->extents), GFP_KERNEL);
	if (!v->extents) {
		kfree(v);
		return -ENOMEM;
	}
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
		if (r->pmem_views || atomic_read(&r->pmem_nc_writers) || r->mmap_mode == OBMM_MMAP_NORMAL) {
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
	struct pmem_volume *v;
	unsigned long flags;
	void __user *user = (void __user *)argument;
	long ret;
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
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
	status.state = 1; /* Serving; no claim of peer state or physical savings. */
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
	WARN_ON(!list_empty(&volumes));
	if (pmem_ro_enable)
		misc_deregister(&pmem_control);
	ida_destroy(&volume_ids);
}
