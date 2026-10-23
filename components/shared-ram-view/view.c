// SPDX-License-Identifier: GPL-2.0-only
/* Normal-page mapping core only. No UB adapter, device node or auto-allocation. */
#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/memremap.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/page_ref.h>
#include <linux/pagemap.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>

#include "view.h"

struct aenv_ram_base {
	struct mutex lock;
	atomic_t views;
	bool retiring;
	unsigned long nr_pages;
	u64 bytes;
	struct page **pages;
	struct module *source_owner;
	void *context;
	void (*release)(void *, struct page *const *, unsigned long);
};

static int compare_pages(const void *left, const void *right)
{
	unsigned long a = page_to_pfn(*(struct page *const *)left);
	unsigned long b = page_to_pfn(*(struct page *const *)right);

	return (a > b) - (a < b);
}

static int validate_pages(struct page *const *pages, unsigned long count)
{
	struct page **ordered;
	unsigned long i;
	int ret = -EINVAL;

	ordered = kvmalloc_array(count, sizeof(*ordered), GFP_KERNEL);
	if (!ordered)
		return -ENOMEM;
	for (i = 0; i < count; i++) {
		struct page *page = pages[i];

		/* The caller is a trusted kernel provider, not an unchecked pointer
		 * received through an ioctl. Do not access the physical contents.
		 */
		if (!page || is_zone_device_page(page) || PageCompound(page) || PageReserved(page) ||
		    PageOffline(page) || PageSlab(page) || PageAnon(page) ||
		    PageLRU(page) || PageLocked(page) || PageDirty(page) || PageWriteback(page) ||
		    page_mapping(page) ||
		    page_mapped(page) || page_ref_count(page) != 1)
			goto out;
#ifdef CONFIG_ARM64
		if (!pfn_is_map_memory(page_to_pfn(page)))
			goto out;
#endif
		ordered[i] = page;
	}
	sort(ordered, count, sizeof(*ordered), compare_pages, NULL);
	for (i = 1; i < count; i++) {
		if (ordered[i] == ordered[i - 1])
			goto out;
	}
	ret = 0;
out:
	kvfree(ordered);
	return ret;
}

struct aenv_ram_base *aenv_ram_base_create(const struct aenv_ram_source *source)
{
	struct aenv_ram_base *base;
	u64 bytes;
	int ret;

	if (!source || !source->pages || !source->nr_pages || !source->release ||
	    check_mul_overflow((u64)source->nr_pages, (u64)PAGE_SIZE, &bytes) ||
	    bytes > S64_MAX)
		return ERR_PTR(-EINVAL);
	if (!try_module_get(source->owner))
		return ERR_PTR(-ENODEV);
	if (!try_module_get(THIS_MODULE)) {
		module_put(source->owner);
		return ERR_PTR(-ENODEV);
	}
	ret = validate_pages(source->pages, source->nr_pages);
	if (ret)
		goto put_modules;
	base = kzalloc(sizeof(*base), GFP_KERNEL);
	if (!base) {
		ret = -ENOMEM;
		goto put_modules;
	}
	base->pages = kvmalloc_array(source->nr_pages, sizeof(*base->pages), GFP_KERNEL);
	if (!base->pages) {
		kfree(base);
		ret = -ENOMEM;
		goto put_modules;
	}
	memcpy(base->pages, source->pages, source->nr_pages * sizeof(*base->pages));
	mutex_init(&base->lock);
	atomic_set(&base->views, 0);
	base->nr_pages = source->nr_pages;
	base->bytes = bytes;
	base->source_owner = source->owner;
	base->context = source->context;
	base->release = source->release;
	return base;
put_modules:
	module_put(source->owner);
	module_put(THIS_MODULE);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(aenv_ram_base_create);

static vm_fault_t aenv_ram_fault(struct vm_fault *vmf)
{
	struct aenv_ram_base *base = vmf->vma->vm_file->private_data;
	struct page *page;

	if (vmf->pgoff >= base->nr_pages)
		return VM_FAULT_SIGBUS;
	page = base->pages[vmf->pgoff];
	get_page(page);
	vmf->page = page;
	/* Normal private-file fault handling performs CoW on writes. Do not
	 * insert a writable base PTE, use PFNMAP, or mark the KVM slot readonly.
	 * Existing mappings may fault while owner retirement waits for them.
	 */
	return 0;
}

static const struct vm_operations_struct aenv_ram_vm_ops = {
	.fault = aenv_ram_fault,
};

static int aenv_ram_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct aenv_ram_base *base = file->private_data;
	int ret = 0;

	if ((vma->vm_flags & VM_MAYSHARE) || vma->vm_pgoff >= base->nr_pages ||
	    vma_pages(vma) > base->nr_pages - vma->vm_pgoff)
		return -EINVAL;
	mutex_lock(&base->lock);
	if (base->retiring) {
		ret = -EBUSY;
		goto out;
	}
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP | VM_NOHUGEPAGE);
	vma->vm_ops = &aenv_ram_vm_ops;
out:
	mutex_unlock(&base->lock);
	return ret;
}

static ssize_t aenv_ram_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct aenv_ram_base *base = iocb->ki_filp->private_data;
	ssize_t done = 0;
	loff_t position = iocb->ki_pos;

	if (position < 0)
		return -EINVAL;
	while ((u64)position < base->bytes && iov_iter_count(to)) {
		unsigned long index = position >> PAGE_SHIFT;
		size_t offset = position & (PAGE_SIZE - 1);
		size_t count = min_t(u64, PAGE_SIZE - offset, base->bytes - position);
		size_t copied;

		count = min(count, iov_iter_count(to));
		copied = copy_page_to_iter(base->pages[index], offset, count, to);
		position += copied;
		done += copied;
		if (copied != count)
			break;
	}
	iocb->ki_pos = position;
	return done ? done : ((u64)position >= base->bytes || !iov_iter_count(to) ? 0 : -EFAULT);
}

static loff_t aenv_ram_llseek(struct file *file, loff_t offset, int whence)
{
	struct aenv_ram_base *base = file->private_data;

	return fixed_size_llseek(file, offset, whence, base->bytes);
}

static int aenv_ram_release(struct inode *inode, struct file *file)
{
	struct aenv_ram_base *base = file->private_data;

	atomic_dec(&base->views);
	return 0;
}

static const struct file_operations aenv_ram_file_ops = {
	.owner = THIS_MODULE,
	.mmap = aenv_ram_mmap,
	.read_iter = aenv_ram_read_iter,
	.llseek = aenv_ram_llseek,
	.release = aenv_ram_release,
};

struct file *aenv_ram_base_open(struct aenv_ram_base *base)
{
	struct file *file;

	mutex_lock(&base->lock);
	if (base->retiring) {
		file = ERR_PTR(-EBUSY);
		goto out;
	}
	atomic_inc(&base->views);
	file = anon_inode_getfile("aenv-shared-ram", &aenv_ram_file_ops, base, O_RDONLY);
	if (IS_ERR(file))
		atomic_dec(&base->views);
	else
		file->f_mode |= FMODE_LSEEK | FMODE_PREAD;
out:
	mutex_unlock(&base->lock);
	return file;
}
EXPORT_SYMBOL_GPL(aenv_ram_base_open);

u64 aenv_ram_base_bytes(const struct aenv_ram_base *base)
{
	return base->bytes;
}
EXPORT_SYMBOL_GPL(aenv_ram_base_bytes);

int aenv_ram_base_retire(struct aenv_ram_base *base)
{
	unsigned long i;
	struct module *owner;

	mutex_lock(&base->lock);
	base->retiring = true;
	if (atomic_read(&base->views))
		goto busy;
	/* No FD/VMA may be admitted now. Wait out pre-existing RCU readers
	 * before inspecting pins; extra page references conservatively retain
	 * the region. No forced release or timeout-based reclamation exists.
	 */
	synchronize_rcu();
	for (i = 0; i < base->nr_pages; i++) {
		if (page_mapped(base->pages[i]) || page_ref_count(base->pages[i]) != 1)
			goto busy;
	}
	mutex_unlock(&base->lock);
	owner = base->source_owner;
	base->release(base->context, base->pages, base->nr_pages);
	kvfree(base->pages);
	kfree(base);
	module_put(owner);
	module_put(THIS_MODULE);
	return 0;
busy:
	mutex_unlock(&base->lock);
	return -EBUSY;
}
EXPORT_SYMBOL_GPL(aenv_ram_base_retire);

static int __init aenv_ram_init(void)
{
	return 0;
}

static void __exit aenv_ram_exit(void)
{
}

module_init(aenv_ram_init);
module_exit(aenv_ram_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AgentENV immutable normal-page private view core; requires a trusted backing provider");
