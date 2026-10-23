/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef AENV_SHARED_RAM_VIEW_H
#define AENV_SHARED_RAM_VIEW_H

#include <linux/types.h>

struct file;
struct module;
struct page;
struct aenv_ram_base;

/*
 * Kernel-only provider contract, NOT an arbitrary-PFN userspace interface.
 *
 * Each page must be an independent, allocated normal-RAM page with one owned
 * reference, no mappings, and a valid, cache-compatible kernel linear alias.
 * The provider must have completed publication/cache maintenance, make the
 * contents immutable, and hold the physical region against revocation.
 * Device PFNs, offline/pre-online metadata and OBMM's invalidated linear
 * aliases do not satisfy this contract. Passing validation is not a proof of
 * UB provenance, hardware coherence or cross-node physical sharing.
 *
 * On create success, page references are transferred to the base; the array
 * itself is copied. On failure the provider keeps all references.
 * release() is invoked exactly once after all views/mappings and observed
 * page pins are gone. It receives those references back and must dispose of
 * them and its local region lease. It must not infer remote-node retirement.
 * It may defer hardware cleanup to its own journalled lifecycle.
 */
struct aenv_ram_source {
	struct module *owner;
	struct page *const *pages;
	unsigned long nr_pages;
	void *context;
	void (*release)(void *context, struct page *const *pages,
			unsigned long nr_pages);
};

struct aenv_ram_base *aenv_ram_base_create(const struct aenv_ram_source *source);

/* Returns a read-only anonymous FD backing file, without installing an FD.
 * MAP_PRIVATE may be writable; all MAP_SHARED mappings are refused.
 * Size is explicit: anon-inode stat size must NOT be treated as base length.
 * pread/seek use the declared byte length and never populate a local cache.
 */
struct file *aenv_ram_base_open(struct aenv_ram_base *base);
u64 aenv_ram_base_bytes(const struct aenv_ram_base *base);

/*
 * The owner must serialize owner API calls and retain this handle until a
 * successful retirement. A busy retirement permanently closes admission,
 * but existing views continue working; retry is permitted after their exit.
 * On success the handle is consumed. Never call again or force a busy base.
 */
int aenv_ram_base_retire(struct aenv_ram_base *base);

#endif
