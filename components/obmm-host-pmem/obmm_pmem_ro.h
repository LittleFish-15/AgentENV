/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OBMM_PMEM_RO_H
#define OBMM_PMEM_RO_H
#include <linux/kconfig.h>
#if IS_ENABLED(CONFIG_FS_DAX)
int obmm_pmem_init(void);
void obmm_pmem_exit(void);
#else
static inline int obmm_pmem_init(void) { return 0; }
static inline void obmm_pmem_exit(void) { }
#endif
#endif
