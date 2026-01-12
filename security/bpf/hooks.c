// SPDX-License-Identifier: GPL-2.0
/*
 * BPF LSM (Linux Security Module) Implementation.
 *
 * This module integrates eBPF with the LSM infrastructure, allowing
 * security policies to be implemented as BPF programs.
 *
 * Copyright (C) 2020 Google LLC.
 * Optimized version for enhanced maintainability and performance.
 */

#include <linux/lsm_hooks.h>
#include <linux/bpf_lsm.h>
#include <linux/printk.h>
#include <linux/init.h>
#include <uapi/linux/lsm.h>

/**
 * struct bpf_lsmid - Unique identifier for the BPF LSM.
 *
 * Using a static const structure ensures the ID is stored in the 
 * read-only data segment after initialization, preventing tampering.
 */
static const struct lsm_id bpf_lsmid = {
	.name = "bpf",
	.id   = LSM_ID_BPF,
};

/**
 * bpf_lsm_hooks - Array of security hooks managed by BPF.
 *
 * This table maps LSM hooks to their respective BPF dispatchers.
 * Marked as __ro_after_init for security hardening.
 */
static struct security_hook_list bpf_lsm_hooks[] __ro_after_init = {
	#define LSM_HOOK(RET, DEFAULT, NAME, ...) \
		LSM_HOOK_INIT(NAME, bpf_lsm_##NAME),
	#include <linux/lsm_hook_defs.h>
	#undef LSM_HOOK
	LSM_HOOK_INIT(inode_free_security, bpf_inode_storage_free),
};

/**
 * bpf_lsm_blob_sizes - Security blob space requirements.
 *
 * Defines the amount of memory to be allocated for BPF-specific 
 * metadata within kernel objects (e.g., inodes).
 */
struct lsm_blob_sizes bpf_lsm_blob_sizes __ro_after_init = {
	.lbs_inode = sizeof(struct bpf_storage_blob),
};

/**
 * bpf_lsm_init - Subsystem initialization.
 *
 * Registers the BPF LSM hooks into the global security framework.
 * Returns 0 on success.
 */
static int __init bpf_lsm_init(void)
{
	security_add_hooks(bpf_lsm_hooks, ARRAY_SIZE(bpf_lsm_hooks), &bpf_lsmid);
	
	pr_info("BPF LSM: Security framework initialized (ID: %d)\n", LSM_ID_BPF);
	return 0;
}

/**
 * DEFINE_LSM - Module declaration.
 *
 * This macro registers the BPF LSM with the kernel's LSM infrastructure,
 * ensuring proper ordering and memory allocation for security blobs.
 */
DEFINE_LSM(bpf) = {
	.id    = &bpf_lsmid,
	.name  = "bpf",
	.init  = bpf_lsm_init,
	.blobs = &bpf_lsm_blob_sizes,
};
