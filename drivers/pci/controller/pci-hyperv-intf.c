// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Microsoft Corporation.
 *
 * Author:
 *   Haiyang Zhang <haiyangz@microsoft.com>
 *
 * This small module is a helper driver allows other drivers to
 * have a common interface with the Hyper-V PCI frontend driver.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hyperv.h>
#include <linux/pci.h>

struct hyperv_pci_block_ops hvpci_block_ops;
EXPORT_SYMBOL_GPL(hvpci_block_ops);

int hyperv_read_cfg_blk(struct pci_dev *dev, void *buf, unsigned int buf_len,
			unsigned int block_id, unsigned int *bytes_returned)
{
	int ret;
	if (!hvpci_block_ops.read_block)
		return -EOPNOTSUPP;

	pci_info(dev, "cdx: %s: line %d: 1: pdev=%px, buf=%px, len=%d, blk_id=%d\n", __func__, __LINE__, dev, buf, buf_len, block_id);
	ret = hvpci_block_ops.read_block(dev, buf, buf_len, block_id,
					  bytes_returned);
	pci_info(dev, "cdx: %s: line %d: 2: pdev=%px, buf=%px, len=%d, blk_id=%d, out_len=%d, ret=%d\n", __func__, __LINE__, dev, buf, buf_len, block_id, *bytes_returned, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(hyperv_read_cfg_blk);

int hyperv_write_cfg_blk(struct pci_dev *dev, void *buf, unsigned int len,
			 unsigned int block_id)
{
	int ret;
	if (!hvpci_block_ops.write_block)
		return -EOPNOTSUPP;

	pci_info(dev, "cdx: %s: line %d: 1: pdev=%px, buf=%px, len=%d, blk_id=%d\n", __func__, __LINE__, dev, buf, len, block_id);
	ret = hvpci_block_ops.write_block(dev, buf, len, block_id);
	pci_info(dev, "cdx: %s: line %d: 2: pdev=%px, buf=%px, len=%d, blk_id=%d, ret=%d\n", __func__, __LINE__, dev, buf, len, block_id, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(hyperv_write_cfg_blk);

int hyperv_reg_block_invalidate(struct pci_dev *dev, void *context,
				void (*block_invalidate)(void *context,
							 u64 block_mask))
{
	int ret;
	if (!hvpci_block_ops.reg_blk_invalidate)
		return -EOPNOTSUPP;

	pci_info(dev, "cdx: %s: line %d: 1: pdev=%px, ctxt=%px, func=%pS\n", __func__, __LINE__, dev, context, block_invalidate);
	ret = hvpci_block_ops.reg_blk_invalidate(dev, context,
						  block_invalidate);
	pci_info(dev, "cdx: %s: line %d: 2: pdev=%px, ctxt=%px, func=%pS, ret=%d\n", __func__, __LINE__, dev, context, block_invalidate, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(hyperv_reg_block_invalidate);

static void __exit exit_hv_pci_intf(void)
{
}

static int __init init_hv_pci_intf(void)
{
	return 0;
}

module_init(init_hv_pci_intf);
module_exit(exit_hv_pci_intf);

MODULE_DESCRIPTION("Hyper-V PCI Interface");
MODULE_LICENSE("GPL v2");
