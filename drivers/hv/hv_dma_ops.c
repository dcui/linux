// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Microsoft Corporation.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/hyperv.h>
#include <linux/pci.h>
#include "hyperv_vmbus.h"
#include "../../kernel/dma/direct.h"

/* Returns true if the PCI device must use private memory for DMA. */
static bool (*pci_dma_isolation_cb)(struct pci_dev *pdev);

void hv_register_dma_isolation_cb(bool (*cb)(struct pci_dev *pdev))
{
	pci_dma_isolation_cb = cb;
}

void hv_unregister_dma_isolation_cb(void)
{
	pci_dma_isolation_cb = NULL;
}

static bool hv_dma_via_priv_mem(struct device *dev)
{
	if (dev_is_vmbus(dev) &&
	    device_to_hv_device(dev)->channel->co_external_memory)
		return true;

	if (dev_is_pci(dev) && pci_dma_isolation_cb &&
	    pci_dma_isolation_cb(to_pci_dev(dev)))
		return true;

	return false;
}

static void *hv_dma_alloc(struct device *dev, size_t size,
			  dma_addr_t *dma_handle, gfp_t flag,
			  unsigned long attrs)
{
	phys_addr_t phys;
	void *ret;

	if (!hv_dma_via_priv_mem(dev))
		return dma_direct_alloc(dev, size, dma_handle, flag, attrs);

	size = ALIGN(size, PAGE_SIZE);
	ret = (void *)__get_free_pages(flag, get_order(size));
	if (!ret)
		return NULL;

	phys = virt_to_phys(ret);

	*dma_handle = dma_addr_encrypted(__phys_to_dma(dev, phys));
	memset(ret, 0, size);

	return ret;
}

static void hv_dma_free(struct device *dev, size_t size, void *vaddr,
			dma_addr_t dma_handle, unsigned long attrs)
{
	if (!hv_dma_via_priv_mem(dev))
		dma_direct_free(dev, size, vaddr, dma_handle, attrs);
	else
		free_pages((unsigned long)vaddr, get_order(size));
}

static dma_addr_t hv_dma_map_phys(struct device *dev, phys_addr_t phys,
				  size_t size, enum dma_data_direction dir,
				  unsigned long attrs)
{
	if (!hv_dma_via_priv_mem(dev))
		return dma_direct_map_phys(dev, phys, size, dir, attrs, true);

	return __phys_to_dma(dev, phys);
}

static void hv_dma_unmap_phys(struct device *dev, dma_addr_t dma_handle,
			      size_t size, enum dma_data_direction dir,
			      unsigned long attrs)
{
	if (!hv_dma_via_priv_mem(dev))
		dma_direct_unmap_phys(dev, dma_handle, size, dir, attrs, true);
}

static int hv_dma_map_sg(struct device *dev, struct scatterlist *sgl,
			 int nelems, enum dma_data_direction dir,
			 unsigned long attrs)
{
	struct scatterlist *sg;
	dma_addr_t dma_addr;
	int i;

	if (!hv_dma_via_priv_mem(dev))
		return dma_direct_map_sg(dev, sgl, nelems, dir, attrs);

	for_each_sg(sgl, sg, nelems, i) {
		dma_addr = __phys_to_dma(dev, sg_phys(sg));
		sg_dma_address(sg) = dma_addr;
		sg_dma_len(sg) = sg->length;
	}

	return nelems;
}

static void hv_dma_unmap_sg(struct device *dev, struct scatterlist *sgl,
			    int nelems, enum dma_data_direction dir,
			    unsigned long attrs)
{
	if (!hv_dma_via_priv_mem(dev))
		dma_direct_unmap_sg(dev, sgl, nelems, dir, attrs);
}

static void hv_dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle,
				       size_t size, enum dma_data_direction dir)
{
	dma_direct_sync_single_for_cpu(dev, dma_handle, size, dir, true);
}

static void hv_dma_sync_single_for_device(struct device *dev, dma_addr_t dma_handle,
					  size_t size, enum dma_data_direction dir)
{
	dma_direct_sync_single_for_device(dev, dma_handle, size, dir);
}

static void hv_dma_sync_sg_for_cpu(struct device *dev, struct scatterlist *sgl,
				   int nelems, enum dma_data_direction dir)
{
	dma_direct_sync_sg_for_cpu(dev, sgl, nelems, dir);
}

static void hv_dma_sync_sg_for_device(struct device *dev, struct scatterlist *sgl,
			       int nelems, enum dma_data_direction dir)
{
	dma_direct_sync_sg_for_device(dev, sgl, nelems, dir);
}

static int hv_dma_supported(struct device *dev, u64 mask)
{
	return 1;
}

static size_t hv_dma_max_mapping_size(struct device *dev)
{
	if (!hv_dma_via_priv_mem(dev))
		return swiotlb_max_mapping_size(dev);

	return SIZE_MAX;
}

const struct dma_map_ops hv_dma_ops = {
	.alloc			= hv_dma_alloc,
	.free			= hv_dma_free,
	.map_phys		= hv_dma_map_phys,
	.unmap_phys		= hv_dma_unmap_phys,
	.map_sg			= hv_dma_map_sg,
	.unmap_sg		= hv_dma_unmap_sg,
	.sync_single_for_cpu	= hv_dma_sync_single_for_cpu,
	.sync_single_for_device	= hv_dma_sync_single_for_device,
	.sync_sg_for_cpu	= hv_dma_sync_sg_for_cpu,
	.sync_sg_for_device	= hv_dma_sync_sg_for_device,
	.dma_supported		= hv_dma_supported,
	.max_mapping_size	= hv_dma_max_mapping_size,
};

void hv_setup_global_dma_ops(void)
{
	dma_ops = &hv_dma_ops;
}
