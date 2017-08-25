/*
 * uio_hv_generic - generic UIO driver for VMBus
 *
 * Copyright (c) 2013-2016 Brocade Communications Systems, Inc.
 * Copyright (c) 2016, Microsoft Corporation.
 *
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * Since the driver does not declare any device ids, you must allocate
 * id and bind the device to the driver yourself.  For example:
 *
 * Associate Network GUID with UIO device
 * # echo "f8615163-df3e-46c5-913f-f2d2f965ed0e" \
 *    > /sys/bus/vmbus/drivers/uio_hv_generic/new_id
 * Then rebind
 * # echo -n "ed963694-e847-4b2a-85af-bc9cfc11d6f3" \
 *    > /sys/bus/vmbus/drivers/hv_netvsc/unbind
 * # echo -n "ed963694-e847-4b2a-85af-bc9cfc11d6f3" \
 *    > /sys/bus/vmbus/drivers/uio_hv_generic/bind
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uio_driver.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/hyperv.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#include "../hv/hyperv_vmbus.h"

#define DRIVER_VERSION	"0.02.1"
#define DRIVER_AUTHOR	"Stephen Hemminger <sthemmin at microsoft.com>"
#define DRIVER_DESC	"Generic UIO driver for VMBus devices"

#define RING_SIZE_MIN 64
#define RING_SIZE_MAX 512

static unsigned int ring_size = 128;
module_param(ring_size, uint, 0444);
MODULE_PARM_DESC(ring_size, "Ring buffer size (# of pages)");

#define RECV_BUFFER_MAX ((16 * 1024 * 1024) / PAGE_SIZE)

static unsigned int recv_buffer_size = RECV_BUFFER_MAX;
module_param(recv_buffer_size, uint, 0444);
MODULE_PARM_DESC(recv_buffer_size, "Receive buffer size (# of pages)");

#define SEND_BUFFER_MAX ((15 * 1024 * 1024) / PAGE_SIZE)

static unsigned int send_buffer_size = SEND_BUFFER_MAX;
module_param(send_buffer_size, uint, 0444);
MODULE_PARM_DESC(send_buffer_size, "Send buffer size (# of pages)");

/* List of resources to be mapped to user space */
enum hv_uio_map {
	TXRX_RING_MAP = 0,
	INT_PAGE_MAP,
	MON_PAGE_MAP,
	RECV_BUF_MAP,
	SEND_BUF_MAP
};

struct hv_uio_private_data {
	struct uio_info info;
	struct hv_device *device;

	void	*recv_buf;
	u32	recv_gpadl;
	char	recv_name[32];	/* "recv_4294967295" */

	void	*send_buf;
	u32	send_gpadl;
	char	send_name[32];
};

struct hv_uio_ring_buffer {
	struct bin_attribute ring;
	struct hv_ring_buffer *buffer;
};

/*
 * This is the irqcontrol callback to be registered to uio_info.
 * It can be used to disable/enable interrupt from user space processes.
 *
 * @param info
 *  pointer to uio_info.
 * @param irq_state
 *  state value. 1 to enable interrupt, 0 to disable interrupt.
 */
static int
hv_uio_irqcontrol(struct uio_info *info, s32 irq_state)
{
	struct hv_uio_private_data *pdata = info->priv;
	struct hv_device *dev = pdata->device;

	dev->channel->inbound.ring_buffer->interrupt_mask = !irq_state;
	virt_mb();

	return 0;
}

/*
 * Callback from vmbus_event when something is in inbound ring.
 */
static void hv_uio_channel_cb(void *context)
{
	struct hv_uio_private_data *pdata = context;
	struct hv_device *dev = pdata->device;

	dev->channel->inbound.ring_buffer->interrupt_mask = 1;
	virt_mb();

	uio_event_notify(&pdata->info);
}

/*
 * Callback from vmbus_event when channel is rescinded.
 */
static void hv_uio_rescind(struct vmbus_channel *channel)
{
	struct hv_device *hv_dev = channel->primary_channel->device_obj;
	struct hv_uio_private_data *pdata = hv_get_drvdata(hv_dev);

	/*
	 * Turn off the interrupt file handle
	 * Next read for event will return -EIO
	 */
	pdata->info.irq = 0;

	/* Wake up reader */
	uio_event_notify(&pdata->info);
}

/*
 * Handle fault when looking for sub channel ring buffer
 * Subchannel ring buffer is same as resource 0 which is main ring buffer
 * This is derived from uio_vma_fault
 */
static int hv_uio_vma_fault(struct vm_fault *vmf)
{
	struct hv_ring_buffer *rb = vmf->vma->vm_private_data;
	struct page *page;
	void *addr;

	addr = (void *)rb + (vmf->pgoff << PAGE_SHIFT);
	page = virt_to_page(addr);
	get_page(page);
	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct hv_uio_vm_ops = {
	.fault = hv_uio_vma_fault,
};

/* Sysfs API to allow mmap of the ring buffers */
static int hv_uio_ring_mmap(struct file *filp, struct kobject *kobj,
			    struct bin_attribute *attr, struct vm_area_struct *vma)
{
	struct hv_uio_ring_buffer *urb
		= container_of(attr, struct hv_uio_ring_buffer, ring);
	unsigned long requested_pages, actual_pages;

	pr_debug("mmap start=%#lx end=%#lx\n",
		 vma->vm_start, vma->vm_end);

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;

	requested_pages = vma_pages(vma);
	actual_pages = 2 * ring_size;
	pr_debug("mmap requested %lu actual %lu\n",
		 requested_pages, actual_pages);

	if (requested_pages > actual_pages)
		return -EINVAL;

	vma->vm_private_data = urb->buffer;
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_ops = &hv_uio_vm_ops;
	return 0;
}

static int
hv_uio_ring_buffer_init(struct vmbus_channel *channel,
			const char *name, struct hv_ring_buffer_info *rbi)
{
	struct hv_uio_ring_buffer *urb;
	int ret;

	urb = kzalloc(sizeof(*urb), GFP_ATOMIC);
	if (!urb)
		return -ENOMEM;

	urb->buffer = rbi->ring_buffer;

	sysfs_bin_attr_init(&urb->attr);
	urb->ring.attr.name = name;
	urb->ring.attr.mode = S_IRUSR | S_IWUSR;
	urb->ring.size = 2 * ring_size * PAGE_SIZE;
	urb->ring.mmap = hv_uio_ring_mmap;

	/* Make a binary sysfs file for channel ring buffer */
	ret = sysfs_create_bin_file(&channel->kobj, &urb->ring);
	if (ret)
		kfree(urb);

	return ret;
}

/* Add subchannel ring attribute file. */
static int
hv_uio_add_channel(struct vmbus_channel *channel)
{
	int ret;

	ret = hv_uio_ring_buffer_init(channel, "out", &channel->outbound);
	if (ret == 0)
		ret = hv_uio_ring_buffer_init(channel, "in", &channel->inbound);

	return ret;
}

/* Callback from VMBUS subystem when new channel created. */
static void
hv_uio_new_channel(struct vmbus_channel *new_sc)
{
	struct hv_device *hv_dev = new_sc->primary_channel->device_obj;
	struct device *device = &hv_dev->device;
	struct hv_uio_private_data *pdata = hv_get_drvdata(hv_dev);
	int ret;

	/* Disable interrupts on sub channel */
	new_sc->inbound.ring_buffer->interrupt_mask = 1;
	set_channel_read_mode(new_sc, HV_CALL_DIRECT);

	/* Create host communication ring */
	ret = vmbus_open(new_sc, ring_size * PAGE_SIZE,
			 ring_size * PAGE_SIZE, NULL, 0,
			 hv_uio_channel_cb, pdata);
	if (ret) {
		dev_err(device, "vmbus_open subchannel failed: %d\n", ret);
		return;
	}

	ret = hv_uio_add_channel(new_sc);
	if (ret)
		vmbus_close(new_sc);
}

static void
hv_uio_cleanup(struct hv_device *dev, struct hv_uio_private_data *pdata)
{
	if (pdata->send_gpadl) {
		vmbus_teardown_gpadl(dev->channel, pdata->send_gpadl);
		pdata->send_gpadl = 0;
	}

	if (pdata->send_buf) {
		vfree(pdata->send_buf);
		pdata->send_buf = NULL;
	}

	if (pdata->recv_gpadl) {
		vmbus_teardown_gpadl(dev->channel, pdata->recv_gpadl);
		pdata->recv_gpadl = 0;
	}

	if (pdata->recv_buf) {
		vfree(pdata->recv_buf);
		pdata->recv_buf = NULL;
	}
}

static int
hv_uio_probe(struct hv_device *dev,
	     const struct hv_vmbus_device_id *dev_id)
{
	struct hv_uio_private_data *pdata;
	size_t buf_size;
	int ret;

	pdata = kzalloc(sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;

	ret = vmbus_open(dev->channel, ring_size * PAGE_SIZE,
			 ring_size * PAGE_SIZE, NULL, 0,
			 hv_uio_channel_cb, pdata);
	if (ret) {
		dev_err(&dev->device, "vmbus_open failed: %d", ret);
		goto fail;
	}

	/* Communicating with host has to be via shared memory not hypercall */
	if (!dev->channel->offermsg.monitor_allocated) {
		dev_err(&dev->device, "vmbus channel requires hypercall\n");
		ret = -ENOTSUPP;
		goto fail_close;
	}

	dev->channel->inbound.ring_buffer->interrupt_mask = 1;
	set_channel_read_mode(dev->channel, HV_CALL_ISR);

	/* Register the primary channel */
	ret = hv_uio_add_channel(dev->channel);
	if (ret)
		goto fail_cleanup;

	/* Fill general uio info */
	pdata->info.name = "uio_hv_generic";
	pdata->info.version = DRIVER_VERSION;
	pdata->info.irqcontrol = hv_uio_irqcontrol;
	pdata->info.irq = UIO_IRQ_CUSTOM;

	/* mem resources */
	pdata->info.mem[TXRX_RING_MAP].name = "txrx_rings";
	pdata->info.mem[TXRX_RING_MAP].addr
		= (phys_addr_t)dev->channel->ringbuffer_pages;
	pdata->info.mem[TXRX_RING_MAP].size
 		= dev->channel->ringbuffer_pagecount << PAGE_SHIFT;
	pdata->info.mem[TXRX_RING_MAP].memtype = UIO_MEM_LOGICAL;

	pdata->info.mem[INT_PAGE_MAP].name = "int_page";
	pdata->info.mem[INT_PAGE_MAP].addr
		= (phys_addr_t)vmbus_connection.int_page;
	pdata->info.mem[INT_PAGE_MAP].size = PAGE_SIZE;
	pdata->info.mem[INT_PAGE_MAP].memtype = UIO_MEM_LOGICAL;

	pdata->info.mem[MON_PAGE_MAP].name = "monitor_page";
	pdata->info.mem[MON_PAGE_MAP].addr
		= (phys_addr_t)vmbus_connection.monitor_pages[1];
	pdata->info.mem[MON_PAGE_MAP].size = PAGE_SIZE;
	pdata->info.mem[MON_PAGE_MAP].memtype = UIO_MEM_LOGICAL;

	if (recv_buffer_size) {
		buf_size = recv_buffer_size * PAGE_SIZE;
		pdata->recv_buf = vzalloc(buf_size);
		if (pdata->recv_buf == NULL) {
			ret = -ENOMEM;
			goto fail_cleanup;
		}

		ret = vmbus_establish_gpadl(dev->channel, pdata->recv_buf,
					    buf_size, &pdata->recv_gpadl);
		if (ret)
			goto fail_cleanup;

		/* put Global Physical Address Label in name */
		snprintf(pdata->recv_name, sizeof(pdata->recv_name),
			 "recv:%u", pdata->recv_gpadl);
		pdata->info.mem[RECV_BUF_MAP].name = pdata->recv_name;
		pdata->info.mem[RECV_BUF_MAP].addr
			= (phys_addr_t)pdata->recv_buf;
		pdata->info.mem[RECV_BUF_MAP].size = buf_size;
		pdata->info.mem[RECV_BUF_MAP].memtype = UIO_MEM_VIRTUAL;
	}

	if (send_buffer_size) {
		buf_size = send_buffer_size * PAGE_SIZE;
		pdata->send_buf = vzalloc(buf_size);
		if (pdata->send_buf == NULL) {
			ret = -ENOMEM;
			goto fail_cleanup;
		}

		ret = vmbus_establish_gpadl(dev->channel, pdata->send_buf,
					    buf_size, &pdata->send_gpadl);
		if (ret)
			goto fail_cleanup;

		snprintf(pdata->send_name, sizeof(pdata->send_name),
			 "send:%u", pdata->send_gpadl);
		pdata->info.mem[SEND_BUF_MAP].name = pdata->send_name;
		pdata->info.mem[SEND_BUF_MAP].addr
			= (phys_addr_t)pdata->send_buf;
		pdata->info.mem[SEND_BUF_MAP].size = buf_size;
		pdata->info.mem[SEND_BUF_MAP].memtype = UIO_MEM_VIRTUAL;
	}

	pdata->info.priv = pdata;
	pdata->device = dev;

	ret = uio_register_device(&dev->device, &pdata->info);
	if (ret) {
		dev_err(&dev->device, "hv_uio register failed\n");
		goto fail_cleanup;
	}

	vmbus_set_sc_create_callback(dev->channel, hv_uio_new_channel);
	vmbus_set_chn_rescind_callback(dev->channel, hv_uio_rescind);

	hv_set_drvdata(dev, pdata);

	return 0;

fail_cleanup:
	hv_uio_cleanup(dev, pdata);
fail_close:
	vmbus_close(dev->channel);
fail:
	kfree(pdata);

	return ret;
}

static int
hv_uio_remove(struct hv_device *dev)
{
	struct hv_uio_private_data *pdata = hv_get_drvdata(dev);

	if (!pdata)
		return 0;

	uio_unregister_device(&pdata->info);
	hv_uio_cleanup(dev, pdata);
	hv_set_drvdata(dev, NULL);
	vmbus_close(dev->channel);
	kfree(pdata);
	return 0;
}

static struct hv_driver hv_uio_drv = {
	.name = "uio_hv_generic",
	.id_table = NULL, /* only dynamic id's */
	.probe = hv_uio_probe,
	.remove = hv_uio_remove,
};

static int __init
hyperv_module_init(void)
{
	if (ring_size < RING_SIZE_MIN) {
		ring_size = RING_SIZE_MIN;
		pr_info("Increased ring_size to %u (min allowed)\n",
			ring_size);
	}

	if (ring_size > RING_SIZE_MAX) {
		ring_size = RING_SIZE_MAX;
		pr_info("Decreased ring_size to %u (max allowed)\n",
			ring_size);
	}

	if (recv_buffer_size > RECV_BUFFER_MAX) {
		recv_buffer_size = RECV_BUFFER_MAX;
		pr_info("Decreased receive_buffer_size to %u (max allowed)\n",
			recv_buffer_size);
	}

	if (send_buffer_size > SEND_BUFFER_MAX) {
		send_buffer_size = SEND_BUFFER_MAX;
		pr_info("Decreased send_buffer_size to %u (max allowed)\n",
			send_buffer_size);
	}

	return vmbus_driver_register(&hv_uio_drv);
}

static void __exit
hyperv_module_exit(void)
{
	vmbus_driver_unregister(&hv_uio_drv);
}

module_init(hyperv_module_init);
module_exit(hyperv_module_exit);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
