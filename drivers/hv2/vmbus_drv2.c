/*
 * Copyright (c) 2009, Microsoft Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Authors:
 *   Haiyang Zhang <haiyangz@microsoft.com>
 *   Hank Janssen  <hjanssen@microsoft.com>
 *   K. Y. Srinivasan <kys@microsoft.com>
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/hyperv.h>
#include <linux/kernel_stat.h>
#include <linux/clockchips.h>
#include <linux/cpu.h>
#include <linux/sched/task_stack.h>

#include <asm/hyperv.h>
#include <asm/hypervisor.h>
#include <asm/mshyperv.h>
#include <linux/notifier.h>
#include <linux/ptrace.h>
#include <linux/screen_info.h>
#include <linux/kdebug.h>
#include <linux/efi.h>
#include <linux/random.h>
#include <linux/workqueue.h>
#include "hyperv_vmbus2.h"

struct vmbus_dynid {
	struct list_head node;
	struct hv_vmbus_device_id id;
};

static int hyperv_cpuhp_online;

#define VMBUS_ALIAS_LEN ((sizeof((struct hv_vmbus_device_id *)0)->guid) * 2)
static void print_alias_name(struct hv_device *hv_dev, char *alias_name)
{
	int i;
	for (i = 0; i < VMBUS_ALIAS_LEN; i += 2)
		sprintf(&alias_name[i], "%02x", hv_dev->dev_type.b[i/2]);
}

static u8 channel_monitor_group(const struct vmbus_channel *channel)
{
	return (u8)channel->offermsg.monitorid / 32;
}

static u8 channel_monitor_offset(const struct vmbus_channel *channel)
{
	return (u8)channel->offermsg.monitorid % 32;
}

static u32 channel_pending(const struct vmbus_channel *channel,
			   const struct hv_monitor_page *monitor_page)
{
	u8 monitor_group = channel_monitor_group(channel);

	return monitor_page->trigger_group[monitor_group].pending;
}

static u32 channel_latency(const struct vmbus_channel *channel,
			   const struct hv_monitor_page *monitor_page)
{
	u8 monitor_group = channel_monitor_group(channel);
	u8 monitor_offset = channel_monitor_offset(channel);

	return monitor_page->latency[monitor_group][monitor_offset];
}

static u32 channel_conn_id(struct vmbus_channel *channel,
			   struct hv_monitor_page *monitor_page)
{
	u8 monitor_group = channel_monitor_group(channel);
	u8 monitor_offset = channel_monitor_offset(channel);
	return monitor_page->parameter[monitor_group][monitor_offset].connectionid.u.id;
}

static ssize_t id_show(struct device *dev, struct device_attribute *dev_attr,
		       char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);

	if (!hv_dev->channel)
		return -ENODEV;
	return sprintf(buf, "%d\n", hv_dev->channel->offermsg.child_relid);
}
static DEVICE_ATTR_RO(id);

static ssize_t state_show(struct device *dev, struct device_attribute *dev_attr,
			  char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);

	if (!hv_dev->channel)
		return -ENODEV;
	return sprintf(buf, "%d\n", hv_dev->channel->state);
}
static DEVICE_ATTR_RO(state);

static ssize_t monitor_id_show(struct device *dev,
			       struct device_attribute *dev_attr, char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);

	if (!hv_dev->channel)
		return -ENODEV;
	return sprintf(buf, "%d\n", hv_dev->channel->offermsg.monitorid);
}
static DEVICE_ATTR_RO(monitor_id);

static ssize_t class_id_show(struct device *dev,
			       struct device_attribute *dev_attr, char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);

	if (!hv_dev->channel)
		return -ENODEV;
	return sprintf(buf, "{%pUl}\n",
		       hv_dev->channel->offermsg.offer.if_type.b);
}
static DEVICE_ATTR_RO(class_id);

static ssize_t device_id_show(struct device *dev,
			      struct device_attribute *dev_attr, char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);

	if (!hv_dev->channel)
		return -ENODEV;
	return sprintf(buf, "{%pUl}\n",
		       hv_dev->channel->offermsg.offer.if_instance.b);
}
static DEVICE_ATTR_RO(device_id);

static ssize_t modalias_show(struct device *dev,
			     struct device_attribute *dev_attr, char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	char alias_name[VMBUS_ALIAS_LEN + 1];

	print_alias_name(hv_dev, alias_name);
	return sprintf(buf, "vmbus:%s\n", alias_name);
}
static DEVICE_ATTR_RO(modalias);

static ssize_t server_monitor_pending_show(struct device *dev,
					   struct device_attribute *dev_attr,
					   char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);

	if (!hv_dev->channel)
		return -ENODEV;
	return sprintf(buf, "%d\n",
		       channel_pending(hv_dev->channel,
				       vmbus_connection.monitor_pages[1]));
}
static DEVICE_ATTR_RO(server_monitor_pending);

static ssize_t client_monitor_pending_show(struct device *dev,
					   struct device_attribute *dev_attr,
					   char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);

	if (!hv_dev->channel)
		return -ENODEV;
	return sprintf(buf, "%d\n",
		       channel_pending(hv_dev->channel,
				       vmbus_connection.monitor_pages[1]));
}
static DEVICE_ATTR_RO(client_monitor_pending);

static ssize_t server_monitor_latency_show(struct device *dev,
					   struct device_attribute *dev_attr,
					   char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);

	if (!hv_dev->channel)
		return -ENODEV;
	return sprintf(buf, "%d\n",
		       channel_latency(hv_dev->channel,
				       vmbus_connection.monitor_pages[0]));
}
static DEVICE_ATTR_RO(server_monitor_latency);

static ssize_t client_monitor_latency_show(struct device *dev,
					   struct device_attribute *dev_attr,
					   char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);

	if (!hv_dev->channel)
		return -ENODEV;
	return sprintf(buf, "%d\n",
		       channel_latency(hv_dev->channel,
				       vmbus_connection.monitor_pages[1]));
}
static DEVICE_ATTR_RO(client_monitor_latency);

static ssize_t server_monitor_conn_id_show(struct device *dev,
					   struct device_attribute *dev_attr,
					   char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);

	if (!hv_dev->channel)
		return -ENODEV;
	return sprintf(buf, "%d\n",
		       channel_conn_id(hv_dev->channel,
				       vmbus_connection.monitor_pages[0]));
}
static DEVICE_ATTR_RO(server_monitor_conn_id);

static ssize_t client_monitor_conn_id_show(struct device *dev,
					   struct device_attribute *dev_attr,
					   char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);

	if (!hv_dev->channel)
		return -ENODEV;
	return sprintf(buf, "%d\n",
		       channel_conn_id(hv_dev->channel,
				       vmbus_connection.monitor_pages[1]));
}
static DEVICE_ATTR_RO(client_monitor_conn_id);

static ssize_t out_intr_mask_show(struct device *dev,
				  struct device_attribute *dev_attr, char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	struct hv_ring_buffer_debug_info outbound;

	if (!hv_dev->channel)
		return -ENODEV;
	hv_ringbuffer_get_debuginfo(&hv_dev->channel->outbound, &outbound);
	return sprintf(buf, "%d\n", outbound.current_interrupt_mask);
}
static DEVICE_ATTR_RO(out_intr_mask);

static ssize_t out_read_index_show(struct device *dev,
				   struct device_attribute *dev_attr, char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	struct hv_ring_buffer_debug_info outbound;

	if (!hv_dev->channel)
		return -ENODEV;
	hv_ringbuffer_get_debuginfo(&hv_dev->channel->outbound, &outbound);
	return sprintf(buf, "%d\n", outbound.current_read_index);
}
static DEVICE_ATTR_RO(out_read_index);

static ssize_t out_write_index_show(struct device *dev,
				    struct device_attribute *dev_attr,
				    char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	struct hv_ring_buffer_debug_info outbound;

	if (!hv_dev->channel)
		return -ENODEV;
	hv_ringbuffer_get_debuginfo(&hv_dev->channel->outbound, &outbound);
	return sprintf(buf, "%d\n", outbound.current_write_index);
}
static DEVICE_ATTR_RO(out_write_index);

static ssize_t out_read_bytes_avail_show(struct device *dev,
					 struct device_attribute *dev_attr,
					 char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	struct hv_ring_buffer_debug_info outbound;

	if (!hv_dev->channel)
		return -ENODEV;
	hv_ringbuffer_get_debuginfo(&hv_dev->channel->outbound, &outbound);
	return sprintf(buf, "%d\n", outbound.bytes_avail_toread);
}
static DEVICE_ATTR_RO(out_read_bytes_avail);

static ssize_t out_write_bytes_avail_show(struct device *dev,
					  struct device_attribute *dev_attr,
					  char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	struct hv_ring_buffer_debug_info outbound;

	if (!hv_dev->channel)
		return -ENODEV;
	hv_ringbuffer_get_debuginfo(&hv_dev->channel->outbound, &outbound);
	return sprintf(buf, "%d\n", outbound.bytes_avail_towrite);
}
static DEVICE_ATTR_RO(out_write_bytes_avail);

static ssize_t in_intr_mask_show(struct device *dev,
				 struct device_attribute *dev_attr, char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	struct hv_ring_buffer_debug_info inbound;

	if (!hv_dev->channel)
		return -ENODEV;
	hv_ringbuffer_get_debuginfo(&hv_dev->channel->inbound, &inbound);
	return sprintf(buf, "%d\n", inbound.current_interrupt_mask);
}
static DEVICE_ATTR_RO(in_intr_mask);

static ssize_t in_read_index_show(struct device *dev,
				  struct device_attribute *dev_attr, char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	struct hv_ring_buffer_debug_info inbound;

	if (!hv_dev->channel)
		return -ENODEV;
	hv_ringbuffer_get_debuginfo(&hv_dev->channel->inbound, &inbound);
	return sprintf(buf, "%d\n", inbound.current_read_index);
}
static DEVICE_ATTR_RO(in_read_index);

static ssize_t in_write_index_show(struct device *dev,
				   struct device_attribute *dev_attr, char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	struct hv_ring_buffer_debug_info inbound;

	if (!hv_dev->channel)
		return -ENODEV;
	hv_ringbuffer_get_debuginfo(&hv_dev->channel->inbound, &inbound);
	return sprintf(buf, "%d\n", inbound.current_write_index);
}
static DEVICE_ATTR_RO(in_write_index);

static ssize_t in_read_bytes_avail_show(struct device *dev,
					struct device_attribute *dev_attr,
					char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	struct hv_ring_buffer_debug_info inbound;

	if (!hv_dev->channel)
		return -ENODEV;
	hv_ringbuffer_get_debuginfo(&hv_dev->channel->inbound, &inbound);
	return sprintf(buf, "%d\n", inbound.bytes_avail_toread);
}
static DEVICE_ATTR_RO(in_read_bytes_avail);

static ssize_t in_write_bytes_avail_show(struct device *dev,
					 struct device_attribute *dev_attr,
					 char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	struct hv_ring_buffer_debug_info inbound;

	if (!hv_dev->channel)
		return -ENODEV;
	hv_ringbuffer_get_debuginfo(&hv_dev->channel->inbound, &inbound);
	return sprintf(buf, "%d\n", inbound.bytes_avail_towrite);
}
static DEVICE_ATTR_RO(in_write_bytes_avail);

static ssize_t channel_vp_mapping_show(struct device *dev,
				       struct device_attribute *dev_attr,
				       char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	struct vmbus_channel *channel = hv_dev->channel, *cur_sc;
	unsigned long flags;
	int buf_size = PAGE_SIZE, n_written, tot_written;
	struct list_head *cur;

	if (!channel)
		return -ENODEV;

	tot_written = snprintf(buf, buf_size, "%u:%u\n",
		channel->offermsg.child_relid, channel->target_cpu);

	spin_lock_irqsave(&channel->lock, flags);

	list_for_each(cur, &channel->sc_list) {
		if (tot_written >= buf_size - 1)
			break;

		cur_sc = list_entry(cur, struct vmbus_channel, sc_list);
		n_written = scnprintf(buf + tot_written,
				     buf_size - tot_written,
				     "%u:%u\n",
				     cur_sc->offermsg.child_relid,
				     cur_sc->target_cpu);
		tot_written += n_written;
	}

	spin_unlock_irqrestore(&channel->lock, flags);

	return tot_written;
}
static DEVICE_ATTR_RO(channel_vp_mapping);

static ssize_t vendor_show(struct device *dev,
			   struct device_attribute *dev_attr,
			   char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	return sprintf(buf, "0x%x\n", hv_dev->vendor_id);
}
static DEVICE_ATTR_RO(vendor);

static ssize_t device_show(struct device *dev,
			   struct device_attribute *dev_attr,
			   char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	return sprintf(buf, "0x%x\n", hv_dev->device_id);
}
static DEVICE_ATTR_RO(device);

/* Set up per device attributes in /sys/bus/vmbus/devices/<bus device> */
static struct attribute *vmbus_dev_attrs[] = {
	&dev_attr_id.attr,
	&dev_attr_state.attr,
	&dev_attr_monitor_id.attr,
	&dev_attr_class_id.attr,
	&dev_attr_device_id.attr,
	&dev_attr_modalias.attr,
	&dev_attr_server_monitor_pending.attr,
	&dev_attr_client_monitor_pending.attr,
	&dev_attr_server_monitor_latency.attr,
	&dev_attr_client_monitor_latency.attr,
	&dev_attr_server_monitor_conn_id.attr,
	&dev_attr_client_monitor_conn_id.attr,
	&dev_attr_out_intr_mask.attr,
	&dev_attr_out_read_index.attr,
	&dev_attr_out_write_index.attr,
	&dev_attr_out_read_bytes_avail.attr,
	&dev_attr_out_write_bytes_avail.attr,
	&dev_attr_in_intr_mask.attr,
	&dev_attr_in_read_index.attr,
	&dev_attr_in_write_index.attr,
	&dev_attr_in_read_bytes_avail.attr,
	&dev_attr_in_write_bytes_avail.attr,
	&dev_attr_channel_vp_mapping.attr,
	&dev_attr_vendor.attr,
	&dev_attr_device.attr,
	NULL,
};
ATTRIBUTE_GROUPS(vmbus_dev);

/*
 * vmbus_uevent - add uevent for our device
 *
 * This routine is invoked when a device is added or removed on the vmbus to
 * generate a uevent to udev in the userspace. The udev will then look at its
 * rule and the uevent generated here to load the appropriate driver
 *
 * The alias string will be of the form vmbus:guid where guid is the string
 * representation of the device guid (each byte of the guid will be
 * represented with two hex characters.
 */
static int vmbus_uevent(struct device *device, struct kobj_uevent_env *env)
{
	struct hv_device *dev = device_to_hv_device(device);
	int ret;
	char alias_name[VMBUS_ALIAS_LEN + 1];

	print_alias_name(dev, alias_name);
	ret = add_uevent_var(env, "MODALIAS=vmbus2:%s", alias_name);
	return ret;
}

static const uuid_le null_guid;

static inline bool is_null_guid(const uuid_le *guid)
{
	if (uuid_le_cmp(*guid, null_guid))
		return false;
	return true;
}

/*
 * Return a matching hv_vmbus_device_id pointer.
 * If there is no match, return NULL.
 */
static const struct hv_vmbus_device_id *hv_vmbus_get_id(struct hv_driver *drv,
					const uuid_le *guid)
{
	const struct hv_vmbus_device_id *id = NULL;
	struct vmbus_dynid *dynid;

	/* Look at the dynamic ids first, before the static ones */
	spin_lock(&drv->dynids.lock);
	list_for_each_entry(dynid, &drv->dynids.list, node) {
		if (!uuid_le_cmp(dynid->id.guid, *guid)) {
			id = &dynid->id;
			break;
		}
	}
	spin_unlock(&drv->dynids.lock);

	if (id)
		return id;

	id = drv->id_table;
	if (id == NULL)
		return NULL; /* empty device table */

	for (; !is_null_guid(&id->guid); id++)
		if (!uuid_le_cmp(id->guid, *guid))
			return id;

	return NULL;
}

/* vmbus_add_dynid - add a new device ID to this driver and re-probe devices */
static int vmbus_add_dynid(struct hv_driver *drv, uuid_le *guid)
{
	struct vmbus_dynid *dynid;

	dynid = kzalloc(sizeof(*dynid), GFP_KERNEL);
	if (!dynid)
		return -ENOMEM;

	dynid->id.guid = *guid;

	spin_lock(&drv->dynids.lock);
	list_add_tail(&dynid->node, &drv->dynids.list);
	spin_unlock(&drv->dynids.lock);

	return driver_attach(&drv->driver);
}

static void vmbus_free_dynids(struct hv_driver *drv)
{
	struct vmbus_dynid *dynid, *n;

	spin_lock(&drv->dynids.lock);
	list_for_each_entry_safe(dynid, n, &drv->dynids.list, node) {
		list_del(&dynid->node);
		kfree(dynid);
	}
	spin_unlock(&drv->dynids.lock);
}

/*
 * store_new_id - sysfs frontend to vmbus_add_dynid()
 *
 * Allow GUIDs to be added to an existing driver via sysfs.
 */
static ssize_t new_id_store(struct device_driver *driver, const char *buf,
			    size_t count)
{
	struct hv_driver *drv = drv_to_hv_drv(driver);
	uuid_le guid;
	ssize_t retval;

	retval = uuid_le_to_bin(buf, &guid);
	if (retval)
		return retval;

	if (hv_vmbus_get_id(drv, &guid))
		return -EEXIST;

	retval = vmbus_add_dynid(drv, &guid);
	if (retval)
		return retval;
	return count;
}
static DRIVER_ATTR_WO(new_id);

/*
 * store_remove_id - remove a PCI device ID from this driver
 *
 * Removes a dynamic pci device ID to this driver.
 */
static ssize_t remove_id_store(struct device_driver *driver, const char *buf,
			       size_t count)
{
	struct hv_driver *drv = drv_to_hv_drv(driver);
	struct vmbus_dynid *dynid, *n;
	uuid_le guid;
	ssize_t retval;

	retval = uuid_le_to_bin(buf, &guid);
	if (retval)
		return retval;

	retval = -ENODEV;
	spin_lock(&drv->dynids.lock);
	list_for_each_entry_safe(dynid, n, &drv->dynids.list, node) {
		struct hv_vmbus_device_id *id = &dynid->id;

		if (!uuid_le_cmp(id->guid, guid)) {
			list_del(&dynid->node);
			kfree(dynid);
			retval = count;
			break;
		}
	}
	spin_unlock(&drv->dynids.lock);

	return retval;
}
static DRIVER_ATTR_WO(remove_id);

static struct attribute *vmbus_drv_attrs[] = {
	&driver_attr_new_id.attr,
	&driver_attr_remove_id.attr,
	NULL,
};
ATTRIBUTE_GROUPS(vmbus_drv);


/*
 * vmbus_match - Attempt to match the specified device to the specified driver
 */
static int vmbus_match(struct device *device, struct device_driver *driver)
{
	struct hv_driver *drv = drv_to_hv_drv(driver);
	struct hv_device *hv_dev = device_to_hv_device(device);

	/* The hv_sock driver handles all hv_sock offers. */
	if (is_hvsock_channel(hv_dev->channel))
		return drv->hvsock;

	if (hv_vmbus_get_id(drv, &hv_dev->dev_type))
		return 1;

	return 0;
}

/*
 * vmbus_probe - Add the new vmbus's child device
 */
static int vmbus_probe(struct device *child_device)
{
	int ret = 0;
	struct hv_driver *drv =
			drv_to_hv_drv(child_device->driver);
	struct hv_device *dev = device_to_hv_device(child_device);
	const struct hv_vmbus_device_id *dev_id;

	dev_id = hv_vmbus_get_id(drv, &dev->dev_type);
	if (drv->probe) {
		ret = drv->probe(dev, dev_id);
		if (ret != 0)
			pr_err("probe failed for device %s (%d)\n",
			       dev_name(child_device), ret);

	} else {
		pr_err("probe not set for driver %s\n",
		       dev_name(child_device));
		ret = -ENODEV;
	}
	return ret;
}

/*
 * vmbus_remove - Remove a vmbus device
 */
static int vmbus_remove(struct device *child_device)
{
	struct hv_driver *drv;
	struct hv_device *dev = device_to_hv_device(child_device);

	if (child_device->driver) {
		drv = drv_to_hv_drv(child_device->driver);
		if (drv->remove)
			drv->remove(dev);
	}

	return 0;
}


/*
 * vmbus_shutdown - Shutdown a vmbus device
 */
static void vmbus_shutdown(struct device *child_device)
{
	struct hv_driver *drv;
	struct hv_device *dev = device_to_hv_device(child_device);


	/* The device may not be attached yet */
	if (!child_device->driver)
		return;

	drv = drv_to_hv_drv(child_device->driver);

	if (drv->shutdown)
		drv->shutdown(dev);
}


/*
 * vmbus_device_release - Final callback release of the vmbus child device
 */
static void vmbus_device_release(struct device *device)
{
	struct hv_device *hv_dev = device_to_hv_device(device);
	struct vmbus_channel *channel = hv_dev->channel;

	mutex_lock(&vmbus_connection2.channel_mutex);
	hv_process_channel_removal(channel->offermsg.child_relid);
	mutex_unlock(&vmbus_connection2.channel_mutex);
	kfree(hv_dev);

}

/* The one and only one */
static struct bus_type  hv_bus = {
	.name =			"vmbus2",
	.match =		vmbus_match,
	.shutdown =		vmbus_shutdown,
	.remove =		vmbus_remove,
	.probe =		vmbus_probe,
	.uevent =		vmbus_uevent,
	.dev_groups =		vmbus_dev_groups,
	.drv_groups =		vmbus_drv_groups,
};

struct onmessage_work_context {
	struct work_struct work;
	struct hv_message msg;
};

static void vmbus_onmessage_work(struct work_struct *work)
{
	struct onmessage_work_context *ctx;

	/* Do not process messages if we're in DISCONNECTED state */
	if (vmbus_connection2.conn_state == DISCONNECTED) {
		return;
	}

	ctx = container_of(work, struct onmessage_work_context,
			   work);
	vmbus_onmessage2(&ctx->msg);
	kfree(ctx);
}

static void vmbus_on_msg_dpc2(unsigned long data)
{
	struct hv_per_cpu_context *hv_cpu = (void *)data;
	void *page_addr = hv_cpu->synic_message_page;
	struct hv_message *msg = (struct hv_message *)page_addr +
				  VMBUS_MESSAGE_SINT;
	struct vmbus_channel_message_header *hdr;
	const struct vmbus_channel_message_table_entry *entry;
	struct onmessage_work_context *ctx;
	u32 message_type = msg->header.message_type;

	if (message_type == HVMSG_NONE)
		/* no msg */
		return;

	hdr = (struct vmbus_channel_message_header *)msg->u.payload;

	if (hdr->msgtype >= CHANNELMSG_COUNT) {
		WARN_ONCE(1, "unknown msgtype=%d\n", hdr->msgtype);
		goto msg_handled;
	}

	entry = &channel_message_table2[hdr->msgtype];
	if (entry->handler_type	== VMHT_BLOCKING) {
		ctx = kmalloc(sizeof(*ctx), GFP_ATOMIC);
		if (ctx == NULL)
			return;

		INIT_WORK(&ctx->work, vmbus_onmessage_work);
		memcpy(&ctx->msg, msg, sizeof(*msg));

		schedule_work(&ctx->work);

		/*
		 * The host can generate a rescind message while we
		 * may still be handling the original offer. We deal with
		 * this condition by ensuring the processing is done on the
		 * same CPU.
		 */
#if 0
		switch (hdr->msgtype) {
		case CHANNELMSG_RESCIND_CHANNELOFFER:
			/*
			 * If we are handling the rescind message;
			 * schedule the work on the global work queue.
			 */
			schedule_work_on(vmbus_connection2.connect_cpu,
					 &ctx->work);
			break;

		case CHANNELMSG_OFFERCHANNEL:
			//atomic_inc(&vmbus_connection2.offer_in_progress);
			queue_work_on(vmbus_connection2.connect_cpu,
				      vmbus_connection2.work_queue,
				      &ctx->work);
			break;

		default:
			queue_work(vmbus_connection2.work_queue, &ctx->work);
		}
#endif
	} else
		entry->message_handler(hdr);

msg_handled:
	vmbus_signal_eom(msg, message_type);
}


/*
 * Direct callback for channels using other deferred processing
 */
static void vmbus_channel_isr(struct vmbus_channel *channel)
{
	void (*callback_fn)(void *);

	callback_fn = READ_ONCE(channel->onchannel_callback);
	if (likely(callback_fn != NULL))
		(*callback_fn)(channel->channel_callback_context);
}

/*
 * Schedule all channels with events pending
 */
static void vmbus_chan_sched(struct hv_per_cpu_context *hv_cpu_1)
{
	struct hv_per_cpu_context *hv_cpu_2
		= this_cpu_ptr(hv_context2.cpu_context); //XXX:TODO

	unsigned long *recv_int_page;
	u32 maxbits, relid;

	if (vmbus_proto_version2 < VERSION_WIN8) {
		maxbits = MAX_NUM_CHANNELS_SUPPORTED;
		recv_int_page = vmbus_connection.recv_int_page;
	} else {
		/*
		 * When the host is win8 and beyond, the event page
		 * can be directly checked to get the id of the channel
		 * that has the interrupt pending.
		 */
		void *page_addr = hv_cpu_1->synic_event_page;
		union hv_synic_event_flags *event
			= (union hv_synic_event_flags *)page_addr +
						 VMBUS_MESSAGE_SINT;

		maxbits = HV_EVENT_FLAGS_COUNT;
		recv_int_page = event->flags;
	}

	if (unlikely(!recv_int_page))
		return;

	for_each_set_bit(relid, recv_int_page, maxbits) {
		struct vmbus_channel *channel;

		if (!sync_test_and_clear_bit(relid, recv_int_page))
			continue;

		/* Special case - vmbus channel protocol msg */
		if (relid == 0)
			continue;

		rcu_read_lock();

		/* Find channel based on relid */
		list_for_each_entry_rcu(channel, &hv_cpu_2->chan_list, percpu_list) {
			if (channel->offermsg.child_relid != relid)
				continue;

			if (channel->rescind)
				continue;

			++channel->interrupts;

			switch (channel->callback_mode) {
			case HV_CALL_ISR:
				vmbus_channel_isr(channel);
				break;

			case HV_CALL_BATCHED:
				hv_begin_read(&channel->inbound);
				/* fallthrough */
			case HV_CALL_DIRECT:
				tasklet_schedule(&channel->callback_event);
			}
		}

		rcu_read_unlock();
	}
}

static void vmbus_isr(void)
{
	struct hv_per_cpu_context *hv_cpu
		= this_cpu_ptr(hv_context.cpu_context); //XXX:TODO
	void *page_addr = hv_cpu->synic_event_page;
	struct hv_message *msg;
	union hv_synic_event_flags *event;
	bool handled = false;

	if (unlikely(page_addr == NULL))
		return;

	event = (union hv_synic_event_flags *)page_addr +
					 VMBUS_MESSAGE_SINT;
	/*
	 * Check for events before checking for messages. This is the order
	 * in which events and messages are checked in Windows guests on
	 * Hyper-V, and the Windows team suggested we do the same.
	 */

	if ((vmbus_proto_version2 == VERSION_WS2008) ||
		(vmbus_proto_version2 == VERSION_WIN7)) {

		/* Since we are a child, we only need to check bit 0 */
		if (sync_test_and_clear_bit(0, event->flags))
			handled = true;
	} else {
		/*
		 * Our host is win8 or above. The signaling mechanism
		 * has changed and we can directly look at the event page.
		 * If bit n is set then we have an interrup on the channel
		 * whose id is n.
		 */
		handled = true;
	}

	if (handled)
		vmbus_chan_sched(hv_cpu);

	page_addr = hv_cpu->synic_message_page;
	msg = (struct hv_message *)page_addr + VMBUS_MESSAGE_SINT;

	/* Check if there are actual msgs to be processed */
	if (msg->header.message_type != HVMSG_NONE) {
		if (msg->header.message_type == HVMSG_TIMER_EXPIRED)
			BUG_ON(1); //XXX: vmbus2 doesn't need to enable Hyper-V timer.
		else
			vmbus_on_msg_dpc2((unsigned long)hv_cpu);
	}

	add_interrupt_randomness(HYPERVISOR_CALLBACK_VECTOR, 0);
}


/*
 * vmbus_bus_init -Main vmbus driver initialization routine.
 *
 * Here, we
 *	- initialize the vmbus driver context
 *	- invoke the vmbus hv main init routine
 *	- retrieve the channel offers
 */
static int vmbus_bus_init(void)
{
	int ret;

	/* Hypervisor initialization...setup hypercall page..etc */
	ret = hv_init();
	if (ret != 0) {
		pr_err("Unable to initialize the hypervisor - 0x%x\n", ret);
		return ret;
	}

	ret = bus_register(&hv_bus);
	if (ret)
		return ret;

	hv_setup_vmbus_irq(vmbus_isr);

	ret = hv_synic_alloc();
	if (ret)
		goto err_alloc;
	/*
	 * Initialize the per-cpu interrupt state and
	 * connect to the host.
	 */
	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "x86/hyperv:online",
				hv_synic_init, hv_synic_cleanup);
	if (ret < 0)
		goto err_alloc;
	hyperv_cpuhp_online = ret;

	ret = vmbus_connect();
	if (ret)
		goto err_connect;


	vmbus_request_offers();

	return 0;

err_connect:
	cpuhp_remove_state(hyperv_cpuhp_online);
err_alloc:
	//hv_synic_free();
	//hv_remove_vmbus_irq();

	//bus_unregister(&hv_bus);

	return ret;
}

/**
 * __vmbus_child_driver_register() - Register a vmbus's driver
 * @hv_driver: Pointer to driver structure you want to register
 * @owner: owner module of the drv
 * @mod_name: module name string
 *
 * Registers the given driver with Linux through the 'driver_register()' call
 * and sets up the hyper-v vmbus handling for this driver.
 * It will return the state of the 'driver_register()' call.
 *
 */
int __vmbus_driver_register2(struct hv_driver *hv_driver, struct module *owner, const char *mod_name)
{
	int ret;

	pr_info("registering driver %s\n", hv_driver->name);

#if 0
	ret = vmbus_exists();
	if (ret < 0)
		return ret;
#endif

	hv_driver->driver.name = hv_driver->name;
	hv_driver->driver.owner = owner;
	hv_driver->driver.mod_name = mod_name;
	hv_driver->driver.bus = &hv_bus;

	spin_lock_init(&hv_driver->dynids.lock);
	INIT_LIST_HEAD(&hv_driver->dynids.list);

	ret = driver_register(&hv_driver->driver);

	return ret;
}
EXPORT_SYMBOL_GPL(__vmbus_driver_register2);

/**
 * vmbus_driver_unregister() - Unregister a vmbus's driver
 * @hv_driver: Pointer to driver structure you want to
 *             un-register
 *
 * Un-register the given driver that was previous registered with a call to
 * vmbus_driver_register()
 */
void vmbus_driver_unregister2(struct hv_driver *hv_driver)
{
	pr_info("unregistering driver %s\n", hv_driver->name);

	if (!vmbus_exists()) {
		driver_unregister(&hv_driver->driver);
		vmbus_free_dynids(hv_driver);
	}
}
EXPORT_SYMBOL_GPL(vmbus_driver_unregister2);

/*
 * vmbus_device_create - Creates and registers a new child device
 * on the vmbus.
 */
struct hv_device *vmbus_device_create(const uuid_le *type,
				      const uuid_le *instance,
				      struct vmbus_channel *channel)
{
	struct hv_device *child_device_obj;

	child_device_obj = kzalloc(sizeof(struct hv_device), GFP_KERNEL);
	if (!child_device_obj) {
		pr_err("Unable to allocate device object for child device\n");
		return NULL;
	}

	child_device_obj->channel = channel;
	memcpy(&child_device_obj->dev_type, type, sizeof(uuid_le));
	memcpy(&child_device_obj->dev_instance, instance,
	       sizeof(uuid_le));
	child_device_obj->vendor_id = 0x1414; /* MSFT vendor ID */


	return child_device_obj;
}

/*
 * vmbus_device_register - Register the child device
 */
int vmbus_device_register(struct hv_device *child_device_obj)
{
	int ret = 0;

	dev_set_name(&child_device_obj->device, "%pUl",
		     child_device_obj->channel->offermsg.offer.if_instance.b);

	child_device_obj->device.bus = &hv_bus;
	//child_device_obj->device.parent = &hv_acpi_dev->dev;
	child_device_obj->device.parent = NULL;
	child_device_obj->device.release = vmbus_device_release;

	/*
	 * Register with the LDM. This will kick off the driver/device
	 * binding...which will eventually call vmbus_match() and vmbus_probe()
	 */
	ret = device_register(&child_device_obj->device);
	if (ret)
		pr_err("Unable to register child device\n");
	else
		pr_debug("child device %s registered\n",
			 dev_name(&child_device_obj->device));

	return ret;
}

/*
 * vmbus_device_unregister - Remove the specified child device
 * from the vmbus.
 */
void vmbus_device_unregister(struct hv_device *device_obj)
{
	pr_debug("child device %s unregistered\n",
		dev_name(&device_obj->device));

	kset_unregister(device_obj->channels_kset);

	/*
	 * Kick off the process of unregistering the device.
	 * This will call vmbus_remove() and eventually vmbus_device_release()
	 */
	device_unregister(&device_obj->device);
}

static int __init hv2_init(void)
{
	int ret;

	if (x86_hyper_type != X86_HYPER_MS_HYPERV)
		return -ENODEV;

	ret = vmbus_bus_init();
	if (ret)
		goto cleanup;

	return 0;

cleanup:
	return ret;
}

static void __exit vmbus_exit(void)
{
	int cpu;

	hv_remove_kexec_handler();
	hv_remove_crash_handler();
	vmbus_connection2.conn_state = DISCONNECTED;
	vmbus_disconnect();
	hv_remove_vmbus_irq();
	for_each_online_cpu(cpu) {
		struct hv_per_cpu_context *hv_cpu
			= per_cpu_ptr(hv_context2.cpu_context, cpu);

		tasklet_kill(&hv_cpu->msg_dpc);
	}
	vmbus_free_channels();

	bus_unregister(&hv_bus);

	cpuhp_remove_state(hyperv_cpuhp_online);
	hv_synic_free();
}


subsys_initcall(hv2_init);
module_exit(vmbus_exit);

MODULE_LICENSE("GPL");
