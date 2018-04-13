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
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/hyperv.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <asm/mshyperv.h>
#include "hyperv_vmbus2.h"

/* The one and only */
extern struct hv_context hv_context; //XXX:

struct hv_context hv_context2  = {
	.synic_initialized	= false,
};

/*
 * hv_init - Main initialization routine.
 *
 * This routine must be called before any other routines in here are called
 */
int hv_init(void)
{
	if (!hv_is_hyperv_initialized())
		return -ENOTSUPP;

#if 1
	hv_context2.cpu_context = alloc_percpu(struct hv_per_cpu_context);
	if (!hv_context2.cpu_context)
		return -ENOMEM;
#endif

	return 0;
}

/*
 * hv_post_message - Post a message using the hypervisor message IPC.
 *
 * This involves a hypercall.
 */
int hv_post_message(union hv_connection_id connection_id,
		  enum hv_message_type message_type,
		  void *payload, size_t payload_size)
{
	struct hv_input_post_message *aligned_msg;
	struct hv_per_cpu_context *hv_cpu;
	u64 status;

	if (payload_size > HV_MESSAGE_PAYLOAD_BYTE_COUNT)
		return -EMSGSIZE;

	hv_cpu = get_cpu_ptr(hv_context2.cpu_context);
	aligned_msg = hv_cpu->post_msg_page;
	aligned_msg->connectionid = connection_id;
	aligned_msg->reserved = 0;
	aligned_msg->message_type = message_type;
	aligned_msg->payload_size = payload_size;
	memcpy((void *)aligned_msg->payload, payload, payload_size);

	status = hv_do_hypercall(HVCALL_POST_MESSAGE, aligned_msg, NULL);

	/* Preemption must remain disabled until after the hypercall
	 * so some other thread can't get scheduled onto this cpu and
	 * corrupt the per-cpu post_msg_page
	 */
	put_cpu_ptr(hv_cpu);

	return status & 0xFFFF;
}

int hv_synic_alloc(void)
{
	int cpu;
#if 0
	hv_context2.hv_numa_map = kzalloc(sizeof(struct cpumask) * nr_node_ids,
					 GFP_ATOMIC);
	if (hv_context2.hv_numa_map == NULL) {
		pr_err("Unable to allocate NUMA map\n");
		goto err;
	}

#endif
	for_each_present_cpu(cpu) {
		struct hv_per_cpu_context *hv_cpu
			= per_cpu_ptr(hv_context2.cpu_context, cpu);

//#if 0
		memset(hv_cpu, 0, sizeof(*hv_cpu));

//		tasklet_init(&hv_cpu->msg_dpc,
//			     vmbus_on_msg_dpc, (unsigned long) hv_cpu);

//		hv_cpu->clk_evt = kzalloc(sizeof(struct clock_event_device),
//					  GFP_KERNEL);
//		if (hv_cpu->clk_evt == NULL) {
//			pr_err("Unable to allocate clock event device\n");
//			goto err;
//		}
//		hv_init_clockevent_device(hv_cpu->clk_evt, cpu);
//
//		hv_cpu->synic_message_page =
//			(void *)get_zeroed_page(GFP_ATOMIC);
//		if (hv_cpu->synic_message_page == NULL) {
//			pr_err("Unable to allocate SYNIC message page\n");
//			goto err;
//		}
//
//		hv_cpu->synic_event_page = (void *)get_zeroed_page(GFP_ATOMIC);
//		if (hv_cpu->synic_event_page == NULL) {
//			pr_err("Unable to allocate SYNIC event page\n");
//			goto err;
//		}
//
		hv_cpu->post_msg_page = (void *)get_zeroed_page(GFP_ATOMIC);
		if (hv_cpu->post_msg_page == NULL) {
			pr_err("Unable to allocate post msg page\n");
			goto err;
		}

		INIT_LIST_HEAD(&hv_cpu->chan_list);
	}

	return 0;
err:
	return -ENOMEM;
}


void hv_synic_free(void)
{
	int cpu;

	for_each_present_cpu(cpu) {
		struct hv_per_cpu_context *hv_cpu
			= per_cpu_ptr(hv_context2.cpu_context, cpu);

		if (hv_cpu->synic_event_page)
			free_page((unsigned long)hv_cpu->synic_event_page);
		if (hv_cpu->synic_message_page)
			free_page((unsigned long)hv_cpu->synic_message_page);
		if (hv_cpu->post_msg_page)
			free_page((unsigned long)hv_cpu->post_msg_page);
	}

	kfree(hv_context2.hv_numa_map);
}

/*
 * hv_synic_init2 - Initialize the Synthethic Interrupt Controller.
 *
 * If it is already initialized by another entity (ie x2v shim), we need to
 * retrieve the initialized message and event pages.  Otherwise, we create and
 * initialize the message and event pages.
 */
int hv_synic_init2(unsigned int cpu)
{
	//struct hv_per_cpu_context *hv_cpu
	//	= per_cpu_ptr(hv_context2.cpu_context, cpu);
	//union hv_synic_simp simp;
	//union hv_synic_siefp siefp;
	union hv_synic_sint shared_sint;
	union hv_synic_scontrol sctrl;
	unsigned int sint = hv_get_sint2();

#if 0
	//XXX: we must share the pages with the primary vmbus driver!!!
	/* Setup the Synic's message page */
	hv_get_simp(simp.as_uint64);
	simp.simp_enabled = 1;
	simp.base_simp_gpa = virt_to_phys(hv_cpu->synic_message_page)
		>> PAGE_SHIFT;

	hv_set_simp(simp.as_uint64);

	/* Setup the Synic's event page */
	hv_get_siefp(siefp.as_uint64);
	siefp.siefp_enabled = 1;
	siefp.base_siefp_gpa = virt_to_phys(hv_cpu->synic_event_page)
		>> PAGE_SHIFT;

	hv_set_siefp(siefp.as_uint64);
#endif

	/* Setup the shared SINT. */
	hv_get_synint_state(HV_X64_MSR_SINT0 + sint,
			    shared_sint.as_uint64);

	//shared_sint.as_uint64 = 0;
	shared_sint.vector = HYPERVISOR_CALLBACK_VECTOR;
	shared_sint.masked = false;
	if (ms_hyperv.hints & HV_X64_DEPRECATING_AEOI_RECOMMENDED)
		shared_sint.auto_eoi = false;
	else
		shared_sint.auto_eoi = true;

	hv_set_synint_state(HV_X64_MSR_SINT0 + sint,
			    shared_sint.as_uint64);

	//XXX: re-enable this after the primary loads???
	//XXX: what if the 2nd vmbus driver unloads???
	/* Enable the global synic bit */
	hv_get_synic_state(sctrl.as_uint64);
	sctrl.enable = 1;

	hv_set_synic_state(sctrl.as_uint64);

	hv_context2.synic_initialized = true;

	return 0;
}

/*
 * hv_synic_cleanup2 - Cleanup routine for hv_synic_init2().
 */
int hv_synic_cleanup2(unsigned int cpu)
{
	union hv_synic_sint shared_sint;
	union hv_synic_simp simp;
	union hv_synic_siefp siefp;
	union hv_synic_scontrol sctrl;
	struct vmbus_channel *channel, *sc;
	bool channel_found = false;
	unsigned long flags;
	unsigned int sint = hv_get_sint2();

	WARN_ON(1);
	if (!hv_context2.synic_initialized)
		return -EFAULT;

	/*
	 * Search for channels which are bound to the CPU we're about to
	 * cleanup. In case we find one and vmbus is still connected we need to
	 * fail, this will effectively prevent CPU offlining. There is no way
	 * we can re-bind channels to different CPUs for now.
	 */
	mutex_lock(&vmbus_connection2.channel_mutex);
	list_for_each_entry(channel, &vmbus_connection2.chn_list, listentry) {
		if (channel->target_cpu == cpu) {
			channel_found = true;
			break;
		}
		spin_lock_irqsave(&channel->lock, flags);
		list_for_each_entry(sc, &channel->sc_list, sc_list) {
			if (sc->target_cpu == cpu) {
				channel_found = true;
				break;
			}
		}
		spin_unlock_irqrestore(&channel->lock, flags);
		if (channel_found)
			break;
	}
	mutex_unlock(&vmbus_connection2.channel_mutex);

	if (channel_found && vmbus_connection2.conn_state == CONNECTED)
		return -EBUSY;

	hv_get_synint_state(HV_X64_MSR_SINT0 + sint,
			    shared_sint.as_uint64);

	shared_sint.masked = 1;

	/* Need to correctly cleanup in the case of SMP!!! */
	/* Disable the interrupt */
	hv_set_synint_state(HV_X64_MSR_SINT0 + sint,
			    shared_sint.as_uint64);

	hv_get_simp(simp.as_uint64);
	simp.simp_enabled = 0;
	simp.base_simp_gpa = 0;

	hv_set_simp(simp.as_uint64);

	hv_get_siefp(siefp.as_uint64);
	siefp.siefp_enabled = 0;
	siefp.base_siefp_gpa = 0;

	hv_set_siefp(siefp.as_uint64);

	/* Disable the global synic bit */
	hv_get_synic_state(sctrl.as_uint64);
	sctrl.enable = 0;
	hv_set_synic_state(sctrl.as_uint64);

	return 0;
}
