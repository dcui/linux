#ifndef _ASM_X86_MSHYPER_H
#define _ASM_X86_MSHYPER_H

#include <linux/types.h>
#include <linux/interrupt.h>
#include <asm/hyperv.h>
#include <linux/slab.h>

struct ms_hyperv_info {
	u32 features;
	u32 misc_features;
	u32 hints;
	u32 max_vp_index;
	u32 max_lp_index;
};

extern struct ms_hyperv_info ms_hyperv;

#define hv_get_vp_index(index) rdmsrl(HV_X64_MSR_VP_INDEX, index)

void hyperv_callback_vector(void);
#ifdef CONFIG_TRACING
#define trace_hyperv_callback_vector hyperv_callback_vector
#endif
void hyperv_vector_handler(struct pt_regs *regs);
void hv_setup_vmbus_irq(void (*handler)(void));
void hv_remove_vmbus_irq(void);

void hv_setup_kexec_handler(void (*handler)(void));
void hv_remove_kexec_handler(void);
void hv_setup_crash_handler(void (*handler)(struct pt_regs *regs));
void hv_remove_crash_handler(void);
#endif

#define HV_LINUX_VENDOR_ID              0x8100
/*
 * Generate the guest ID based on the guideline described above.
 */
static inline  __u64 generate_guest_id(__u64 d_info1, __u64 kernel_version,
				       __u64 d_info2)
{
	__u64 guest_id = 0;

	guest_id = (((__u64)HV_LINUX_VENDOR_ID) << 48);
	guest_id |= (d_info1 << 48);
	guest_id |= (kernel_version << 16);
	guest_id |= d_info2;

	return guest_id;
}

extern u32 *hv_vp_index;
extern u32 hv_max_vp_index;


/**
 * hv_cpu_number_to_vp_number() - Map CPU to VP.
 * @cpu_number: CPU number in Linux terms
 *
 * This function returns the mapping between the Linux processor
 * number and the hypervisor's virtual processor number, useful
 * in making hypercalls and such that talk about specific
 * processors.
 *
 * Return: Virtual processor number in Hyper-V terms
 */

static inline int hv_cpu_number_to_vp_number(int cpu_number)
{
	return hv_vp_index[cpu_number];
}

union hv_x64_msr_hypercall_contents {
	u64 as_uint64;
	struct {
		u64 enable:1;
		u64 reserved:11;
		u64 guest_physical_address:52;
	};
};

void hyperv_init(void);
void hyperv_cleanup(void);
void hyperv_report_panic(struct pt_regs *regs, long err);
int hv_cpu_init(unsigned int cpu);

