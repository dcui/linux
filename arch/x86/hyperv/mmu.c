#include <linux/types.h>
#include <linux/hyperv.h>
#include <linux/slab.h>
#include <linux/log2.h>
#include <asm/mshyperv.h>
#include <asm/tlbflush.h>
#include <asm/msr.h>
#include <asm/fpu/api.h>

/* HvFlushVirtualAddressSpace, HvFlushVirtualAddressList hypercalls */
struct hv_flush_pcpu {
	__u64 address_space;
	__u64 flags;
	__u64 processor_mask;
	__u64 gva_list[];
};

static struct hv_flush_pcpu __percpu *pcpu_flush;

static void hyperv_flush_tlb_others(const struct cpumask *cpus,
				    struct mm_struct *mm, unsigned long start,
				    unsigned long end)
{
	struct hv_flush_pcpu *flush;
	unsigned long cur, flags;
	u64 status = -1ULL;
	int cpu, vcpu, gva_n, max_gvas;

	if (!pcpu_flush || !hv_hypercall_pg)
		goto do_native;

	if (cpumask_empty(cpus))
		return;

	local_irq_save(flags);

	flush = this_cpu_ptr(pcpu_flush);

	if (mm) {
		flush->address_space = virt_to_phys(mm->pgd);
		flush->flags = 0;
	} else {
		flush->address_space = 0;
		flush->flags = HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES;
	}

	flush->processor_mask = 0;
	if (cpumask_equal(cpus, cpu_present_mask)) {
		flush->flags |= HV_FLUSH_ALL_PROCESSORS;
	} else {
		for_each_cpu(cpu, cpus) {
			vcpu = hv_cpu_number_to_vp_number(cpu);
			if (vcpu != -1 && vcpu < 64)
				flush->processor_mask |= 1 << vcpu;
			else
				goto do_native;
		}
	}

	/*
	 * We can flush not more than max_gvas with one hypercall. Flush the
	 * whole address space if we were asked to do more.
	 */
	max_gvas = (PAGE_SIZE - sizeof(*flush)) / 8;

	if (end == TLB_FLUSH_ALL ||
	    (end && ((end - start)/(PAGE_SIZE*PAGE_SIZE)) > max_gvas)) {
		if (end == TLB_FLUSH_ALL)
			flush->flags |= HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY;
		status = hv_do_hypercall(HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE,
					 flush, NULL);
	} else {
		cur = start;
		gva_n = 0;
		do {
			flush->gva_list[gva_n] = cur & PAGE_MASK;
			/*
			 * Lower 12 bits encode the number of additional
			 * pages to flush (in addition to the 'cur' page).
			 */
			if (end >= cur + PAGE_SIZE * PAGE_SIZE)
				flush->gva_list[gva_n] |= ~PAGE_MASK;
			else if (end > cur)
				flush->gva_list[gva_n] |=
					(end - cur - 1) >> PAGE_SHIFT;

			cur += PAGE_SIZE * PAGE_SIZE;
			++gva_n;

		} while (cur < end);

		status = hv_do_rep_hypercall(HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST,
					     gva_n, 0, flush, NULL);

	}

	local_irq_restore(flags);

	if (!(status & 0xffff))
		return;
do_native:
	native_flush_tlb_others(cpus, mm, start, end);
}

void hyperv_setup_mmu_ops(void)
{
	if (ms_hyperv.hints & HV_X64_REMOTE_TLB_FLUSH_RECOMMENDED) {
		pr_info("Hyper-V: Using hypercall for remote TLB flush\n");
		pv_mmu_ops.flush_tlb_others = hyperv_flush_tlb_others;
	}
}

void hyper_alloc_mmu(void)
{
	if (ms_hyperv.hints & HV_X64_REMOTE_TLB_FLUSH_RECOMMENDED)
		pcpu_flush = __alloc_percpu(PAGE_SIZE, PAGE_SIZE);
}
