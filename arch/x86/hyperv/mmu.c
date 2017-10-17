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

/* HvFlushVirtualAddressSpaceEx, HvFlushVirtualAddressListEx hypercalls */
struct hv_flush_pcpu_ex {
	__u64 address_space;
	__u64 flags;
	struct {
		__u64 format;
		__u64 valid_bank_mask;
		__u64 bank_contents[];
	} hv_vp_set;
	__u64 gva_list[];
};

static struct hv_flush_pcpu __percpu *pcpu_flush;

static struct hv_flush_pcpu_ex __percpu *pcpu_flush_ex;

static inline int cpumask_to_vp_set(struct hv_flush_pcpu_ex *flush,
				    const struct cpumask *cpus)
{
	int cur_bank, cpu, vcpu, nr_bank = 0;
	bool has_cpus;

	/*
	 * We can't be sure that translated vcpu numbers will always be
	 * in ascending order, so iterate over all possible banks and
	 * check all vcpus in it instead.
	 */
	for (cur_bank = 0; cur_bank < ms_hyperv.max_vp_index/64; cur_bank++) {
		has_cpus = false;
		for_each_cpu(cpu, cpus) {
			vcpu = hv_cpu_number_to_vp_number(cpu);
			if (vcpu/64 != cur_bank)
				continue;
			if (!has_cpus) {
				flush->hv_vp_set.valid_bank_mask |=
					1 << vcpu / 64;
				flush->hv_vp_set.bank_contents[nr_bank] =
					1 << vcpu % 64;
				has_cpus = true;
			} else {
				flush->hv_vp_set.bank_contents[nr_bank] |=
					1 << vcpu % 64;
			}
		}
		if (has_cpus)
			nr_bank++;
	}

	return nr_bank;
}

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

static void hyperv_flush_tlb_others_ex(const struct cpumask *cpus,
				       struct mm_struct *mm,
				       unsigned long start,
				       unsigned long end)
{
	struct hv_flush_pcpu_ex *flush;
	unsigned long cur, flags;
	u64 status = -1ULL;
	int nr_bank = 0, max_gvas, gva_n;

	if (!pcpu_flush_ex || !hv_hypercall_pg)
		goto do_native;

	if (cpumask_empty(cpus))
		return;

	local_irq_save(flags);

	flush = this_cpu_ptr(pcpu_flush_ex);

	if (mm) {
		flush->address_space = virt_to_phys(mm->pgd);
		flush->flags = 0;
	} else {
		flush->address_space = 0;
		flush->flags = HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES;
	}

	flush->hv_vp_set.valid_bank_mask = 0;

	if (cpumask_equal(cpus, cpu_present_mask)) {
		flush->hv_vp_set.format = HV_GENERIC_SET_ALL;
		flush->flags |= HV_FLUSH_ALL_PROCESSORS;
	} else {
		flush->hv_vp_set.format = HV_GENERIC_SET_SPARCE_4K;
		nr_bank = cpumask_to_vp_set(flush, cpus);
	}

	/*
	 * We can flush not more than max_gvas with one hypercall. Flush the
	 * whole address space if we were asked to do more.
	 */
	max_gvas = (PAGE_SIZE - sizeof(*flush) - nr_bank*8) / 8;

	if (end == TLB_FLUSH_ALL ||
	    (end && ((end - start)/(PAGE_SIZE*PAGE_SIZE)) > max_gvas)) {
		if (end == TLB_FLUSH_ALL)
			flush->flags |= HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY;

		status = hv_do_rep_hypercall(
			HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX,
			0, nr_bank + 2, flush, NULL);
	} else {
		cur = start;
		gva_n = nr_bank;
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

		status = hv_do_rep_hypercall(
			HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX,
			gva_n, nr_bank + 2, flush, NULL);
	}

	local_irq_restore(flags);

	if (!(status & 0xffff))
		return;
do_native:
	native_flush_tlb_others(cpus, mm, start, end);
}

void hyperv_setup_mmu_ops(void)
{
	if (!(ms_hyperv.hints & HV_X64_REMOTE_TLB_FLUSH_RECOMMENDED))
		return;

	if (!(ms_hyperv.hints & HV_X64_EX_PROCESSOR_MASKS_RECOMMENDED)) {
		pr_info("Hyper-V: Using hypercall for remote TLB flush\n");
		pv_mmu_ops.flush_tlb_others = hyperv_flush_tlb_others;
	} else {
		pr_info("Hyper-V: Using ext hypercall for remote TLB flush\n");
		pv_mmu_ops.flush_tlb_others = hyperv_flush_tlb_others_ex;
	}
}

void hyper_alloc_mmu(void)
{
	if (!(ms_hyperv.hints & HV_X64_REMOTE_TLB_FLUSH_RECOMMENDED))
		return;

	if (!(ms_hyperv.hints & HV_X64_EX_PROCESSOR_MASKS_RECOMMENDED))
		pcpu_flush = __alloc_percpu(PAGE_SIZE, PAGE_SIZE);
	else
		pcpu_flush_ex = __alloc_percpu(PAGE_SIZE, PAGE_SIZE);
}
