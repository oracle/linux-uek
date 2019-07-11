/*
 *	Routines to identify additional cpu features that are scattered in
 *	cpuid space.
 */
#include <linux/cpu.h>

#include <asm/pat.h>
#include <asm/processor.h>
#include <asm/spec_ctrl.h>
#include <asm/apic.h>
#include <asm/intel-family.h>

#include <xen/xen.h>

struct cpuid_bit {
	u16 feature;
	u8 reg;
	u8 bit;
	u32 level;
	u32 sub_leaf;
};

enum cpuid_regs {
	CR_EAX = 0,
	CR_ECX,
	CR_EDX,
	CR_EBX
};

/*
 * Early microcode releases for the Spectre v2 mitigation were broken.
 * Information taken from;
 * - https://newsroom.intel.com/wp-content/uploads/sites/11/2018/01/microcode-update-guidance.pdf
 * - https://kb.vmware.com/s/article/52345
 * - Microcode revisions observed in the wild
 * - Release note from 20180108 microcode release
 */
struct sku_microcode {
	u8 model;
	u8 stepping;
	u32 microcode;
};

static const struct sku_microcode spectre_bad_microcodes[] = {
	{ INTEL_FAM6_KABYLAKE_DESKTOP,	0x0B,	0x84 },
	{ INTEL_FAM6_KABYLAKE_DESKTOP,	0x0A,	0x84 },
	{ INTEL_FAM6_KABYLAKE_DESKTOP,	0x09,	0x84 },
	{ INTEL_FAM6_KABYLAKE_MOBILE,	0x0A,	0x84 },
	{ INTEL_FAM6_KABYLAKE_MOBILE,	0x09,	0x84 },
	{ INTEL_FAM6_SKYLAKE_X,		0x03,	0x0100013e },
	{ INTEL_FAM6_SKYLAKE_X,		0x04,	0x0200003c },
	{ INTEL_FAM6_BROADWELL_CORE,	0x04,	0x28 },
	{ INTEL_FAM6_BROADWELL_GT3E,	0x01,	0x1b },
	{ INTEL_FAM6_BROADWELL_XEON_D,	0x02,	0x14 },
	{ INTEL_FAM6_BROADWELL_XEON_D,	0x03,	0x07000011 },
	{ INTEL_FAM6_BROADWELL_X,	0x01,	0x0b000025 },
	{ INTEL_FAM6_HASWELL_ULT,	0x01,	0x21 },
	{ INTEL_FAM6_HASWELL_GT3E,	0x01,	0x18 },
	{ INTEL_FAM6_HASWELL_CORE,	0x03,	0x23 },
	{ INTEL_FAM6_HASWELL_X,		0x02,	0x3b },
	{ INTEL_FAM6_HASWELL_X,		0x04,	0x10 },
	{ INTEL_FAM6_IVYBRIDGE_X,	0x04,	0x42a },
	/* Updated in the 20180108 release; blacklist until we know otherwise */
	{ INTEL_FAM6_ATOM_GEMINI_LAKE,	0x01,	0x22 },
	/* Observed in the wild */
	{ INTEL_FAM6_SANDYBRIDGE_X,	0x06,	0x61b },
	{ INTEL_FAM6_SANDYBRIDGE_X,	0x07,	0x712 },
};

bool bad_spectre_microcode(struct cpuinfo_x86 *c)
{
	int i;

	/*
	 * We know that the hypervisor lie to us on the microcode version so
	 * we may as well trust that it is running the correct microcode version.
	 */
	if (cpu_has(c, X86_FEATURE_HYPERVISOR))
		return false;

	if (c->x86 != 6)
		return false;

	for (i = 0; i < ARRAY_SIZE(spectre_bad_microcodes); i++) {
		if (c->x86_model == spectre_bad_microcodes[i].model &&
		    c->x86_mask == spectre_bad_microcodes[i].stepping)
			return (c->microcode <= spectre_bad_microcodes[i].microcode);
	}
	return false;
}

void init_scattered_cpuid_features(struct cpuinfo_x86 *c)
{
	u32 max_level;
	u32 regs[4];
	const struct cpuid_bit *cb;

	static const struct cpuid_bit cpuid_bits[] = {
		{ X86_FEATURE_DTHERM,		CR_EAX, 0, 0x00000006, 0 },
		{ X86_FEATURE_IDA,		CR_EAX, 1, 0x00000006, 0 },
		{ X86_FEATURE_ARAT,		CR_EAX, 2, 0x00000006, 0 },
		{ X86_FEATURE_PLN,		CR_EAX, 4, 0x00000006, 0 },
		{ X86_FEATURE_PTS,		CR_EAX, 6, 0x00000006, 0 },
		{ X86_FEATURE_HWP,		CR_EAX, 7, 0x00000006, 0 },
		{ X86_FEATURE_HWP_NOITFY,	CR_EAX, 8, 0x00000006, 0 },
		{ X86_FEATURE_HWP_ACT_WINDOW,	CR_EAX, 9, 0x00000006, 0 },
		{ X86_FEATURE_HWP_EPP,		CR_EAX,10, 0x00000006, 0 },
		{ X86_FEATURE_HWP_PKG_REQ,	CR_EAX,11, 0x00000006, 0 },
		{ X86_FEATURE_APERFMPERF,	CR_ECX, 0, 0x00000006, 0 },
		{ X86_FEATURE_EPB,		CR_ECX, 3, 0x00000006, 0 },
		{ X86_FEATURE_INTEL_PT,		CR_EBX,25, 0x00000007, 0 },
		{ X86_FEATURE_MD_CLEAR,		CR_EDX,10, 0x00000007, 0 },
		{ X86_FEATURE_IBRS,		CR_EDX,26, 0x00000007, 0 },
		{ X86_FEATURE_STIBP,            CR_EDX,27, 0x00000007, 0 },
		{ X86_FEATURE_IA32_ARCH_CAPS,   CR_EDX,29, 0x00000007, 0 },
		{ X86_FEATURE_SSBD,		CR_EDX,31, 0x00000007, 0 },
		{ X86_FEATURE_HW_PSTATE,	CR_EDX, 7, 0x80000007, 0 },
		{ X86_FEATURE_CPB,		CR_EDX, 9, 0x80000007, 0 },
		{ X86_FEATURE_PROC_FEEDBACK,	CR_EDX,11, 0x80000007, 0 },
		{ X86_FEATURE_NPT,		CR_EDX, 0, 0x8000000a, 0 },
		{ X86_FEATURE_LBRV,		CR_EDX, 1, 0x8000000a, 0 },
		{ X86_FEATURE_SVML,		CR_EDX, 2, 0x8000000a, 0 },
		{ X86_FEATURE_NRIPS,		CR_EDX, 3, 0x8000000a, 0 },
		{ X86_FEATURE_TSCRATEMSR,	CR_EDX, 4, 0x8000000a, 0 },
		{ X86_FEATURE_VMCBCLEAN,	CR_EDX, 5, 0x8000000a, 0 },
		{ X86_FEATURE_FLUSHBYASID,	CR_EDX, 6, 0x8000000a, 0 },
		{ X86_FEATURE_DECODEASSISTS,	CR_EDX, 7, 0x8000000a, 0 },
		{ X86_FEATURE_PAUSEFILTER,	CR_EDX,10, 0x8000000a, 0 },
		{ X86_FEATURE_PFTHRESHOLD,	CR_EDX,12, 0x8000000a, 0 },
		{ 0, 0, 0, 0, 0 }
	};

	for (cb = cpuid_bits; cb->feature; cb++) {

		/* Verify that the level is valid */
		max_level = cpuid_eax(cb->level & 0xffff0000);
		if (max_level < cb->level ||
		    max_level > (cb->level | 0xffff))
			continue;

		cpuid_count(cb->level, cb->sub_leaf, &regs[CR_EAX],
			    &regs[CR_EBX], &regs[CR_ECX], &regs[CR_EDX]);

		if (regs[cb->reg] & (1 << cb->bit))
			set_cpu_cap(c, cb->feature);
	}
}
