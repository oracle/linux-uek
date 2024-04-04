/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_KVM_CPUID_H
#define ARCH_X86_KVM_CPUID_H

#include "x86.h"
#include <asm/cpu.h>
#include <asm/processor.h>

/*
 * Hardware-defined CPUID leafs that are scattered in the kernel, but need to
 * be directly used by KVM.  Note, these word values conflict with the kernel's
 * "bug" caps, but KVM doesn't use those.
 */
enum kvm_only_cpuid_leafs {
	NR_KVM_CPU_CAPS = NCAPINTS,

	NKVMCAPINTS = NR_KVM_CPU_CAPS - NCAPINTS,
};

#define X86_KVM_FEATURE(w, f)		((w)*32 + (f))

extern u32 kvm_cpu_caps[NR_KVM_CPU_CAPS] __read_mostly;
void kvm_set_cpu_caps(void);

void kvm_update_cpuid_runtime(struct kvm_vcpu *vcpu);
struct kvm_cpuid_entry2 *kvm_find_cpuid_entry(struct kvm_vcpu *vcpu,
					      u32 function, u32 index);
int kvm_dev_ioctl_get_cpuid(struct kvm_cpuid2 *cpuid,
			    struct kvm_cpuid_entry2 __user *entries,
			    unsigned int type);
int kvm_vcpu_ioctl_set_cpuid(struct kvm_vcpu *vcpu,
			     struct kvm_cpuid *cpuid,
			     struct kvm_cpuid_entry __user *entries);
int kvm_vcpu_ioctl_set_cpuid2(struct kvm_vcpu *vcpu,
			      struct kvm_cpuid2 *cpuid,
			      struct kvm_cpuid_entry2 __user *entries);
int kvm_vcpu_ioctl_get_cpuid2(struct kvm_vcpu *vcpu,
			      struct kvm_cpuid2 *cpuid,
			      struct kvm_cpuid_entry2 __user *entries);
bool kvm_cpuid(struct kvm_vcpu *vcpu, u32 *eax, u32 *ebx,
	       u32 *ecx, u32 *edx, bool check_limit);

int cpuid_query_maxphyaddr(struct kvm_vcpu *vcpu);

static inline int cpuid_maxphyaddr(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.maxphyaddr;
}

static inline bool kvm_vcpu_is_legal_gpa(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	return !(gpa >> cpuid_maxphyaddr(vcpu));
}

static inline bool kvm_vcpu_is_illegal_gpa(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	return !kvm_vcpu_is_legal_gpa(vcpu, gpa);
}

static inline bool kvm_vcpu_is_legal_aligned_gpa(struct kvm_vcpu *vcpu,
						 gpa_t gpa, gpa_t alignment)
{
	return IS_ALIGNED(gpa, alignment) && kvm_vcpu_is_legal_gpa(vcpu, gpa);
}

static inline bool page_address_valid(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	return kvm_vcpu_is_legal_aligned_gpa(vcpu, gpa, PAGE_SIZE);
}

struct cpuid_reg {
	u32 function;
	u32 index;
	int reg;
};

static const struct cpuid_reg reverse_cpuid[] = {
	[CPUID_1_EDX]         = {         1, 0, CPUID_EDX},
	[CPUID_8000_0001_EDX] = {0x80000001, 0, CPUID_EDX},
	[CPUID_8086_0001_EDX] = {0x80860001, 0, CPUID_EDX},
	[CPUID_1_ECX]         = {         1, 0, CPUID_ECX},
	[CPUID_C000_0001_EDX] = {0xc0000001, 0, CPUID_EDX},
	[CPUID_8000_0001_ECX] = {0x80000001, 0, CPUID_ECX},
	[CPUID_7_0_EBX]       = {         7, 0, CPUID_EBX},
	[CPUID_D_1_EAX]       = {       0xd, 1, CPUID_EAX},
	[CPUID_8000_0008_EBX] = {0x80000008, 0, CPUID_EBX},
	[CPUID_6_EAX]         = {         6, 0, CPUID_EAX},
	[CPUID_8000_000A_EDX] = {0x8000000a, 0, CPUID_EDX},
	[CPUID_7_ECX]         = {         7, 0, CPUID_ECX},
	[CPUID_8000_0007_EBX] = {0x80000007, 0, CPUID_EBX},
	[CPUID_7_EDX]         = {         7, 0, CPUID_EDX},
	[CPUID_7_1_EAX]       = {         7, 1, CPUID_EAX},
	[CPUID_8000_0021_EAX] = {0x80000021, 0, CPUID_EAX},
};

/*
 * Reverse CPUID and its derivatives can only be used for hardware-defined
 * feature words, i.e. words whose bits directly correspond to a CPUID leaf.
 * Retrieving a feature bit or masking guest CPUID from a Linux-defined word
 * is nonsensical as the bit number/mask is an arbitrary software-defined value
 * and can't be used by KVM to query/control guest capabilities.  And obviously
 * the leaf being queried must have an entry in the lookup table.
 */
static __always_inline void reverse_cpuid_check(unsigned int x86_leaf)
{
	BUILD_BUG_ON(x86_leaf == CPUID_LNX_1);
	BUILD_BUG_ON(x86_leaf == CPUID_LNX_2);
	BUILD_BUG_ON(x86_leaf == CPUID_LNX_3);
	BUILD_BUG_ON(x86_leaf == CPUID_LNX_4);
	BUILD_BUG_ON(x86_leaf >= ARRAY_SIZE(reverse_cpuid));
	BUILD_BUG_ON(reverse_cpuid[x86_leaf].function == 0);
}

/*
 * Translate feature bits that are scattered in the kernel's cpufeatures word
 * into KVM feature words that align with hardware's definitions.
 */
static __always_inline u32 __feature_translate(int x86_feature)
{
	return x86_feature;
}

static __always_inline u32 __feature_leaf(int x86_feature)
{
	return __feature_translate(x86_feature) / 32;
}

/*
 * Retrieve the bit mask from an X86_FEATURE_* definition.  Features contain
 * the hardware defined bit number (stored in bits 4:0) and a software defined
 * "word" (stored in bits 31:5).  The word is used to index into arrays of
 * bit masks that hold the per-cpu feature capabilities, e.g. this_cpu_has().
 */
static __always_inline u32 __feature_bit(int x86_feature)
{
	x86_feature = __feature_translate(x86_feature);

	reverse_cpuid_check(x86_feature / 32);
	return 1 << (x86_feature & 31);
}

#define feature_bit(name)  __feature_bit(X86_FEATURE_##name)

static __always_inline struct cpuid_reg x86_feature_cpuid(unsigned int x86_feature)
{
	unsigned int x86_leaf = __feature_leaf(x86_feature);

	reverse_cpuid_check(x86_leaf);
	return reverse_cpuid[x86_leaf];
}

static __always_inline u32 *__cpuid_entry_get_reg(struct kvm_cpuid_entry2 *entry,
						  u32 reg)
{
	switch (reg) {
	case CPUID_EAX:
		return &entry->eax;
	case CPUID_EBX:
		return &entry->ebx;
	case CPUID_ECX:
		return &entry->ecx;
	case CPUID_EDX:
		return &entry->edx;
	default:
		BUILD_BUG();
		return NULL;
	}
}

static __always_inline u32 *cpuid_entry_get_reg(struct kvm_cpuid_entry2 *entry,
						unsigned int x86_feature)
{
	const struct cpuid_reg cpuid = x86_feature_cpuid(x86_feature);

	return __cpuid_entry_get_reg(entry, cpuid.reg);
}

static __always_inline u32 cpuid_entry_get(struct kvm_cpuid_entry2 *entry,
					   unsigned int x86_feature)
{
	u32 *reg = cpuid_entry_get_reg(entry, x86_feature);

	return *reg & __feature_bit(x86_feature);
}

static __always_inline bool cpuid_entry_has(struct kvm_cpuid_entry2 *entry,
					    unsigned int x86_feature)
{
	return cpuid_entry_get(entry, x86_feature);
}

static __always_inline void cpuid_entry_clear(struct kvm_cpuid_entry2 *entry,
					      unsigned int x86_feature)
{
	u32 *reg = cpuid_entry_get_reg(entry, x86_feature);

	*reg &= ~__feature_bit(x86_feature);
}

static __always_inline void cpuid_entry_set(struct kvm_cpuid_entry2 *entry,
					    unsigned int x86_feature)
{
	u32 *reg = cpuid_entry_get_reg(entry, x86_feature);

	*reg |= __feature_bit(x86_feature);
}

static __always_inline void cpuid_entry_change(struct kvm_cpuid_entry2 *entry,
					       unsigned int x86_feature,
					       bool set)
{
	u32 *reg = cpuid_entry_get_reg(entry, x86_feature);

	/*
	 * Open coded instead of using cpuid_entry_{clear,set}() to coerce the
	 * compiler into using CMOV instead of Jcc when possible.
	 */
	if (set)
		*reg |= __feature_bit(x86_feature);
	else
		*reg &= ~__feature_bit(x86_feature);
}

static __always_inline void cpuid_entry_override(struct kvm_cpuid_entry2 *entry,
						 unsigned int leaf)
{
	u32 *reg = cpuid_entry_get_reg(entry, leaf * 32);

	BUILD_BUG_ON(leaf >= ARRAY_SIZE(kvm_cpu_caps));
	*reg = kvm_cpu_caps[leaf];
}

static __always_inline u32 *guest_cpuid_get_register(struct kvm_vcpu *vcpu,
						     unsigned int x86_feature)
{
	const struct cpuid_reg cpuid = x86_feature_cpuid(x86_feature);
	struct kvm_cpuid_entry2 *entry;

	entry = kvm_find_cpuid_entry(vcpu, cpuid.function, cpuid.index);
	if (!entry)
		return NULL;

	return __cpuid_entry_get_reg(entry, cpuid.reg);
}

static __always_inline bool guest_cpuid_has(struct kvm_vcpu *vcpu,
					    unsigned int x86_feature)
{
	u32 *reg;

	if (x86_feature == X86_FEATURE_XSAVE &&
			!static_cpu_has(X86_FEATURE_XSAVE))
		return false;

	reg = guest_cpuid_get_register(vcpu, x86_feature);
	if (!reg)
		return false;

	return *reg & __feature_bit(x86_feature);
}

static __always_inline void guest_cpuid_clear(struct kvm_vcpu *vcpu,
					      unsigned int x86_feature)
{
	u32 *reg;

	reg = guest_cpuid_get_register(vcpu, x86_feature);
	if (reg)
		*reg &= ~__feature_bit(x86_feature);
}

static inline bool guest_cpuid_is_amd(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *best;

	best = kvm_find_cpuid_entry(vcpu, 0, 0);
	return best && best->ebx == X86EMUL_CPUID_VENDOR_AuthenticAMD_ebx;
}

static inline int guest_cpuid_family(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *best;

	best = kvm_find_cpuid_entry(vcpu, 0x1, 0);
	if (!best)
		return -1;

	return x86_family(best->eax);
}

static inline int guest_cpuid_model(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *best;

	best = kvm_find_cpuid_entry(vcpu, 0x1, 0);
	if (!best)
		return -1;

	return x86_model(best->eax);
}

static inline int guest_cpuid_stepping(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *best;

	best = kvm_find_cpuid_entry(vcpu, 0x1, 0);
	if (!best)
		return -1;

	return x86_stepping(best->eax);
}

static inline bool guest_has_spec_ctrl_msr(struct kvm_vcpu *vcpu)
{
	return (guest_cpuid_has(vcpu, X86_FEATURE_SPEC_CTRL) ||
		guest_cpuid_has(vcpu, X86_FEATURE_AMD_STIBP) ||
		guest_cpuid_has(vcpu, X86_FEATURE_AMD_IBRS) ||
		guest_cpuid_has(vcpu, X86_FEATURE_AMD_SSBD));
}

static inline bool guest_has_pred_cmd_msr(struct kvm_vcpu *vcpu)
{
	return (guest_cpuid_has(vcpu, X86_FEATURE_SPEC_CTRL) ||
		guest_cpuid_has(vcpu, X86_FEATURE_AMD_IBPB));
}

static inline bool supports_cpuid_fault(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.msr_platform_info & MSR_PLATFORM_INFO_CPUID_FAULT;
}

static inline bool cpuid_fault_enabled(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.msr_misc_features_enables &
		  MSR_MISC_FEATURES_ENABLES_CPUID_FAULT;
}

static __always_inline void kvm_cpu_cap_clear(unsigned int x86_feature)
{
	unsigned int x86_leaf = __feature_leaf(x86_feature);

	reverse_cpuid_check(x86_leaf);
	kvm_cpu_caps[x86_leaf] &= ~__feature_bit(x86_feature);
}

static __always_inline void kvm_cpu_cap_set(unsigned int x86_feature)
{
	unsigned int x86_leaf = __feature_leaf(x86_feature);

	reverse_cpuid_check(x86_leaf);
	kvm_cpu_caps[x86_leaf] |= __feature_bit(x86_feature);
}

static __always_inline u32 kvm_cpu_cap_get(unsigned int x86_feature)
{
	unsigned int x86_leaf = __feature_leaf(x86_feature);

	reverse_cpuid_check(x86_leaf);
	return kvm_cpu_caps[x86_leaf] & __feature_bit(x86_feature);
}

static __always_inline bool kvm_cpu_cap_has(unsigned int x86_feature)
{
	return !!kvm_cpu_cap_get(x86_feature);
}

static __always_inline void kvm_cpu_cap_check_and_set(unsigned int x86_feature)
{
	if (boot_cpu_has(x86_feature))
		kvm_cpu_cap_set(x86_feature);
}

#endif
