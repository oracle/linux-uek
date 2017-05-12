/* adi_64.h: ADI related data structures
 *
 * Copyright (C) 2016 Khalid Aziz (khalid.aziz@oracle.com)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */
#ifndef __ASM_SPARC64_ADI_H
#define __ASM_SPARC64_ADI_H

#include <linux/types.h>
#include <asm/processor.h>

#ifndef __ASSEMBLY__

struct adi_caps {
	__u64 blksz;
	__u64 nbits;
	__u64 ue_on_adi;
};

struct adi_config {
	bool enabled;
	struct adi_caps caps;
};

extern struct adi_config adi_state;

extern int mcd_on_by_default;

extern void mdesc_adi_init(void);

static inline bool adi_capable(void)
{
	return adi_state.enabled;
}

static inline unsigned long adi_blksize(void)
{
	return adi_state.caps.blksz;
}

static inline unsigned long adi_nbits(void)
{
	return adi_state.caps.nbits;
}

static inline unsigned char adi_get_version(void *addr)
{
	long version;

	asm volatile("ldxa [%1] %2, %0\n\t"
		     : "=r" (version)
		     : "r" (addr), "i" (ASI_MCD_PRIV_PRIMARY));
	return (unsigned char)version;
}

static inline void adi_set_version(void *addr, int version)
{
	asm volatile("stxa %1, [%0] %2\n\t"
		     :
		     : "r" (addr), "r" (version), "i" (ASI_MCD_PRIV_PRIMARY));
}

static inline unsigned long adi_normalize(long addr)
{
	return addr << adi_nbits() >> adi_nbits();
}

static inline unsigned long adi_pstate_disable(void)
{
	unsigned long saved_pstate;

	__asm__ __volatile__(
		"rdpr   %%pstate, %0    \n\t"
		"andn   %0, %1, %%g1    \n\t"
		"wrpr   %%g1, %%pstate  \n\t"
		: "=&r" (saved_pstate)
		: "i"   (PSTATE_MCDE)
		: "g1");

	return saved_pstate;
}

static inline void adi_pstate_restore(unsigned long saved_pstate)
{
	__asm__ __volatile__(
		"wrpr   %0, %%pstate  \n\t"
		:
		: "r" (saved_pstate)
		: );
}

#endif	/* __ASSEMBLY__ */

#endif	/* !(__ASM_SPARC64_ADI_H) */
