#ifndef _ASM_X86_VNUMA_H
#define _ASM_X86_VNUMA_H

#ifdef CONFIG_XEN
int xen_numa_init(void);
#else
static inline int xen_numa_init(void) { return -1; };
#endif

#endif /* _ASM_X86_VNUMA_H */
