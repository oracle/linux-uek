#ifndef _SPARC64_SPARSEMEM_H
#define _SPARC64_SPARSEMEM_H

#ifdef __KERNEL__

#define SECTION_SIZE_BITS       30
#ifdef CONFIG_SPARC_PGTABLE_LEVEL4
#define MAX_PHYSADDR_BITS       47
#define MAX_PHYSMEM_BITS        47
#else
#define MAX_PHYSADDR_BITS       42
#define MAX_PHYSMEM_BITS        42
#endif

#endif /* !(__KERNEL__) */

#endif /* !(_SPARC64_SPARSEMEM_H) */
