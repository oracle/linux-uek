#ifndef _SPARC64_PAGE_LVL4_H
#define _SPARC64_PAGE_LVL4_H

#ifdef STRICT_MM_TYPECHECKS
/* These are used to make use of C type-checking.. */
typedef struct { unsigned long pmd; } pmd_t;
typedef struct { unsigned long pud; } pud_t;
typedef struct { unsigned long pgd; } pgd_t;

#define	__pud(x)	((pud_t) { (x) } )

#else
typedef unsigned long pmd_t;
typedef unsigned long pud_t;
typedef unsigned long pgd_t;

#define	__pud(x)	(x)

#endif /* (STRICT_MM_TYPECHECKS) */

#endif /* !_SPARC64_PAGE_LVL4_H */
