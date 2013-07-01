#ifndef _SPARC64_PAGE_LVL3_H
#define _SPARC64_PAGE_LVL3_H

#ifdef STRICT_MM_TYPECHECKS
/* These are used to make use of C type-checking.. */
typedef struct { unsigned int pmd; } pmd_t;
typedef struct { unsigned int pgd; } pgd_t;

#else
typedef unsigned int pmd_t;
typedef unsigned int pgd_t;

#endif /* (STRICT_MM_TYPECHECKS) */

#endif /* !_SPARC64_PAGE_LVL3_H */
