#ifndef __ASMSPARC_AUXVEC_H
#define __ASMSPARC_AUXVEC_H

#define AT_SYSINFO_EHDR		33

#ifdef CONFIG_SPARC64
#define AT_ADI_BLKSZ	34
#define AT_ADI_NBITS	35
#define AT_ADI_UEONADI	36

#define AT_VECTOR_SIZE_ARCH	3
#endif

#endif /* !(__ASMSPARC_AUXVEC_H) */
