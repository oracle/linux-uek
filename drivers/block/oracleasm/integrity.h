#ifndef ASM_INTEGRITY_H
#define ASM_INTEGRITY_H

#if defined(CONFIG_BLK_DEV_INTEGRITY)

extern u32  asm_integrity_format(struct block_device *);
extern int  asm_integrity_check(struct oracleasm_integrity_v2 *, struct block_device *);
extern int  asm_integrity_map(struct oracleasm_integrity_v2 *, struct asm_request *, int);
extern void asm_integrity_unmap(struct bio *);
extern unsigned int asm_integrity_error(struct asm_request *);

#else  /* CONFIG_BLK_DEV_INTEGRITY */

#define asm_integrity_format(a)		(0)
#define asm_integrity_check(a, b)	(0)
#define asm_integrity_map(a, b, c)	(0)
#define asm_integrity_unmap(a)		do { } while (0)
#define asm_integrity_error(a)		(ASM_ERR_IO)

#endif	/* CONFIG_BLK_DEV_INTEGRITY */

#endif
