#include <asm/head_64.h>
#include <asm/asi.h>
#include <asm/ptrace.h>
#include <asm/ttable.h>
#include <asm/hypervisor.h>
#include <asm/kexec.h>
	.text
	.section sparc64_kexec, "axw"
#define	KX_SCRATCH		((0x200 << 5) << 1)
#define KX_HV_FAULT_I_TYPE_OFFSET	HV_FAULT_I_TYPE_OFFSET
#define	KX_HV_FAULT_I_ADDR_OFFSET	HV_FAULT_I_ADDR_OFFSET
#define KX_HV_FAULT_D_TYPE_OFFSET	HV_FAULT_D_TYPE_OFFSET
#define	KX_HV_FAULT_D_ADDR_OFFSET	HV_FAULT_D_ADDR_OFFSET
#define	KX_NR_NTTE			0x0080
#define	KX_NR_KTTE			0x0088
#define	KX_KTTE				0x0090
#define	KX_NR_ITTE			0x00d0
#define	KX_ITTE				0x00d8
#define	KX_OBP_CIF			0x0118
#define	KX_OBP_SP			0x0120
#define	KX_OBP_TRANSLATIONS		0x0128
#define BKT(LVL)					\
	wrpr	%g0, 0, %gl;				\
	ldxa	[%g0] ASI_SCRATCHPAD, %g1;		\
	ldx	[%g1 + KX_OBP_CIF], %o4;		\
	ldx	[%g1 + KX_OBP_SP], %o6;			\
	ba,a,pt	%xcc, bad_bkt_trap;			\
	nop; nop; nop;
#define	BKTS(LVL) BKT(LVL) BKT(LVL+1) BKT(LVL+2) BKT(LVL+3)
#define KX_ITLB_MISS					\
	ldxa	[%g0] ASI_SCRATCHPAD, %g2;		\
	ldx	[%g2 + KX_HV_FAULT_I_ADDR_OFFSET], %g1;	\
	or	%g0, %lo(HV_MMU_IMMU), %g3;		\
	ba,a,pt	%xcc, kx_tlb_miss;			\
	nop; nop; nop; nop;
#define KX_DTLB_MISS					\
	ldxa	[%g0] ASI_SCRATCHPAD, %g2;		\
	ldx	[%g2 + KX_HV_FAULT_D_ADDR_OFFSET], %g1;	\
	or	%g0, %lo(HV_MMU_DMMU), %g3;		\
	ba,a,pt	%xcc, kx_tlb_miss;			\
	nop; nop; nop; nop;
	.align 0x10000
	.global sparc64_kexec_trap_tl0
sparc64_kexec_trap_tl0:
tl0_kexec_000:	BKT(0x000) BKT(0x001) BKT(0x002) BKT(0x003)
tl0_kexec_004:	BKT(0x004) BKT(0x005) BKT(0x006) BKT(0x007)
tl0_kexec_008:	BKT(0x008)
tl0_kexec_sun4v_itsb: BKT(0x009)
tl0_kexec_00a:	BKT(0x00a) BKT(0x00b)
tl0_kexec_00c:	BKT(0x00c) BKT(0x00d) BKT(0x00e) BKT(0x00f)
tl0_kexec_010:	BKT(0x010) BKT(0x011) BKT(0x012) BKT(0x013)
tl0_kexec_014:	BKT(0x014) BKT(0x015) BKT(0x016) BKT(0x017)
tl0_kexec_018:	BKT(0x018) BKT(0x019) BKT(0x01a) BKT(0x01b)
tl0_kexec_01c:	BKT(0x01c) BKT(0x01d) BKT(0x01e) BKT(0x01f)
tl0_kexec_020:	BKT(0x020) BKT(0x021) BKT(0x022) BKT(0x023)
tl0_kexec_clean_window:
		CLEAN_WINDOW
tl0_kexec_028:	BKT(0x028) BKT(0x029) BKT(0x02a) BKT(0x02b)
tl0_kexec_02c:	BKT(0x02c) BKT(0x02d) BKT(0x02e) BKT(0x02f)
tl0_kexec_030:	BKT(0x030)
tl0_kexec_sun4v_dtsb: BKT(0x031)
tl0_kexec_032:	BKT(0x032) BKT(0x033)
tl0_kexec_034:	BKT(0x034) BKT(0x035) BKT(0x036) BKT(0x037)
tl0_kexec_038:	BKT(0x038) BKT(0x039) BKT(0x03a) BKT(0x03b)
tl0_kexec_03c:	BKT(0x03c) BKT(0x03d) BKT(0x03e) BKT(0x03f)
tl0_kexec_040:	BKT(0x040) BKT(0x041) BKT(0x042) BKT(0x043)
tl0_kexec_044:	BKT(0x044) BKT(0x045) BKT(0x046) BKT(0x047)
tl0_kexec_048:	BKT(0x048) BKT(0x049) BKT(0x04a) BKT(0x04b)
tl0_kexec_04c:	BKT(0x04c) BKT(0x04d) BKT(0x04e) BKT(0x04f)
tl0_kexec_050:	BKT(0x050) BKT(0x051) BKT(0x052) BKT(0x053)
tl0_kexec_054:	BKT(0x054) BKT(0x055) BKT(0x056) BKT(0x057)
tl0_kexec_058:	BKT(0x058) BKT(0x059) BKT(0x05a) BKT(0x05b)
tl0_kexec_05c:	BKT(0x05c) BKT(0x05d) BKT(0x05e) BKT(0x05f)
tl0_kexec_060:	BKT(0x060) BKT(0x061) BKT(0x062) BKT(0x063)
tl0_kexec_fast_instruction_access_MMU_miss:
		KX_ITLB_MISS BKT(0x065) BKT(0x066) BKT(0x067)
tl0_kexec_fast_data_access_MMU_miss:
		KX_DTLB_MISS BKT(0x069) BKT(0x06a) BKT(0x06b)
tl0_kexec_06c:	BKT(0x06c) BKT(0x06d) BKT(0x06e) BKT(0x06f)
tl0_kexec_070:	BKT(0x070) BKT(0x071) BKT(0x072) BKT(0x073)
tl0_kexec_074:	BKT(0x074) BKT(0x075) BKT(0x076) BKT(0x077)
tl0_kexec_078:	BKT(0x078) BKT(0x079) BKT(0x07a) BKT(0x07b)
tl0_kexec_07c:	BKT(0x07c) BKT(0x07d) BKT(0x07e) BKT(0x07f)
tl0_spill_0_normal:
		SPILL_0_NORMAL
tl0_kexec_084:	BKT(0x084) BKT(0x085) BKT(0x086) BKT(0x087)
tl0_kexec_088:	BKT(0x088) BKT(0x089) BKT(0x08a) BKT(0x08b)
tl0_kexec_08c:	BKT(0x08c) BKT(0x08d) BKT(0x08e) BKT(0x08f)
tl0_kexec_090:	BKT(0x090) BKT(0x091) BKT(0x092) BKT(0x093)
tl0_kexec_094:	BKT(0x094) BKT(0x095) BKT(0x096) BKT(0x097)
tl0_kexec_098:	BKT(0x098) BKT(0x099) BKT(0x09a) BKT(0x09b)
tl0_kexec_09c:	BKT(0x09c) BKT(0x09d) BKT(0x09e) BKT(0x09f)
tl0_kexec_0a0:	BKT(0x0a0) BKT(0x0a1) BKT(0x0a2) BKT(0x0a3)
tl0_kexec_0a4:	BKT(0x0a4) BKT(0x0a5) BKT(0x0a6) BKT(0x0a7)
tl0_kexec_0a8:	BKT(0x0a8) BKT(0x0a9) BKT(0x0aa) BKT(0x0ab)
tl0_kexec_0ac:	BKT(0x0ac) BKT(0x0ad) BKT(0x0ae) BKT(0x0af)
tl0_kexec_0b0:	BKT(0x0b0) BKT(0x0b1) BKT(0x0b2) BKT(0x0b3)
tl0_kexec_0b4:	BKT(0x0b4) BKT(0x0b5) BKT(0x0b6) BKT(0x0b7)
tl0_kexec_0b8:	BKT(0x0b8) BKT(0x0b9) BKT(0x0ba) BKT(0x0bb)
tl0_kexec_0bc:	BKT(0x0bc) BKT(0x0bd) BKT(0x0be) BKT(0x0bf)
tl0_fill_0_normal:
		FILL_0_NORMAL
tl0_kexec_0c4:	BKT(0x0c4) BKT(0x0c5) BKT(0x0c6) BKT(0x0c7)
tl0_kexec_0c8:	BKT(0x0c8) BKT(0x0c9) BKT(0x0ca) BKT(0x0cb)
tl0_kexec_0cc:	BKT(0x0cc) BKT(0x0cd) BKT(0x0ce) BKT(0x0cf)
tl0_kexec_0d0:	BKT(0x0d0) BKT(0x0d1) BKT(0x0d2) BKT(0x0d3)
tl0_kexec_0d4:	BKT(0x0d4) BKT(0x0d5) BKT(0x0d6) BKT(0x0d7)
tl0_kexec_0d8:	BKT(0x0d8) BKT(0x0d9) BKT(0x0da) BKT(0x0db)
tl0_kexec_0dc:	BKT(0x0dc) BKT(0x0dd) BKT(0x0de) BKT(0x0df)
tl0_kexec_0e0:	BKT(0x0e0) BKT(0x0e1) BKT(0x0e2) BKT(0x0e3)
tl0_kexec_0e4:	BKT(0x0e4) BKT(0x0e5) BKT(0x0e6) BKT(0x0e7)
tl0_kexec_0e8:	BKT(0x0e8) BKT(0x0e9) BKT(0x0ea) BKT(0x0eb)
tl0_kexec_0ec:	BKT(0x0ec) BKT(0x0ed) BKT(0x0ee) BKT(0x0ef)
tl0_kexec_0f0:	BKT(0x0f0) BKT(0x0f1) BKT(0x0f2) BKT(0x0f3)
tl0_kexec_0f4:	BKT(0x0f4) BKT(0x0f5) BKT(0x0f6) BKT(0x0f7)
tl0_kexec_0f8:	BKT(0x0f8) BKT(0x0f9) BKT(0x0fa) BKT(0x0fb)
tl0_kexec_0fc:	BKT(0x0fc) BKT(0x0fd) BKT(0x0fe) BKT(0x0ff)
! Note this is a PITA but cleanly done is best. Should my typos be nonexistent.
tl0_kexec_100:  BKTS(0x100) BKTS(0x104) BKTS(0x108) BKTS(0x10c)
tl0_kexec_110:  BKTS(0x110) BKTS(0x114) BKTS(0x118) BKTS(0x11c)
tl0_kexec_120:  BKTS(0x120) BKTS(0x124) BKTS(0x128) BKTS(0x12c)
tl0_kexec_130:  BKTS(0x130) BKTS(0x134) BKTS(0x138) BKTS(0x13c)
tl0_kexec_140:  BKTS(0x140) BKTS(0x144) BKTS(0x148) BKTS(0x14c)
tl0_kexec_150:  BKTS(0x150) BKTS(0x154) BKTS(0x158) BKTS(0x15c)
tl0_kexec_160:  BKTS(0x160) BKTS(0x164) BKTS(0x168) BKTS(0x16c)
tl0_kexec_170:  BKTS(0x170) BKTS(0x174) BKTS(0x178) BKTS(0x17c)
tl0_kexec_180:  BKTS(0x180) BKTS(0x184) BKTS(0x188) BKTS(0x18c)
tl0_kexec_190:  BKTS(0x190) BKTS(0x194) BKTS(0x198) BKTS(0x19c)
tl0_kexec_1a0:  BKTS(0x1a0) BKTS(0x1a4) BKTS(0x1a8) BKTS(0x1ac)
tl0_kexec_1b0:  BKTS(0x1b0) BKTS(0x1b4) BKTS(0x1b8) BKTS(0x1bc)
tl0_kexec_1c0:  BKTS(0x1c0) BKTS(0x1c4) BKTS(0x1c8) BKTS(0x1cc)
tl0_kexec_1d0:  BKTS(0x1d0) BKTS(0x1d4) BKTS(0x1d8) BKTS(0x1dc)
tl0_kexec_1e0:  BKTS(0x1e0) BKTS(0x1e4) BKTS(0x1e8) BKTS(0x1ec)
tl0_kexec_1f0:  BKTS(0x1f0) BKTS(0x1f4) BKTS(0x1f8) BKTS(0x1fc)
tl1_kexec_000:  BKTS(0x000) BKTS(0x004) BKTS(0x008) BKTS(0x00c)
tl1_kexec_010:  BKTS(0x010) BKTS(0x014) BKTS(0x018) BKTS(0x01c)
tl1_kexec_020:  BKTS(0x020) BKTS(0x024) BKTS(0x028) BKTS(0x02c)
tl1_kexec_030:  BKTS(0x030) BKTS(0x034) BKTS(0x038) BKTS(0x03c)
tl1_kexec_040:  BKTS(0x040) BKTS(0x044) BKTS(0x048) BKTS(0x04c)
tl1_kexec_050:  BKTS(0x050) BKTS(0x054) BKTS(0x058) BKTS(0x05c)
tl1_kexec_060:  BKTS(0x000)
tl1_kexec_fast_instruction_access_MMU_miss:
		KX_ITLB_MISS BKT(0x065) BKT(0x066)  BKT(0x067)
tl1_kexec_fast_data_access_MMU_miss:
		KX_DTLB_MISS BKT(0x069) BKT(0x06a)  BKT(0x06b)
tl1_kexec_06c:	BKTS(0x06c)
tl1_kexec_070:  BKTS(0x070) BKTS(0x074) BKTS(0x078) BKTS(0x07c)
tl1_kexec_080:  BKTS(0x080) BKTS(0x084) BKTS(0x088) BKTS(0x08c)
tl1_kexec_090:  BKTS(0x090) BKTS(0x094) BKTS(0x098) BKTS(0x09c)
tl1_kexec_0a0:  BKTS(0x0a0) BKTS(0x0a4) BKTS(0x0a8) BKTS(0x0ac)
tl1_kexec_0b0:  BKTS(0x0b0) BKTS(0x0b4) BKTS(0x0b8) BKTS(0x0bc)
tl1_kexec_0c0:  BKTS(0x0c0) BKTS(0x0c4) BKTS(0x0c8) BKTS(0x0cc)
tl1_kexec_0d0:  BKTS(0x0d0) BKTS(0x0d4) BKTS(0x0d8) BKTS(0x0dc)
tl1_kexec_0e0:  BKTS(0x0e0) BKTS(0x0e4) BKTS(0x0e8) BKTS(0x0ec)
tl1_kexec_0f0:  BKTS(0x0f0) BKTS(0x0f4) BKTS(0x0f8) BKTS(0x0fc)
tl1_kexec_100:  BKTS(0x100) BKTS(0x104) BKTS(0x108) BKTS(0x10c)
tl1_kexec_110:  BKTS(0x110) BKTS(0x114) BKTS(0x118) BKTS(0x11c)
tl1_kexec_120:  BKTS(0x120) BKTS(0x124) BKTS(0x128) BKTS(0x12c)
tl1_kexec_130:  BKTS(0x130) BKTS(0x134) BKTS(0x138) BKTS(0x13c)
tl1_kexec_140:  BKTS(0x140) BKTS(0x144) BKTS(0x148) BKTS(0x14c)
tl1_kexec_150:  BKTS(0x150) BKTS(0x154) BKTS(0x158) BKTS(0x15c)
tl1_kexec_160:  BKTS(0x160) BKTS(0x164) BKTS(0x168) BKTS(0x16c)
tl1_kexec_170:  BKTS(0x170) BKTS(0x174) BKTS(0x178) BKTS(0x17c)
tl1_kexec_180:  BKTS(0x180) BKTS(0x184) BKTS(0x188) BKTS(0x18c)
tl1_kexec_190:  BKTS(0x190) BKTS(0x194) BKTS(0x198) BKTS(0x19c)
tl1_kexec_1a0:  BKTS(0x1a0) BKTS(0x1a4) BKTS(0x1a8) BKTS(0x1ac)
tl1_kexec_1b0:  BKTS(0x1b0) BKTS(0x1b4) BKTS(0x1b8) BKTS(0x1bc)
tl1_kexec_1c0:  BKTS(0x1c0) BKTS(0x1c4) BKTS(0x1c8) BKTS(0x1cc)
tl1_kexec_1d0:  BKTS(0x1d0) BKTS(0x1d4) BKTS(0x1d8) BKTS(0x1dc)
tl1_kexec_1e0:  BKTS(0x1e0) BKTS(0x1e4) BKTS(0x1e8) BKTS(0x1ec)
tl1_kexec_1f0:  BKTS(0x1f0) BKTS(0x1f4) BKTS(0x1f8) BKTS(0x1fc)
kx_data_start:
kx_hv_fault_status:
	.=.+(16<<3)			! HV fault status
kx_nr_tte:				! current tte pinned
	.=.+8
kx_nr_ktte:				! kexec kernel tte
	.=.+8
kx_ktte:
	.=.+(8<<3)
kx_nr_itte:				! initrd for kexec-tools --load
	.=.+8
kx_itte:
	.=.+(8<<3)
kx_obp_cif:
	.=.+8
kx_obp_sp:
	.=.+8
kx_obp_translations:			! this should suffice
	.=.+(24*128)
kx_data_end:
kx_prom_exit:
	.asciz	"exit"
	.align 4
bad_bkt_trap:
	rd	%pc, %l0
	or	(bad_bkt_trap - kx_prom_exit), %g0, %l1
	sub	%l0, %l1, %l1
					! arguments: "exit", 0 ins, 0 outs
	stx	%l1, [%sp + 2047 + 128 + 0x00]
	stx	%g0, [%sp + 2047 + 128 + 0x08]
	stx	%g0, [%sp + 2047 + 128 + 0x10]
	jmpl	%o4, %g0		! goodbye
	add	%sp, (2047 + 128), %o0
bad_early:
	ldx	[%g2 + KX_OBP_SP], %o6
	ldx	[%g2 + KX_OBP_CIF], %o4
	ba,a,pt	%xcc,bad_bkt_trap
	.global kexec_start
kexec_start:
	or	%o0, %g0, %g1
	or	%o1, %g0, %g3
	wrpr	%g0, PIL_NORMAL_MAX, %pil
	rdpr	%pstate, %g2
	andn	%g2, PSTATE_IE, %g2
	wrpr	%g2, %g0, %pstate
	wrpr	%g0, 0, %canrestore
	wrpr	%g0, 0, %otherwin
	wrpr	%g0, 6, %cansave
	wrpr	%g0, 6, %cleanwin
	wrpr	%g0, 0, %cwp
	wrpr	%g0, 0, %wstate
	sethi	%hi(KX_SCRATCH), %g2
	add	%g1, %g2, %g2
	wrpr	%g1, %tba
	stxa	%g2, [%g0] ASI_SCRATCHPAD
	or	%g3, %g3, %o0
	mov	HV_FAST_MMU_FAULT_AREA_CONF, %o5
	ta	HV_FAST_TRAP
	brnz,pn	%o0, bad_early

	ldx	[%g2 + KX_NR_NTTE], %g4	! unmap current kernel hv pinned tte-s
	sethi	%hi(REAL_HPAGE_SIZE), %g5
	or	%g5, %g5, %g7
	sllx	%g4, 22, %g4
	sethi	%hi(KERNBASE), %g6
	add	%g6, %g4, %g4
1:	or	%g6, %g6, %o0
	or	%g0, %g0, %o1
	or	%g0, %lo(HV_MMU_ALL), %o2
	mov	HV_FAST_MMU_UNMAP_PERM_ADDR, %o5
	ta	HV_FAST_TRAP
	brnz,pn	%o0, bad_early		! prom exit for failure
	add	%g5, %g7, %g5
	subcc	%g5, %g4, %g0
	bne	1b
	add	%g7, %g6, %g6

	or	%g0, %g0, %o0		! demap all old translations
	or	%g0, %g0, %o1
	or	%g0, %lo(HV_MMU_ALL), %o2
	or	%g0, %lo(HV_FAST_MMU_DEMAP_ALL), %o5
	ta	HV_FAST_TRAP

	ldx	[%g2 + KX_NR_KTTE], %g4	! map the kexec-ed kernel
	sethi	%hi(REAL_HPAGE_SIZE), %g5
	sethi   %hi(KERNBASE), %g6
	add	%g2,  %lo(KX_KTTE), %g7
	ldx	[%g7 + %g0], %g1
2:	or	%g6, %g6, %o0
	or	%g0, %g0, %o1
	or	%g1, %g1, %o2
	or	%g0, %lo(HV_MMU_ALL), %o3
	mov	HV_FAST_MMU_MAP_PERM_ADDR, %o5
	ta	HV_FAST_TRAP
	brnz,pn	%o0, bad_early
	add	%g7, 8, %g7
	ldx	[%g7 + %g0], %g1
	subcc	%g4, 1, %g4
	bne	2b
	add	%g6, %g5, %g6

	! Loaded and time to launch.
	! For now leave kernel entry point at 0x404000
	ldx	[%g2 + KX_OBP_SP], %o6
	ldx	[%g2 + KX_OBP_CIF], %o4
	sethi	%hi(KERNBASE), %g1
	sethi	%hi(0x4000), %g2
	or	%g1, %g2, %g1
	jmpl	%g1, %g0
	nop

	! g1 is VA
	! g2 is HV status area
	! g3 is MMU flag
kx_tlb_miss:
	add	%g2, %lo(KX_OBP_TRANSLATIONS), %g2
10:	ldx	[%g2 + 0x0], %g4
	brz,pn	%g4, bad_bkt_trap
	nop
	ldx	[%g2 + 0x8], %g5
	add	%g5, %g4, %g5
	cmp	%g5, %g1
	bleu	%xcc, 20f
	cmp	%g1, %g5
	bgeu	20f
	sub	%g1, %g4, %g4
	ba,pt	%xcc, 30f
	ldx	[%g2 + 0x10], %g2
20:	ba,pt	%xcc, 10b
	add	%g2, (3<<3), %g2
30:	add	%g2, %g4, %g2		! TTE
	or	%o0, %o0, %g7
	or	%o1, %o1, %g6
	or	%o2, %o2, %g5
	or	%o3, %o3, %g4
	or	%g1, %g1, %o0
	or	%g0, %g0, %o1
	or	%g2, %g2, %o2
	or	%g3, %g3, %o3
	ta	HV_MMU_MAP_ADDR_TRAP
	brnz	%o0, bad_bkt_trap
	or	%g7, %g7, %o0
	or	%g6, %g6, %o1
	or	%g5, %g5, %o2
	or	%g4, %g4, %o3
	retry
. = KX_SHIM_SIZE
kexec_end:
