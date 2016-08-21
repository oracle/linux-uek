ccflags-y +=  -DSIF_TRACE_MASK \
  -Wno-packed-bitfield-compat -Werror

obj-$(CONFIG_INFINIBAND_SIF) := sif.o

sif-y := sif_main.o sif_mmu.o sif_dma.o sif_qp.o sif_sq.o \
   sif_cq.o sif_mr.o sif_mw.o sif_fmr.o sif_ah.o sif_pd.o sif_rq.o sif_srq.o \
   sif_tqp.o sif_sndrcv.o sif_base.o sif_hwi.o sif_r3.o sif_hwmon.o sif_vf.o sif_ireg.o sif_defs.o \
   sif_debug.o sif_epsc.o sif_eq.o sif_query.o sif_pqp.o \
   sif_verbs.o sif_fwa.o sif_checksum.o sif_spt.o sif_elog.o \
   sif_xmmu.o sif_xrc.o sif_mem.o sif_pt.o sif_idr.o version.o

