obj-$(CONFIG_INFINIBAND_XSVHBA) := xsvhba.o
xsvhba-y := vhba_main.o vhba_xsmp.o vhba_create.o vhba_init.o vhba_delete.o \
	    vhba_attr.o vhba_wq.o vhba_proc.o vhba_stats.o vhba_ib.o        \
	    vhba_scsi_intf.o vhba_align.o

EXTRA_CFLAGS += -DXSIGO_LOCAL_VERSION=\"6.0.r7269\" -DHAS_SKB_ACCESS_FUNCTIONS
EXTRA_CFLAGS += -DSCSI_STRUCT_CHANGES -DSCSI_TIMEOUT_CHANGES -DLLE
EXTRA_CFLAGS += -DXG_FRAG_SIZE_PRESENT -DXG_FRAG_PAGE_PRESENT -DOVCA_400
EXTRA_CFLAGS += -Idrivers/infiniband/ulp/xsigo/xscore
