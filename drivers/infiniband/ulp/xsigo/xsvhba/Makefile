obj-$(CONFIG_INFINIBAND_XSVHBA) := xsvhba.o
xsvhba-y := vhba_main.o vhba_xsmp.o vhba_create.o vhba_init.o vhba_delete.o \
	    vhba_attr.o vhba_wq.o vhba_proc.o vhba_stats.o vhba_ib.o        \
	    vhba_scsi_intf.o vhba_align.o

ccflags-y += -DXSIGO_LOCAL_VERSION=\"6.0.r8044\"
ccflags-y += -DRDMA_PORT_LINK_LAYER_CHANGES -DHAS_SKB_ACCESS_FUNCTIONS
ccflags-y += -DSCSI_STRUCT_CHANGES -DSCSI_TIMEOUT_CHANGES -DLLE
ccflags-y += -DXG_FRAG_SIZE_PRESENT -DXG_FRAG_PAGE_PRESENT
ccflags-y += -Idrivers/infiniband/ulp/xsigo/xscore
ccflags-y += -Idrivers/infiniband/include
