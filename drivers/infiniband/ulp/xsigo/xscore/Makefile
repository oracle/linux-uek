obj-$(CONFIG_INFINIBAND_XSCORE) := xscore.o
xscore-y := xscore_impl.o xs_ud.o xscore_vpci.o xscore_api.o xsmp.o \
	    xscore_stats.o xscore_uadm.o

EXTRA_CFLAGS += -DXSIGO_LOCAL_VERSION=\"6.0.r7269\" -DHAS_SKB_ACCESS_FUNCTIONS
EXTRA_CFLAGS += -DSCSI_STRUCT_CHANGES -DSCSI_TIMEOUT_CHANGES -DLLE
EXTRA_CFLAGS += -DXG_FRAG_SIZE_PRESENT -DXG_FRAG_PAGE_PRESENT -DOVCA_400
EXTRA_CFLAGS += -Idrivers/infiniband/include
