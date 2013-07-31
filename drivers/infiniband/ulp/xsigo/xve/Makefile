obj-$(CONFIG_INFINIBAND_XVE) := xve.o
xve-y := xve_main.o xve_verbs.o xve_multicast.o xve_ib.o xve_tables.o \
	 xve_ethtool.o xve_cm.o xve_stats.o

EXTRA_CFLAGS += -DXSIGO_LOCAL_VERSION=\"6.0.r7269\" -DHAS_SKB_ACCESS_FUNCTIONS
EXTRA_CFLAGS += -DSCSI_STRUCT_CHANGES -DSCSI_TIMEOUT_CHANGES -DLLE
EXTRA_CFLAGS += -DXG_FRAG_SIZE_PRESENT -DXG_FRAG_PAGE_PRESENT -DOVCA_400
EXTRA_CFLAGS += -Idrivers/infiniband/ulp/xsigo/xscore
