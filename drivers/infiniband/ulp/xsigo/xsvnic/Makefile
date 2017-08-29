obj-$(CONFIG_INFINIBAND_XSVNIC) := xsvnic.o
xsvnic-y := xsvnic_main.o xsvnic_stats.o

ccflags-y += -DXSIGO_LOCAL_VERSION=\"6.0.r8044\"
ccflags-y += -DRDMA_PORT_LINK_LAYER_CHANGES -DHAS_SKB_ACCESS_FUNCTIONS
ccflags-y += -DSCSI_STRUCT_CHANGES -DSCSI_TIMEOUT_CHANGES -DLLE
ccflags-y += -DXG_FRAG_SIZE_PRESENT -DXG_FRAG_PAGE_PRESENT
ccflags-y += -Idrivers/infiniband/ulp/xsigo/xscore
ccflags-y += -Idrivers/infiniband/include
