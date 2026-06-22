TARGET = pddf_xcvr_driver_module

obj-$(CONFIG_PDDF_XCVR) += $(TARGET).o

$(TARGET)-objs := pddf_xcvr_api.o pddf_xcvr_driver.o

ccflags-y := -I$(srctree)/drivers/platform/pddf-sonic/include
