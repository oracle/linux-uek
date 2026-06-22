TARGET = pddf_psu_driver_module
obj-$(CONFIG_PDDF_PSU) += $(TARGET).o

$(TARGET)-objs := pddf_psu_api.o pddf_psu_driver.o

ccflags-y := -I$(srctree)/drivers/platform/pddf-sonic/include
