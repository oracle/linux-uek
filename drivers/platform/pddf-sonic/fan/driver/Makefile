TARGET := pddf_fan_driver_module
obj-$(CONFIG_PDDF_FAN) += $(TARGET).o

$(TARGET)-objs := pddf_fan_api.o pddf_fan_driver.o

ccflags-y := -I$(srctree)/drivers/platform/pddf-sonic/include
