ccflags-y := -Werror

ifeq ($(ARISTA_SCD_DRIVER_CONFIG),n)
KBUILD_EXTRA_SYMBOLS += $(EXTRA_SYMBOLS)
else
obj-$(ARISTA_SCD_DRIVER_CONFIG) += scd.o
endif

obj-m += scd-hwmon.o
scd-hwmon-objs += scd-fan.o
scd-hwmon-objs += scd-gpio.o
scd-hwmon-objs += scd-led.o
scd-hwmon-objs += scd-main.o
scd-hwmon-objs += scd-mdio.o
scd-hwmon-objs += scd-reset.o
scd-hwmon-objs += scd-smbus.o
scd-hwmon-objs += scd-spi.o
scd-hwmon-objs += scd-uart.o
scd-hwmon-objs += scd-xcvr.o
# Add module src path as include dir for tracepoints
CFLAGS_scd-smbus.o := -I$M

obj-m += crow-fan-driver.o
obj-m += raven-fan-driver.o
obj-m += rook-led-driver.o
obj-m += rook-fan-cpld.o
obj-m += tmp468.o
obj-m += amax31732.o
obj-m += amax31790.o
obj-m += minke-fan-cpld.o
