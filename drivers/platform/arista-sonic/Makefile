obj-$(CONFIG_ARISTA_SCD_DRIVER) += scd-hwmon.o scd.o
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
CFLAGS_scd-smbus.o := -I$(src)

obj-$(CONFIG_ARISTA_SCD_DRIVER) += crow-fan-driver.o
obj-$(CONFIG_ARISTA_SCD_DRIVER) += raven-fan-driver.o
obj-$(CONFIG_ARISTA_SCD_DRIVER) += rook-led-driver.o
obj-$(CONFIG_ARISTA_SCD_DRIVER) += rook-fan-cpld.o
obj-$(CONFIG_ARISTA_SCD_DRIVER) += tmp468.o
obj-$(CONFIG_ARISTA_SCD_DRIVER) += amax31732.o
obj-$(CONFIG_ARISTA_SCD_DRIVER) += amax31790.o
obj-$(CONFIG_ARISTA_SCD_DRIVER) += minke-fan-cpld.o
