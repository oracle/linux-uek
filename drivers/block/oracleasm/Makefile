
obj-$(CONFIG_ORACLEASM) := oracleasm.o
oracleasm-y += driver.o transaction_file.o
oracleasm-$(CONFIG_BLK_DEV_INTEGRITY) += integrity.o
CFLAGS_driver.o = -I$(src)

