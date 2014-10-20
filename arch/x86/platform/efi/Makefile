obj-$(CONFIG_EFI) 		+= efi.o efi_$(BITS).o efi_stub_$(BITS).o
ifdef CONFIG_XEN
obj-$(CONFIG_EFI)		+= xen.o
endif
obj-$(CONFIG_ACPI_BGRT) += efi-bgrt.o
