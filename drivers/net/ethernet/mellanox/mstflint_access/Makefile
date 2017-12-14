KPVER ?= $(shell uname -r)
KSRC ?= /lib/modules/$(KPVER)/build
CPU_ARCH ?= $(shell uname -m)

# GCC earlier than 4.6.0 will build modules which require 'mcount',
# and this symbol will not be available in the kernel if the kernel was
# compiled with GCC 4.6.0 and above.
# therefore, to prevent unknown symbol issues we disable function tracing.
#

ifeq ($(CC),)
CC  = $(CROSS_COMPILE)gcc
endif
CPP = $(CC) -E
ifneq ($(CC),cc)
override WITH_MAKE_PARAMS += CC=$(CC)
endif

CPP_MAJOR := $(shell $(CPP) -dumpversion 2>&1 | cut -d'.' -f1)
CPP_MINOR := $(shell $(CPP) -dumpversion 2>&1 | cut -d'.' -f2)
CPP_PATCH := $(shell $(CPP) -dumpversion 2>&1 | cut -d'.' -f3)
# Assumes that major, minor, and patch cannot exceed 999
CPP_VERS  := $(shell expr 0$(CPP_MAJOR) \* 1000000 + 0$(CPP_MINOR) \* 1000 + 0$(CPP_PATCH))
compile_h=$(shell /bin/ls -1 $(KSRC)/include/*/compile.h 2> /dev/null | head -1)
ifneq ($(compile_h),)
KERNEL_GCC_MAJOR := $(shell grep LINUX_COMPILER $(compile_h) | sed -r -e 's/.*gcc version ([0-9\.\-]*) .*/\1/g' | cut -d'.' -f1)
KERNEL_GCC_MINOR := $(shell grep LINUX_COMPILER $(compile_h) | sed -r -e 's/.*gcc version ([0-9\.\-]*) .*/\1/g' | cut -d'.' -f2)
KERNEL_GCC_PATCH := $(shell grep LINUX_COMPILER $(compile_h) | sed -r -e 's/.*gcc version ([0-9\.\-]*) .*/\1/g' | cut -d'.' -f3)
KERNEL_GCC_VER  := $(shell expr 0$(KERNEL_GCC_MAJOR) \* 1000000 + 0$(KERNEL_GCC_MINOR) \* 1000 + 0$(KERNEL_GCC_PATCH))
ifneq ($(shell if [ $(CPP_VERS) -lt 4006000 ] && [ $(KERNEL_GCC_VER) -ge 4006000 ]; then \
                                       echo "YES"; else echo ""; fi),)
$(info Warning: The kernel was compiled with GCC newer than 4.6.0, while the current GCC is older than 4.6.0, Disabling function tracing to prevent unknown symbol issues...)
override WITH_MAKE_PARAMS += CONFIG_FUNCTION_TRACER= CONFIG_HAVE_FENTRY=
endif
ifneq ($(shell if [ $(CPP_VERS) -ge 4006000 ] && [ $(KERNEL_GCC_VER) -lt 4006000 ]; then \
                                       echo "YES"; else echo ""; fi),)
$(info Warning: The kernel was compiled with GCC older than 4.6.0, while the current GCC is newer than 4.6.0, Disabling function tracing to prevent unknown symbol issues...)
override WITH_MAKE_PARAMS += CONFIG_FUNCTION_TRACER= CONFIG_HAVE_FENTRY=
endif
endif
ifneq ($(shell if (echo $(KPVER) | grep -qE 'uek'); then \
                                       echo "YES"; else echo ""; fi),)
override WITH_MAKE_PARAMS += ctf-dir=$(CWD)/.ctf
endif

obj-m += mstflint_access.o
mstflint_access-objs += mst_vpd.o mst_main.o

all:
	make -C $(KSRC) M=$(PWD) CONFIG_CTF= CONFIG_CC_STACKPROTECTOR_STRONG= $(WITH_MAKE_PARAMS) modules

clean:
	make -C $(KSRC) M=$(PWD) clean
