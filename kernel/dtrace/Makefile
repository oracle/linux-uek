#
# Makefile for DTrace
#

GCOV_PROFILE := y

DT_CORE_ARCH_OBJS		= $(addprefix ../../arch/$(SRCARCH)/kernel/, \
				    dtrace_syscall.o dtrace_syscall_stubs.o \
				    dtrace_fbt.o dtrace_sdt.o dtrace_util.o)

ifdef CONFIG_DT_CORE
obj-y				+= cyclic.o dtrace_os.o dtrace_cpu.o \
				   dtrace_sdt_core.o dtrace_fbt_core.o \
				   $(DT_CORE_ARCH_OBJS)
endif
