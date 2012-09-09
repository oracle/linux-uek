#
# Makefile for DTrace
#

GCOV_PROFILE := y

ifdef CONFIG_DT_CORE
obj-y				+= dtrace_os.o dtrace_cpu.o \
				   dtrace_stubs_x86_64.o dtrace_sdt.o
obj-m				+= dtrace_ctf.o
endif
