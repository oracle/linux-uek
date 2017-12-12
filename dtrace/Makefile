#
# Copyright (c) 2011, 2017, Oracle and/or its affiliates. All rights reserved.
#

obj-$(CONFIG_DT_CORE)		+= dtrace.o
obj-$(CONFIG_DT_FASTTRAP)	+= fasttrap.o
obj-$(CONFIG_DT_FBT)		+= fbt.o
obj-$(CONFIG_DT_PROFILE)	+= profile.o
obj-$(CONFIG_DT_SDT)		+= sdt.o
obj-$(CONFIG_DT_SYSTRACE)	+= systrace.o
obj-$(CONFIG_DT_DT_TEST)	+= dt_test.o

dtrace-y			:= dtrace_mod.o dtrace_dev.o \
				   dtrace_actdesc.o dtrace_anon.o \
				   dtrace_buffer.o dtrace_dif.o dtrace_dof.o \
				   dtrace_ecb.o dtrace_enable.o \
				   dtrace_fmt.o dtrace_hash.o dtrace_isa.o \
				   dtrace_match.o dtrace_priv.o \
				   dtrace_probe.o dtrace_probe_ctx.o \
				   dtrace_ptofapi.o dtrace_predicate.o \
				   dtrace_spec.o dtrace_state.o dtrace_util.o
fasttrap-y			:= fasttrap_mod.o fasttrap_dev.o
fbt-y				:= fbt_mod.o fbt_dev.o
profile-y			:= profile_mod.o profile_dev.o
sdt-y				:= sdt_mod.o sdt_dev.o
systrace-y			:= systrace_mod.o systrace_dev.o
dt_test-y			:= dt_test_mod.o dt_test_dev.o

-include arch/$(SRCARCH)/dtrace/Makefile.arch
