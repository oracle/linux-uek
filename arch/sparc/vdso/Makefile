#
# Building vDSO images for sparc64.
#

KBUILD_CFLAGS += $(DISABLE_LTO)

VDSO64-$(CONFIG_SPARC64)	:= y

# files to link into the vdso
vobjs-y := vdso-note.o vclock_gettime.o

# files to link into kernel
obj-y				+= vma.o

# vDSO images to build
vdso_img-$(VDSO64-y)		+= 64

vobjs := $(foreach F,$(vobjs-y),$(obj)/$F)

$(obj)/vdso.o: $(obj)/vdso.so

targets += vdso.lds $(vobjs-y)

# Build the vDSO image C files and link them in.
vdso_img_objs := $(vdso_img-y:%=vdso-image-%.o)
vdso_img_cfiles := $(vdso_img-y:%=vdso-image-%.c)
vdso_img_sodbg := $(vdso_img-y:%=vdso%.so.dbg)
obj-y += $(vdso_img_objs)
targets += $(vdso_img_cfiles)
targets += $(vdso_img_sodbg)
.SECONDARY: $(vdso_img-y:%=$(obj)/vdso-image-%.c) \
	$(vdso_img-y:%=$(obj)/vdso%.so)

export CPPFLAGS_vdso.lds += -P -C

VDSO_LDFLAGS_vdso.lds = -m64 -Wl,-soname=linux-vdso.so.1 \
			-Wl,--no-undefined \
			-Wl,-z,max-page-size=8192 -Wl,-z,common-page-size=8192 \
			$(DISABLE_LTO)

$(obj)/vdso64.so.dbg: $(src)/vdso.lds $(vobjs) FORCE
	$(call if_changed,vdso)

HOST_EXTRACFLAGS += -I$(srctree)/tools/include
hostprogs-y			+= vdso2c

quiet_cmd_vdso2c = VDSO2C  $@
define cmd_vdso2c
	$(obj)/vdso2c $< $(<:%.dbg=%) $@
endef

$(obj)/vdso-image-%.c: $(obj)/vdso%.so.dbg $(obj)/vdso%.so $(obj)/vdso2c FORCE
	$(call if_changed,vdso2c)

#
# Don't omit frame pointers for ease of userspace debugging, but do
# optimize sibling calls.
#
CFL := $(PROFILING) -mcmodel=medlow -fPIC -O2 -fasynchronous-unwind-tables \
       -m64 -ffixed-g2 -ffixed-g3 -fcall-used-g4 -fcall-used-g5 -ffixed-g6 \
       -ffixed-g7 $(filter -g%,$(KBUILD_CFLAGS)) \
       $(call cc-option, -fno-stack-protector) -fno-omit-frame-pointer \
       -foptimize-sibling-calls -DBUILD_VDSO

$(vobjs): KBUILD_CFLAGS += $(CFL)

#
# vDSO code runs in userspace and -pg doesn't help with profiling anyway.
#
CFLAGS_REMOVE_vdso-note.o = -pg
CFLAGS_REMOVE_vclock_gettime.o = -pg

$(obj)/%.so: OBJCOPYFLAGS := -S
$(obj)/%.so: $(obj)/%.so.dbg
	$(call if_changed,objcopy)

#
# The DSO images are built using a special linker script.
#
quiet_cmd_vdso = VDSO    $@
      cmd_vdso = $(CC) -nostdlib -o $@ \
		       $(VDSO_LDFLAGS) $(VDSO_LDFLAGS_$(filter %.lds,$(^F))) \
		       -Wl,-T,$(filter %.lds,$^) $(filter %.o,$^) && \
		 sh $(srctree)/$(src)/checkundef.sh '$(NM)' '$@'

VDSO_LDFLAGS = -fPIC -shared $(call cc-ldoption, -Wl$(comma)--hash-style=sysv) \
	$(call cc-ldoption, -Wl$(comma)--build-id) -Wl,-Bsymbolic
GCOV_PROFILE := n

#
# Install the unstripped copies of vdso*.so.  If our toolchain supports
# build-id, install .build-id links as well.
#
quiet_cmd_vdso_install = INSTALL $(@:install_%=%)
define cmd_vdso_install
	cp $< "$(MODLIB)/vdso/$(@:install_%=%)"; \
	if readelf -n $< |grep -q 'Build ID'; then \
	  buildid=`readelf -n $< |grep 'Build ID' |sed -e 's/^.*Build ID: \(.*\)$$/\1/'`; \
	  first=`echo $$buildid | cut -b-2`; \
	  last=`echo $$buildid | cut -b3-`; \
	  mkdir -p "$(MODLIB)/vdso/.build-id/$$first"; \
	  ln -sf "../../$(@:install_%=%)" "$(MODLIB)/vdso/.build-id/$$first/$$last.debug"; \
	fi
endef

vdso_img_insttargets := $(vdso_img_sodbg:%.dbg=install_%)

$(MODLIB)/vdso: FORCE
	@mkdir -p $(MODLIB)/vdso

$(vdso_img_insttargets): install_%: $(obj)/%.dbg $(MODLIB)/vdso FORCE
	$(call cmd,vdso_install)

PHONY += vdso_install $(vdso_img_insttargets)
vdso_install: $(vdso_img_insttargets) FORCE
