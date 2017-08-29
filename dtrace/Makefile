#
# Makefile for DTrace
#

KERNELDIR := /lib/modules/`uname -r`/build

modules::

install:: modules_install

%::
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@

# Headers named *_ioctl.h have to be compiled in kernel mode so that
# typechecking is enabled. The rest get compiled in user mode. We go to some
# lengths to use any ioctl() identifiers, since typechecking only kicks in at
# time of use.

headers_check:
	@for name in $(notdir $(wildcard include/uapi/linux/dtrace/*.h)); do \
		if [[ $$name =~ .*ioctl\.h$$ ]]; then \
			INC="-I../arch/x86/include -I../include -I../include/asm-generic -Iinclude -D__KERNEL__ -include linux/types.h -include dtrace/types.h"; \
		else \
			INC="-include sys/types.h -include sys/ctf_types.h -include unistd.h -I../include"; \
		fi; \
		echo -e "#include <linux/dtrace/$$name>\nint main (void) { long junk[] = { $$(grep '#define ' include/uapi/linux/dtrace/$$name | grep -E 'IO[RW]' | sed 's@.*#define \([^ \t]*\).*$$@\1,@')};}" | \
		    $(CC) -c -x c - -o /dev/null -D_GNU_SOURCE -DHEADERS_CHECK \
		    $$INC -Iinclude/uapi $$INC -include linux/dtrace_os.h || \
		    { echo "$$name is not standalone." >&2; exit 1; } \
	done

headers_install:
	mkdir -p $(INSTALL_HDR_PATH)/usr/include/linux/dtrace
	for name in include/dtrace/provider*.h include/dtrace/types*.h include/uapi/linux/dtrace/*.h; do \
		install -m 0644 $$name $(INSTALL_HDR_PATH)/usr/include/linux/dtrace; \
	done
