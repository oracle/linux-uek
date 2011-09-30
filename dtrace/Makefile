#
# Makefile for DTrace
#

KERNELDIR := /lib/modules/`uname -r`/build

modules::

install:: modules_install

%::
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@
