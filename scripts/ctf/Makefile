ifdef CONFIG_CTF
ifdef CONFIG_CTF_USING_BINUTILS
hostprogs-always-y	:= ctfarchive
ctfarchive-objs		:= ctfarchive.o modules_thick.o
else
hostprogs-always-y	:= dwarf2ctf
dwarf2ctf-objs		:= dwarf2ctf.o eu_simple.o modules_thick.o
endif

HOSTCFLAGS_eu_simple.o := -I.
HOSTCFLAGS_dwarf2ctf.o := $(shell pkg-config --cflags glib-2.0) -I.
HOSTLDLIBS_dwarf2ctf := -ldtrace-ctf -lelf -ldw $(shell pkg-config --libs glib-2.0) -lz
HOSTLDLIBS_ctfarchive := -lctf -lbfd -liberty -lz -ldl
endif
