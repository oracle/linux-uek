ifdef CONFIG_CTF
hostprogs-y	:= dwarf2ctf
always		:= $(hostprogs-y)

dwarf2ctf-objs  := dwarf2ctf.o eu_simple.o

HOSTCFLAGS_eu_simple.o := -I$(srctree)/scripts
HOSTCFLAGS_dwarf2ctf.o := $(shell pkg-config --cflags glib-2.0) -I$(srctree)/scripts

HOSTLDLIBS_dwarf2ctf := -ldtrace-ctf -lelf -ldw $(shell pkg-config --libs glib-2.0) -lz
endif
