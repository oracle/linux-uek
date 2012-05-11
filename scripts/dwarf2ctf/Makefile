hostprogs-y	:= dwarf2ctf
always		:= $(hostprogs-y)

HOSTCFLAGS_dwarf2ctf.o := $(shell pkg-config --cflags glib-2.0)
HOSTLOADLIBES_dwarf2ctf := -ldtrace-ctf -lelf -ldw $(shell pkg-config --libs glib-2.0) -lz
