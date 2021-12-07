# SPDX-License-Identifier: GPL-2.0
# See Makefile.vmlinux_o

BEGIN {
    discards = 0; p = 0
}

/^====/ { p = 1; next; }
p && /\.ctf/ { next; }
p && !discards && /DISCARD/ { sub(/\} *$/, " *(.ctf) }"); discards = 1 }
p && /^\}/ && !discards { print "  /DISCARD/ : { *(.ctf) }"; }
p { print $0; }
