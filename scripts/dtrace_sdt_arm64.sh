#!/bin/sh

LANG=C
export LANG

#
# Syntax:
#	dtrace_sdt_arm64.sh sdtinfo <S-file> <l-file> <o-file>
#		This is used to generate DTrace SDT probe definitions for a
#		linked kernel image file <l-file>, based on relocation info
#		from the kernel object file <o-file>.  The output is written
#		to <S-file>.
#

opr="$1"
shift
if [ -z "$opr" ]; then
    echo "ERROR: Missing operation" > /dev/stderr
    exit 1
elif [ "$opr" != "sdtinfo" ]; then
    echo "ERROR: Invalid operation: ${opr}" > /dev/stderr
    exit 1
fi

tfn="$1"
shift
if [ -z "$tfn" ]; then
    echo "ERROR: Missing target filename" > /dev/stderr
    exit 1
fi

lfn="$1"
ofn="$2"

if [ -z "$lfn" ]; then
    echo "ERROR: Missing linked kernel file argument" > /dev/stderr
    exit 1
elif [ -z "$ofn" ]; then
    echo "ERROR: Missing kernel object file argument" > /dev/stderr
    exit 1
fi

# For arm64, the kernel is built using "-ffunction-sections -fdata-sections"
# which due to the linked bug conflicts with "--emit-relocs".  Probe discovery
# therefore is a bit more complicated.
#
# First we collect the VMA address of all the code sections in the linked
# kernel image.
#
# Subsequently, we go through the list of symbols in the linked kernel image,
# and write out records for some select symbols that are used in the processing
# of probe locations:
#
#	<section> <address> B <name>
#	    Named identifier at a specific address (global variable).
#
# We also process any function symbols, and build a lookup map with varying
# levels of detail to assist in symbol lookup later on (each map entry stores
# the symbol offset relative to its section):
#	section, name, and offset
#	section and name
#	name and offset
#	name
# (If multiple symbols map to any of the above combinations, that specific
#  combination is omitted from the mapping.)
#
# Next, we process the list of function symbols, and for any function that
# is not located in a section that starts with .exit.text, .init.text, or
# .meminit.text) we determine its in-section offset and output a record:
#
#	<section> <offset> F <name> <address>
#	    Named function at a specific address.
#
# Finally, each relocation record from a non-init or exit section that relates
# to SDT probes is written to the output stream:
#
#	<section> <address> R <value>
#	    Relocation within a section at a specific address
#
# Probes are identified in the relocation records as symbols with either a
# __dtrace_probe_ or __dtrace_isenabled_ prefix.
#
# All these records are sorted by section and offset, and any SDT probe
# location relocation records (R) result in writing out an entry that records
# its offset relative to the _stext symbol, along with the name of the function
# it was found in, and the probe name.

(
    objdump -ht ${lfn}
    objdump -tr ${ofn}
) | \
    awk 'function subl(v0, v1, v0h, v0l, v1h, v1l, d, tmp) {
	     tmp = $0;
	     if (length(v0) > 8) {
		 d = length(v0);
		 v0h = strtonum("0x"substr(v0, 1, d - 8));
		 v0l = strtonum("0x"substr(v0, d - 8 + 1));
		 d = length(v1);
		 v1h = strtonum("0x"substr(v1, 1, d - 8));
		 v1l = strtonum("0x"substr(v1, d - 8 + 1));

		 if (v0l >= v1l) {
		     if (v0h >= v1h) {
			 d = sprintf("%08x%08x", v0h - v1h, v0l - v1l);
		     } else {
			 printf "ERROR: Invalid addresses: %s vs %s\n", v0, v1;
			 d = 0;
			 errc++;
		     }
		 } else {
		     if (v0h > v1h) {
			 v0h--;
			 v0l += 4294967296;
			 d = sprintf("%08x%08x", v0h - v1h, v0l - v1l);
		     } else {
			 printf "ERROR: Invalid addresses: %s vs %s\n", v0, v1;
			 d = 0;
			 errc++;
		     }
		 }
	     } else {
		 v0 = strtonum("0x"v0);
		 v1 = strtonum("0x"v1);
		 d = sprintf("%016x", v0 - v1);
	     }
	     $0 = tmp;

	     return d;
	 }

	 BEGIN {
	     phase = 0;
	 }

	 /^SYMBOL / {
	     phase++;
	     next;
	 }

	 phase == 0 && /^ *[1-9][0-9]* / {
	     snam = $2;
	     addr = $4;
	     getline;
	     if (/CODE/)
		 secs[snam] = addr;

	     next;
	 }

	 phase == 1 && $NF ~ /_(stext|_init_(begin|end))$/ {
	     print ". " $1 " B " $NF;
	     next;
	 }

	 phase == 1 && / F / {
	     if ($4 ~ /^\.(exit|init|meminit)\.text/)
		 next;

	     off = subl($1, secs[$4]);
	     id = $4 " " $6 " " off;
	     if (id in smap) {
		 if (smap[id] != $1)
		     smap[id] = 0;
	     } else
		 smap[id] = $1;

	     id = $4 " " $6;
	     if (id in smap) {
		 if (smap[id] != $1)
		     smap[id] = 0;
	     } else
		 smap[id] = $1;

	     id = $6 " " off;
	     if (id in smap) {
		 if (smap[id] != $1)
		     smap[id] = 0;
	     } else
		 smap[id] = $1;

	     id = $6;
	     if (id in smap) {
		 if (smap[id] != $1)
		     smap[id] = 0;
	     } else
		 smap[id] = $1;

	     next;
	 }

	 phase == 2 && / F / {
	     if ($4 ~ /^\.(exit|init|meminit)\.text/)
		 next;

	     id = $4 " " $6 " " $1;
	     if (!(id in smap))
		 id = $4 " " $6;
	     if (!(id in smap))
		 id = $6 " " $1;
	     if (!(id in smap))
		 id = $6;
	     if (id in smap) {
		 addr = smap[id];
		 if (!addr)
		     print "ERROR: Non-unique symbol: " $4 " " $6 " " $1;
	     } else {
		 print "ERROR: Could not find " $4 " " $6 " " $1;
		 addr = 0;
	     }

	     print $4 " "  $1 " F " $6 "  " addr " " secs[$4];
	     next;
	 }

	 /^RELOC/ {
	     sect = substr($4, 2, length($4) - 3);
	     next;
	 }

	 sect ~ /^\.(exit|init|meminit)\.text/ {
	     next;
	 }

	 sect && /__dtrace_probe_/ {
	     $3 = substr($3, 16);
	     sub(/[\-+].*$/, "", $3);
	     print sect " " $1 " R " $3;
	     next;
	 }

	 sect && /__dtrace_isenabled_/ {
	     $3 = substr($3, 20);
	     sub(/[\-+].*$/, "", $3);
	     print sect " " $1 " R ?" $3;
	     next;
	 }' | \
    sort -u | \
    awk 'function addl(v0, v1, v0h, v0l, v1h, v1l, d, tmp) {
	     tmp = $0;
	     if (length(v0) > 8 || length(v1) > 8) {
		 d = length(v0);
		 v0h = strtonum("0x"substr(v0, 1, d - 8));
		 v0l = strtonum("0x"substr(v0, d - 8 + 1));
		 d = length(v1);
		 v1h = strtonum("0x"substr(v1, 1, d - 8));
		 v1l = strtonum("0x"substr(v1, d - 8 + 1));

		 v0l += v1l;
		 v0h += v1h;
		 d = sprintf("%x", v0l);
		 if (length(d) > 8) {
		     v0h++;
		     v0l -= 4294967296;
		 }
		 d = sprintf("%x", v0h);
		 if (length(d) <= 8) {
		     d = sprintf("%08x%08x", v0h, v0l);
		 } else {
		     printf "#error Invalid addresses: %s + %s\n", v0, v1 \
			    >"/dev/stderr";
		     errc++;
		 }
	     } else {
		 v0 = strtonum("0x"v0);
		 v1 = strtonum("0x"v1);
		 d = sprintf("%016x", v0 + v1);
	     }
	     $0 = tmp;

	     return d;
	 }

	 function subl(v0, v1, v0h, v0l, v1h, v1l, d, tmp) {
	     tmp = $0;
	     if (length(v0) > 8) {
		 d = length(v0);
		 v0h = strtonum("0x"substr(v0, 1, d - 8));
		 v0l = strtonum("0x"substr(v0, d - 8 + 1));
		 d = length(v1);
		 v1h = strtonum("0x"substr(v1, 1, d - 8));
		 v1l = strtonum("0x"substr(v1, d - 8 + 1));

		 if (v0l >= v1l) {
		     if (v0h >= v1h) {
			 d = sprintf("%08x%08x", v0h - v1h, v0l - v1l);
		     } else {
			 printf "#error Invalid addresses: %s - %s\n", v0, v1 \
				>"/dev/stderr";
			 errc++;
		     }
		 } else {
		     if (v0h > v1h) {
			 v0h--;
			 v0l += 4294967296;
			 d = sprintf("%08x%08x", v0h - v1h, v0l - v1l);
		     } else {
			 printf "#error Invalid addresses: %s - %s\n", v0, v1 \
				>"/dev/stderr";
			 errc++;
		     }
		 }
	     } else {
		 v0 = strtonum("0x"v0);
		 v1 = strtonum("0x"v1);
		 d = sprintf("%016x", v0 - v1);
	     }
	     $0 = tmp;

	     return d;
	 }

	 function map_string(str, off) {
	     if (str in strmap)
		 off = strmap[str];
	     else {
		 off = strsz;
		 strmap[str] = strsz;
		 strv[strc++] = str;
		 strsz += length(str) + 1;
	     }

	     return off;
	 }

	 BEGIN {
	     print "#include <asm/types.h>";
	     print "#if BITS_PER_LONG == 64";
	     print "# define PTR .quad";
	     if (arch == "aarch64")
		 print "# define ALGN .align 3";
	     else
		 print "# define ALGN .align 8";
	     print "#else";
	     print "# define PTR .long";
	     if (arch == "aarch64")
		 print "# define ALGN .align 2";
	     else
		 print "# define ALGN .align 4";
	     print "#endif";

	     print "\t.section .rodata, \042a\042";
	     print "";

	     print ".globl dtrace_sdt_probes";
	     print "\tALGN";
	     print "dtrace_sdt_probes:";

	     probec = 0;
	     stroff = 0;
	     strc = 0;
	 }

	 $1 == "ERROR:" {
	     next;
	 }

	 $4 == "_stext" {
	     stext = $2;
	     next;
	 }

	 $4 == "__init_begin" {
	     init_beg = $2;
	     next;
	 }

	 $4 == "__init_end" {
	     init_end = $2;
	     next;
	 }

	 $3 == "F" {
	     fnam = $4;
	     sub(/\..*$/, "", fnam);
	     foff = $2;
	     fadr = $5;

	     if (fadr != padr)
		 funcc++;
	     padr = fadr;

	     next;
	 }

	 $3 == "R" {
	     addr = addl(fadr, subl($2, foff));
	     if (addr >= init_beg && addr <= init_end)
		 next;
	     addr = subl(addr, stext);

	     print "/*";
	     print " * " $1 " " foff " F " fnam " " fadr;
	     print " * " $0;
	     print " * (" fadr " + (" $2 " - " foff ")) - " stext;
	     print " */";
	     printf "\tPTR\t_stext + 0x%s\n", addr;
	     printf "\tPTR\t%d\n", map_string($4);
	     printf "\tPTR\t%d\n", map_string(fnam);

	     probec++;

	     next;
	 }

	 END {
	     print "";
	     print ".globl dtrace_sdt_strings";
	     print "\tALGN";
	     print "dtrace_sdt_strings:";


	     for (i = 0; i < strc; i++)
		 printf "\t.asciz\t\042%s\042\n", strv[i];

	     print "";
	     print ".globl dtrace_sdt_nprobes";
	     print ".globl dtrace_fbt_nfuncs";
	     print "\tALGN";
	     print "dtrace_sdt_nprobes:";
	     printf "\tPTR\t%d\n", probec;
	     print "dtrace_fbt_nfuncs:";
	     printf "\tPTR\t%d\n", funcc;

	     exit(errc == 0 ? 0 : 1);
	 }' > ${tfn}

exit $?
