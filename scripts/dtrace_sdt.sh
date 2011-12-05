#!/bin/sh

LANG=C

fn="$1"

objdump -htr "$fn" | \
    awk '/^Sections:/ {
	     getline;
	     getline;
	     while ($0 !~ /SYMBOL/) {
		 sect = $2;
		 addr = $6;

		 getline;
		 if (/CODE/)
		     sectbase[sect] = addr;

		 getline;
	     }
	     next;
	 }

	 / F / {
	     printf "%16s %s F %s\n", $4, $1, $6;
	     next;
	 }

	 /^RELOC/ {
	     sub(/^[^\[]+\[/, "");
	     sub(/].*$/, "");
	     sect = $1;
	     next;
	 }

	 /__dtrace_probe_/ {
	     $3 = substr($3, 16);
	     sub(/-.*$/, "", $3);

	     printf "%16s %s R %s %s\n", sect, $1, $3, sectbase[sect];
	     next;
	 }' | \
    sort | \
    awk 'BEGIN {
	     print "#include <asm/types.h>";
	     print "#if BITS_PER_LONG == 64";
	     print "# define PTR .quad";
	     print "# define ALGN .align 8";
	     print "#else";
	     print "# define PTR .long";
	     print "# define ALGN .align 4";
	     print "#endif";

	     print "\t.section .rodata, \042a\042";
	     print "";

	     print ".globl dtrace_sdt_probes";
	     print "\tALGN";
	     print "dtrace_sdt_probes:";
	 }

	 / F / {
	     fun = $4;
	     next;
	 }

	 / R / {
	     print "\tPTR\t0x" $2;
	     print "\tPTR\t0x" $5;
	     print "\tPTR\t" length($4);
	     print "\tPTR\t" length(fun);
	     print "\t.asciz\t\042" $4 "\042";
	     print "\t.asciz\t\042" fun "\042";
	     print "\tALGN";

	     probec++;
	 }

	 END {
	     print "";
	     print ".globl dtrace_sdt_nprobes";
	     print "\tALGN";
	     print "dtrace_sdt_nprobes:";
	     print "\tPTR\t" probec;
	 }'
