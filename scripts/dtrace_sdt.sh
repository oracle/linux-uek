#!/bin/sh

LANG=C

ofn="$1"
lfn="$2"

(
    objdump -htr "$ofn" | \
	awk -v lfn=${lfn} \
	    '/^Sections:/ {
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

	     $3 == "F" {
		 printf "%16s %s F %s\n", $4, $1, $6;

		 if (!lfn)
		     printf "%s t %s\n", $1, $6;

		 next;
	     }

	     /^RELOC/ {
		 sub(/^[^\[]+\[/, "");
		 sub(/].*$/, "");
		 sect = $1;
		 next;
	     }

	     /__dtrace_probe_/ && sect !~ /debug/ {
		 $3 = substr($3, 16);
		 sub(/-.*$/, "", $3);
		 printf "%16s %s R %s %s\n", sect, $1, $3, sectbase[sect];
		 next;
	     }' | \
	sort
    [ "x${lfn}" != "x" ] && nm ${lfn}
) | \
    awk 'function addl(v0, v1, v0h, v0l, v1h, v1l, d, tmp) {
	     tmp = $0;
	     if (length(v0) > 8) {
		 d = length(v0);
		 v0h = strtonum("0x"substr(v0, 1, d - 8));
		 v0l = strtonum("0x"substr(v0, d - 8 + 1));
		 d = length(v1);
		 v1h = strtonum("0x"substr(v1, 1, d - 8));
		 v1l = strtonum("0x"substr(v1, d - 8 + 1));

		 v0h += v1h;
		 v0l += v1l;

		 d = sprintf("%x", v0l);
		 if (length(d) > 8)
		     v0h++;

		 d = sprintf("%x%x", v0h, v0l);
	     } else {
		 v0 = strtonum("0x"v0);
		 v1 = strtonum("0x"v1);
		 d = sprintf("%x", v0 + v1);
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

		 if (v0l > v1l) {
		     if (v0h >= v1h) {
			 d = sprintf("%x%x", v0h - v1h, v0l - v1l);
		     } else {
		         printf "#error Invalid addresses: %x vs %x", v0, v1 \
								> /dev/stderr;
			 errc++;
		     }
		 } else {
		     printf "#error Invalid addresses: %x vs %x", v0, v1 \
								> /dev/stderr;
		     errc++;
		 }
	     } else {
		 v0 = strtonum("0x"v0);
		 v1 = strtonum("0x"v1);
		 d = sprintf("%x", v0 - v1);
	     }
	     $0 = tmp;

	     return d;
	 }

	 BEGIN {
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

	 $2 ~ /^[tT]$/ {
	     fun = $3;

	     if (fun in probes) {
		 baseaddr = $1;
		 sub(/^0+/, "", baseaddr);

		 $0 = probes[fun];

		 for (i = 1; i <= NF; i++) {
		     prb = $i;

		     print "\tPTR\t0x" addl(baseaddr, poffst[prb]);
		     print "\tPTR\t" length(prb);
		     print "\tPTR\t" length(fun);
		     print "\t.asciz\t\042" prb "\042";
		     print "\t.asciz\t\042" fun "\042";
		     print "\tALGN";

		     probec++;
		 }
	     }

	     next;
	 }

	 $3 == "F" {
	     fun = $4;
	     addr = $2;

	     sub(/^0+/, "", addr);

	     next;
	 }

	 $3 == "R" {
	     sub(/^0+/, "", $2);

	     probes[fun] = $4 " " probes[fun];
	     poffst[$4] = subl($2, addr);

	     next;
	 }

	 END {
	     print "";
	     print ".globl dtrace_sdt_nprobes";
	     print "\tALGN";
	     print "dtrace_sdt_nprobes:";
	     print "\tPTR\t" probec;

	     if (errc > 0) {
		 print errc " errors generating SDT probe data." > /dev/stderr;
		 exit 1;
	     }
	 }'
