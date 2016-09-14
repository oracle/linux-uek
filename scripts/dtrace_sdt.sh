#!/bin/sh

LANG=C

#
# Syntax:
#	dtrace_sdt.sh sdtstub <S-file> <o-file>+
#		This is used to generate DTrace SDT probe stubs based on one
#		or more object file(s).  The stubs are written to <S-file>.
#	dtrace_sdt.sh sdtinfo <c-file> <o-file> kmod
#		This is used to generate DTrace SDT probe definitions for a
#		kmod .o file.  The output is written to <c-file>.
#	dtrace_sdt.sh sdtinfo <S-file> <l-file>
#		This is used to generate DTrace SDT probe definitions for a
#		linked kernel image file <l-file>.  The output is written to
#		<S-file>.
#

opr="$1"
shift
if [ -z "$opr" ]; then
    echo "ERROR: Missing operation" > /dev/stderr
    exit 1
fi

tfn="$1"
shift
if [ -z "$tfn" ]; then
    echo "ERROR: Missing target filename" > /dev/stderr
    exit 1
fi

ofn="$1"
tok="$2"

if [ -z "$ofn" ]; then
    echo "ERROR: Missing object file argument" > /dev/stderr
    exit 1
fi

if [ "$opr" = "sdtstub" ]; then
    ${NM} -u $* | \
	grep __dtrace_probe_ | sort | uniq | \
	${AWK} -v arch=${ARCH} \
	       '{
		    printf("\t.globl %s\n\t.type %s,@function\n%s:\n",
			   $2, $2, $2);
		    count++;
		}

		END {
		    if (count) {
			if (arch == "x86" || arch == "x86_64") {
			    print "\tret";
			} else if (arch == "sparc" || arch == "sparc64") {
			    print "\tretl";
			    print "\tnop";
			}
		    }
		}' > $tfn
    exit $?
fi

if [ "$opr" != "sdtinfo" ]; then
    echo "ERROR: Invalid operation, should be sdtstub or sdtinfo" > /dev/stderr
    exit 1
fi

if [ "$tok" = "kmod" ]; then
    # Pre-process the object file to handle any local functions that contain
    # SDT probes.
    scripts/kmodsdt ${ofn}

    # Output all function symbols in the symbol table of the object file.
    # Subsequently, output all relocation records for DTrace SDT probes.  The
    # probes are identified by their __dtrace_probe_ prefix.
    #
    # We sort the output primarily based on the section, using the value (or
    # offset) as secondary sort criterion  The overall result is that the
    # output will be structured as a list of functions, and for any functions
    # that contain DTrace SDT probes, relocation records will follow the
    # function entry they are associated with.
    #
    # Relocations are reported by objdump per section, with a header line
    # documenting the specific section being reported:
    #	RELOCATION RECORDS FOR [<section>]:
    # This is followed by a column header line, and a list of relocations.
    # The relocations are listed with 3 tokens per line:
    #	<offset> <type> <value>
    #
    # Three different types can show up in the output (all with 4 tokens):
    #    <section> <offset> F <value>
    #        Function within a section at a specific offset.
    #        (See STAGE 3a below.)
    #    <section> <offset> G <value>
    #        Global alias for a local function within a section at a specific
    #        offset.  A function can only have one alias, and there cannot be
    #        an alias without its respective function.
    #        (See STAGE 3a below.)
    #    <section> <offset> R <value>
    #        Relocation within a section at a specific offset.
    #        (See STAGE 3b below.)
    #
    ${OBJDUMP} -tr ${ofn} | \
    awk '/^RELOC/ {
	     sect = substr($4, 2, length($4) - 3);
	     next;
	 }

	 sect && /__dtrace_probe_/ {
	     $3 = substr($3, 16);
	     sub(/[\-+].*$/, "", $3);
	     print sect " " $1 " R " $3;
	     next;
	 }

	 /file format/ {
	     next;
	 }

	 / F / {
	     if ($6 == ".hidden")
		 print $4 " " $1 " G " $7;
	     else
		 print $4 " " $1 " F " $6;
	 }' | \
    sort -k1,2 | \
    awk -v arch=${ARCH} \
	'function subl(v0, v1, v0h, v0l, v1h, v1l, d, tmp) {
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
                         d = sprintf("%08x%08x", v0h - v1h, v0l - v1l);
                     } else {
                         printf "#error Invalid addresses: %x vs %x", v0, v1 \
                                                                >"/dev/stderr";
                         errc++;
                     }
                 } else {
                     printf "#error Invalid addresses: %x vs %x", v0, v1 \
                                                                >"/dev/stderr";
                     errc++;
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
	     print "#include <linux/sdt.h>";

	     probec = 0;
	 }

	 #
	 # Process a symbol table definition for a function in the object
	 # file ($ofn).  As we pass through the symbol table, we record the
	 # function name, address, and symbol table index or alias.  This
	 # information is needed for any potential DTrace probes that may exist
	 # in the function.  They will be listed in relocation records
	 # subsequent to this function definition (and are processed in the
	 # next action block).
	 #
	 NF == 4 && $3 == "F" {
	     fname = $4;
	     sub(/\..*$/, "", fname);
	     alias = $4;
	     faddr = $2;
	     sub(/^0+/, "", faddr);

	     next;
	 }

	 NF == 4 && $3 == "G" {
	     alias = $4;

	     next;
	 }

	 #
	 # Process a relocation record associated with the preceding function.
	 #
	 # For kernel modules:
	 # Convert the section offset into an offset in the function where the
	 # DTrace probe is located, i.e. an offset from the start of the
	 # function.  This will be resolved in an absolute address at runtime
	 # when the module is loaded.
	 #
	 NF == 4 && $3 == "R" {
	     sub(/^0+/, "", $2);

	     addr = subl($2, faddr);

	     if (arch == "x86" || arch == "x86_64")
		 addr = subl(addr, 1);

	     protom[alias] = 1;
	     probev[probec] = sprintf("  {\042%s\042,  \042%s\042 /* %s */, (uintptr_t)%s+0x%s },", $4, fname, $1, alias, addr);
	     probec++;

	     next;
	 }

	 END {
	     if (probec > 0) {
		 for (alias in protom)
		     printf "extern void %s(void);\n", alias;
		 print "\nstatic sdt_probedesc_t\t_sdt_probes[] = {";
		 for (i = 0; i < probec; i++)
		     print probev[i];
		 print "};\n";
	     } else
		print "#define _sdt_probes\tNULL";

	     print "#define _sdt_probec\t" probec;

	     exit(errc == 0 ? 0 : 1);
	 }' > $tfn
else
    # For a linked kernel (with relocation data), the scope of DTrace SDT
    # probe discovery can be limited to just the .text section.
    #
    # First the section record is retrieved in order to determine the base
    # address for symbols in the .text section.
    #
    # Subsequently, all function symbols that are located in the .text sectio
    # are read from the symbol table of the linked kernel object.  Each symbol
    # is reported in the output stream with its address, a token identifying it
    # as a function (or alias), and its name.
    #
    # Finally, each relocation record from the .text section that relates to
    # SDT probes are written to the output stream with its address, a token
    # identifying it as a relocation, and its name.  Probes are identified in
    # the relocation records as symbols with __dtrace_probe_ as prefix.
    #
    # We sort the output based on the address, which guarantees that the output
    # will be a list of functions, and each function record will be followed 
    # immediately by any DTrace SDT probe records that are used in that
    # function.
    #
    # Three different record types can show up in the output (3 tokens each):
    #    <address> F <name>
    #        Named function at a specific address.
    #    <address> G <name>
    #        Global alias for a local function at a specific offset.  A
    #        function can only have one alias, and there cannot be an alias
    #        without its respective function.
    #    <address> R <value>
    #        Relocation within a section at a specific address
    #
    ${OBJDUMP} -htrj .text ${ofn} | \
    awk 'function addl(v0, v1, v0h, v0l, v1h, v1l, d, tmp) {
             tmp = $0;
             if (length(v0) > 8 || length(v1) > 8) {
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

                 d = sprintf("%08x%08x", v0h, v0l);
             } else {
                 v0 = strtonum("0x"v0);
                 v1 = strtonum("0x"v1);
                 d = sprintf("%016x", v0 + v1);
             }
             $0 = tmp;

             return d;
         }

	 NF == 7 && $2 == ".text" {
	     base = $4;
	     next;
	 }

	 /^RELOC/ {
	     in_reloc = $4 == "[.text]:";
	     next;
	 }

	 in_reloc && /__dtrace_probe_/ {
	     $3 = substr($3, 16);
	     sub(/[\-+].*$/, "", $3);
	     print addl(base, $1) " R " $3;
	     next;
	 }

	 / F / {
	     if ($6 == ".hidden")
		 print $1 " G " $7;
	     else
		 print $1 " F " $6;
	 }' | \
    sort -k1,2 | \
    awk -v arch=${ARCH} \
	'function subl(v0, v1, v0h, v0l, v1h, v1l, d, tmp) {
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
                         d = sprintf("%08x%08x", v0h - v1h, v0l - v1l);
                     } else {
                         printf "#error Invalid addresses: %x vs %x", v0, v1 \
                                                                >"/dev/stderr";
                         errc++;
                     }
                 } else {
                     printf "#error Invalid addresses: %x vs %x", v0, v1 \
                                                                >"/dev/stderr";
                     errc++;
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

	     probec = 0;
	 }

	 #
	 # Process a symbol table definition for a function in the .text
	 # section of the kernel image.  As we pass through the symbol table,
	 # we record the function name and address.
	 #
	 NF == 3 && $2 == "F" {
	     fname = $3;
	     sub(/\..*$/, "", fname);
	     alias = $3;

	     next;
	 }

	 NF == 3 && $2 == "G" {
	     alias = $3;

	     next;
	 }

	 #
	 # Process a relocation record associated with the preceding function.
	 #
	 # Since all addresses are already resolved earlier, we can simply
	 # generate the SDT probe information record.
	 #
	 NF == 3 && $2 == "R" {
	     sub(/^0+/, "", $1);

	     addr = $1;

	     if (arch == "x86" || arch == "x86_64")
		 addr = subl(addr, 1);

	     printf "\tPTR\t0x%s\n", addr;
	     printf "\tPTR\t%d\n", length($3);
	     printf "\tPTR\t%d\n", length(fname);
	     printf "\t.asciz\t\042%s\042\n", $3;
	     printf "\t.asciz\t\042%s\042\n", fname;
	     print "\tALGN";

	     probec++;

	     next;
	 }

	 END {
	     print "";
	     print ".globl dtrace_sdt_nprobes";
	     print "\tALGN";
	     print "dtrace_sdt_nprobes:";
	     printf "\tPTR\t%d\n", probec;

	     exit(errc == 0 ? 0 : 1);
	 }' > $tfn
fi

exit $?
