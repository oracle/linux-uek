/* Generate assembler source containing __dtrace_probe_* calls (reloc info)
 *
 * Based on scripts/kallsyms.c
 * Copyright 2002       by Kai Germaschewski
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 *
 * Usage: dtrace_relocs input_file_text output_file_elf
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <elf.h>

//#define INFO	1
//#define SCANF	1

struct sym_entry {
	unsigned long long addr;
	unsigned char is_section;
	unsigned char section_used;
	int section_index;
	unsigned long long section_base;
	unsigned int len;
	char *sym;
};

struct text_range {
	const char *stext, *etext;
	unsigned long long start, end;
};

static unsigned long long _text, _stext;	// from System.map

static struct sym_entry *table;
static unsigned int table_size, table_cnt;
static int this_section_index;
static unsigned long long this_section_addr;
static int relocs_count;

static void usage(void)
{
	fprintf(stderr, "Usage: dtrace_relocs input_file_text output_file_elf\n");
	exit(1);
}

// skip over whitespace (spaces or tabs)
static char *deblank(char *str)
{
	while (*str == ' ' || *str == '\t')
			str++;
	return str;
}

static int find_section(char *sect, int sectlen)
{
	int ix;
	struct sym_entry *sym = table;

#if 0
	fprintf(stderr, "%s: search for sect=<%s>, sectlen=%d:\n",
		__func__, sect, sectlen);
#endif

	for (ix = 0; ix < table_cnt; ix++, sym++) {
#if 0
		if (sym->is_section && strlen(sym->sym) == sectlen)
			fprintf(stderr, "%s: ix=%d, symlen=%d, symname=<%s>\n",
				__func__, ix, strlen(sym->sym), sym->sym);
#endif
		if (sym->is_section && strlen(sym->sym) == sectlen &&
			strncmp(sym->sym, sect, sectlen) == 0) {
				sym->section_used = true;
				this_section_addr = sym->addr;
				return sym->section_index;
		}
	}

	return -1;
}

static int get_this_section(char buf[500])
{
	char *sect;
	int sectlen;
	int sect_index;

	if (strncmp(buf, "RELOCATION RECORDS FOR [", 24) != 0) {
		fprintf(stderr, "Bad relocation header: %s\n", buf);
		exit(2);
	}

	sect = buf + 24;
	sectlen = strlen(sect); // includes a trailing newline
#if 0
	fprintf(stderr, "%s: sect=<%s>, sectlen=%d\n",
		__func__, sect, sectlen);
#endif
	if (*(sect + sectlen - 3) != ']' || *(sect + sectlen - 2) != ':') {
		fprintf(stderr, "Bad relocation header: %s\n", buf);
		exit(2);
	}
	*(sect + sectlen - 3) = '\0';
	sectlen -= 3;	// drop the "]:\n"
#if 0
	fprintf(stderr, "%s: isolated section name=<%s>\n", __func__, sect);
#endif
	sect_index = find_section(sect, sectlen);
	if (sect_index < 0) {
		fprintf(stderr, "Bad section name in relocation header: %s\n",
			sect);
		exit(2);
	}

	return sect_index;
}

/*
 * scans 2 lines of section info;
 * first line is already in buf;
 * second line is noise for now;
 */
static int get_section_info(FILE *fin, char buf[500], struct sym_entry *sect)
{
	int rc;
	int sect_index;
	char sect_name[200], sect_align[100];
	unsigned long sect_size, file_offset;
	unsigned long long vma, lma;
	char sect_flags[500];
	char *flags;

	rc = sscanf(buf, " %d %s %lx %llx %llx %lx %s \n",
		&sect_index, (char *)&sect_name, &sect_size, &vma, &lma,
		&file_offset, (char *)&sect_align);
#ifdef SCANF
	fprintf(stderr, "%s: sscanf.1 rc= %d\n", __func__, rc);
#endif
	if (rc != 7)
		return -1;

	if (!fgets(sect_flags, sizeof(sect_flags), fin))
		return -1;

#ifdef SCANF
	fprintf(stderr, "%s: fgets.2 read=<%s>", __func__, sect_flags);
#endif
	flags = deblank(sect_flags);

	sect->addr = file_offset;
	sect->is_section = true;
	sect->section_used = false;
	sect->section_index = sect_index;
	sect->len = sect_size;
	sect->sym = malloc(strlen(sect_name));
	if (!sect->sym) {
		fprintf(stderr, "relocs failure: "
			"unable to allocate required amount of memory\n");
		exit(1);
	}
	strcpy((char *)sect->sym, sect_name);

#ifdef INFO
	fprintf(stderr, "sect: index=%d, name=%s, addr/offset=0x%llx, sect_size=0x%x, align=%s, vma=0x%llx, lma=0x%llx, flags=%s\n",
		sect_index, sect->sym, sect->addr, sect->len, sect_align,
		vma, lma, flags);
#endif

	return 0;
}

static int get_symbol_info(char buf[500], struct sym_entry *s)
{
	int rc;
	unsigned long long relo_offset, pp_offset;
	char relo_type[200];
	char probepoint[200];

	//rc = sscanf(buf, " %llx %s %200s-%llx \n",
	rc = sscanf(buf, " %llx %s %[^ -]-%llx \n",
		&relo_offset, (char *)&relo_type,
		(char *)&probepoint, &pp_offset);
#ifdef SCANF
	fprintf(stderr, "%s: sscanf.1 rc= %d\n", __func__, rc);
#endif
	if (rc != 4)
		return -1;

	s->addr = relo_offset;
	s->len = strlen(probepoint);
	s->is_section = false;
	s->section_used = false;
	s->section_index = -1;
	s->section_base = this_section_addr;
	s->sym = malloc(s->len + 1);
	if (!s->sym) {
		fprintf(stderr, "relocs failure: "
			"unable to allocate required amount of memory\n");
		exit(1);
	}
	strcpy((char *)s->sym, probepoint);

#ifdef INFO
	fprintf(stderr, "sym: addr/offset=0x%llx, strlen=%d, type=%s, name=%s\n",
		s->addr, s->len, relo_type, s->sym);
#endif

	relocs_count++;
	return 0;
}

static void get_text_addr(char buf[500], char *str_match,
			unsigned long long *_adr)
{
	int rc;
	unsigned long long adr;
	char relo_type[100];
	char symbol_name[200];

	rc = sscanf(buf, "%llx %s %s\n",
		&adr, (char *)&relo_type,
		(char *)&symbol_name);
#ifdef SCANF
	fprintf(stderr, "%s: sscanf.1 rc= %d\n", __func__, rc);
#endif
	if (rc != 3)
		return;

	if (strcmp(relo_type, "T"))
		return;
	if (strcmp(symbol_name, str_match))
		return;

	*_adr = adr;
#ifdef INFO
	fprintf(stderr, "found '%s':_addr/offset=0x%llx, type=%s, name=%s\n",
		str_match, adr, relo_type, symbol_name);
#endif
}

static void read_info(FILE *fin)
{
	char buf[500];
	bool in_sections = false, in_symbols = false;

	while (!feof(fin)) {
		if (table_cnt >= table_size) {
			table_size += 10000;
			table = realloc(table, sizeof(*table) * table_size);
			if (!table) {
				fprintf(stderr, "out of memory\n");
				exit(1);
			}
		}

		if (!fgets(buf, sizeof(buf), fin))
			break;
#ifdef SCANF
		fprintf(stderr, "dtr: buf=<%s>\n", buf);
#endif

		if (strncmp(buf, "Sections:", 9) == 0) {
			in_sections = true;
			continue;
		}
		if (strncmp(buf, "RELOCATION RECORDS", 11) == 0) {
			in_sections = false;
			in_symbols = true;
			// isolate & look up section name, get its index
			// this call also sets 'this_section_addr'
			this_section_index = get_this_section(buf);
			continue;
		}

		if (in_sections) {
			if (strncmp(buf, "Idx ", 4) != 0)
				if (get_section_info(fin, buf, &table[table_cnt]) == 0)
					table_cnt++;
			continue;
		}

		if (in_symbols) {
			if (get_symbol_info(buf, &table[table_cnt]) == 0)
				table_cnt++;
			else if (_text == 0)
				get_text_addr(buf, "_text", &_text);
			else if (_stext == 0)
				get_text_addr(buf, "_stext", &_stext);
		}
	}
}

static void output_label(FILE *fout, char *label)
{
	fprintf(fout, ".globl %s\n", label);
	fprintf(fout, "\tALGN\n");
	fprintf(fout, "%s:\n", label);
}

static void write_relocs(FILE *fout)
{
	unsigned int i;
	int reloc_count = 0;

	fprintf(fout, "#include <asm/types.h>\n");
	fprintf(fout, "#if BITS_PER_LONG == 64\n");
	fprintf(fout, "#define PTR .quad\n");
	fprintf(fout, "#define ALGN .align 8\n");
	fprintf(fout, "#else\n");
	fprintf(fout, "#define PTR .long\n");
	fprintf(fout, "#define ALGN .align 4\n");
	fprintf(fout, "#endif\n");

	fprintf(fout, "\t.section .rodata, \"a\"\n");
	fprintf(fout, "\n");

	output_label(fout, "dtrace_relocs_count");
	fprintf(fout, "\tPTR\t%d\n", relocs_count);
	fprintf(fout, "\n");

	fprintf(fout, "_text_\t= 0x%llx\n", _text);
	fprintf(fout, "_stext_\t= 0x%llx\n", _stext);
	fprintf(fout, "\n");

	/*
	 * Provide proper symbols relocatability by their '_text'
	 * relativeness.  The symbol names cannot be used to construct
	 * normal symbol references as the list of symbols contains
	 * symbols that are declared static and are private to their
	 * .o files.  This prevents .tmp_kallsyms.o or any other
	 * object from referencing them.
	 */
	output_label(fout, "dtrace_relocs");
	for (i = 0; i < table_cnt; i++) {
		// for reloc symbols (not sections):
		// print symbol relative address, section base address,
		// call target string length, call target string/name;
		if (!table[i].is_section) {
			fprintf(fout, "\tPTR\t%#llx\n", _stext + table[i].addr);
			fprintf(fout, "\tPTR\t%#llx\n", table[i].section_base);
			fprintf(fout, "\tPTR\t%d\n", table[i].len);
			fprintf(fout, "\t.asciz\t\"%s\"\n", table[i].sym);
			fprintf(fout, "\tALGN\n");
			reloc_count++;
		}
	}

	fprintf(fout, "\n");

	if (reloc_count != relocs_count) {
		fprintf(fout, "relocs error: reloc counters do not agree (%d vs. %d\n)",
			relocs_count, reloc_count);
		exit(3);
	}
}

int main(int argc, char *argv[])
{
	char *infile, *outfile;
	FILE *fin, *fout;


	if (argc != 3)
		usage();

	infile = argv[1];
	outfile = argv[2];

	fin = fopen(infile, "r");
	if (!fin) {
		fprintf(stderr, "relocs: cannot open input file '%s'\n",
			infile);
		exit(2);
	}
	fout = fopen(outfile, "w");
	if (!fout) {
		fprintf(stderr, "relocs: cannot create output file '%s'\n",
			outfile);
		exit(2);
	}

	read_info(fin);
	fclose(fin);

	write_relocs(fout);
	fclose(fout);

	return 0;
}
