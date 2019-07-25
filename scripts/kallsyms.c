/* Generate assembler source containing symbol information
 *
 * Copyright 2002       by Kai Germaschewski
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 *
 * Usage: nm -n -S vmlinux
 *        | scripts/kallsyms [--all-symbols] [--absolute-percpu]
 *             [--base-relative] [--builtin=modules_thick.builtin]
 *        > symbols.S
 *
 *      Table compression uses all the unused char codes on the symbols and
 *  maps these to the most used substrings (tokens). For instance, it might
 *  map char code 0xF7 to represent "write_" and then in every symbol where
 *  "write_" appears it can be replaced by 0xF7, saving 5 bytes.
 *      The used codes themselves are also placed in the table so that the
 *  decompresion can work without "special cases".
 *      Applied to kernel symbols, this usually produces a compression ratio
 *  of about 50%.
 *
 */

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#include "../include/generated/autoconf.h"

#ifdef CONFIG_KALLMODSYMS
#include <errno.h>
#include <modules_thick.h>
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

#define KSYM_NAME_LEN		128

struct sym_entry {
	unsigned long long addr;
	unsigned long long size;
	unsigned int len;
	unsigned int start_pos;
	unsigned char *sym;
	unsigned int percpu_absolute;
#ifdef CONFIG_KALLMODSYMS
	unsigned int module;
#endif
};

struct addr_range {
	const char *start_sym, *end_sym;
	unsigned long long start, end;
};

static unsigned long long _text;
static unsigned long long relative_base;
static struct addr_range text_ranges[] = {
	{ "_stext",     "_etext"     },
	{ "_sinittext", "_einittext" },
};
#define text_range_text     (&text_ranges[0])
#define text_range_inittext (&text_ranges[1])

static struct addr_range percpu_range = {
	"__per_cpu_start", "__per_cpu_end", -1ULL, 0
};

static struct sym_entry *table;
static unsigned int table_size, table_cnt;
static int all_symbols = 0;
static int absolute_percpu = 0;
static int base_relative = 0;

static int token_profit[0x10000];

/* the table that holds the result of the compression */
static unsigned char best_table[256][2];
static unsigned char best_table_len[256];

#ifdef CONFIG_KALLMODSYMS
static unsigned int strhash(const char *s)
{
	/* fnv32 hash */
	unsigned int hash = 2166136261U;

	for (; *s; s++)
		hash = (hash ^ *s) * 0x01000193;
	return hash;
}

#define OBJ2MOD_BITS 10
#define OBJ2MOD_N (1 << OBJ2MOD_BITS)
#define OBJ2MOD_MASK (OBJ2MOD_N - 1)
struct obj2mod_elem {
	char *obj;
	int mod;
	struct obj2mod_elem *next;
};

static struct obj2mod_elem *obj2mod[OBJ2MOD_N];

static void obj2mod_init(void)
{
	memset(obj2mod, 0, sizeof(obj2mod));
}

static void obj2mod_put(char *obj, int mod)
{
	int i = strhash(obj) & OBJ2MOD_MASK;
	struct obj2mod_elem *elem = malloc(sizeof(struct obj2mod_elem));

	if (!elem) {
		fprintf(stderr, "kallsyms: out of memory\n");
		exit(1);
	}

	elem->obj = strdup(obj);
	if (!elem->obj) {
		fprintf(stderr, "kallsyms: out of memory\n");
		free(elem);
		exit(1);
	}

	elem->mod = mod;
	elem->next = obj2mod[i];
	obj2mod[i] = elem;
}

static int obj2mod_get(char *obj)
{
	int i = strhash(obj) & OBJ2MOD_MASK;
	struct obj2mod_elem *elem;

	for (elem = obj2mod[i]; elem; elem = elem->next)
		if (strcmp(elem->obj, obj) == 0)
			return elem->mod;
	return 0;
}

static void obj2mod_free(void)
{
	int i;

	for (i = 0; i < OBJ2MOD_N; i++) {
		struct obj2mod_elem *elem = obj2mod[i];
		struct obj2mod_elem *next;

		while (elem) {
			next = elem->next;
			free(elem->obj);
			free(elem);
			elem = next;
		}
	}
}

/*
 * The builtin module names.  The "offset" points to the name as if
 * all builtin module names were concatenated to a single string.
 */
static unsigned int builtin_module_size;	/* number allocated */
static unsigned int builtin_module_len;		/* number assigned */
static char **builtin_modules;			/* array of module names */
static unsigned int *builtin_module_offsets;	/* offset */

/*
 * An ordered list of address ranges and how they map to built-in modules.
 */
struct addrmap_entry {
	unsigned long long addr;
	unsigned long long size;
	unsigned int module;
};
static struct addrmap_entry *addrmap;
static int addrmap_num, addrmap_alloced;
#endif

static void usage(void)
{
	fprintf(stderr, "Usage: kallsyms [--all-symbols] [--absolute-percpu] "
			"[--base-relative] [--builtin=modules_thick.builtin] "
			"< nm_vmlinux.out > symbols.S\n");
	exit(1);
}

/*
 * This ignores the intensely annoying "mapping symbols" found
 * in ARM ELF files: $a, $t and $d.
 */
static int is_arm_mapping_symbol(const char *str)
{
	return str[0] == '$' && strchr("axtd", str[1])
	       && (str[2] == '\0' || str[2] == '.');
}

static int check_symbol_range(const char *sym, unsigned long long addr,
			      struct addr_range *ranges, int entries)
{
	size_t i;
	struct addr_range *ar;

	for (i = 0; i < entries; ++i) {
		ar = &ranges[i];

		if (strcmp(sym, ar->start_sym) == 0) {
			ar->start = addr;
			return 0;
		} else if (strcmp(sym, ar->end_sym) == 0) {
			ar->end = addr;
			return 0;
		}
	}

	return 1;
}

#ifdef CONFIG_KALLMODSYMS
static int addrmap_compare(const void *keyp, const void *rangep)
{
	unsigned long long addr = *((const unsigned long long *)keyp);
	const struct addrmap_entry *range = (const struct addrmap_entry *)rangep;

	if (addr < range->addr)
		return -1;
	if (addr < range->addr + range->size)
		return 0;
	return 1;
}
#endif

static int read_symbol(FILE *in, struct sym_entry *s)
{
	char sym[500], stype;
	int rc, init_scratch = 0;
#ifdef CONFIG_KALLMODSYMS
	struct addrmap_entry *range;
#endif

read_another:
	rc = fscanf(in, "%llx %llx %c %499s\n",
		    &s->addr, &s->size, &stype, sym);
	if (rc != 4) {
		if (rc != EOF && fgets(sym, 500, in) == NULL)
			fprintf(stderr, "Read error or end of file.\n");
		return -1;
	}
	if (strlen(sym) >= KSYM_NAME_LEN) {
		fprintf(stderr, "Symbol %s too long for kallsyms (%zu >= %d).\n"
				"Please increase KSYM_NAME_LEN both in kernel and kallsyms.c\n",
			sym, strlen(sym), KSYM_NAME_LEN);
		return -1;
	}

	/* skip the .init.scratch section */
	if (strcmp(sym, "__init_scratch_end") == 0) {
		init_scratch = 0;
		goto read_another;
	}
	if (strcmp(sym, "__init_scratch_begin") == 0)
		init_scratch = 1;
	if (init_scratch)
		goto read_another;

	/* Ignore most absolute/undefined (?) symbols. */
	if (strcmp(sym, "_text") == 0)
		_text = s->addr;
	else if (check_symbol_range(sym, s->addr, text_ranges,
				    ARRAY_SIZE(text_ranges)) == 0)
		/* nothing to do */;
	else if (toupper(stype) == 'A')
	{
		/* Keep these useful absolute symbols */
		if (strcmp(sym, "__kernel_syscall_via_break") &&
		    strcmp(sym, "__kernel_syscall_via_epc") &&
		    strcmp(sym, "__kernel_sigtramp") &&
		    strcmp(sym, "__gp"))
			return -1;

	}
	else if (toupper(stype) == 'U' ||
		 is_arm_mapping_symbol(sym))
		return -1;
	/* exclude also MIPS ELF local symbols ($L123 instead of .L123) */
	else if (sym[0] == '$')
		return -1;
	/* exclude debugging symbols */
	else if (stype == 'N' || stype == 'n')
		return -1;
	/* exclude s390 kasan local symbols */
	else if (!strncmp(sym, ".LASANPC", 8))
		return -1;

#ifdef CONFIG_KALLMODSYMS
	/* look up the builtin module this is part of (if any) */
	range = (struct addrmap_entry *) bsearch(&s->addr,
	    addrmap, addrmap_num, sizeof(*addrmap), &addrmap_compare);
	if (range)
		s->module = builtin_module_offsets[range->module];
	else
		s->module = 0;
#endif

	/* include the type field in the symbol name, so that it gets
	 * compressed together */
	s->len = strlen(sym) + 1;
	s->sym = malloc(s->len + 1);
	if (!s->sym) {
		fprintf(stderr, "kallsyms failure: "
			"unable to allocate required amount of memory\n");
		exit(EXIT_FAILURE);
	}
	strcpy((char *)s->sym + 1, sym);
	s->sym[0] = stype;

	s->percpu_absolute = 0;

	/* Record if we've found __per_cpu_start/end. */
	check_symbol_range(sym, s->addr, &percpu_range, 1);

	return 0;
}

static int symbol_in_range(struct sym_entry *s, struct addr_range *ranges,
			   int entries)
{
	size_t i;
	struct addr_range *ar;

	for (i = 0; i < entries; ++i) {
		ar = &ranges[i];

		if (s->addr >= ar->start && s->addr <= ar->end)
			return 1;
	}

	return 0;
}

static int symbol_valid(struct sym_entry *s)
{
	/* Symbols which vary between passes.  Passes 1 and 2 must have
	 * identical symbol lists.  The kallsyms_* symbols below are only added
	 * after pass 1, they would be included in pass 2 when --all-symbols is
	 * specified so exclude them to get a stable symbol list.
	 */
	static char *special_symbols[] = {
		"kallsyms_addresses",
		"kallsyms_offsets",
		"kallsyms_relative_base",
		"kallsyms_sizes",
		"kallsyms_num_syms",
		"kallsyms_names",
		"kallsyms_markers",
		"kallsyms_token_table",
		"kallsyms_token_index",
		"kallsyms_symbol_modules",
		"kallsyms_modules",

	/* Exclude linker generated symbols which vary between passes */
		"_SDA_BASE_",		/* ppc */
		"_SDA2_BASE_",		/* ppc */
		NULL };

	static char *special_prefixes[] = {
		"__crc_",		/* modversions */
		"__efistub_",		/* arm64 EFI stub namespace */
		NULL };

	static char *special_suffixes[] = {
		"_veneer",		/* arm */
		"_from_arm",		/* arm */
		"_from_thumb",		/* arm */
		NULL };

	int i;
	char *sym_name = (char *)s->sym + 1;

	/* if --all-symbols is not specified, then symbols outside the text
	 * and inittext sections are discarded */
	if (!all_symbols) {
		if (symbol_in_range(s, text_ranges,
				    ARRAY_SIZE(text_ranges)) == 0)
			return 0;
		/* Corner case.  Discard any symbols with the same value as
		 * _etext _einittext; they can move between pass 1 and 2 when
		 * the kallsyms data are added.  If these symbols move then
		 * they may get dropped in pass 2, which breaks the kallsyms
		 * rules.
		 */
		if ((s->addr == text_range_text->end &&
				strcmp(sym_name,
				       text_range_text->end_sym)) ||
		    (s->addr == text_range_inittext->end &&
				strcmp(sym_name,
				       text_range_inittext->end_sym)))
			return 0;
	}

	/* Exclude symbols which vary between passes. */
	for (i = 0; special_symbols[i]; i++)
		if (strcmp(sym_name, special_symbols[i]) == 0)
			return 0;

	for (i = 0; special_prefixes[i]; i++) {
		int l = strlen(special_prefixes[i]);

		if (l <= strlen(sym_name) &&
		    strncmp(sym_name, special_prefixes[i], l) == 0)
			return 0;
	}

	for (i = 0; special_suffixes[i]; i++) {
		int l = strlen(sym_name) - strlen(special_suffixes[i]);

		if (l >= 0 && strcmp(sym_name + l, special_suffixes[i]) == 0)
			return 0;
	}

	return 1;
}

static void read_map(FILE *in)
{
	while (!feof(in)) {
		if (table_cnt >= table_size) {
			table_size += 10000;
			table = realloc(table, sizeof(*table) * table_size);
			if (!table) {
				fprintf(stderr, "out of memory\n");
				exit (1);
			}
		}
		if (read_symbol(in, &table[table_cnt]) == 0) {
			table[table_cnt].start_pos = table_cnt;
			table_cnt++;
		}
	}
}

static void output_label(char *label)
{
	printf(".globl %s\n", label);
	printf("\tALGN\n");
	printf("%s:\n", label);
}

/* uncompress a compressed symbol. When this function is called, the best table
 * might still be compressed itself, so the function needs to be recursive */
static int expand_symbol(unsigned char *data, int len, char *result)
{
	int c, rlen, total=0;

	while (len) {
		c = *data;
		/* if the table holds a single char that is the same as the one
		 * we are looking for, then end the search */
		if (best_table[c][0]==c && best_table_len[c]==1) {
			*result++ = c;
			total++;
		} else {
			/* if not, recurse and expand */
			rlen = expand_symbol(best_table[c], best_table_len[c], result);
			total += rlen;
			result += rlen;
		}
		data++;
		len--;
	}
	*result=0;

	return total;
}

static int symbol_absolute(struct sym_entry *s)
{
	return s->percpu_absolute;
}

static void write_src(void)
{
	unsigned int i, k, off;
	unsigned int best_idx[256];
	unsigned int *markers;
	char buf[KSYM_NAME_LEN];

	printf("#include <asm/bitsperlong.h>\n");
	printf("#if BITS_PER_LONG == 64\n");
	printf("#define PTR .quad\n");
	printf("#define ALGN .balign 8\n");
	printf("#else\n");
	printf("#define PTR .long\n");
	printf("#define ALGN .balign 4\n");
	printf("#endif\n");

	printf("\t.section .rodata, \"a\"\n");

	/* Provide proper symbols relocatability by their relativeness
	 * to a fixed anchor point in the runtime image, either '_text'
	 * for absolute address tables, in which case the linker will
	 * emit the final addresses at build time. Otherwise, use the
	 * offset relative to the lowest value encountered of all relative
	 * symbols, and emit non-relocatable fixed offsets that will be fixed
	 * up at runtime.
	 *
	 * The symbol names cannot be used to construct normal symbol
	 * references as the list of symbols contains symbols that are
	 * declared static and are private to their .o files.  This prevents
	 * .tmp_kallsyms.o or any other object from referencing them.
	 */
	if (!base_relative)
		output_label("kallsyms_addresses");
	else
		output_label("kallsyms_offsets");

	for (i = 0; i < table_cnt; i++) {
		if (base_relative) {
			long long offset;
			int overflow;

			if (!absolute_percpu) {
				offset = table[i].addr - relative_base;
				overflow = (offset < 0 || offset > UINT_MAX);
			} else if (symbol_absolute(&table[i])) {
				offset = table[i].addr;
				overflow = (offset < 0 || offset > INT_MAX);
			} else {
				offset = relative_base - table[i].addr - 1;
				overflow = (offset < INT_MIN || offset >= 0);
			}
			if (overflow) {
				fprintf(stderr, "kallsyms failure: "
					"%s symbol value %#llx out of range in relative mode\n",
					symbol_absolute(&table[i]) ? "absolute" : "relative",
					table[i].addr);
				exit(EXIT_FAILURE);
			}
			printf("\t.long\t%#x\n", (int)offset);
		} else if (!symbol_absolute(&table[i])) {
			if (_text <= table[i].addr)
				printf("\tPTR\t_text + %#llx\n",
					table[i].addr - _text);
			else
				printf("\tPTR\t_text - %#llx\n",
					_text - table[i].addr);
		} else {
			printf("\tPTR\t%#llx\n", table[i].addr);
		}
	}
	printf("\n");

	if (base_relative) {
		output_label("kallsyms_relative_base");
		printf("\tPTR\t_text - %#llx\n", _text - relative_base);
		printf("\n");
	}

	output_label("kallsyms_sizes");
	for (i = 0; i < table_cnt; i++)
		printf("\tPTR\t%#llx\n", table[i].size);
	printf("\n");

	output_label("kallsyms_num_syms");
	printf("\t.long\t%u\n", table_cnt);
	printf("\n");

	/* table of offset markers, that give the offset in the compressed stream
	 * every 256 symbols */
	markers = malloc(sizeof(unsigned int) * ((table_cnt + 255) / 256));
	if (!markers) {
		fprintf(stderr, "kallsyms failure: "
			"unable to allocate required memory\n");
		exit(EXIT_FAILURE);
	}

	output_label("kallsyms_names");
	off = 0;
	for (i = 0; i < table_cnt; i++) {
		if ((i & 0xFF) == 0)
			markers[i >> 8] = off;

		printf("\t.byte 0x%02x", table[i].len);
		for (k = 0; k < table[i].len; k++)
			printf(", 0x%02x", table[i].sym[k]);
		printf("\n");

		off += table[i].len + 1;
	}
	printf("\n");

	output_label("kallsyms_markers");
	for (i = 0; i < ((table_cnt + 255) >> 8); i++)
		printf("\t.long\t%u\n", markers[i]);
	printf("\n");

	free(markers);

	output_label("kallsyms_token_table");
	off = 0;
	for (i = 0; i < 256; i++) {
		best_idx[i] = off;
		expand_symbol(best_table[i], best_table_len[i], buf);
		printf("\t.asciz\t\"%s\"\n", buf);
		off += strlen(buf) + 1;
	}
	printf("\n");

	output_label("kallsyms_token_index");
	for (i = 0; i < 256; i++)
		printf("\t.short\t%d\n", best_idx[i]);
	printf("\n");

#ifdef CONFIG_KALLMODSYMS
	output_label("kallsyms_modules");
	for (i = 0; i < builtin_module_len; i++)
		printf("\t.asciz\t\"%s\"\n", builtin_modules[i]);
	printf("\n");

	for (i = 0; i < builtin_module_len; i++)
		free(builtin_modules[i]);

	output_label("kallsyms_symbol_modules");
	for (i = 0; i < table_cnt; i++)
		printf("\t.int\t%d\n", table[i].module);
	printf("\n");
#endif
}

/* table lookup compression functions */

/* count all the possible tokens in a symbol */
static void learn_symbol(unsigned char *symbol, int len)
{
	int i;

	for (i = 0; i < len - 1; i++)
		token_profit[ symbol[i] + (symbol[i + 1] << 8) ]++;
}

/* decrease the count for all the possible tokens in a symbol */
static void forget_symbol(unsigned char *symbol, int len)
{
	int i;

	for (i = 0; i < len - 1; i++)
		token_profit[ symbol[i] + (symbol[i + 1] << 8) ]--;
}

/* remove all the invalid symbols from the table and do the initial token count */
static void build_initial_tok_table(void)
{
	unsigned int i, pos;

	pos = 0;
	for (i = 0; i < table_cnt; i++) {
		if ( symbol_valid(&table[i]) ) {
			if (pos != i)
				table[pos] = table[i];
			learn_symbol(table[pos].sym, table[pos].len);
			pos++;
		}
	}
	table_cnt = pos;
}

static void *find_token(unsigned char *str, int len, unsigned char *token)
{
	int i;

	for (i = 0; i < len - 1; i++) {
		if (str[i] == token[0] && str[i+1] == token[1])
			return &str[i];
	}
	return NULL;
}

/* replace a given token in all the valid symbols. Use the sampled symbols
 * to update the counts */
static void compress_symbols(unsigned char *str, int idx)
{
	unsigned int i, len, size;
	unsigned char *p1, *p2;

	for (i = 0; i < table_cnt; i++) {

		len = table[i].len;
		p1 = table[i].sym;

		/* find the token on the symbol */
		p2 = find_token(p1, len, str);
		if (!p2) continue;

		/* decrease the counts for this symbol's tokens */
		forget_symbol(table[i].sym, len);

		size = len;

		do {
			*p2 = idx;
			p2++;
			size -= (p2 - p1);
			memmove(p2, p2 + 1, size);
			p1 = p2;
			len--;

			if (size < 2) break;

			/* find the token on the symbol */
			p2 = find_token(p1, size, str);

		} while (p2);

		table[i].len = len;

		/* increase the counts for this symbol's new tokens */
		learn_symbol(table[i].sym, len);
	}
}

/* search the token with the maximum profit */
static int find_best_token(void)
{
	int i, best, bestprofit;

	bestprofit=-10000;
	best = 0;

	for (i = 0; i < 0x10000; i++) {
		if (token_profit[i] > bestprofit) {
			best = i;
			bestprofit = token_profit[i];
		}
	}
	return best;
}

/* this is the core of the algorithm: calculate the "best" table */
static void optimize_result(void)
{
	int i, best;

	/* using the '\0' symbol last allows compress_symbols to use standard
	 * fast string functions */
	for (i = 255; i >= 0; i--) {

		/* if this table slot is empty (it is not used by an actual
		 * original char code */
		if (!best_table_len[i]) {

			/* find the token with the best profit value */
			best = find_best_token();
			if (token_profit[best] == 0)
				break;

			/* place it in the "best" table */
			best_table_len[i] = 2;
			best_table[i][0] = best & 0xFF;
			best_table[i][1] = (best >> 8) & 0xFF;

			/* replace this token in all the valid symbols */
			compress_symbols(best_table[i], i);
		}
	}
}

/* start by placing the symbols that are actually used on the table */
static void insert_real_symbols_in_table(void)
{
	unsigned int i, j, c;

	for (i = 0; i < table_cnt; i++) {
		for (j = 0; j < table[i].len; j++) {
			c = table[i].sym[j];
			best_table[c][0]=c;
			best_table_len[c]=1;
		}
	}
}

static void optimize_token_table(void)
{
	build_initial_tok_table();

	insert_real_symbols_in_table();

	/* When valid symbol is not registered, exit to error */
	if (!table_cnt) {
		fprintf(stderr, "No valid symbol.\n");
		exit(1);
	}

	optimize_result();
}

/* guess for "linker script provide" symbol */
static int may_be_linker_script_provide_symbol(const struct sym_entry *se)
{
	const char *symbol = (char *)se->sym + 1;
	int len = se->len - 1;

	if (len < 8)
		return 0;

	if (symbol[0] != '_' || symbol[1] != '_')
		return 0;

	/* __start_XXXXX */
	if (!memcmp(symbol + 2, "start_", 6))
		return 1;

	/* __stop_XXXXX */
	if (!memcmp(symbol + 2, "stop_", 5))
		return 1;

	/* __end_XXXXX */
	if (!memcmp(symbol + 2, "end_", 4))
		return 1;

	/* __XXXXX_start */
	if (!memcmp(symbol + len - 6, "_start", 6))
		return 1;

	/* __XXXXX_end */
	if (!memcmp(symbol + len - 4, "_end", 4))
		return 1;

	return 0;
}

static int prefix_underscores_count(const char *str)
{
	const char *tail = str;

	while (*tail == '_')
		tail++;

	return tail - str;
}

static int compare_symbols(const void *a, const void *b)
{
	const struct sym_entry *sa;
	const struct sym_entry *sb;
	int wa, wb;

	sa = a;
	sb = b;

	/* sort by address first */
	if (sa->addr > sb->addr)
		return 1;
	if (sa->addr < sb->addr)
		return -1;

	/* zero-size markers before nonzero-size symbols */
	if (sa->size > 0 && sb->size == 0)
		return 1;
	if (sa->size == 0 && sb->size > 0)
		return -1;

	/* sort by size (large size preceding symbols it encompasses) */
	if (sa->size < sb->size)
		return 1;
	if (sa->size > sb->size)
		return -1;

	/* sort by "weakness" type */
	wa = (sa->sym[0] == 'w') || (sa->sym[0] == 'W');
	wb = (sb->sym[0] == 'w') || (sb->sym[0] == 'W');
	if (wa != wb)
		return wa - wb;

	/* sort by "linker script provide" type */
	wa = may_be_linker_script_provide_symbol(sa);
	wb = may_be_linker_script_provide_symbol(sb);
	if (wa != wb)
		return wa - wb;

	/* sort by the number of prefix underscores */
	wa = prefix_underscores_count((const char *)sa->sym + 1);
	wb = prefix_underscores_count((const char *)sb->sym + 1);
	if (wa != wb)
		return wa - wb;

	/* sort by initial order, so that other symbols are left undisturbed */
	return sa->start_pos - sb->start_pos;
}

static void sort_symbols(void)
{
	qsort(table, table_cnt, sizeof(struct sym_entry), compare_symbols);
}

static void make_percpus_absolute(void)
{
	unsigned int i;

	for (i = 0; i < table_cnt; i++)
		if (symbol_in_range(&table[i], &percpu_range, 1)) {
			/*
			 * Keep the 'A' override for percpu symbols to
			 * ensure consistent behavior compared to older
			 * versions of this tool.
			 */
			table[i].sym[0] = 'A';
			table[i].percpu_absolute = 1;
		}
}

/* find the minimum non-absolute symbol address */
static void record_relative_base(void)
{
	unsigned int i;

	relative_base = -1ULL;
	for (i = 0; i < table_cnt; i++)
		if (!symbol_absolute(&table[i]) &&
		    table[i].addr < relative_base)
			relative_base = table[i].addr;
}

#ifdef CONFIG_KALLMODSYMS
/*
 * Expand the builtin modules list.
 */
static void expand_builtin_modules(void)
{
	builtin_module_size += 50;

	builtin_modules = realloc(builtin_modules,
				  sizeof(*builtin_modules) *
				  builtin_module_size);
	builtin_module_offsets = realloc(builtin_module_offsets,
					 sizeof(*builtin_module_offsets) *
					 builtin_module_size);

	if (!builtin_modules || !builtin_module_offsets) {
		fprintf(stderr, "kallsyms failure: out of memory.\n");
		exit(EXIT_FAILURE);
	}
}

/*
 * Add a single built-in module (possibly composed of many files) to the
 * modules list.  Take the offset of the current module and return it
 * (purely for simplicity's sake in the caller).
 */
static size_t add_builtin_module(const char *module_name, char **module_paths,
				 size_t offset)
{
	/* map the module's object paths to the module offset */
	while (*module_paths) {
		obj2mod_put(*module_paths, builtin_module_len);
		module_paths++;
	}

	/* add the module name */
	if (builtin_module_size <= builtin_module_len)
		expand_builtin_modules();
	builtin_modules[builtin_module_len] = strdup(module_name);
	builtin_module_offsets[builtin_module_len] = offset;
	builtin_module_len++;

	return (offset + strlen(module_name) + 1);
}

/*
 * Read the linker map.
 */
static void read_linker_map(void)
{
	unsigned long long addr, size;
	char obj[PATH_MAX+1];
	FILE *f = fopen(".tmp_vmlinux.ranges", "r");

	if (!f) {
		fprintf(stderr, "Cannot open '.tmp_vmlinux.ranges'.\n");
		exit(1);
	}

	addrmap_num = 0;
	addrmap_alloced = 4096;
	addrmap = malloc(sizeof(*addrmap) * addrmap_alloced);
	if (!addrmap)
		goto oom;

	/*
	 * For each address range (addr,size) and object, add to addrmap
	 * the range and the built-in module to which the object maps.
	 */
	while (fscanf(f, "%llx %llx %s\n", &addr, &size, obj) == 3) {
		int m = obj2mod_get(obj);

		if (addr == 0 || size == 0 || m == 0)
			continue;

		if (addrmap_num >= addrmap_alloced) {
			addrmap_alloced *= 2;
			addrmap = realloc(addrmap,
			    sizeof(*addrmap) * addrmap_alloced);
			if (!addrmap)
				goto oom;
		}

		addrmap[addrmap_num].addr = addr;
		addrmap[addrmap_num].size = size;
		addrmap[addrmap_num].module = m;
		addrmap_num++;
	}
	fclose(f);
	return;

oom:
	fprintf(stderr, "kallsyms: out of memory\n");
	exit(1);
}

/*
 * Read "modules_thick.builtin" (the list of built-in modules).  Construct:
 *   - builtin_modules: array of built-in-module names
 *   - builtin_module_offsets: array of offsets that will later be
 *       used to access a concatenated list of built-in-module names
 *   - obj2mod: a temporary, many-to-one, hash mapping
 *       from object-file paths to built-in-module names
 * Read ".tmp_vmlinux.ranges" (the linker map).
 *   - addrmap[] maps address ranges to built-in module names (using obj2mod)
 */
static void read_modules(const char *modules_builtin)
{
	struct modules_thick_iter *i;
	size_t offset = 0;
	char *module_name = NULL;
	char **module_paths;

	obj2mod_init();

	/*
	 * builtin_modules[0] is a null entry signifying a symbol that cannot be
	 * modular.
	 */
	builtin_module_size = 50;
	builtin_modules = malloc(sizeof(*builtin_modules) *
				 builtin_module_size);
	builtin_module_offsets = malloc(sizeof(*builtin_module_offsets) *
				 builtin_module_size);
	if (!builtin_modules || !builtin_module_offsets) {
		fprintf(stderr, "kallsyms: out of memory\n");
		exit(1);
	}
	builtin_modules[0] = strdup("");
	builtin_module_offsets[0] = 0;
	builtin_module_len = 1;
	offset++;

	/*
	 * Iterate over all modules in modules_thick.builtin and add each.
	 */
	i = modules_thick_iter_new(modules_builtin);
	if (i == NULL) {
		fprintf(stderr, "Cannot iterate over builtin modules.\n");
		exit(1);
	}

	while ((module_paths = modules_thick_iter_next(i, &module_name))) {
		offset = add_builtin_module(module_name, module_paths, offset);
		free(module_paths);
		module_paths = NULL;
	}

	free(module_name);
	modules_thick_iter_free(i);

	/*
	 * Read linker map.
	 */
	read_linker_map();

	obj2mod_free();
}
#else
static void read_modules(const char *unused) {}
#endif /* CONFIG_KALLMODSYMS */

int main(int argc, char **argv)
{
	const char *modules_builtin = "modules_thick.builtin";

	if (argc >= 2) {
		int i;
		for (i = 1; i < argc; i++) {
			if (strcmp(argv[i], "--all-symbols") == 0)
				all_symbols = 1;
			else if (strcmp(argv[i], "--absolute-percpu") == 0)
				absolute_percpu = 1;
			else if (strcmp(argv[i], "--base-relative") == 0)
				base_relative = 1;
			else if (strncmp(argv[i], "--builtin=", 10) == 0)
				modules_builtin = &argv[i][10];
			else
				usage();
		}
	} else if (argc != 1)
		usage();

	read_modules(modules_builtin);
	read_map(stdin);
	if (absolute_percpu)
		make_percpus_absolute();
	if (base_relative)
		record_relative_base();
	sort_symbols();
	optimize_token_table();
	write_src();

	return 0;
}
