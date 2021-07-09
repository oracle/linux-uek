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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <assert.h>
#include "modules_thick.h"

#include "../include/generated/autoconf.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define KSYM_NAME_LEN		128

struct sym_entry {
	unsigned long long addr;
	unsigned long long size;
	unsigned int len;
	unsigned int start_pos;
	unsigned int percpu_absolute;
	unsigned char sym[];
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

static struct sym_entry **table;
static unsigned int table_size, table_cnt;
static int all_symbols;
static int absolute_percpu;
static int base_relative;

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

static unsigned int memhash(char *s, size_t len)
{
	/* fnv32 hash */
	unsigned int hash = 2166136261U;
	size_t i;

	for (i = 0; i < len; i++)
		hash = (hash ^ *(s + i)) * 0x01000193;
	return hash;
}

#define OBJ2MOD_BITS 10
#define OBJ2MOD_N (1 << OBJ2MOD_BITS)
#define OBJ2MOD_MASK (OBJ2MOD_N - 1)
struct obj2mod_elem {
	char *obj;
	char *mods;			/* sorted module name strtab */
	size_t nmods;			/* number of modules in "mods" */
	size_t mods_size;		/* size of all mods together */
	int mod_offset;			/* offset in .kallsyms_module_names */
	/*
	 * If set at emission time, this points at another obj2mod entry that
	 * contains the module name we need (possibly at a slightly later
	 * offset, if the entry is for an objfile that appears in many modules).
	 */
	struct obj2mod_elem *xref;
	struct obj2mod_elem *obj2mod_next;
	struct obj2mod_elem *mod2obj_next;
};

/*
 * Map from object files to obj2mod entries (a unique mapping), and vice versa
 * (not unique, but entries for objfiles in more than one module in this hash
 * are ignored).
 */

static struct obj2mod_elem *obj2mod[OBJ2MOD_N];
static struct obj2mod_elem *mod2obj[OBJ2MOD_N];
static size_t num_objfiles;

/*
 * An ordered list of address ranges and the objfile that occupies that range.
 */
struct addrmap_entry {
	unsigned long long addr;
	struct obj2mod_elem *objfile;
};
static struct addrmap_entry *addrmap;
static int addrmap_num, addrmap_alloced;

static void obj2mod_init(void)
{
	memset(obj2mod, 0, sizeof(obj2mod));
}

static struct obj2mod_elem *obj2mod_get(const char *obj)
{
	int i = strhash(obj) & OBJ2MOD_MASK;
	struct obj2mod_elem *elem;

	for (elem = obj2mod[i]; elem; elem = elem->obj2mod_next) {
		if (strcmp(elem->obj, obj) == 0)
			return elem;
	}
	return NULL;
}

/*
 * Note that a given object file is found in some module, interning it in the
 * obj2mod hash.  Should not be called more than once for any given (module,
 * object) pair.
 */
static void obj2mod_add(char *obj, char *mod)
{
	int i = strhash(obj) & OBJ2MOD_MASK;
	struct obj2mod_elem *elem;

	elem = obj2mod_get(obj);
	if (!elem) {
		int j = strhash(mod) & OBJ2MOD_MASK;

		elem = malloc(sizeof(struct obj2mod_elem));
		if (!elem)
			goto oom;
		memset(elem, 0, sizeof(struct obj2mod_elem));
		elem->obj = strdup(obj);
		if (!elem->obj)
			goto oom;
		elem->mods = strdup(mod);
		if (!elem->mods)
			goto oom;

		elem->obj2mod_next = obj2mod[i];
		obj2mod[i] = elem;
		elem->mod2obj_next = mod2obj[j];
		mod2obj[j] = elem;
		num_objfiles++;
	} else {
		/*
		 * TU appears in multiple modules.  mod2obj for this entry will
		 * be ignored from now on, except insofar as it is needed to
		 * maintain the hash chain.
		 */
		elem->mods = realloc(elem->mods, elem->mods_size +
				     strlen(mod) + 1);
		if (!elem->mods)
			goto oom;
		strcpy(elem->mods + elem->mods_size, mod);
	}

	elem->mods_size += strlen(mod) + 1;
	elem->nmods++;
	if (elem->nmods > 255) {
		fprintf(stderr, "kallsyms: %s: too many modules associated with this object file\n",
			obj);
		exit(EXIT_FAILURE);
	}
	return;
oom:
	fprintf(stderr, "kallsyms: out of memory\n");
	exit(1);
}

/*
 * Used inside optimize_obj2mod to identify duplicate module entries.
 */
struct obj2mod_modhash_elem {
	struct obj2mod_elem *elem;
	unsigned int modhash;		/* hash value of this entry */
};

static int qstrcmp(const void *a, const void *b)
{
	return strcmp((const char *) a, (const char *) b);
}

static int qmodhash(const void *a, const void *b)
{
	const struct obj2mod_modhash_elem *el_a = a;
	const struct obj2mod_modhash_elem *el_b = b;
	if (el_a->modhash < el_b->modhash)
		return -1;
	else if (el_a->modhash > el_b->modhash)
		return 1;
	return 0;
}

/*
 * Associate all TUs in obj2mod which refer to the same module with a single
 * obj2mod entry for emission, preferring to point into the module list in a
 * multi-module objfile.
 */
static void optimize_obj2mod(void)
{
	size_t i;
	size_t n = 0;
	struct obj2mod_elem *elem;
	struct obj2mod_elem *dedup;
	/* An array of all obj2mod_elems, later sorted by hashval.  */
	struct obj2mod_modhash_elem *uniq;
	struct obj2mod_modhash_elem *last;

	/*
	 * Canonicalize all module lists by sorting them, then compute their
	 * hash values.
	 */
	uniq = malloc(sizeof(struct obj2mod_modhash_elem) * num_objfiles);
	if (uniq == NULL)
		goto oom;

	for (i = 0; i < OBJ2MOD_N; i++) {
		for (elem = obj2mod[i]; elem; elem = elem->obj2mod_next) {
			if (elem->nmods >= 2) {
				char **sorter;
				char *walk;
				char *tmp_mods;
				size_t j;

				tmp_mods = malloc(elem->mods_size);
				sorter = malloc(sizeof(char *) * elem->nmods);
				if (sorter == NULL || tmp_mods == NULL)
					goto oom;
				memcpy(tmp_mods, elem->mods, elem->mods_size);

				for (j = 0, walk = tmp_mods; j < elem->nmods;
				     j++) {
					sorter[j] = walk;
					walk += strlen(walk) + 1;
				}
				qsort(sorter, elem->nmods, sizeof (char *),
				      qstrcmp);
				for (j = 0, walk = elem->mods; j < elem->nmods;
				     j++) {
					strcpy(walk, sorter[j]);
					walk += strlen(walk) + 1;
				}
				free(tmp_mods);
				free(sorter);
			}

			uniq[n].elem = elem;
			uniq[n].modhash = memhash(elem->mods, elem->mods_size);
			n++;
		}
	}

	qsort (uniq, num_objfiles, sizeof (struct obj2mod_modhash_elem),
	       qmodhash);

	/*
	 * Work over multimodule entries.  These must be emitted into
	 * .kallsyms_module_names as a unit, but we can still optimize by
	 * reusing some other identical entry.  Single-file modules are amenable
	 * to the same optimization, but we avoid doing it for now so that we
	 * can prefer to point them directly inside a multimodule entry.
	 */
	for (i = 0, last = NULL; i < num_objfiles; i++) {
		const char *onemod;
		size_t j;

		if (uniq[i].elem->nmods < 2)
			continue;

		/* Duplicate multimodule.  Reuse the first we saw.  */
		if (last != NULL && last->modhash == uniq[i].modhash) {
			uniq[i].elem->xref = last->elem;
			continue;
		}

		/*
		 * Single-module entries relating to modules also emitted as
		 * part of this multimodule entry can refer to it: later, we
		 * will hunt down the right specific module name within this
		 * multimodule entry and point directly to it.
		 */
		onemod = uniq[i].elem->mods;
		for (j = uniq[i].elem->nmods; j > 0; j--) {
			int h = strhash(onemod) & OBJ2MOD_MASK;

			for (dedup = mod2obj[h]; dedup;
			     dedup = dedup->mod2obj_next) {
				if (dedup->nmods > 1)
					continue;

				if (strcmp(dedup->mods, onemod) != 0)
					continue;
				dedup->xref = uniq[i].elem;
				assert (uniq[i].elem->xref == NULL);
			}
			onemod += strlen(onemod) + 1;
		}

		last = &uniq[i];
	}

	/*
	 * Now traverse all single-module entries, xreffing every one that
	 * relates to a given module to the first one we saw that refers to that
	 * module.
	 */
	for (i = 0, last = NULL; i < num_objfiles; i++) {
		if (uniq[i].elem->nmods > 1)
			continue;

		if (uniq[i].elem->xref != NULL)
			continue;

		/* Duplicate module name.  Reuse the first we saw.  */
		if (last != NULL && last->modhash == uniq[i].modhash) {
			uniq[i].elem->xref = last->elem;
			assert (last->elem->xref == NULL);
			continue;
		}
		last = &uniq[i];
	}
	return;
oom:
	fprintf(stderr, "kallsyms: out of memory optimizing module list\n");
	exit(EXIT_FAILURE);
}
#endif /* CONFIG_KALLMODSYMS */

static void usage(void)
{
	fprintf(stderr, "Usage: kallsyms [--all-symbols] [--absolute-percpu] "
			"[--base-relative] [--builtin=modules_thick.builtin] "
			"< nm_vmlinux.out > symbols.S\n");
	exit(1);
}

static char *sym_name(const struct sym_entry *s)
{
	return (char *)s->sym + 1;
}

static bool is_ignored_symbol(const char *name, char type)
{
	/* Symbol names that exactly match to the following are ignored.*/
	static const char * const ignored_symbols[] = {
		/*
		 * Symbols which vary between passes. Passes 1 and 2 must have
		 * identical symbol lists. The kallsyms_* symbols below are
		 * only added after pass 1, they would be included in pass 2
		 * when --all-symbols is specified so exclude them to get a
		 * stable symbol list.
		 */
		"kallsyms_addresses",
		"kallsyms_offsets",
		"kallsyms_relative_base",
		"kallsyms_sizes",
		"kallsyms_num_syms",
		"kallsyms_num_modules",
		"kallsyms_names",
		"kallsyms_markers",
		"kallsyms_token_table",
		"kallsyms_token_index",
		"kallsyms_module_offsets",
		"kallsyms_module_addresses",
		"kallsyms_modules",
		"kallsyms_module_names",
		"kallsyms_module_names_len",
		/* Exclude linker generated symbols which vary between passes */
		"_SDA_BASE_",		/* ppc */
		"_SDA2_BASE_",		/* ppc */
		NULL
	};

	/* Symbol names that begin with the following are ignored.*/
	static const char * const ignored_prefixes[] = {
		"$",			/* local symbols for ARM, MIPS, etc. */
		".LASANPC",		/* s390 kasan local symbols */
		"__crc_",		/* modversions */
		"__efistub_",		/* arm64 EFI stub namespace */
		"__kvm_nvhe_",		/* arm64 non-VHE KVM namespace */
		"__AArch64ADRPThunk_",	/* arm64 lld */
		"__ARMV5PILongThunk_",	/* arm lld */
		"__ARMV7PILongThunk_",
		"__ThumbV7PILongThunk_",
		"__LA25Thunk_",		/* mips lld */
		"__microLA25Thunk_",
		NULL
	};

	/* Symbol names that end with the following are ignored.*/
	static const char * const ignored_suffixes[] = {
		"_from_arm",		/* arm */
		"_from_thumb",		/* arm */
		"_veneer",		/* arm */
		NULL
	};

	/* Symbol names that contain the following are ignored.*/
	static const char * const ignored_matches[] = {
		".long_branch.",	/* ppc stub */
		".plt_branch.",		/* ppc stub */
		NULL
	};

	const char * const *p;

	for (p = ignored_symbols; *p; p++)
		if (!strcmp(name, *p))
			return true;

	for (p = ignored_prefixes; *p; p++)
		if (!strncmp(name, *p, strlen(*p)))
			return true;

	for (p = ignored_suffixes; *p; p++) {
		int l = strlen(name) - strlen(*p);

		if (l >= 0 && !strcmp(name + l, *p))
			return true;
	}

	for (p = ignored_matches; *p; p++) {
		if (strstr(name, *p))
			return true;
	}

	if (type == 'U' || type == 'u')
		return true;
	/* exclude debugging symbols */
	if (type == 'N' || type == 'n')
		return true;

	if (toupper(type) == 'A') {
		/* Keep these useful absolute symbols */
		if (strcmp(name, "__kernel_syscall_via_break") &&
		    strcmp(name, "__kernel_syscall_via_epc") &&
		    strcmp(name, "__kernel_sigtramp") &&
		    strcmp(name, "__gp"))
			return true;
	}

	return false;
}

static void check_symbol_range(const char *sym, unsigned long long addr,
			       struct addr_range *ranges, int entries)
{
	size_t i;
	struct addr_range *ar;

	for (i = 0; i < entries; ++i) {
		ar = &ranges[i];

		if (strcmp(sym, ar->start_sym) == 0) {
			ar->start = addr;
			return;
		} else if (strcmp(sym, ar->end_sym) == 0) {
			ar->end = addr;
			return;
		}
	}
}

static struct sym_entry *read_symbol(FILE *in)
{
	char name[500], type;
	unsigned long long addr;
	unsigned int len;
	struct sym_entry *sym;
	int rc = 0;
	unsigned long long size;

	rc = fscanf(in, "%llx %llx %c %499s\n", &addr, &size, &type, name);
	if (rc != 4) {
		if (rc != EOF && fgets(name, 500, in) == NULL)
			fprintf(stderr, "Read error or end of file.\n");
		return NULL;
	}
	if (strlen(name) >= KSYM_NAME_LEN) {
		fprintf(stderr, "Symbol %s too long for kallsyms (%zu >= %d).\n"
				"Please increase KSYM_NAME_LEN both in kernel and kallsyms.c\n",
			name, strlen(name), KSYM_NAME_LEN);
		return NULL;
	}

	if (strcmp(name, "_text") == 0)
		_text = addr;

	/* Ignore most absolute/undefined (?) symbols. */
	if (is_ignored_symbol(name, type))
		return NULL;

	check_symbol_range(name, addr, text_ranges, ARRAY_SIZE(text_ranges));
	check_symbol_range(name, addr, &percpu_range, 1);

	/* include the type field in the symbol name, so that it gets
	 * compressed together */

	len = strlen(name) + 1;

	sym = malloc(sizeof(*sym) + len + 1);
	if (!sym) {
		fprintf(stderr, "kallsyms failure: "
			"unable to allocate required amount of memory\n");
		exit(EXIT_FAILURE);
	}
	sym->addr = addr;
	sym->len = len;
	sym->sym[0] = type;
	strcpy(sym_name(sym), name);
	sym->percpu_absolute = 0;
	sym->size = size;

	return sym;
}

static int addr_in_range(unsigned long long addr,
			 const struct addr_range *ranges, int entries)
{
	size_t i;
	const struct addr_range *ar;

	for (i = 0; i < entries; ++i) {
		ar = &ranges[i];

		if (addr >= ar->start && addr <= ar->end)
			return 1;
	}

	return 0;
}

static int symbol_valid(const struct sym_entry *s)
{
	const char *name = sym_name(s);

	/* if --all-symbols is not specified, then symbols outside the text
	 * and inittext sections are discarded */
	if (!all_symbols) {
		if (addr_in_range(s->addr, text_ranges,
				  ARRAY_SIZE(text_ranges)) == 0)
			return 0;
		/* Corner case.  Discard any symbols with the same value as
		 * _etext _einittext; they can move between pass 1 and 2 when
		 * the kallsyms data are added.  If these symbols move then
		 * they may get dropped in pass 2, which breaks the kallsyms
		 * rules.
		 */
		if ((s->addr == text_range_text->end &&
		     strcmp(name, text_range_text->end_sym)) ||
		    (s->addr == text_range_inittext->end &&
		     strcmp(name, text_range_inittext->end_sym)))
			return 0;
	}

	return 1;
}

/* remove all the invalid symbols from the table */
static void shrink_table(void)
{
	unsigned int i, pos;

	pos = 0;
	for (i = 0; i < table_cnt; i++) {
		if (symbol_valid(table[i])) {
			if (pos != i)
				table[pos] = table[i];
			pos++;
		} else {
			free(table[i]);
		}
	}
	table_cnt = pos;

	/* When valid symbol is not registered, exit to error */
	if (!table_cnt) {
		fprintf(stderr, "No valid symbol.\n");
		exit(1);
	}
}

static void read_map(FILE *in)
{
	struct sym_entry *sym;

	while (!feof(in)) {
		sym = read_symbol(in);
		if (!sym)
			continue;

		sym->start_pos = table_cnt;

		if (table_cnt >= table_size) {
			table_size += 10000;
			table = realloc(table, sizeof(*table) * table_size);
			if (!table) {
				fprintf(stderr, "out of memory\n");
				exit (1);
			}
		}

		table[table_cnt++] = sym;
	}
}

static void output_label(const char *label)
{
	printf(".globl %s\n", label);
	printf("\tALGN\n");
	printf("%s:\n", label);
}

/* Provide proper symbols relocatability by their '_text' relativeness. */
static void output_address(unsigned long long addr)
{
	if (_text <= addr)
		printf("\tPTR\t_text + %#llx\n", addr - _text);
	else
		printf("\tPTR\t_text - %#llx\n", _text - addr);
}

#ifdef CONFIG_KALLMODSYMS
/* Output the .kallmodsyms_modules symbol content. */
static void output_kallmodsyms_modules(void)
{
	struct obj2mod_elem *elem;
	size_t offset = 1;
	size_t i;

	/*
	 * Traverse and emit, chasing xref and updating mod_offset accordingly.
	 * Emit a single \0 at the start, to encode non-modular objfiles.
	 */
	output_label("kallsyms_module_names");
	printf("\t.byte\t0\n");
	for (i = 0; i < OBJ2MOD_N; i++) {
		for (elem = obj2mod[i]; elem;
		     elem = elem->obj2mod_next) {
			const char *onemod;
			size_t i;
			struct obj2mod_elem *out_elem = elem;

			if (elem->xref)
				out_elem = elem->xref;
			if (out_elem->mod_offset != 0)
				continue;	/* Already emitted.  */

			out_elem->mod_offset = offset;
			onemod = out_elem->mods;

			/*
			 * Technically this is a waste of space: we could just
			 * as well implement multimodule entries by pointing one
			 * byte further back, to the trailing \0 of the previous
			 * entry, but doing it this way makes it more obvious
			 * when an entry is a multimodule entry.
			 */
			if (out_elem->nmods != 1) {
				printf("\t.byte\t0\n");
				printf("\t.byte\t%zi\n", out_elem->nmods);
				offset += 2;
			}

			for (i = out_elem->nmods; i > 0; i--) {
				printf("\t.asciz\t\"%s\"\n", onemod);
				offset += strlen(onemod) + 1;
				onemod += strlen(onemod) + 1;
			}
		}
	}
	printf("\n");
	output_label("kallsyms_module_names_len");
	printf("\t.long\t%zi\n", offset);
}

static void output_kallmodsyms_objfiles(void)
{
	size_t i = 0;
	size_t emitted_offsets = 0;
	size_t emitted_objfiles = 0;

	if (base_relative)
		output_label("kallsyms_module_offsets");
	else
		output_label("kallsyms_module_addresses");

	for (i = 0; i < addrmap_num; i++) {
		long long offset;
		int overflow;

                /*
                 * Fuse consecutive address ranges citing the same object file
                 * into one.
                 */
                if (i > 0 && addrmap[i-1].objfile == addrmap[i].objfile)
                        continue;

		if (base_relative) {
			if (!absolute_percpu) {
				offset = addrmap[i].addr - relative_base;
				overflow = (offset < 0 || offset > UINT_MAX);
			} else {
				offset = relative_base - addrmap[i].addr - 1;
				overflow = (offset < INT_MIN || offset >= 0);
			}
			if (overflow) {
				fprintf(stderr, "kallsyms failure: "
					"objfile %s at address %#llx out of range in relative mode\n",
					addrmap[i].objfile ? addrmap[i].objfile->obj :
					"in always-built-in object", table[i]->addr);
				exit(EXIT_FAILURE);
			}
			printf("\t.long\t0x%x\n", (int)offset);
		} else
			printf("\tPTR\t%#llx\n", addrmap[i].addr);
		emitted_offsets++;
	}

	output_label("kallsyms_modules");

	for (i = 0; i < addrmap_num; i++) {
		struct obj2mod_elem *elem = addrmap[i].objfile;
		int orig_nmods;
		const char *orig_modname;
		int mod_offset;

		if (i > 0 && addrmap[i-1].objfile == addrmap[i].objfile)
			continue;

		/*
		 * Address range cites no object file: point at 0, the built-in
		 * module.
		 */
		if (addrmap[i].objfile == NULL) {
			printf("\t.long\t0x0\n");
			emitted_objfiles++;
			continue;
		}

		orig_nmods = elem->nmods;
		orig_modname = elem->mods;

		/*
		 * Chase down xrefs, if need be.  There can only be one layer of
		 * these: from single-module entry to other single-module entry,
		 * or from single- or multi-module entry to another multi-module
		 * entry.  Single -> single and multi -> multi always points at
		 * the start of the xref target, so its offset can be used as is.
		 */
		if (elem->xref)
			elem = elem->xref;

		if (elem->nmods == 1 || orig_nmods > 1)
			mod_offset = elem->mod_offset;
		else {
			/*
			 * If this is a reference from a single-module entry to
			 * a multi-module entry, hunt down the offset to this
			 * specific module's name (which is guaranteed to be
			 * present: see optimize_obj2mod).
			 */

			size_t j = elem->nmods;
			const char *onemod = elem->mods;
			mod_offset = elem->mod_offset;

			for (; j > 0; j--) {
				if (strcmp(orig_modname, onemod) == 0)
					break;
				onemod += strlen(onemod) + 1;
			}
			assert (j > 0);
			/*
			 * +2 to skip the null byte and count at the start of
			 * the multimodule entry.
			 */
			mod_offset += onemod - elem->mods + 2;
		}

		/*
		 * Zero offset is the initial \0, there to catch uninitialized
		 * obj2mod entries, and is forbidden.
		 */
		assert (mod_offset != 0);

		printf("\t.long\t0x%x\n", mod_offset);
		emitted_objfiles++;
	}

	assert (emitted_offsets == emitted_objfiles);
	output_label("kallsyms_num_modules");
	printf("\t.long\t%zi\n", emitted_objfiles);
	printf("\n");
}
#endif /* CONFIG_KALLMODSYMS */

/* uncompress a compressed symbol. When this function is called, the best table
 * might still be compressed itself, so the function needs to be recursive */
static int expand_symbol(const unsigned char *data, int len, char *result)
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

static int symbol_absolute(const struct sym_entry *s)
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

	if (!base_relative)
		output_label("kallsyms_addresses");
	else
		output_label("kallsyms_offsets");

	for (i = 0; i < table_cnt; i++) {
		if (base_relative) {
			/*
			 * Use the offset relative to the lowest value
			 * encountered of all relative symbols, and emit
			 * non-relocatable fixed offsets that will be fixed
			 * up at runtime.
			 */

			long long offset;
			int overflow;

			if (!absolute_percpu) {
				offset = table[i]->addr - relative_base;
				overflow = (offset < 0 || offset > UINT_MAX);
			} else if (symbol_absolute(table[i])) {
				offset = table[i]->addr;
				overflow = (offset < 0 || offset > INT_MAX);
			} else {
				offset = relative_base - table[i]->addr - 1;
				overflow = (offset < INT_MIN || offset >= 0);
			}
			if (overflow) {
				fprintf(stderr, "kallsyms failure: "
					"%s symbol value %#llx out of range in relative mode\n",
					symbol_absolute(table[i]) ? "absolute" : "relative",
					table[i]->addr);
				exit(EXIT_FAILURE);
			}
			printf("\t.long\t%#x\n", (int)offset);
		} else if (!symbol_absolute(table[i])) {
			output_address(table[i]->addr);
		} else {
			printf("\tPTR\t%#llx\n", table[i]->addr);
		}
	}
	printf("\n");

	if (base_relative) {
		output_label("kallsyms_relative_base");
		output_address(relative_base);
		printf("\n");
	}

	output_label("kallsyms_sizes");
	for (i = 0; i < table_cnt; i++)
		printf("\tPTR\t%#llx\n", table[i]->size);
	printf("\n");

#ifdef CONFIG_KALLMODSYMS
	output_kallmodsyms_modules();
	output_kallmodsyms_objfiles();
#endif

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

		printf("\t.byte 0x%02x", table[i]->len);
		for (k = 0; k < table[i]->len; k++)
			printf(", 0x%02x", table[i]->sym[k]);
		printf("\n");

		off += table[i]->len + 1;
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
}


/* table lookup compression functions */

/* count all the possible tokens in a symbol */
static void learn_symbol(const unsigned char *symbol, int len)
{
	int i;

	for (i = 0; i < len - 1; i++)
		token_profit[ symbol[i] + (symbol[i + 1] << 8) ]++;
}

/* decrease the count for all the possible tokens in a symbol */
static void forget_symbol(const unsigned char *symbol, int len)
{
	int i;

	for (i = 0; i < len - 1; i++)
		token_profit[ symbol[i] + (symbol[i + 1] << 8) ]--;
}

/* do the initial token count */
static void build_initial_tok_table(void)
{
	unsigned int i;

	for (i = 0; i < table_cnt; i++)
		learn_symbol(table[i]->sym, table[i]->len);
}

static unsigned char *find_token(unsigned char *str, int len,
				 const unsigned char *token)
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
static void compress_symbols(const unsigned char *str, int idx)
{
	unsigned int i, len, size;
	unsigned char *p1, *p2;

	for (i = 0; i < table_cnt; i++) {

		len = table[i]->len;
		p1 = table[i]->sym;

		/* find the token on the symbol */
		p2 = find_token(p1, len, str);
		if (!p2) continue;

		/* decrease the counts for this symbol's tokens */
		forget_symbol(table[i]->sym, len);

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

		table[i]->len = len;

		/* increase the counts for this symbol's new tokens */
		learn_symbol(table[i]->sym, len);
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
		for (j = 0; j < table[i]->len; j++) {
			c = table[i]->sym[j];
			best_table[c][0]=c;
			best_table_len[c]=1;
		}
	}
}

static void optimize_token_table(void)
{
	build_initial_tok_table();

	insert_real_symbols_in_table();

	optimize_result();
}

/* guess for "linker script provide" symbol */
static int may_be_linker_script_provide_symbol(const struct sym_entry *se)
{
	const char *symbol = sym_name(se);
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

static int compare_symbols(const void *a, const void *b)
{
	const struct sym_entry *sa = *(const struct sym_entry **)a;
	const struct sym_entry *sb = *(const struct sym_entry **)b;
	int wa, wb;

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
	wa = strspn(sym_name(sa), "_");
	wb = strspn(sym_name(sb), "_");
	if (wa != wb)
		return wa - wb;

	/* sort by initial order, so that other symbols are left undisturbed */
	return sa->start_pos - sb->start_pos;
}

static void sort_symbols(void)
{
	qsort(table, table_cnt, sizeof(table[0]), compare_symbols);
}

static void make_percpus_absolute(void)
{
	unsigned int i;

	for (i = 0; i < table_cnt; i++)
		if (addr_in_range(table[i]->addr, &percpu_range, 1)) {
			/*
			 * Keep the 'A' override for percpu symbols to
			 * ensure consistent behavior compared to older
			 * versions of this tool.
			 */
			table[i]->sym[0] = 'A';
			table[i]->percpu_absolute = 1;
		}
}

/* find the minimum non-absolute symbol address */
static void record_relative_base(void)
{
	unsigned int i;

	for (i = 0; i < table_cnt; i++)
		if (!symbol_absolute(table[i])) {
			/*
			 * The table is sorted by address.
			 * Take the first non-absolute symbol value.
			 */
			relative_base = table[i]->addr;
			return;
		}
}

#ifdef CONFIG_KALLMODSYMS
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
	 * For each address range, add to addrmap the address and the objfile
	 * entry to which the range maps.  Only add entries relating to text
	 * ranges.  (We assume that the text ranges are tightly packed, because
	 * in any reasonable object file format they will be, so we can ignore
	 * the size.)
	 *
	 * Ranges that do not correspond to a built-in module, but to an
	 * always-built-in object file, have no obj2mod_elem and point at NULL
	 * instead.
	 */

	while (fscanf(f, "%llx %llx %s\n", &addr, &size, obj) == 3) {
		struct obj2mod_elem *elem = obj2mod_get(obj);

		if (addr == 0 || size == 0 ||
		    !addr_in_range(addr, text_ranges, ARRAY_SIZE(text_ranges)))
			continue;

		if (addrmap_num >= addrmap_alloced) {
			addrmap_alloced *= 2;
			addrmap = realloc(addrmap,
			    sizeof(*addrmap) * addrmap_alloced);
			if (!addrmap)
				goto oom;
		}

                addrmap[addrmap_num].addr = addr;
                addrmap[addrmap_num].objfile = elem;
		addrmap_num++;
	}
	fclose(f);
	return;

oom:
	fprintf(stderr, "kallsyms: out of memory\n");
	exit(1);
}

/*
 * Read "modules_thick.builtin" (the list of built-in modules).  Construct the
 * obj2mod hash to track objfile -> module mappings.  Read ".tmp_vmlinux.ranges"
 * (the linker map) and build addrmap[], which maps address ranges to built-in
 * module names (using obj2mod).
 */
static void read_modules(const char *modules_builtin)
{
	struct modules_thick_iter *i;
	char *module_name = NULL;
	char **module_paths;

	obj2mod_init();
	/*
	 * Iterate over all modules in modules_thick.builtin and add each.
	 */
	i = modules_thick_iter_new(modules_builtin);
	if (i == NULL) {
		fprintf(stderr, "Cannot iterate over builtin modules.\n");
		exit(1);
	}

	while ((module_paths = modules_thick_iter_next(i, &module_name))) {
		char **walk = module_paths;
		while (*walk) {
			obj2mod_add(*walk, module_name);
			walk++;
		}
		free(module_paths);
	}

	free(module_name);
	modules_thick_iter_free(i);
	optimize_obj2mod();

	/*
	 * Read linker map.
	 */
	read_linker_map();
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

	read_map(stdin);
	read_modules(modules_builtin);
	shrink_table();
	if (absolute_percpu)
		make_percpus_absolute();
	sort_symbols();
	if (base_relative)
		record_relative_base();
	optimize_token_table();
	write_src();

	return 0;
}
