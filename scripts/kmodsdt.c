/*
 * Copyright 2016 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "../include/generated/autoconf.h"

#define	ELF_TARGET_ALL
#include <elf.h>
#include <gelf.h>

#include <sys/types.h>

#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

typedef struct symtbl {
	struct symtbl *next;
	void *strtab;
	void *symtab;
} symtbl_t;

static int
dt_elf_symtab_lookup(Elf_Data *data_sym, int nsym, uintptr_t addr, uint32_t shn,
    GElf_Sym *sym)
{
	int i, ret = -1;
	GElf_Sym s;

	for (i = 0; i < nsym && gelf_getsym(data_sym, i, sym) != NULL; i++) {
		if (GELF_ST_TYPE(sym->st_info) == STT_FUNC &&
		    shn == sym->st_shndx &&
		    sym->st_value <= addr &&
		    addr < sym->st_value + sym->st_size) {
			if (GELF_ST_BIND(sym->st_info) == STB_GLOBAL)
				return i;

			ret = i;
			s = *sym;
		}
	}

	if (ret >= 0)
		*sym = s;
	return (ret);
}

static int
process_obj(const char *obj)
{
	static const char dt_ppref[] = "__dtrace_probe_";
	static const char dt_spref[] = "__dta_";
	int fd, i, sidx, mod = 0;
	Elf *elf = NULL;
	GElf_Ehdr ehdr;
	Elf_Scn *scn_rel, *scn_sym, *scn_str;
	Elf_Data *data_rel, *data_sym, *data_str;
	GElf_Shdr shdr_rel, shdr_sym, shdr_str;
	GElf_Sym rsym, fsym, dsym;
	GElf_Rela rela;
	char *p, *r, *f, *a;
	uint32_t eclass, emachine1, emachine2;
	size_t symsize, nsym, nstr, isym, istr, osym, len;
	symtbl_t *pair, *bufs = NULL;
	char **alttab;
	const char *elferrstr = "no error";

	if ((fd = open(obj, O_RDWR)) == -1) {
		fprintf(stderr, "failed to open %s: %s\n", obj,
			strerror(errno));
		return 1;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "ELF library version too old\n");
		return 1;
	}

	if ((elf = elf_begin(fd, ELF_C_RDWR, NULL)) == NULL) {
		fprintf(stderr, "failed to process %s: %s\n", obj,
			elf_errmsg(elf_errno()));
		return 1;
	}

	switch (elf_kind(elf)) {
	case ELF_K_ELF:
		break;
	case ELF_K_AR:
		fprintf(stderr, "archives are not permitted; %s\n", obj);
		return 1;
	default:
		fprintf(stderr, "invalid file type: %s\n", obj);
		return 1;
	}

	if (gelf_getehdr(elf, &ehdr) == NULL) {
		fprintf(stderr, "corrupt file: %s\n", obj);
		return 1;
	}

#ifdef CONFIG_64BIT
	eclass = ELFCLASS64;
# if defined(__sparc)
	emachine1 = emachine2 = EM_SPARCV9;
# elif defined(__i386) || defined(__amd64)
	emachine1 = emachine2 = EM_X86_64;
# endif
	symsize = sizeof(Elf64_Sym);
#else
	eclass = ELFCLASS32;
# if defined(__sparc)
	emachine1 = EM_SPARC;
	emachine2 = EM_SPARC32PLUS;
# elif defined(__i386) || defined(__amd64)
	emachine1 = emachine2 = EM_386;
# endif
	symsize = sizeof(Elf32_Sym);
#endif

	if (ehdr.e_ident[EI_CLASS] != eclass) {
		fprintf(stderr, "incorrect ELF class for %s: %d "
			"(expected %d)\n", obj, ehdr.e_ident[EI_CLASS],
			eclass);
		return 1;
	}
	if (ehdr.e_machine != emachine1 && ehdr.e_machine != emachine2) {
		fprintf(stderr, "incorrect ELF machine type for %s: %d "
			"(expected %d or %d)\n",
			obj, ehdr.e_machine, emachine1, emachine2);
		return 1;
	}

	scn_rel = NULL;
	while ((scn_rel = elf_nextscn(elf, scn_rel)) != NULL) {
		if (gelf_getshdr(scn_rel, &shdr_rel) == NULL) {
			elferrstr = "failed to get section header";
			goto elf_err;
		}

		/*
		 * Skip any non-relocation sections.
		 */
		if (shdr_rel.sh_type != SHT_RELA && shdr_rel.sh_type != SHT_REL)
			continue;

		if ((data_rel = elf_getdata(scn_rel, NULL)) == NULL) {
			elferrstr = "failed to get relocation data";
			goto elf_err;
		}

		/*
		 * Grab the section, section header and section data for the
		 * symbol table that this relocation section references.
		 */
		if ((scn_sym = elf_getscn(elf, shdr_rel.sh_link)) == NULL ||
		    gelf_getshdr(scn_sym, &shdr_sym) == NULL ||
		    (data_sym = elf_getdata(scn_sym, NULL)) == NULL) {
			elferrstr = "failed to get symbol table";
			goto elf_err;
		}

		/*
		 * Ditto for that symbol table's string table.
		 */
		if ((scn_str = elf_getscn(elf, shdr_sym.sh_link)) == NULL ||
		    gelf_getshdr(scn_str, &shdr_str) == NULL ||
		    (data_str = elf_getdata(scn_str, NULL)) == NULL) {
			elferrstr = "failed to get string table";
			goto elf_err;
		}

		/*
		 * We're looking for relocations to symbols matching this form:
		 *
		 *   __dtrace_probe_<probe>
		 *
		 * If the function containing the probe is locally scoped
		 * (static), we create an alias.  The alias, a new symbol,
		 * will be global (so that it can be referenced from sdtinfo
		 * entries) and hidden (so that it is converted to a local
		 * symbol at link time). Such aliases have this form:
		 *
		 *   __dta_<function>_<symindex>
		 *
		 * The <symindex> is appended to ensure that aliases are unique
		 * because they are referenced in global scope.  Two local
		 * functions with identical names need to be distrinct at the
		 * level of the aliases.
		 *
		 * We take a first pass through all the relocations to
		 * populate our string table and count the number of extra
		 * symbols we'll require.  Note that the <function> is
		 * sanitized to ensure that it is a valid C identifier, i.e.
		 * any periods in the name are converted to underscores.
		 */
		isym = osym = data_sym->d_size / symsize;
		istr = data_str->d_size;

		/*
		 * Allocate the alias table to be the exact same size as the
		 * symtab.  If an alias is required for a specific symbol, its
		 * corresponding entry in this alias table will contain the
		 * alias name.  Otherwise, the entry will be NULL.
		 */
		alttab = (char **)calloc(isym, sizeof(char *));

		nsym = 0;
		nstr = 0;

		for (i = 0; i < shdr_rel.sh_size / shdr_rel.sh_entsize; i++) {
			if (shdr_rel.sh_type == SHT_RELA) {
				if (gelf_getrela(data_rel, i, &rela) == NULL)
					continue;
			} else {
				GElf_Rel rel;
				if (gelf_getrel(data_rel, i, &rel) == NULL)
					continue;
				rela.r_offset = rel.r_offset;
				rela.r_info = rel.r_info;
				rela.r_addend = 0;
			}

			if (gelf_getsym(data_sym, GELF_R_SYM(rela.r_info),
					&rsym) == NULL) {
				elferrstr = "relocation symbol not found";
				goto elf_err;
			}

			assert(rsym.st_name < data_str->d_size);

			r = (char *)data_str->d_buf + rsym.st_name;
			if (strncmp(r, dt_ppref, sizeof(dt_ppref) - 1) != 0)
				continue;

			sidx = dt_elf_symtab_lookup(data_sym, isym,
						    rela.r_offset,
						    shdr_rel.sh_info, &fsym);
			if (sidx < 0) {
				fprintf(stderr, "relocation %x not in "
					"function\n", i);
				goto err;
			}

			assert(fsym.st_name < data_str->d_size);
			assert(GELF_ST_TYPE(fsym.st_info) == STT_FUNC);

			if (GELF_ST_BIND(fsym.st_info) != STB_LOCAL)
				continue;

			f = (char *)data_str->d_buf + fsym.st_name;

			if (alttab[sidx] != NULL)
				continue;

			len = snprintf(NULL, 0, "%s%s_%d", dt_spref, f, sidx)
			      + 1;
			a = malloc(len);
			assert(a != NULL);
			nstr += snprintf(a, len, "%s%s_%d", dt_spref, f, sidx)
				 + 1;
			for (p = a; *p != '\0'; p++) {
				if (*p == '.')
					*p = '_';
			}
			alttab[sidx] = a;
			nsym++;
		}

		if (!nsym) {
			free(alttab);
			continue;
		}

		if ((pair = malloc(sizeof(symtbl_t))) == NULL) {
			fprintf(stderr, "failed to alloc new symtbl\n");
			goto err;
		}
		if ((pair->strtab = malloc(data_str->d_size + nstr)) == NULL) {
			fprintf(stderr, "failed to alloc new symtbl->strtab\n");
			free(pair);
			goto err;
		}
		if ((pair->symtab =
		     malloc(data_sym->d_size + nsym * symsize)) == NULL) {
			fprintf(stderr, "failed to alloc new symtbl->symtab\n");
			free(pair->strtab);
			free(pair);
			goto err;
		}

		pair->next = bufs;
		bufs = pair;

		memcpy(pair->strtab, data_str->d_buf, data_str->d_size);
		data_str->d_buf = pair->strtab;
		data_str->d_size += nstr;
		elf_flagdata(data_str, ELF_C_SET, ELF_F_DIRTY);
		shdr_str.sh_size += nstr;
		gelf_update_shdr(scn_str, &shdr_str);

		memcpy(pair->symtab, data_sym->d_buf, data_sym->d_size);
		data_sym->d_buf = pair->symtab;
		data_sym->d_size += nsym * symsize;
		elf_flagdata(data_sym, ELF_C_SET, ELF_F_DIRTY);
		shdr_sym.sh_size += nsym * symsize;
		gelf_update_shdr(scn_sym, &shdr_sym);

		nsym += isym;

		/*
		 * Now that the tables have been allocated, add the aliases as
		 * described above.  Since we already know the symtab index of
		 * the symbol that the alias refers to, we can simply run down
		 * the alttab and add alias for any non-NULL entries.
		 */
		for (i = 1; i < osym; i++) {
			if (alttab[i] == NULL)
				continue;

			if (gelf_getsym(data_sym, i, &fsym) == NULL) {
				fprintf(stderr, "failed to get symbol %d: %s\n",
					i, elf_errmsg(elf_errno()));
				goto err;
			}

			assert(GELF_ST_TYPE(fsym.st_info) == STT_FUNC);
			assert(GELF_ST_BIND(fsym.st_info) == STB_LOCAL);
			/*
			 * Add the alias as a new symbol to the symtab.
			 */
			dsym = fsym;
			dsym.st_name = istr;
			dsym.st_info = GELF_ST_INFO(STB_GLOBAL, STT_FUNC);
			dsym.st_other = ELF64_ST_VISIBILITY(STV_HIDDEN);

			len = strlen(alttab[i]) + 1;
			assert(istr + len <= data_str->d_size);
			a = (char *)data_str->d_buf + istr;
			memcpy(a, alttab[i], len);

			gelf_update_sym(data_sym, isym, &dsym);
			istr += len;
			isym++;

			assert(isym <= nsym);

			mod = 1;

			free(alttab[i]);
		}

		free(alttab);
	}

	if (mod && elf_update(elf, ELF_C_WRITE) == -1) {
		elferrstr = "Failed to update ELF object";
		goto elf_err;
	}

	elf_end(elf);
	close(fd);

	while ((pair = bufs) != NULL) {
		bufs = pair->next;
		free(pair->strtab);
		free(pair->symtab);
		free(pair);
	}

	return 0;

elf_err:
	fprintf(stderr, "%s: %s\n", elferrstr, elf_errmsg(elf_errno()));
err:
	fprintf(stderr, "an error was encountered while processing %s\n", obj);
	return 1;
}

int
main(int argc, char *argv[])
{
	int i;

	for (i = 1; i < argc; i++) {
		if (process_obj(argv[i]))
			exit(1);
	}

	exit(0);
}
