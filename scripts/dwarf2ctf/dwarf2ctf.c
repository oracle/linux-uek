/*
 * dwarf2ctf.c: Read in DWARF[23] debugging information from some set of ELF
 * files, and generate CTF in correspondingly-named files.
 *
 * (C) 2011, 2012, 2013, 2014 Oracle, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

#include <libelf.h>
#include <dwarf.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <elfutils/version.h>
#include <sys/ctf_api.h>
#include <glib.h>

#include <eu_simple.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#ifndef __GNUC__
#define __attribute__((foo))
#endif

#define __unused__ __attribute__((__unused__))

/*
 * If non-NULL, tracing is on.
 */
static const char *trace;

/*
 * Trace something.
 */
#ifdef DEBUG
#define dw_ctf_trace(format, ...) if (trace) fprintf(stderr, (format), ## __VA_ARGS__)
#else
#define dw_ctf_trace(format, ...)
#endif

/*
 * Run dwarf2ctf over a single object file or set thereof.
 *
 * output_dir is the directory into which the CTF goes.
 */
static void run(char *output_dir);

/*
 * A fully descriptive CTF type ID: both file and type ID in one place.
 */
typedef struct ctf_full_id {
	ctf_file_t *ctf_file;
	ctf_id_t ctf_id;
#ifdef DEBUG
	char module_name[PATH_MAX];
	char file_name[PATH_MAX];
#endif
} ctf_full_id_t;

/*
 * A mapping from the type ID of a DIE (see type_id()) to ctf_full_id_t's
 * describing the type with that ID.
 *
 * This is used to look up types regardless of which CTF file they may reside
 * in.  Not the same as a DWARF4 type signature because we must encode scope
 * information which DWARF4 can encode in its DIE refs.
 *
 * (TODO: store a hash of the ID rather than the ID itself, to save memory.
 * Makes debugging slightly harder though.)
 */
static GHashTable *id_to_type;

/*
 * A mapping from the type ID of a DIE to the name of the module (and thus CTF
 * table) incorporating that type.  (Modules in this context, and throughout
 * dwarf2ctf, are DTrace modules: a name without suffix or path.)
 *
 * This is used to merge types identical across modules (e.g. those in global
 * header files).
 */
static GHashTable *id_to_module;

/*
 * A mapping from module name to ctf_file_t *.  The CTF named 'vmlinux' is the
 * CTF corresponding to the types in always-built-in translation units; the CTF
 * named 'shared_ctf' (not appearing in this mapping) is the CTF corresponding
 * to types shared between more than one module (even between two currently-
 * built-in modules: we do not distinguish at this level between built-in
 * modules and non-built-in modules.)
 */
static GHashTable *module_to_ctf_file;

/*
 * The names of the object files to run over.  Except in -e mode, this comes
 * straight from the module filelist passed in.
 */
static char **object_names;
static size_t object_names_cnt;

/*
 * Populate the object_names list from the module filelist.
 */
static void init_object_names(const char *object_names_file);

/*
 * The names of module object files presently built in to the kernel, in the
 * same format as the module names in tu_to_module.
 *
 * If this is NULL, an external module is being processed, and type
 * deduplication is disabled.
 */
static char **builtin_modules;
static size_t builtin_modules_cnt;

/*
 * The names of object files that are *always* built in to the kernel.
 * (If something is in neither this list nor builtin_modules, it is
 * an external module.)
 */
static char **builtin_objects;
static size_t builtin_objects_cnt;

/*
 * Populate the builtin_modules and builtin_objects lists from the
 * objects.builtin and modules.builtin files.
 */
static void init_builtin(const char *builtin_objects_file,
			 const char *builtin_module_file);

/*
 * The deduplication blacklist bans specific modules that do notably insane
 * things with the preprocessor from participating in deduplication.  The list
 * of sins is short: things like #including two different source files that
 * proceed to add or remove members from structures depending on which source
 * file they were included from.
 *
 * These modules still share types with the rest of the kernel, but types that
 * only they share with other modules will not be shared for that reason alone.
 *
 * This is, of course, only used if deduplication is turned on.
 */
static GHashTable *dedup_blacklist;

/*
 * Populate the deduplication blacklist from the dedup_blacklist file.
 */
static void init_dedup_blacklist(const char *dedup_blacklist_file);

/*
 * The member blacklist bans fields with specific names in specifically named
 * structures, declared in specific source files, from being emitted.  The
 * mapping is from absolute source file name:structure.member to NULL (this is
 * safe because type names cannot contain a colon, and structure names cannot
 * contain a period).
 */
static GHashTable *member_blacklist;

/*
 * Populate the member blacklist from the member_blacklist file.
 */
static void init_member_blacklist(const char *member_blacklist_file);

/*
 * Return 1 if a given DWARF DIE, which must be a DW_TAG_member, appears in the
 * member blacklist.
 */
static int member_blacklisted(Dwarf_Die *die, Dwarf_Die *parent_die);

/*
 * A mapping from translation unit name to the name of the module that
 * translation unit is part of.  Module names have no trailing suffix.
 *
 * This table is not complete until the first detect_duplicates pass is over,
 * but names corresponding to builtin modules and objects are populated early.
 */
static GHashTable *tu_to_module;

/*
 * Populate the tu_to_module hash with names corresponding to builtin modules.
 */
static void init_tu_to_modules(void);

/*
 * Initialize a CTF type table, and possibly fill it with those special types
 * that appear in CTF but not in DWARF (such as 'void').  (This filling happens
 * only for the type table named "shared_ctf", unless deduplication is turned
 * off, signified by the builtin_modules list being NULL.)
 *
 * If this is a local type table, and deduplication is active, make the global
 * type table its parent.
 */
static ctf_file_t *init_ctf_table(const char *module_name);

/*
 * A few useful singleton CTF type IDs in the global type table: a void pointer
 * and a function pointer.  Constructed by init_ctf_table().
 */
static ctf_id_t ctf_void_type;
static ctf_id_t ctf_funcptr_type;

/*
 * Compute the type ID of a DWARF DIE and return it in a new dynamically-
 * allocated string.
 *
 * Optionally, call a callback with the computed ID once we know it (this is a
 * recursive process, so the callback can be called multiple times as the ID
 * is built up).
 *
 * An ID of NULL indicates that this DIE has no ID and need not be considered.
 */
static char *type_id(Dwarf_Die *die, void (*fun)(Dwarf_Die *die,
						 const char *id,
						 void *data),
		     void *data) __attribute__((__warn_unused_result__));

/*
 * Process a file, calling the dwarf_process function for every type found
 * therein (even types in functions).  Optionally call tu_init() at the start of
 * each translation unit, and tu_done() at the end.
 */
static void process_file(const char *file_name,
			 void (*dwarf_process)(const char *module_name,
					       const char *file_name,
					       Dwarf_Die *die,
					       Dwarf_Die *parent_die,
					       void *data),
			 void (*tu_init)(const char *module_name,
					 const char *file_name,
					 Dwarf_Die *tu_die,
					 void *data),
			 void (*tu_done)(const char *module_name,
					 const char *file_name,
					 Dwarf_Die *tu_die,
					 void *data),
			 void *data);

/*
 * process_file() helper, walking over subroutines recursively and picking up
 * types therein.
 */
static void process_tu_func(const char *module_name,
			    const char *file_name,
			    Dwarf_Die *parent_die,
			    Dwarf_Die *die,
			    void (*dwarf_process)(const char *module_name,
						  const char *file_name,
						  Dwarf_Die *die,
						  Dwarf_Die *parent_die,
						  void *data),
			    void *data);

/*
 * Scan and identify duplicates across the entire set of object files.
 */
static void scan_duplicates(void);

/*
 * Recursively detect duplicate types and types referenced by them, and
 * determine which CTF file they should be located in, and request a
 * detect_duplicates_alias_fixup() pass if any structures are shared.
 * Determine the mapping from translation unit name to module name.
 */
static void detect_duplicates(const char *module_name, const char *file_name,
			      Dwarf_Die *die, Dwarf_Die *parent_die,
			      void *data);

/*
 * Mark any aggregates contained within a particular type DIE as seen.  This is
 * needed since even nameless aggregates contained within other aggregates can
 * be used as the type of members of the outer aggregate (though they cannot
 * possibly be found in a module different from that of their containing
 * aggregate, any more than a structure member can).
 */
static void mark_seen_contained(Dwarf_Die *die, const char *module_name);

/*
 * Second duplication detection pass, checking for opaque/nonopaque structure
 * aliasing, marking all aliases as shared, and requesting a new
 * detect_duplicates() pass if any was found.
 */
static void detect_duplicates_alias_fixup(const char *module_name,
					  const char *file_name,
					  Dwarf_Die *die,
					  Dwarf_Die *parent_die,
					  void *data);
/*
 * Determine if some type (whose ultimate base type is an non-opaque structure,
 * alias, or enum) has an opaque equivalent which is shared, and mark it and
 * all its bases as shared too if so.
 *
 * A type_id() callback.
 */
static void detect_duplicates_alias_fixup_internal(Dwarf_Die *die,
						   const char *id, void *data);

/*
 * Determine if a type is a named struct, union, or enum.
 *
 * A type_id() callback.
 */
static void is_named_struct_union_enum(Dwarf_Die *die, const char *unused,
				       void *data);

/*
 * Set up state for detect_duplicates().  A tu_init() callback.
 */
static void detect_duplicates_init(const char *module_name,
				   const char *file_name,
				   Dwarf_Die *tu_die,
				   void *data);

/*
 * Free state for detect_duplicates().  A tu_done() callback.
 */
static void detect_duplicates_done(const char *module_name,
				   const char *file_name,
				   Dwarf_Die *tu_die,
				   void *data);

/*
 * Mark a type (optionally, with an already-known ID) as duplicated and located
 * in the shared CTF table.
 *
 * A type_id() callback (though also called directly).
 */
static void mark_shared(Dwarf_Die *die, const char *id,
			void *data);

/*
 * The structure used as the data argument for detect_duplicates() and
 * detect_duplicates_alias_fixup().
 *
 * structs_seen tracks the IDs of structures marked as duplicates within a given
 * translation unit, in order that recursion terminates if two such structures
 * have pointers to each other.
 *
 * repeat_detection is set by each phase if it considers that another round of
 * alias fixup detection is needed.
 */
struct detect_duplicates_state {
	const char *module_name;
	GHashTable *structs_seen;
	int repeat_detection;
};

/*
 * Construct CTF out of each type.
 */
static void construct_ctf(const char *module_name, const char *file_name,
			  Dwarf_Die *die,
			  Dwarf_Die *parent_die,
			  void *unused __unused__);

/*
 * Write out the CTF files from the module_to_ctf_file hashtable into files in
 * the output_dir.
 */
static void write_types(char *output_dir);

/*
 * Construct CTF out of each type and return that type's ID and file.
 */
static ctf_full_id_t *construct_ctf_id(const char *module_name,
				       const char *file_name,
				       Dwarf_Die *die,
				       Dwarf_Die *parent_die);

/*
 * Things to do after a CTF recursion step.
 */
enum skip_type { SKIP_CONTINUE = 0, SKIP_SKIP, SKIP_ABORT };

/*
 * Recursive over a given DWARF DIE and its children andconstruct CTF out of it.
 *
 * Most parameters are shared with the ctf_assembly_fun: see the comment below.
 */
static ctf_id_t die_to_ctf(const char *module_name, const char *file_name,
			   Dwarf_Die *die, Dwarf_Die *parent_die,
			   ctf_file_t *ctf, ctf_id_t parent_ctf_id,
			   ulong_t parent_bias, int top_level_type,
			   enum skip_type *skip, int *override,
			   const char *id);

/*
 * Look up a type through its reference: return its ctf_id_t, or
 * recursively construct it if need be.
 *
 * Must be called on a DIE with a type attribute.
 */
static ctf_id_t lookup_ctf_type(const char *module_name, const char *file_name,
				Dwarf_Die *die, ctf_file_t *ctf,
				const char *locerrstr);

/*
 * Assemble a given DIE and its children into CTF in some fashion, returning the
 * ID of the top-level piece of generated CTF (only relevant for aggregates).
 *
 * The parent_ctf_id is the ID of the CTF entity that was or is being generated
 * from the enclosing DWARF DIE, or 0 if population succeeded but did not yield
 * a type ID (e.g. for variable assembly), or -1 on error.  The parent_die is
 * the parent of the current DWARF DIE, and is always populated (even if just
 * with the CU's DIE).  The parent_ctf_id is always in the same CTF file as the
 * ctf_id, just as the parent DWARF DIE is always in the same DWARF CU: this is
 * lexical scope, not dynamic, so referenced types themselves located at the top
 * level have the CU as their parent.  The parent_bias is an offset which should
 * be added to the member offset of any structure or union members above and
 * beyond the offset given in the member itself (used for unnamed structures and
 * unions).
 *
 * Returning an error value (see below) indicates that no CTF was generated from
 * this DWARF DIE.
 *
 * Setting skip to SKIP_ABORT indicates that the translation of this entity
 * failed, and the entire top-level type of which it is a part should be
 * skipped.  Setting it to SKIP_SKIP indicates that this entity does not need to
 * be translated (perhaps because it already exists), so recursion into
 * sub-entities can be skipped, but translation of the containing type should
 * continue.  Setting it to SKIP_CONTINUE indicates no error.
 *
 * Setting 'override' to 1 in a child DIE indicates that this type should
 * entirely *override* its parent's type (generally because it has wrapped it up
 * in something).  This override takes immediate effect for later children of
 * the same DIE.
 *
 * die_to_ctf() calls these functions repeatedly for every child of the
 * requested DIE: the CTF ID eventually returned is whatever ID is returned by
 * the last such function, and parent_ctf_id is repeatedly replaced with the ID
 * returned by the last assembly function.  Thus, assembly functions that
 * augment an already-present ctf_id should return parent_ctf_id: assembly
 * functions that wrap it in a new ctf_id referring to the parent_ctf_id should
 * return the new ID.  (Assembly functions should never entirely disregard the
 * parent_ctf_id.)
 */
typedef ctf_id_t (*ctf_assembly_fun)(const char *module_name,
				     const char *file_name,
				     Dwarf_Die *die,
				     Dwarf_Die *parent_die,
				     ulong_t parent_bias,
				     ctf_file_t *ctf,
				     ctf_id_t parent_ctf_id,
				     const char *locerrstr,
				     int top_level_type,
				     enum skip_type *skip,
				     int *override);

#define ASSEMBLY_FUN(name)					     \
	static ctf_id_t assemble_ctf_##name(const char *module_name,  \
					    const char *file_name,    \
					    Dwarf_Die *die,	      \
					    Dwarf_Die *parent_die,    \
					    ulong_t parent_bias,      \
					    ctf_file_t *ctf,	      \
					    ctf_id_t parent_ctf_id,   \
					    const char *locerrstr,    \
					    int top_level_type,	      \
					    enum skip_type *skip,     \
					    int *override)

/*
 * Defined assembly functions.
 */
ASSEMBLY_FUN(base);
ASSEMBLY_FUN(array);
ASSEMBLY_FUN(array_dimension);
ASSEMBLY_FUN(cvr_qual);
ASSEMBLY_FUN(enumeration);
ASSEMBLY_FUN(enumerator);
ASSEMBLY_FUN(pointer);
ASSEMBLY_FUN(struct_union);
ASSEMBLY_FUN(su_member);
ASSEMBLY_FUN(typedef);
ASSEMBLY_FUN(variable);

/*
 * An assembly filter is an optional function called with the DIE and parent DIE
 * of a top-level type alone, before calling down into the process_file()
 * processing function: it can be used to rapidly determine that this DIE is not
 * worth processing.  (It should return 0 in this case, and nonzero otherwise.)
 */
typedef int (*ctf_assembly_filter_fun)(Dwarf_Die *die,
				       Dwarf_Die *parent_die);

/*
 * A CTF assembly filter function which excludes all types not at the global
 * scope (i.e. whose immediate parent is not a CU DIE).
 */
static int filter_ctf_file_scope(Dwarf_Die *die __unused__,
				 Dwarf_Die *parent_die);

/*
 * A CTF assembly filter function which excludes all names not at the global
 * scope, all static symbols, and all names whose names are unlikely to be
 * interesting.  (DTrace userspace contains a similar list, but the two lists
 * need not be in sync.)
 */
static int filter_ctf_uninteresting(Dwarf_Die *die,
				    Dwarf_Die *parent_die);

/*
 * Error return values from CTF assembly functions.  These differ only in that
 * die_to_ctf() reports the ctf_errmsg() if CTF_NO_ERROR_REPORTED is returned,
 * but says nothing in the CTF_ERROR_REPORTED case.
 */
#define CTF_NO_ERROR_REPORTED CTF_ERR
#define CTF_ERROR_REPORTED (-2L)

/*
 * The total number of type errors encountered.
 */
static long num_errors;

/*
 * A mapping from DW_TAG_* to functions which assemble this DW_TAG_* and
 * possibly its children into the passed CTF.  This table is not used
 * directly, but rather assembled into a lookup table.
 */
static struct assembly_tab_t
{
	int tag;
	ctf_assembly_filter_fun filter;
	ctf_assembly_fun fun;
} assembly_tab_init[] =
{{ DW_TAG_base_type, filter_ctf_file_scope, assemble_ctf_base },
 { DW_TAG_array_type, filter_ctf_file_scope, assemble_ctf_array },
 { DW_TAG_subrange_type, NULL, assemble_ctf_array_dimension },
 { DW_TAG_const_type, filter_ctf_file_scope, assemble_ctf_cvr_qual },
 { DW_TAG_restrict_type, filter_ctf_file_scope, assemble_ctf_cvr_qual },
 { DW_TAG_enumeration_type, NULL, assemble_ctf_enumeration },
 { DW_TAG_enumerator, NULL, assemble_ctf_enumerator },
 { DW_TAG_pointer_type, filter_ctf_file_scope, assemble_ctf_pointer },
 { DW_TAG_structure_type, NULL, assemble_ctf_struct_union },
 { DW_TAG_union_type, NULL, assemble_ctf_struct_union },
 { DW_TAG_member, NULL, assemble_ctf_su_member },
 { DW_TAG_typedef, NULL, assemble_ctf_typedef },
 { DW_TAG_variable, filter_ctf_uninteresting, assemble_ctf_variable },
 { DW_TAG_volatile_type, filter_ctf_file_scope, assemble_ctf_cvr_qual },
 { 0, NULL }};

/*
 * The CTF assembly and filter lookup tables, in constructed form.
 */
static ctf_assembly_fun *assembly_tab;
static ctf_assembly_filter_fun *assembly_filter_tab;
static size_t assembly_len;

/*
 * Populate the assembly_tab and assembly_filter_tab from the assembly_tab_init.
 */
static void init_assembly_tab(void);

/*
 * A mapping from sizeof() to CTF type encoding.
 */
struct type_encoding_tab {
	size_t size;
	int ctf_encoding;
};

/*
 * Given a type encoding table, and a size, return the CTF encoding for that
 * type, or 0 if none.
 */
static int find_ctf_encoding(struct type_encoding_tab *type_tab, size_t size);

/*
 * Count the number of members of a DWARF aggregate.
 */
static long count_dwarf_members(Dwarf_Die *die);

/*
 * Count the number of members of a CTF aggregate.
 */
static long count_ctf_members(ctf_file_t *fp, ctf_id_t souid);

/*
 * Increment said count.
 */
static int count_ctf_members_internal(const char *name, ctf_id_t member,
				      ulong_t offset, void *count);

/*
 * Given a DIE that may contain a type attribute, look up the target of that
 * attribute and return it, or NULL if none.
 */

static Dwarf_Die *private_dwarf_type(Dwarf_Die *die, Dwarf_Die *target_die);

/*
 * Determine the dimensions of an array subrange, or 0 if variable.
 */
static Dwarf_Word private_subrange_dimensions(Dwarf_Die *die);

/*
 * A string appender working on dynamic strings.
 */
static char *str_append(char *s, const char *append)
	__attribute__((__warn_unused_result__));

/*
 * A vararg string appender.
 */
static char *str_appendn(char *s, ...)
	__attribute__((__warn_unused_result__, sentinel));

/*
 * An error-checking strdup().
 */
static char *xstrdup(const char *s) __attribute__((__nonnull__,
						   __warn_unused_result__,
						   __malloc__));

/*
 * Figure out the (pathless, suffixless) module name for a given module file (.o
 * or .ko), and return it in a new dynamically allocated string.
 */
static char *fn_to_module(const char *file_name);

/*
 * Determine, and cache, absolute filenames.
 */
static const char *abs_file_name(const char *file_name);

/*
 * Trivial wrapper, avoid an incompatible pointer type warning.
 */
static void private_ctf_free(void *ctf_file);

/* Initialization.  */

int main(int argc, char *argv[])
{
	char *output_dir;

	trace = getenv("DWARF2CTF_TRACE");

	if ((argc != 4 && argc != 7) ||
	    (argc == 4 && strcmp(argv[2], "-e") != 0)) {
		fprintf(stderr, "Syntax: dwarf2ctf outputdir objects.builtin modules.builtin dedup.blacklist\n");
		fprintf(stderr, "                  member.blacklist filelist\n");
		fprintf(stderr, "    or dwarf2ctf outputdir -e filelist"
			"for external module use\n");
		exit(1);
	}

	output_dir = argv[1];

	elf_version(EV_CURRENT);

	if (elf_errno()) {
		fprintf(stderr, "Version synchronization fault: %s\n",
			elf_errmsg(elf_errno()));
		exit(1);
	}

	init_assembly_tab();

	/*
	 * When not building an external module, we run over all the arguments
	 * at once, deduplicating them.  In external-module mode, we act as if
	 * independently invoked with every argument.
	 */
	if (strcmp(argv[2], "-e") != 0) {
		char *builtin_objects_file;
		char *builtin_module_file;
		char *dedup_blacklist_file;
		char *member_blacklist_file;

		builtin_objects_file = argv[2];
		builtin_module_file = argv[3];
		dedup_blacklist_file = argv[4];
		member_blacklist_file = argv[5];

		init_builtin(builtin_objects_file, builtin_module_file);
		init_dedup_blacklist(dedup_blacklist_file);
		init_member_blacklist(member_blacklist_file);
		init_object_names(argv[6]);

		run(output_dir);
	} else {
		char *single_object_name;
		char **all_object_names;
		size_t all_object_names_cnt;
		size_t i;

		init_object_names(argv[3]);

		/*
		 * Repeatedly populate object_names with one object name, and
		 * call run() with that.
		 */
		all_object_names = object_names;
		all_object_names_cnt = object_names_cnt;
		object_names = &single_object_name;
		object_names_cnt = 1;

		for (i = 0; i < all_object_names_cnt; i++) {
			single_object_name = all_object_names[i];

			run(output_dir);
		}
	}

	if (num_errors > 0)
		fprintf(stderr, "%li CTF construction errors.\n", num_errors);

	return 0;
}

/*
 * Run dwarf2ctf over a single object file or set thereof.
 *
 * output_dir is the directory into which the CTF goes.
 */
static void run(char *output_dir)
{
	size_t i;

	/*
	 * Create all the hashes, assemble the translation unit->module list for
	 * builtin modules, and create the shared CTF file if deduplicating.
	 */

	id_to_type = g_hash_table_new_full(g_str_hash, g_str_equal,
					   free, free);
	id_to_module = g_hash_table_new_full(g_str_hash, g_str_equal,
					     free, free);
	tu_to_module = g_hash_table_new_full(g_str_hash, g_str_equal,
					     free, free);
	module_to_ctf_file = g_hash_table_new_full(g_str_hash, g_str_equal,
						   free, private_ctf_free);

	dw_ctf_trace("Initializing...\n");
	init_tu_to_modules();

	if (builtin_modules != NULL)
		init_ctf_table("shared_ctf");

	scan_duplicates();

	/*
	 * Now construct CTF out of the types.
	 */
	dw_ctf_trace("CTF construction.\n");
	for (i = 0; i < object_names_cnt; i++)
		process_file(object_names[i], construct_ctf, NULL, NULL, NULL);

	/*
	 * Finally, emit the types into their .ctf files, and generate the
	 * necessary linker scripts.
	 */
	dw_ctf_trace("Writeout.\n");
	write_types(output_dir);

	g_hash_table_destroy(id_to_type);
	g_hash_table_destroy(id_to_module);
	g_hash_table_destroy(tu_to_module);
	g_hash_table_destroy(module_to_ctf_file);
}


/*
 * Populate the builtin_modules and builtin_objects lists from the
 * objects.builtin and modules.builtin file.
 */
static void init_object_names(const char *object_names_file)
{
	FILE *f;
	char *line = NULL;
	size_t line_size = 0;

	if ((f = fopen(object_names_file, "r")) == NULL) {
		fprintf(stderr, "Cannot open object names file %s: "
			"%s\n", object_names_file, strerror(errno));
		exit(1);
	}

	/*
	 * This needs no massaging other than linefeed removal, just reading and
	 * stashing.
	 */

	while (getline(&line, &line_size, f) >= 0) {
		size_t len = strlen(line);

		if (len == 0)
			continue;

		if (line[len-1] == '\n')
			line[len-1] = '\0';

		object_names = realloc(object_names,
				       ++object_names_cnt *
				       sizeof (char *));

		if (object_names == NULL) {
			fprintf(stderr, "Out of memory reading %s",
				object_names_file);
			exit(1);
		}

		object_names[object_names_cnt-1] = xstrdup(line);
	}

	if (ferror(f)) {
		fprintf(stderr, "Error reading from %s: %s\n",
			object_names_file, strerror(errno));
		exit(1);
	}

	fclose(f);
}

/*
 * Populate the builtin_modules and builtin_objects lists from the
 * objects.builtin and modules.builtin file.
 */
static void init_builtin(const char *builtin_objects_file,
			 const char *builtin_module_file)
{
	FILE *f;
	char *line = NULL;
	size_t line_size = 0;

	if ((f = fopen(builtin_objects_file, "r")) == NULL) {
		fprintf(stderr, "Cannot open builtin objects file %s: "
			"%s\n", builtin_objects_file, strerror(errno));
		exit(1);
	}

	/*
	 * This needs no massaging other than linefeed removal, just reading and
	 * stashing.
	 */

	while (getline(&line, &line_size, f) >= 0) {
		size_t len = strlen(line);

		if (len == 0)
			continue;

		if (line[len-1] == '\n')
			line[len-1] = '\0';

		builtin_objects = realloc(builtin_objects,
					  ++builtin_objects_cnt *
					  sizeof (char *));

		if (builtin_objects == NULL) {
			fprintf(stderr, "Out of memory reading %s",
				builtin_objects_file);
			exit(1);
		}

		builtin_objects[builtin_objects_cnt-1] = xstrdup(line);
	}

	if (ferror(f)) {
		fprintf(stderr, "Error reading from %s: %s\n",
			builtin_objects_file, strerror(errno));
		exit(1);
	}

	fclose(f);

	if ((f = fopen(builtin_module_file, "r")) == NULL) {
		fprintf(stderr, "Cannot open builtin module file %s: "
			"%s\n", builtin_module_file, strerror(errno));
		exit(1);
	}

	/*
	 * Read in, realloc()ing and assigning as we go, stripping off the
	 * leading path element, if any, and transforming the suffix into .o
	 * from .ko.  Any elements that don't have files corresponding to them
	 * elicit a warning.
	 */

	while (getline(&line, &line_size, f) >= 0) {
		char *first_slash;
		char *last_dot;

		if (line[0] == '\0')
			continue;

		if ((first_slash = strchr(line, '/')) != NULL)
			first_slash++;
		else
			first_slash = line;

		last_dot = strrchr(line, '.');
		if ((last_dot != NULL) &&
		    ((strcmp(last_dot, ".ko") == 0) ||
		     (strcmp(last_dot, ".ko\n") == 0))) {
			strcpy(last_dot, ".o");
		}

		if (access(first_slash, R_OK) == 0) {
			builtin_modules = realloc(builtin_modules,
						  ++builtin_modules_cnt *
						  sizeof (char *));

			if (builtin_modules == NULL) {
				fprintf(stderr, "Out of memory reading %s",
					builtin_module_file);
				exit(1);
			}

			builtin_modules[builtin_modules_cnt-1] = xstrdup(first_slash);
		} else {
			fprintf(stderr, "%s population: module %s is not "
				"readable.\n", builtin_module_file,
				first_slash);
		}
	}
	free(line);

	if (ferror(f)) {
		fprintf(stderr, "Error reading from %s: %s\n",
			builtin_module_file, strerror(errno));
		exit(1);
	}

	fclose(f);
}

/*
 * Translate the assembly lookup table into the assembly_tab and
 * assembly_filter_tab arrays.
 */
static void init_assembly_tab(void)
{
	struct assembly_tab_t *walk;

	for (walk = assembly_tab_init; walk->fun != NULL; walk++) {
		if (assembly_len < walk->tag)
			assembly_len = walk->tag;
	}

	if ((assembly_tab = calloc(sizeof (ctf_assembly_fun *),
				   assembly_len + 1)) == NULL) {
		fprintf(stderr, "Out of memory allocating assembly table\n");
		exit(1);
	}

	if ((assembly_filter_tab = calloc(sizeof (ctf_assembly_filter_fun *),
				   assembly_len + 1)) == NULL) {
		fprintf(stderr, "Out of memory allocating assembly filter "
			"table\n");
		exit(1);
	}

	for (walk = assembly_tab_init; walk->fun != NULL; walk++) {
		assembly_tab[walk->tag] = walk->fun;
		assembly_filter_tab[walk->tag] = walk->filter;
	}
}

/*
 * Populate the deduplication blacklist from the dedup_blacklist file.
 */
static void init_dedup_blacklist(const char *dedup_blacklist_file)
{
	FILE *f;
	char *line = NULL;
	size_t line_size = 0;

	/*
	 * Not having a deduplication blacklist is not an error.
	 */
	if ((f = fopen(dedup_blacklist_file, "r")) == NULL)
		return;

	dedup_blacklist = g_hash_table_new(g_str_hash, g_str_equal);

	while (getline(&line, &line_size, f) >= 0) {
		size_t len = strlen(line);

		if (len == 0)
			continue;

		if (line[len-1] == '\n')
			line[len-1] = '\0';


		g_hash_table_insert(dedup_blacklist, strdup(line), NULL);
	}

	if (ferror(f)) {
		fprintf(stderr, "Error reading from %s: %s\n",
			dedup_blacklist_file, strerror(errno));
		exit(1);
	}

	fclose(f);
}

/*
 * Populate the member blacklist from the member_blacklist file.
 */
static void init_member_blacklist(const char *member_blacklist_file)
{
	FILE *f;
	char *line = NULL;
	size_t line_num = 0;
	size_t line_size = 0;

	/*
	 * Not having a member blacklist is not an error.
	 */
	if ((f = fopen(member_blacklist_file, "r")) == NULL)
		return;

	member_blacklist = g_hash_table_new(g_str_hash, g_str_equal);

	while (getline(&line, &line_size, f) >= 0) {
		size_t len = strlen(line);
		char *last_colon;
		const char *last_dot;
		char *absolutized;

		line_num++;

		if (len == 0)
			continue;

		if (line[len-1] == '\n')
			line[len-1] = '\0';

		last_colon = strrchr(line, ':');
		last_dot = strrchr(last_colon + 1, '.');
		if (!last_colon || !last_dot) {
			fprintf(stderr, "Syntax error on line %li of %s.\n"
			    "Syntax: filename:structure.member.\n",
			    line_num, member_blacklist_file);
			continue;
		}

		*last_colon = '\0';
		last_colon++;
		absolutized = xstrdup(abs_file_name(line));
		absolutized = str_appendn(absolutized, ":", last_colon, NULL);

		g_hash_table_insert(member_blacklist, absolutized, NULL);
	}

	if (ferror(f)) {
		fprintf(stderr, "Error reading from %s: %s\n",
			member_blacklist_file, strerror(errno));
		exit(1);
	}

	fclose(f);
}

/*
 * Return 1 if a given DWARF DIE, which must be a DW_TAG_member, appears in the
 * member blacklist.
 */
static int member_blacklisted(Dwarf_Die *die, Dwarf_Die *parent_die)
{
	const char *fname = dwarf_decl_file(die);
	char *id;
	int blacklisted = 0;

	/*
	 * If there is no member blacklist, do nothing.
	 */
	if (!member_blacklist)
		return 0;

	/*
	 * Unnamed structure and union members cannot be blacklisted, for now.
	 */
	if ((dwarf_diename(parent_die) == NULL) ||
	    (dwarf_diename(die) == NULL))
		return 0;

	/*
	 * If the compiler is now emitting members without decl_files, we
	 * want to know.
	 */
	if (fname == NULL) {
		static int warned = 0;

		if (!warned)
			fprintf(stderr, "Warning: member_blacklisted() called with "
			    "NULL decl_file, which should never happen.\n");

		warned = 1;
		return 0;
	}

	fname = abs_file_name(fname);

	if (dwarf_tag(die) != DW_TAG_member ||
	    (dwarf_tag(parent_die) != DW_TAG_structure_type &&
		dwarf_tag(parent_die) != DW_TAG_union_type)) {
		fprintf(stderr, "Warning: member_blacklisted() called on "
		    "%s:%s.%s at offset %li, which is not a structure member.",
		    fname, dwarf_diename(parent_die), dwarf_diename(die),
		    dwarf_dieoffset(die));
		return 0;
	}

	id = xstrdup(fname);
	id = str_appendn(id, ":", dwarf_diename(parent_die), ".",
	    dwarf_diename(die), NULL);

	if (g_hash_table_lookup_extended(member_blacklist, id, NULL, NULL))
		blacklisted = 1;

	free(id);
	return blacklisted;
}

/*
 * Initialize a CTF type table, and possibly fill it with those special types
 * that appear in CTF but not in DWARF (such as 'void').  (This filling happens
 * only for the type table named "shared_ctf", unless deduplication is turned
 * off, signified by the builtin_modules list being NULL.)
 *
 * If this is a local type table, and deduplication is active, make the global
 * type table its parent.
 */
static ctf_file_t *init_ctf_table(const char *module_name)
{
	ctf_file_t *ctf_file;
	int ctf_err;

	if ((ctf_file = ctf_create(&ctf_err)) == NULL) {
		fprintf(stderr, "Cannot create CTF file: %s\n",
			strerror(ctf_err));
		exit(1);
	}
	g_hash_table_replace(module_to_ctf_file, xstrdup(module_name),
			     ctf_file);

	dw_ctf_trace("Initializing module: %s\n", module_name);
	if ((strcmp(module_name, "shared_ctf") == 0) ||
	    (builtin_modules == NULL)) {
		ctf_encoding_t void_encoding = { CTF_INT_SIGNED, 0, 0 };
		ctf_encoding_t int_encoding = { CTF_INT_SIGNED, 0,
						sizeof (int) };
		ctf_id_t int_type;
		ctf_id_t func_type;
		ctf_funcinfo_t func_info;

		/*
		 * Global types module, or deduplication is disabled.  Add a
		 * type for 'void *' to point to, and a type for the return
		 * value of pointers to functions: then add the (single,
		 * universal) pointer-to-function value.
		 */
		ctf_void_type = ctf_add_integer(ctf_file, CTF_ADD_ROOT,
						"void", &void_encoding);
		int_type = ctf_add_integer(ctf_file, CTF_ADD_ROOT, "int",
					   &int_encoding);

		func_info.ctc_return = int_type;
		func_info.ctc_argc = 0;
		func_info.ctc_flags = 0;
		func_type = ctf_add_function(ctf_file, CTF_ADD_ROOT,
					     &func_info, NULL);
		ctf_funcptr_type = ctf_add_pointer(ctf_file, CTF_ADD_ROOT,
						   func_type);

		if (ctf_update(ctf_file) < 0) {
			fprintf(stderr, "Cannot initialize shared CTF "
				"file: %s\n", ctf_errmsg(ctf_errno(ctf_file)));
			exit(1);
		}
	} else {
		/*
		 * Local types module with deduplication enabled: point the
		 * parent at the global CTF file, which must exist by this
		 * point.
		 */
		if (ctf_import(ctf_file,
			       g_hash_table_lookup(module_to_ctf_file,
						   "shared_ctf")) < 0) {
			fprintf(stderr, "Cannot set parent of CTF file for "
				"module %s: %s\n", module_name,
				ctf_errmsg(ctf_errno(ctf_file)));
			exit(1);
		}
		ctf_parent_name_set(ctf_file, "shared_ctf");
	}

	dw_ctf_trace("Created CTF file for module %s: %p\n",
		     module_name, ctf_file);

	return ctf_file;
}

/* DWARF walkers.  */

/*
 * Compute the mapping from translation unit name to module name for built-in
 * modules and always-built-in object files.
 */
static void init_tu_to_modules(void)
{
	size_t i;

	/*
	 * Always-built-in object files map from their TU name to 'vmlinux'.
	 */
	for (i = 0; i < builtin_objects_cnt; i++) {
		/*
		 * Walk over the translation units in the object files and
		 * construct mappings from each TU to "vmlinux".
		 */

		Dwfl *dwfl = simple_dwfl_new(builtin_objects[i]);
		Dwarf_Die *tu = NULL;
		Dwarf_Addr junk;

		while ((tu = dwfl_nextcu(dwfl, tu, &junk)) != NULL) {
			const char *tu_name = dwarf_diename(tu);

			if ((tu_name != NULL) &&
			    (dwarf_tag(tu) == DW_TAG_compile_unit))
				g_hash_table_replace(tu_to_module,
						     xstrdup(tu_name),
						     xstrdup("vmlinux"));
		}
		simple_dwfl_free(dwfl);
	}

	/*
	 * Built-in modules map from their TU name to their module name.
	 */

	for (i = 0; i < builtin_modules_cnt; i++) {
		char *module_name = fn_to_module(builtin_modules[i]);

		/*
		 * Walk over the translation units in this module and construct
		 * mappings from each TU to the module name.
		 */

		Dwfl *dwfl = simple_dwfl_new(builtin_modules[i]);
		Dwarf_Die *tu = NULL;
		Dwarf_Addr junk;

		while ((tu = dwfl_nextcu(dwfl, tu, &junk)) != NULL) {
			const char *tu_name = dwarf_diename(tu);

			if ((tu_name != NULL) &&
			    (dwarf_tag(tu) == DW_TAG_compile_unit))
				g_hash_table_replace(tu_to_module,
						     xstrdup(tu_name),
						     xstrdup(module_name));
		}
		simple_dwfl_free(dwfl);
		free(module_name);
	}
}

/*
 * Type ID computation.
 *
 * A type ID is a constant, recursively-constructed, dynamically-allocated
 * string describing a given DWARF DIE in such a way that any DWARF file
 * containing the same type will have the same type ID.  (It even works for
 * variables!  Variables of the same name and referring to the same type have
 * the same ID...)
 *
 * Optionally, call a callback with the computed ID once we know it (this is a
 * recursive process, so the callback can be called multiple times as the ID is
 * built up).
 *
 * An ID of NULL indicates that this DIE has no ID and need not be considered.
 *
 * It is probably an error for two DWARF DIEs representing top-level types to
 * return the same ID, but for certain other DIEs (notably those representing the
 * members of structures or unions), it is expected that they return the same
 * ID as their type DIE.
 *
 * This function is the hottest hot spot in dwarf2ctf, so is somewhat
 * aggressively optimized.
 */
static char *type_id(Dwarf_Die *die, void (*fun)(Dwarf_Die *die,
						 const char *id,
						 void *data),
		     void *data)
{
	char *id = NULL;
	int no_type_id = 0;
	int decorated = 1;
	Dwarf_Die type_die;

	/*
	 * The ID of a null pointer is NULL.
	 */
	if (die == NULL)
		return NULL;

	/*
	 * The ID of a function pointer is '//fp//', as a special case,
	 * with no location, ever.
	 */
	if (dwarf_tag(die) == DW_TAG_subroutine_type) {
		id = xstrdup("//fp//");
		if (fun)
			fun(die, id, data);
		return id;
	}

	/*
	 * If we have a type DIE, generate it first.
	 *
	 * Otherwise, note the location of this DIE, providing scoping
	 * information for all types based upon this one.  Location elements are
	 * separated by //, an element impossible in a Linux path.
	 *
	 * Array dimensions get none of this: they must be contained within
	 * another DIE, so will always have a location attached via that DIE,
	 * and get their type chased further down (so as to arrange that they
	 * appear inside an [].)
	 */
	if (dwarf_tag(die) != DW_TAG_subrange_type) {
		if (dwarf_tag(die) != DW_TAG_base_type)
			id = type_id(private_dwarf_type(die, &type_die), fun, data);

		/*
		 * Location information.  We use cached realpath() results, and
		 * call str_appendn() only once, minimizing the number of
		 * strlen()s.
		 */
		if (id == NULL) {
			const char *decl_file_name = dwarf_decl_file(die);
			int decl_line_num;
			const char *fname = "";
			char line_num[21] = "";	 /* bigger than 2^64's digit count */

			no_type_id = 1;
			if (decl_file_name != NULL) {
				fname = abs_file_name(decl_file_name);
			}

			if (dwarf_decl_line(die, &decl_line_num) >= 0) {
				snprintf(line_num, sizeof (line_num), "%i",
					 decl_line_num);
			}
			id = str_appendn(id, fname, "//", line_num, "//", NULL);
		}
	}

	/*
	 * We implement this via a switch statement, rather than a jump table
	 * like the assembly_tab, simply because most cases are so small that
	 * splitting them into separate functions would do more harm than good
	 * to readability.
	 *
	 * WARNING: The spaces in the strings in this switch statement are not
	 * just for appearance: types with spaces in their names are impossible
	 * in C.  If you move those spaces around for appearance's sake, please
	 * adjust detect_duplicates_alias_fixup() and
	 * detect_duplicates_alias_fixup_internal(), which construct structure/
	 * union type names by hand.
	 */
	switch (dwarf_tag(die)) {
	case DW_TAG_base_type:
		id = str_appendn(id, dwarf_diename(die), " ", NULL);
		break;
	case DW_TAG_enumeration_type:
		id = str_appendn(id, "enum ", dwarf_diename(die), " ", NULL);
		break;
	case DW_TAG_structure_type:
		id = str_appendn(id, "struct ", dwarf_diename(die), " ", NULL);
		break;
	case DW_TAG_union_type:
		id = str_appendn(id, "union ", dwarf_diename(die), " ", NULL);
		break;
	case DW_TAG_variable:
		id = str_appendn(id, "var ", dwarf_diename(die), " ", NULL);
		break;
	case DW_TAG_typedef:
		id = str_appendn(id, "typedef ", dwarf_diename(die), " ", NULL);
		break;
	case DW_TAG_const_type:
		id = str_append(id, "const ");
		break;
	case DW_TAG_restrict_type:
		id = str_append(id, "restrict ");
		break;
	case DW_TAG_volatile_type:
		id = str_append(id, "volatile ");
		break;
	case DW_TAG_pointer_type:
		if (no_type_id)
			id = str_append(id, "void ");
		id = str_append(id, "* ");
		break;

	case DW_TAG_array_type: {
		/*
		 * No explicit notation: all done per-dimension: so recurse to
		 * those.
		 */

		int sib_ret;
		int dimens = 0;
		Dwarf_Die dim_die;

		switch (dwarf_child(die, &dim_die)) {
		case -1:
			fprintf(stderr, "Corrupt DWARF: Cannot get array "
				"dimensions: %s\n", dwarf_errmsg(dwarf_errno()));
			exit(1);
		case 1: /* No dimensions.  */
			id = str_append(id, "[] ");
			break;
		default:
			dimens = 1;
		}

		if (!dimens)
			break;

		do {
			char *sub_id = type_id(&dim_die, fun, data);
			id = str_append(id, sub_id);
			free(sub_id);
		} while ((sib_ret = dwarf_siblingof(&dim_die, &dim_die)) == 0);

		if (sib_ret == -1) {
			fprintf(stderr, "Corrupt DWARF: Cannot get array "
				"dimensions: %s\n", dwarf_errmsg(dwarf_errno()));
			exit(1);
		}
		break;
	}
	case DW_TAG_subrange_type: {
		Dwarf_Word nelems = private_subrange_dimensions(die);

		id = str_append(id, "[");

		if (nelems > 0)
		{
			char elems[22];	    /* bigger than 2^64's digit count */
			char *sub_id = type_id(private_dwarf_type(die, &type_die),
					       fun, data);

			snprintf(elems, sizeof (elems), " %li", nelems);
			id = str_appendn(id, sub_id, elems, NULL);
			free(sub_id);
		}
		id = str_append(id, "] ");
		break;
	}
	default:
		/*
		 * Some tags (e.g. structure members) get the same ID as their
		 * associated type.  We don't need to call the hook function
		 * again for such tags.
		 */
		decorated = 0;
	}

	if (fun && decorated)
		fun(die, id, data);

	return id;
}

/*
 * Process a file, calling the dwarf_process function for every top-level type
 * found therein.  Optionally call tu_init() at the start of each translation
 * unit, and tu_done() at the end.
 */
static void process_file(const char *file_name,
			 void (*dwarf_process)(const char *module_name,
					       const char *file_name,
					       Dwarf_Die *die,
					       Dwarf_Die *parent_die,
					       void *data),
			 void (*tu_init)(const char *module_name,
					 const char *file_name,
					 Dwarf_Die *tu_die,
					 void *data),
			 void (*tu_done)(const char *module_name,
					 const char *file_name,
					 Dwarf_Die *tu_die,
					 void *data),
			 void *data)
{
	const char *err;
	char *fn_module_name = fn_to_module(file_name);
	const char *module_name = fn_module_name;

	Dwfl *dwfl = simple_dwfl_new(file_name);
	GHashTable *seen_before = g_hash_table_new_full(g_str_hash, g_str_equal,
							free, free);
	Dwarf_Die *tu_die = NULL;
	Dwarf_Addr junk;

	if (seen_before == NULL) {
		fprintf(stderr, "Out of memory creating seen_before hash\n");
		exit(1);
	}

	while ((tu_die = dwfl_nextcu(dwfl, tu_die, &junk)) != NULL) {
		const char *tu_name;

		if (dwarf_tag(tu_die) != DW_TAG_compile_unit) {
			err = "Malformed DWARF: non-compile_unit at top level";
			goto fail;
		}

		tu_name = dwarf_diename(tu_die);

		dw_ctf_trace("Processing %s\n", tu_name);

		/*
		 * If we have seen this TU before, skip it.  We assume that
		 * types in multiple identical TUs are always entirely
		 * identical.  This lets us skip cases where the same object
		 * file is linked in multiple places without scanning every type
		 * in it.  (Note: this may be inaccurate if a TU is built
		 * repeatedly with different #defines in force.  I hope this
		 * cannot happen, but if it does, a workaround a-la libtool is
		 * simple: rename or symlink the TU for such repeated builds.)
		 *
		 * Otherwise, note the name of the module to which this TU maps,
		 * if it is not already known: otherwise, extract that name.
		 */
		if (g_hash_table_lookup_extended(seen_before, tu_name,
						 NULL, NULL))
			continue;

		g_hash_table_replace(seen_before, xstrdup(tu_name), NULL);

		if (!g_hash_table_lookup(tu_to_module, tu_name))
			g_hash_table_replace(tu_to_module,
					     xstrdup(tu_name),
					     xstrdup(fn_module_name));
		else
			module_name = g_hash_table_lookup(tu_to_module, tu_name);

		/*
		 * We are only interested in top-level definitions within each
		 * TU.
		 */
		Dwarf_Die die;

		switch (dwarf_child(tu_die, &die)) {
		case -1:
			err = "fetch first child of TU";
			goto fail;
		case 1: /* No DIEs at all in this TU */
			continue;
		default: /* Child DIEs exist.  */
			break;
		}


		if (tu_init != NULL)
			tu_init(module_name, file_name, tu_die, data);

		process_tu_func(module_name, file_name, tu_die, &die,
				dwarf_process, data);

		if (tu_done != NULL)
			tu_done(module_name, file_name, tu_die, data);
	}

	free(fn_module_name);
	simple_dwfl_free(dwfl);
	g_hash_table_destroy(seen_before);

	return;

 fail:
	fprintf(stderr, "Cannot %s for %s: %s\n", err, module_name,
		dwarf_errmsg(dwarf_errno()));
	exit(1);
}

/*
 * process_file() helper, walking over subroutines and their contained blocks
 * recursively and picking up types therein.
 */
static void process_tu_func(const char *module_name,
			    const char *file_name,
			    Dwarf_Die *parent_die,
			    Dwarf_Die *die,
			    void (*dwarf_process)(const char *module_name,
						  const char *file_name,
						  Dwarf_Die *die,
						  Dwarf_Die *parent_die,
						  void *data),
			    void *data)
{
	const char *err;
	int sib_ret;

	/*
	 * We are only interested in definitions for which we can (eventually)
	 * emit CTF: call the processing function for all such.  Recurse into
	 * subprograms to catch type declarations there as well, since there may
	 * be definitions of aggregates referred to outside this function only
	 * opaquely.
	 */
	do {
		if ((dwarf_tag(die) <= assembly_len) &&
		    (assembly_filter_tab[dwarf_tag(die)] == NULL ||
		     assembly_filter_tab[dwarf_tag(die)](die, parent_die)) &&
		    (assembly_tab[dwarf_tag(die)] != NULL))
			dwarf_process(module_name, file_name, die,
				      parent_die, data);

		if ((dwarf_tag(die) == DW_TAG_subprogram) ||
		    (dwarf_tag(die) == DW_TAG_lexical_block)) {
			Dwarf_Die subroutine_die;

			switch (dwarf_child(die, &subroutine_die)) {
			case -1:
				err = "fetch first child of subroutine";
				goto fail;
			case 1: /* No DIEs at all in this subroutine */
				continue;
			default: /* Child DIEs exist.  */
				break;
			}
			process_tu_func(module_name, file_name, die,
					&subroutine_die, dwarf_process, data);
		}
	} while ((sib_ret = dwarf_siblingof(die, die)) == 0);

	if (sib_ret == -1) {
		err = "fetch sibling";
		goto fail;
	}

	return;
 fail:
	fprintf(stderr, "Cannot %s for %s: %s\n", err, module_name,
		dwarf_errmsg(dwarf_errno()));
	exit(1);
}

/* Duplicate detection. */

/*
 * Scan and identify duplicates across the entire set of object files.
 */
static void scan_duplicates(void)
{
	size_t i;

	/*
	 * First, determine which types are referenced by more than one
	 * translation unit, and construct the mapping from translation unit to
	 * non-builtin module name.
	 *
	 * The first pass detects duplicated types in need of sharing, without
	 * considering opaque/transparent structure/union aliasing.  It requests
	 * an alias detection pass if any structures, or typedefs to them, are
	 * newly marked as shared.
	 *
	 * We must do this even when deduplication is disabled, because we need
	 * the TU->module-name mapping, even if in this case it is trivial.
	 */

	struct detect_duplicates_state state;

	dw_ctf_trace("Duplicate detection: primary pass.\n");

	state.repeat_detection = 0;
	for (i = 0; i < object_names_cnt; i++)
		process_file(object_names[i], detect_duplicates,
			     detect_duplicates_init,
			     detect_duplicates_done, &state);

	if ((!state.repeat_detection) || (builtin_modules == NULL))
		return;

	do {
		/*
		 * The second pass recognizes that opaque structures must be
		 * shared if the transparent equivalents are, and vice versa,
		 * and re-traces all transparent types that need sharing.
		 *
		 * It requests another alias detection pass if any non-opaque
		 * structures are newly marked as shared.
		 */
		dw_ctf_trace("Duplicate detection: alias fixup pass.\n");

		state.repeat_detection = 0;

		for (i = 0; i < object_names_cnt; i++)
			process_file(object_names[i],
				     detect_duplicates_alias_fixup,
				     detect_duplicates_init,
				     detect_duplicates_done, &state);
	} while (state.repeat_detection);
	dw_ctf_trace("Duplicate detection: complete.\n");
}

/*
 * Set up state for detect_duplicates().  A tu_init() callback.
 */
static void detect_duplicates_init(const char *module_name,
				   const char *file_name,
				   Dwarf_Die *tu_die,
				   void *data)
{
	struct detect_duplicates_state *state = data;

	state->module_name = module_name;
	state->structs_seen = g_hash_table_new_full(g_str_hash, g_str_equal,
						    free, free);
}

/*
 * Free state for detect_duplicates().  A tu_done() callback.
 */
static void detect_duplicates_done(const char *module_name,
				   const char *file_name,
				   Dwarf_Die *tu_die,
				   void *data)
{
	struct detect_duplicates_state *state = data;

	g_hash_table_destroy(state->structs_seen);
	state->structs_seen = NULL;
}

/*
 * Duplicate detection.
 *
 * Scan for duplicate types.  A duplicate type is defined as any type which
 * appears in more than one module, or, more precisely, any type for which a
 * type with the same ID already exists in another module.
 *
 * This pass also constructs the id_to_module table, so is essential even when
 * deduplication is disabled (though then it need be run only once.)
 */

static void detect_duplicates(const char *module_name,
			      const char *file_name,
			      Dwarf_Die *die,
			      Dwarf_Die *parent_die,
			      void *data)
{
	char *id = type_id(die, NULL, NULL);

	/*
	 * If a DWARF-4 type signature is found, abort.  While we can support
	 * DWARF-4 eventually, support in elfutils is insufficiently robust for
	 * now (elfutils 0.152).
	 */
	if (dwarf_hasattr(die, DW_AT_type)) {
		Dwarf_Attribute type_attr;

		if ((dwarf_attr(die, DW_AT_type, &type_attr) != NULL) &&
		    (dwarf_whatform(&type_attr) == DW_FORM_ref_sig8)) {
			fprintf(stderr, "sorry, not yet implemented: %s "
				"contains DWARF-4 debugging information.\n",
				file_name);
			exit(1);
		}
	}


	/*
	 * If we know of a single module incorporating this type, and it is not
	 * the same as the module we are currently in, then this type is
	 * duplicated across modules and belongs in the global type table.
	 * (This means that duplicated types are repeatedly so marked: this
	 * is unavoidable, because pass 3 requires re-marking structures that
	 * have already been marked, to pick up unmarked intermediate types.)
	 *
	 * We never consider types in modules on the deduplication blacklist
	 * to introduce duplicates.
	 */
	const char *existing_type_module;

	existing_type_module = g_hash_table_lookup(id_to_module, id);

	if (existing_type_module != NULL) {
		if ((strcmp(existing_type_module, module_name) != 0) &&
		    (builtin_modules != NULL) &&
		    (dedup_blacklist == NULL ||
		     !g_hash_table_lookup_extended(dedup_blacklist, module_name,
						   NULL, NULL))) {
			mark_shared(die, NULL, data);
			mark_seen_contained(die, "shared_ctf");
		}

		/*
		 * A duplicated type, but in the same module, or deduplication
		 * is disabled, so id_to_module is already correct.  (When
		 * deduplication is disabled, we will be running with only one
		 * module at a time, and id_to_module will be a trivial
		 * mapping.)
		 */
		free(id);
		return;
	}

	/*
	 * Record that we have seen this type in this module.
	 */

	dw_ctf_trace("Marking %s as seen in %s\n", id, module_name);
	g_hash_table_replace(id_to_module, id, xstrdup(module_name));
	mark_seen_contained(die, module_name);
}

/*
 * Mark any aggregates contained within a particular type DIE as seen.  This is
 * needed since even nameless aggregates contained within other aggregates can
 * be used as the type of members of the outer aggregate (though they cannot
 * possibly be found in a module different from that of their containing
 * aggregate, any more than a structure member can).
 */
static void mark_seen_contained(Dwarf_Die *die, const char *module_name)
{
	const char *err;
	Dwarf_Die child;

	if ((dwarf_tag(die) != DW_TAG_structure_type) &&
	    (dwarf_tag(die) != DW_TAG_union_type))
		return;

	switch (dwarf_child(die, &child)) {
	case -1:
		err = "fetch first child of aggregate";
		goto fail;
	case 1: /* No DIEs at all in this aggregate */
		return;
	default: /* Child DIEs exist.  */
		break;
	}

	/*
	 * We are only interested in children of type DW_TAG_structure_type,
	 * DW_TAG_union_type, or DW_TAG_enumeration_type (and only the former
	 * two require further recursion, since only they can have members).
	 */
	int sib_ret;

	do
		switch (dwarf_tag(&child)) {
		case DW_TAG_structure_type:
		case DW_TAG_union_type:
			mark_seen_contained(&child, module_name);
			/* fall through */
		case DW_TAG_enumeration_type: {
			char *id = type_id(&child, NULL, NULL);

			dw_ctf_trace("Marking %s as seen in %s\n", id,
				     module_name);
			g_hash_table_replace(id_to_module, id,
					     xstrdup(module_name));
		}
		}
	while ((sib_ret = dwarf_siblingof(&child, &child)) == 0);

	if (sib_ret == -1) {
		err = "iterate over members";
		goto fail;
	}

	return;

 fail:
	fprintf(stderr, "Cannot %s while marking aggregates as seen: %s\n",
		err, dwfl_errmsg(dwfl_errno()));
	exit(1);
}

/*
 * Mark a type as duplicated and located in the shared CTF table.  Recursive,
 * via the type_id() callback mechanism.
 *
 * A type_id() callback (though also called directly).
 */
static void mark_shared(Dwarf_Die *die, const char *id, void *data)
{
	struct detect_duplicates_state *state = data;
	const char *existing_module;

	/*
	 * Non-recursive call.  Trigger type_id for its recursive callback,
	 * throwing the result away.
	 */
	if (id == NULL) {
		free(type_id(die, mark_shared, state));
		return;
	}

	existing_module = g_hash_table_lookup(id_to_module, id);

	if ((existing_module == NULL) ||
	    (strcmp(existing_module, "shared_ctf") != 0)) {

		dw_ctf_trace("Marking %s as duplicate\n", id);
		g_hash_table_replace(id_to_module, xstrdup(id),
				     xstrdup("shared_ctf"));

		/*
		 * Newly-marked structures or unions must trigger a new
		 * duplicate detection pass (even if they are opaque).
		 */

		if (((dwarf_tag(die) == DW_TAG_structure_type) ||
		     (dwarf_tag(die) == DW_TAG_union_type)) &&
		    (!state->repeat_detection)) {
			dw_ctf_trace("Requesting another duplicate detection "
				     "pass.\n");
			state->repeat_detection = 1;
		}
	}

	/*
	 * If this is a structure or union, mark its members as duplicates too.
	 *
	 * Do this even if we've seen this structure before, as this instance of
	 * the structure may have more members than the last we saw.  However,
	 * if we have seen this structure before *in this translation unit*,
	 * skip it, to avoid infinite recursion in mutually referential
	 * structures.
	 */
	if ((dwarf_tag(die) == DW_TAG_structure_type) ||
	    (dwarf_tag(die) == DW_TAG_union_type)) {
		Dwarf_Die child;

		if (g_hash_table_lookup_extended(state->structs_seen, id,
						 NULL, NULL))
			return;
		g_hash_table_replace(state->structs_seen, xstrdup(id), NULL);

		switch (dwarf_child(die, &child)) {
		case -1:
			goto fail;
		case 1: /* No DIEs at all in this aggregate */
			return;
		}

		/*
		 * We are only interested in non-blacklisted children of type
		 * DW_TAG_member.
		 */
		int sib_ret;

		do
			if (!member_blacklisted(&child, die))
				free(type_id(&child, mark_shared, state));
		while ((sib_ret = dwarf_siblingof(&child, &child)) == 0);

		if (sib_ret == -1)
			goto fail;
	}

	return;

 fail:
	fprintf(stderr, "Cannot mark aggregate %s members as duplicated: %s\n",
		dwarf_diename(die), dwarf_errmsg(dwarf_errno()));
	exit(1);
}

/*
 * Duplicate detection alias fixup pass.  Once the first pass is complete, we
 * may have marked an opaque 'struct foo' for sharing but not caught the
 * non-opaque instance, because no users of the non-opaque instance appeared in
 * the DWARF after the opaque copy was detected as a duplicate.
 *
 * (The inverse case of a non-opaque structure/union/enum detected as a
 * duplicate after the last usage of its opaque alias will be caught by this
 * trap too.)
 *
 * This detects such cases, and marks their members as duplicates too.
 * (Structures, unions, and enums with no name are skipped, because they cannot
 * have opaque equivalents, so must have been marked in the primary pass.)
 */
static void detect_duplicates_alias_fixup(const char *module_name,
					  const char *file_name,
					  Dwarf_Die *die,
					  Dwarf_Die *parent_die,
					  void *data)
{
	int is_sou = 0;

	/*
	 * We skip this for all modules in the deduplication blacklist, if there
	 * is one.
	 */
	if (dedup_blacklist != NULL &&
	    g_hash_table_lookup_extended(dedup_blacklist, module_name,
					 NULL, NULL))
		return;

	/*
	 * We only do anything for structures and unions that are not opaque,
	 * and that have names.
	 */

	char *id = type_id(die, is_named_struct_union_enum, &is_sou);

	if ((strncmp(id, "////", strlen("////")) == 0) || !is_sou) {
		free(id);
		return;
	}
	free(id);

	free(type_id(die, detect_duplicates_alias_fixup_internal, data));
}

/*
 * Determine if a type is a named struct, union, or enum.
 *
 * A type_id() callback.
 */
static void is_named_struct_union_enum(Dwarf_Die *die, const char *unused,
				       void *data)
{
	int *is_sou = data;

	if (((dwarf_tag(die) == DW_TAG_structure_type) ||
	     (dwarf_tag(die) == DW_TAG_union_type) ||
	     (dwarf_tag(die) == DW_TAG_enumeration_type)) &&
	    (dwarf_hasattr(die, DW_AT_name)))
		*is_sou = 1;
}

/*
 * Determine if some type (whose ultimate base type is an non-opaque structure,
 * alias, or enum) has an opaque equivalent which is shared, and mark it and
 * all its bases as shared too if so.
 *
 * A type_id() callback.
 *
 * Warning: this routine directly computes type_id()s without access to the
 * corresponding type DIE, and as such is dependent on the format of type_id()s.
 * (This is why it must run over non-opaque structures: given a non-opaque
 * structure, its opaque alias is easy to compute, but the converse is not
 * true.)
 */
static void detect_duplicates_alias_fixup_internal(Dwarf_Die *die,
						   const char *id, void *data)
{
	int transparent_shared = 0;
	int opaque_shared = 0;

	char *opaque_id;
	const char *line_num;
	const char *type_name;

	/*
	 * We don't care about array index types, which will never be structures
	 * in C.
	 */
	if (id[0] == '[')
		return;

	/*
	 * Compute the opaque variant corresponding to this transparent type,
	 * and check to see if either is marked shared, then mark both as shared
	 * if either is.  (Unfortunately this means a double recursion in such
	 * cases, but this is unavoidable.)
	 */

	line_num = strstr(id, "//");
	if (!line_num) {
		fprintf(stderr, "Internal error: type ID %s is corrupt.\n",
			id);
		exit(1);
	}

	type_name = strstr(line_num + 1, "//");
	if (!type_name) {
		fprintf(stderr, "Internal error: type ID %s is corrupt.\n",
			id);
		exit(1);
	}
	type_name += 2;

	opaque_id = xstrdup("////");
	opaque_id = str_append(opaque_id, type_name);

	const char *transparent_module = g_hash_table_lookup(id_to_module,
							     id);
	const char *opaque_module = g_hash_table_lookup(id_to_module,
							opaque_id);

	transparent_shared = ((transparent_module != NULL) &&
			      (strcmp(transparent_module, "shared_ctf") == 0));

	opaque_shared = ((opaque_module != NULL) &&
			 (strcmp(opaque_module, "shared_ctf") == 0));

	/*
	 * Transparent type needs sharing.
	 */
	if (opaque_shared && !transparent_shared)
		mark_shared(die, NULL, data);

	/*
	 * We don't have the opaque type's DIE, so we can't use mark_shared():
	 * this is also good since this triggers another duplicate detection
	 * pass, and we don't want to trigger another pass merely because of a
	 * nonshared opaque type (since they don't have members that may have
	 * structure or union type themselves and thus force more unshared
	 * types to become shared).
	 *
	 * Instead, do it by hand: this is simple, as member recursion is
	 * guaranteed not to be required for an opaque type.
	 */
	if (transparent_shared && !opaque_shared) {
		dw_ctf_trace("Marking %s as duplicate\n", opaque_id);
		g_hash_table_replace(id_to_module, xstrdup(opaque_id),
				     xstrdup("shared_ctf"));
	}

	free(opaque_id);
}

/*
 * Type assembly.
 *
 * Given a DWARF DIE corresponding to a top-level type, call the appropriate
 * construction function, passing it the appropriate ctf_file_t, constructing it
 * if necessary, and stashing them in the appropriate hashes.  Return the
 * ctf_file_t and ctf_id_t of this type.
 *
 * Indirectly recursively called for types depending on other types, and for
 * the types of variables (which for the sake of argument we call 'types' here
 * too, since we treat them exactly like types, and dealing with types is our
 * most important function.)
 */
static ctf_full_id_t *construct_ctf_id(const char *module_name,
				       const char *file_name,
				       Dwarf_Die *die,
				       Dwarf_Die *parent_die)
{
	char *id = type_id(die, NULL, NULL);
	char *ctf_module;
	ctf_file_t *ctf;

	dw_ctf_trace("    %p: %s: looking up %s: %s\n", &id, module_name,
		     dwarf_diename(die), id);
	/*
	 * Make sure this type does not already exist.  (Recursive chasing for
	 * referenced types can lead to construct_ctf() being called on them
	 * more than once.)
	 */
	ctf_full_id_t *ctf_id;
	if ((ctf_id = g_hash_table_lookup(id_to_type, id)) != NULL) {
		dw_ctf_trace("    %p: %p:%i found in module %s, file %s\n", &id,
			     ctf_id->ctf_file, (int) ctf_id->ctf_id,
			     ctf_id->module_name, ctf_id->file_name);
		free(id);
		return ctf_id;
	}

	/*
	 * Create the CTF file for this type, if it does not exist.  Verify that
	 * the duplicate-detection pass scanned this type, and that this is
	 * either the current module or the shared CTF module.
	 */

	ctf_module = g_hash_table_lookup(id_to_module, id);

	if (ctf_module == NULL) {
		fprintf(stderr, "Internal error: within file %s, module %s, "
			"type at DIE offset %lx with ID %s was not already "
			"noted by detect_duplicates().\n", file_name,
			module_name, (unsigned long) dwarf_dieoffset(die), id);
		fprintf(stderr, "detect_duplicates() is probably buggy.\n");
		exit(1);
	}

	if ((strcmp(ctf_module, module_name) != 0) &&
	    (strcmp(ctf_module, "shared_ctf") != 0)) {
		fprintf(stderr, "Internal error: within file %s, module %s, "
			"type at DIE offset %lx with ID %s is in a different "
			"non-shared module, %s.\n", file_name, module_name,
			(unsigned long) dwarf_dieoffset(die), id, ctf_module);
		fprintf(stderr, "detect_duplicates() is probably buggy.\n");
		exit(1);
	}

	ctf = g_hash_table_lookup(module_to_ctf_file, ctf_module);

	if (ctf == NULL) {
		ctf = init_ctf_table(ctf_module);
		dw_ctf_trace("%p: %s: initialized CTF file %p\n", &id,
			     module_name, ctf);
	}

	/*
	 * Construct the CTF, then insert the top-level CTF entity into the
	 * id->type hash so that references from other types can find it, and
	 * update the CTF container.  If conversion failed, roll back all
	 * changes made since the last successful call to this function.
	 *
	 * NOTE: references within DWARF to non-top-level types will currently
	 * fail, but I'm not sure if these can exist.  (The type ID
	 * representation implicitly assumes that they cannot.)
	 */

	enum skip_type skip = SKIP_CONTINUE;
	dw_ctf_trace("%p: into die_to_ctf() for %s\n", &id, id);
	ctf_id_t this_ctf_id = die_to_ctf(module_name, file_name, die,
					  parent_die, ctf, -1, 0, 1, &skip,
					  NULL, id);
	dw_ctf_trace("%p: out of die_to_ctf()\n", &id);

	ctf_id = malloc(sizeof (struct ctf_full_id));
	if (ctf_id == NULL) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}

	if (skip != SKIP_ABORT) {
		if (ctf_update(ctf) < 0) {
			fprintf(stderr, "Cannot update CTF file: %s\n",
				ctf_errmsg(ctf_errno(ctf)));
			exit(1);
		}

		ctf_id->ctf_file = ctf;
		ctf_id->ctf_id = this_ctf_id;
#ifdef DEBUG
		strcpy(ctf_id->module_name, module_name);
		strcpy(ctf_id->file_name, file_name);
#endif
		g_hash_table_replace(id_to_type, id, ctf_id);

		dw_ctf_trace("    %lx: %s: new type added, CTF ID %p:%i\n",
			     (unsigned long) dwarf_dieoffset(die), id,
			     ctf_id->ctf_file, (int) ctf_id->ctf_id);
	} else {
		/*
		 * Failure.  Remove the type from the id_to_type mapping, if it
		 * is there, and discard any added types from the CTF.
		 */

		if (ctf_discard(ctf) < 0) {
			fprintf(stderr, "Cannot discard from CTF file on "
				"conversion failure or skip: %s\n",
				ctf_errmsg(ctf_errno(ctf)));
			exit(1);
		}

		free(ctf_id);
		ctf_id = NULL;

		g_hash_table_remove(id_to_type, id);
		free(id);

		dw_ctf_trace("    %p: (failure)\n", &id);
	}

	return ctf_id;
}

/*
 * Given a DWARF DIE corresponding to a top-level type, or to an aggregate
 * member, and the ctf_file_t where it is to be placed, call the appropriate
 * construction function to place it and (for aggregates) its siblings there,
 * recursing to handle contained aggregates.
 *
 * The parameters to this function are:
 *
 * module_name: The kernel module.
 * file_name: The object file.
 * die: The DWARF DIE.
 * parent_die: Its parent, i.e. if a structure member, this is a structure: if
 * top-level, this is a CU DIE.
 * ctf: The CTF file this object should go into (possibly shared_ctf).
 * parent_ctf_id: The CTF ID of the parent DIE, or -1 if none.
 * parent_bias: any bias applied to structure members.  Normally 0, may be
 * nonzero for unnamed structure members.
 * top_level_type: 1 if this is a top-level type that can have a name and be
 * referred to by other types.
 * skip: The error-handling / skipping enum.
 * override: if 1, this type should replace its parent type entirely.
 * id: the ID of this type.
 *
 * Note: id is only defined when top_level_type is 1.  (We never use it
 * in other situations, and computing it is quite expensive.)
 */
static ctf_id_t die_to_ctf(const char *module_name, const char *file_name,
			   Dwarf_Die *die, Dwarf_Die *parent_die,
			   ctf_file_t *ctf, ctf_id_t parent_ctf_id,
			   ulong_t parent_bias, int top_level_type,
			   enum skip_type *skip, int *override,
			   const char *id)
{
	int sib_ret = 0;
	ctf_id_t this_ctf_id;
	int dummy;

	do {
		const char *id_name;
		const char *decl_file_name = dwarf_decl_file(die);
		int decl_line_num;
		char locerrstr[1024];

		/*
		 * Compute a name for our current location, for error messages.
		 * (The type representation could be used, but is likely to be
		 * hard for users to comprehend, and should we move to a hashed
		 * representation would be entirely useless for this purpose.)
		 */

		if ((decl_file_name == NULL) ||
		    (dwarf_decl_line(die, &decl_line_num) < 0)) {
			decl_file_name = "global";
			decl_line_num = 0;
		}

		id_name = dwarf_diename(die);
		if (id_name == NULL)
			id_name = "(unnamed type)";

		snprintf(locerrstr, sizeof (locerrstr), "%s:%i:%s",
			 decl_file_name, decl_line_num, id_name);

		dw_ctf_trace("Working over %s:%s:%s:%lx:%x with CTF file %p\n",
			     module_name, file_name,
			     dwarf_diename(die)==NULL?"NULL":dwarf_diename(die),
			     (unsigned long) dwarf_dieoffset(die),
			     dwarf_tag(die), ctf);

		/*
		 * Only process a given node, or its children, if we know how to
		 * do so.
		 */
		if ((dwarf_tag(die) >= assembly_len) ||
		    (assembly_tab[dwarf_tag(die)] == NULL)) {
			fprintf(stderr, "%s:%i: warning: skipping identifier "
				"%s with unknown DWARF tag %lx.\n",
				decl_file_name, decl_line_num, id_name,
				(unsigned long) dwarf_tag(die));
			return -1;
		}

		*skip = SKIP_CONTINUE;

		this_ctf_id = assembly_tab[dwarf_tag(die)](module_name,
							   file_name,
							   die, parent_die,
							   parent_bias, ctf,
							   parent_ctf_id,
							   locerrstr,
							   top_level_type,
							   skip,
							   override ? override :
							   &dummy);
		dw_ctf_trace("%s: out of assembly function for tag %lx with "
			     "type ID %li\n", locerrstr,
			     (unsigned long) dwarf_tag(die), this_ctf_id);

		if (this_ctf_id < 0) {
			if ((this_ctf_id == CTF_NO_ERROR_REPORTED) &&
			    (ctf_errno(ctf) != 0))
				fprintf(stderr, "%s: CTF error in assembly of "
					"item with tag %i: %s\n", locerrstr,
					dwarf_tag(die),
					ctf_errmsg(ctf_errno(ctf)));

			num_errors++;
#ifdef DEBUG
			exit(1);
#endif
			*skip = SKIP_ABORT;
		}

		/*
		 * Add newly-added non-skipped top-level structure or union CTF
		 * IDs to the type table at once.  This allows circular type
		 * references via pointers in structure/union member DIEs to be
		 * looked up correctly.
		 */
		if (top_level_type && (*skip == SKIP_CONTINUE) &&
		    ((dwarf_tag(die) == DW_TAG_structure_type) ||
		     (dwarf_tag(die) == DW_TAG_union_type))) {
			ctf_full_id_t full_ctf_id = { ctf, this_ctf_id };
			ctf_full_id_t *ctf_id;

#ifdef DEBUG
			strcpy(full_ctf_id.module_name, module_name);
			strcpy(full_ctf_id.file_name, file_name);
#endif

			if ((ctf_id = malloc(sizeof (ctf_full_id_t))) == NULL) {
				fprintf(stderr, "Out of memory allocating "
					"type ID\n");
				exit(1);
			}

			dw_ctf_trace("    die_to_ctf(): immediate addition of "
				     "%s, CTF ID %p:%li in module %s, file %s\n",
				     id, full_ctf_id.ctf_file, full_ctf_id.ctf_id,
				     module_name, file_name);
			*ctf_id = full_ctf_id;

			g_hash_table_replace(id_to_type, xstrdup(id), ctf_id);

			/*
			 * This prevents a clean rollback on error from deeply
			 * nested types: some unreachable types may persist.
			 * Probably unfixable wihtout a radical rewrite of
			 * libctf (a good idea anyway, ctf_update() is terribly
			 * slow).
			 */
			if (ctf_update(ctf) < 0) {
				fprintf(stderr, "Cannot update CTF file: %s\n",
					ctf_errmsg(ctf_errno(ctf)));
				exit(1);
			}
		}

		/*
		 * Recurse to handle contained DIEs.
		 */

		if ((dwarf_haschildren(die)) && (*skip == SKIP_CONTINUE)) {
			Dwarf_Die child_die;
			ctf_id_t new_id;
			int override = 0;

			if (dwarf_child(die, &child_die) < 0) {
				fprintf(stderr, "%s: Cannot recurse to "
					"DWARF DIE children: %s\n", locerrstr,
					dwarf_errmsg(dwarf_errno()));
				exit(1);
			}

			new_id = die_to_ctf(module_name, file_name, &child_die,
					    die, ctf, this_ctf_id, parent_bias,
					    0, skip, &override, NULL);

			if (override)
				this_ctf_id = new_id;
		}

		/*
		 * Walk siblings of non-top-level types only: the sibling walk
		 * of top-level types is done by process_file(), so that
		 * construct_ctf_id() gets a chance to put each such type in the
		 * right CTF file.
		 */
	} while (*skip != SKIP_ABORT && !top_level_type &&
		 (sib_ret = dwarf_siblingof(die, die)) == 0);

	if (sib_ret == -1) {
		fprintf(stderr, "In module %s, failure walking the sibling "
			"list: %s\n", module_name, dwarf_errmsg(dwarf_errno()));
		exit(1);
	}

	dw_ctf_trace("New type ID: %p:%li\n", ctf, this_ctf_id);
	return this_ctf_id;
}

/*
 * Calls construct_ctf_id() and throws the ID away.  Used as a process_file()
 * callback.
 */
static void construct_ctf(const char *module_name, const char *file_name,
			  Dwarf_Die *die, Dwarf_Die *parent_die,
			  void *unused __unused__)
{
	construct_ctf_id(module_name, file_name, die, parent_die);
}

/*
 * Look up a type through its reference: return its ctf_id, or recursively
 * construct it if need be.
 */
static ctf_id_t lookup_ctf_type(const char *module_name, const char *file_name,
				Dwarf_Die *die, ctf_file_t *ctf,
				const char *locerrstr)
{
	Dwarf_Die tmp;
	Dwarf_Die *type_die = private_dwarf_type(die, &tmp);
	Dwarf_Die cu_die;
	ctf_full_id_t *type_ref;

	/*
	 * Pointers to functions and void are special cases: there is only one
	 * of each of these in CTF, so we can use global singletons.
	 */

	if (type_die == NULL)
		return ctf_void_type;

	if (dwarf_tag(type_die) == DW_TAG_subroutine_type)
		return ctf_funcptr_type;

	/*
	 * Look up or construct CTF for this type.
	 */

	dwarf_diecu(type_die, &cu_die, NULL, NULL);

	dw_ctf_trace("    %s: Looking up dependent type at offset %lx "
		     "for type %s at module %s, file %s\n", locerrstr,
		     (unsigned long) dwarf_dieoffset(type_die),
		     dwarf_diename(die) ? dwarf_diename(die) : "NULL",
		     module_name, file_name);

	type_ref = construct_ctf_id(module_name, file_name,
				    type_die, &cu_die);

	/*
	 * Pass any error back up.
	 */
	if (type_ref == NULL) {
		fprintf(stderr, "%s: type lookup failed.\n", locerrstr);
		return -1;
	}

	if ((type_ref->ctf_file != ctf) &&
	    type_ref->ctf_file != g_hash_table_lookup(module_to_ctf_file,
						      "shared_ctf")) {
#ifdef DEBUG
		fprintf(stderr, "%s: Internal error: lookup of %s found in "
			"different file: %s/%s versus %s/%s.\n", locerrstr,
			dwarf_diename(die) ? dwarf_diename(die) : "(unnamed)",
			type_ref->module_name, type_ref->file_name, module_name,
			file_name);
#else
		fprintf(stderr, "%s: Internal error: lookup of %s found in different "
			"file.\n", locerrstr,
			dwarf_diename(die) ? dwarf_diename(die) : "(unnamed)");
#endif
		fprintf(stderr, "detect_duplicates() is probably buggy.\n");
		exit(1);
	}

	return type_ref->ctf_id;
}

/* Assembly functions.  */

#define CTF_DW_ENFORCE(attribute) do 						\
		if (!dwarf_hasattr(die, (DW_AT_##attribute))) {			\
			fprintf(stderr, "%s: %s: %lx: skipping type, %s attribute not "	\
				"present.\n", locerrstr, __func__,		\
				(unsigned long) dwarf_dieoffset(die), #attribute); \
			*skip = SKIP_ABORT;					\
			return CTF_ERROR_REPORTED;				\
		}								\
	while (0)

#define CTF_DW_ENFORCE_NOT(attribute) do					\
		if (dwarf_hasattr(die, (DW_AT_##attribute))) {			\
			fprintf(stderr, "%s: %s: %lx: skipping type, %s attribute not "	\
				"supported.\n", locerrstr, __func__,		\
				(unsigned long) dwarf_dieoffset(die), #attribute); \
			*skip = SKIP_ABORT;					\
			return CTF_ERROR_REPORTED;				\
		}								\
	while (0)

/*
 * A CTF assembly filter function which excludes all types not at the global
 * scope (i.e. whose immediate parent is not a CU DIE).
 */
static int filter_ctf_file_scope(Dwarf_Die *die __unused__, Dwarf_Die *parent_die)
{
	return (dwarf_tag(parent_die) == DW_TAG_compile_unit);
}

/*
 * A CTF assembly filter function which excludes all names not at the global
 * scope, all static symbols, and all names whose names are unlikely to be
 * interesting.  (DTrace userspace contains a similar list, but the two lists
 * need not be in sync.)
 */
static int filter_ctf_uninteresting(Dwarf_Die *die,
				    Dwarf_Die *parent_die)
{
	const char *sym_name = dwarf_diename(die);

	/*
	 * 'Variables' with no name are not interesting.
	 */
	if (sym_name == NULL)
		return 0;

#define strstarts(var, x) (strncmp(var, x, strlen (x)) == 0)
	return ((dwarf_tag(parent_die) == DW_TAG_compile_unit) &&
		(dwarf_hasattr(die, DW_AT_external)) &&
		!((strcmp(sym_name, "__per_cpu_start") == 0) ||
		  (strcmp(sym_name, "__per_cpu_end") == 0) ||
		  (strstarts(sym_name, "__crc_")) ||
		  (strstarts(sym_name, "__ksymtab_")) ||
		  (strstarts(sym_name, "__kcrctab_")) ||
		  (strstarts(sym_name, "__kstrtab_")) ||
		  (strstarts(sym_name, "__param_")) ||
		  (strstarts(sym_name, "__syscall_meta__")) ||
		  (strstarts(sym_name, "__p_syscall_meta__")) ||
		  (strstarts(sym_name, "__event_")) ||
		  (strstarts(sym_name, "event_")) ||
		  (strstarts(sym_name, "ftrace_event_")) ||
		  (strstarts(sym_name, "types__")) ||
		  (strstarts(sym_name, "args__")) ||
		  (strstarts(sym_name, "__tracepoint_")) ||
		  (strstarts(sym_name, "__tpstrtab_")) ||
		  (strstarts(sym_name, "__tpstrtab__")) ||
		  (strstarts(sym_name, "__initcall_")) ||
		  (strstarts(sym_name, "__setup_")) ||
		  (strstarts(sym_name, "__pci_fixup_")) ||
		  (strstr(sym_name, ".") != NULL)));
#undef strstarts
}

/*
 * Assemble base types.
 */
static ctf_id_t assemble_ctf_base(const char *module_name,
				  const char *file_name, Dwarf_Die *die,
				  Dwarf_Die *parent_die, ulong_t parent_bias,
				  ctf_file_t *ctf, ctf_id_t parent_ctf_id,
				  const char *locerrstr, int top_level_type,
				  enum skip_type *skip, int *override)
{
	typedef ctf_id_t (*ctf_add_fun)(ctf_file_t *, uint_t,
					const char *, const ctf_encoding_t *);

	const char *name = dwarf_diename(die);
	Dwarf_Attribute encoding_attr, size_attr;
	Dwarf_Word encoding, size;
	ctf_add_fun ctf_add_func;
	ctf_encoding_t ctf_encoding;
	size_t encoding_search;

	struct dwarf_encoding_tab {
		Dwarf_Word encoding;
		ctf_add_fun func;
		uint_t encoding_fixed;
		struct type_encoding_tab *size_lookup;
	};

	struct type_encoding_tab float_encoding[] =
		{{sizeof (float), CTF_FP_SINGLE },
		 {sizeof (double), CTF_FP_DOUBLE },
		 {sizeof (long double), CTF_FP_LDOUBLE },
		 {0, 0}};

	struct type_encoding_tab float_cplx_encoding[] =
		{{sizeof (float), CTF_FP_CPLX },
		 {sizeof (double), CTF_FP_DCPLX },
		 {sizeof (long double), CTF_FP_LDCPLX },
		 {0, 0}};

	struct type_encoding_tab float_imagry_encoding[] =
		{{sizeof (float), CTF_FP_IMAGRY },
		 {sizeof (double), CTF_FP_DIMAGRY },
		 {sizeof (long double), CTF_FP_LDIMAGRY },
		 {0, 0}};

	struct dwarf_encoding_tab all_encodings[] =
		{{DW_ATE_boolean, ctf_add_integer, CTF_INT_BOOL, NULL},
		 {DW_ATE_signed, ctf_add_integer, CTF_INT_SIGNED, NULL},
		 {DW_ATE_signed_char, ctf_add_integer,
		  CTF_INT_SIGNED | CTF_INT_CHAR, NULL},
		 {DW_ATE_unsigned, ctf_add_integer, 0, NULL},
		 {DW_ATE_unsigned_char, ctf_add_integer, CTF_INT_CHAR, NULL},
		 {DW_ATE_float, ctf_add_float, 0, float_encoding},
		 {DW_ATE_complex_float, ctf_add_float, 0, float_cplx_encoding},
		 {DW_ATE_imaginary_float, ctf_add_float, 0,
		  float_imagry_encoding},
		 {0, 0, 0, 0}};

	CTF_DW_ENFORCE(name);
	CTF_DW_ENFORCE(encoding);
	CTF_DW_ENFORCE(byte_size);
	CTF_DW_ENFORCE_NOT(bit_size);
	CTF_DW_ENFORCE_NOT(endianity);

	dwarf_attr(die, DW_AT_encoding, &encoding_attr);
	dwarf_formudata(&encoding_attr, &encoding);

	if ((dwarf_attr(die, DW_AT_byte_size, &size_attr) == NULL) ||
	    (dwarf_formudata(&size_attr, &size) < 0)) {
		fprintf(stderr, "%s: skipping type, cannot get size: %s\n",
			locerrstr, dwarf_errmsg(dwarf_errno()));
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}

	for (encoding_search = 0; all_encodings[encoding_search].func != 0;
	     encoding_search++) {
		if (all_encodings[encoding_search].encoding == encoding) {
			ctf_add_func = all_encodings[encoding_search].func;
			if (all_encodings[encoding_search].size_lookup != NULL)
				ctf_encoding.cte_format =
					find_ctf_encoding(all_encodings[encoding_search].size_lookup,
							  size);
			else
				ctf_encoding.cte_format =
					all_encodings[encoding_search].encoding_fixed;
			break;
		}
	}

	if (all_encodings[encoding_search].func == 0) {
		fprintf(stderr, "%s: skipping type, base type %li "
			"not yet implemented.\n", locerrstr, (long) encoding);
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}
	ctf_encoding.cte_offset = 0;
	ctf_encoding.cte_bits = size * 8;

	return ctf_add_func(ctf, top_level_type ? CTF_ADD_ROOT : CTF_ADD_NONROOT,
			    name, &ctf_encoding);
}

/*
 * Assemble pointer types.
 */
static ctf_id_t assemble_ctf_pointer(const char *module_name,
				     const char *file_name,
				     Dwarf_Die *die, Dwarf_Die *parent_die,
				     ulong_t parent_bias, ctf_file_t *ctf,
				     ctf_id_t parent_ctf_id,
				     const char *locerrstr, int top_level_type,
				     enum skip_type *skip, int *override)
{
	ctf_id_t type_ref;

	if ((type_ref = lookup_ctf_type(module_name, file_name, die, ctf,
					locerrstr)) < 0) {
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}

	/*
	 * Pointers to functions are all the same type in CTF: don't bother
	 * adding it over again.
	 */
	if (type_ref == ctf_funcptr_type)
		return type_ref;

	return ctf_add_pointer(ctf, top_level_type ? CTF_ADD_ROOT : CTF_ADD_NONROOT,
			       type_ref);
}

/*
 * Assemble array types.  This function looks up the array type, but does not do
 * any array construction: that is left to assemble_ctf_array_dimension().
 */
static ctf_id_t assemble_ctf_array(const char *module_name,
				   const char *file_name, Dwarf_Die *die,
				   Dwarf_Die *parent_die, ulong_t parent_bias,
				   ctf_file_t *ctf, ctf_id_t parent_ctf_id,
				   const char *locerrstr, int top_level_type,
				   enum skip_type *skip, int *override)
{
	ctf_id_t type_ref;

	CTF_DW_ENFORCE_NOT(name);
	CTF_DW_ENFORCE_NOT(ordering);
	CTF_DW_ENFORCE_NOT(bit_stride);
	CTF_DW_ENFORCE_NOT(byte_stride);

	if ((type_ref = lookup_ctf_type(module_name, file_name, die, ctf,
					locerrstr)) < 0) {
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}
	return type_ref;
}

/*
 * Assemble an array dimension, wrapping an array round the parent_ctf_id and
 * replacing it.
 */
static ctf_id_t assemble_ctf_array_dimension(const char *module_name,
					     const char *file_name,
					     Dwarf_Die *die,
					     Dwarf_Die *parent_die,
					     ulong_t parent_bias,
					     ctf_file_t *ctf,
					     ctf_id_t parent_ctf_id,
					     const char *locerrstr,
					     int top_level_type,
					     enum skip_type *skip,
					     int *override)
{
	ctf_arinfo_t arinfo;

	CTF_DW_ENFORCE_NOT(bit_size);
	CTF_DW_ENFORCE_NOT(byte_size);
	CTF_DW_ENFORCE_NOT(bit_stride);
	CTF_DW_ENFORCE_NOT(byte_stride);
	CTF_DW_ENFORCE_NOT(lower_bound);
	CTF_DW_ENFORCE_NOT(threads_scaled);

	arinfo.ctr_contents = parent_ctf_id;

	if ((arinfo.ctr_index = lookup_ctf_type(module_name, file_name, die,
						ctf, locerrstr)) < 0) {
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}

	arinfo.ctr_nelems = private_subrange_dimensions(die);

	/*
	 * For each array dimension, construct an appropriate array of the
	 * type-so-far, overriding the parent type.
	 */

	*override = 1;
	return ctf_add_array(ctf, top_level_type ? CTF_ADD_ROOT : CTF_ADD_NONROOT,
			     &arinfo);
}

/*
 * Assemble an enumeration.
 */
static ctf_id_t assemble_ctf_enumeration(const char *module_name,
					 const char *file_name,
					 Dwarf_Die *die,
					 Dwarf_Die *parent_die,
					 ulong_t parent_bias,
					 ctf_file_t *ctf,
					 ctf_id_t parent_ctf_id,
					 const char *locerrstr,
					 int top_level_type,
					 enum skip_type *skip,
					 int *override)
{
	const char *name = dwarf_diename(die);

	return ctf_add_enum(ctf, top_level_type ? CTF_ADD_ROOT : CTF_ADD_NONROOT,
			    name);
}

/*
 * Assemble an enumeration value.
 */
static ctf_id_t assemble_ctf_enumerator(const char *module_name,
					const char *file_name,
					Dwarf_Die *die,
					Dwarf_Die *parent_die,
					ulong_t parent_bias,
					ctf_file_t *ctf,
					ctf_id_t parent_ctf_id,
					const char *locerrstr,
					int top_level_type,
					enum skip_type *skip,
					int *override)
{
	const char *name = dwarf_diename(die);
	Dwarf_Attribute value_attr;
	Dwarf_Word value;
	int err;

	CTF_DW_ENFORCE(name);
	CTF_DW_ENFORCE(const_value);
	CTF_DW_ENFORCE_NOT(bit_stride);
	CTF_DW_ENFORCE_NOT(byte_stride);

	dwarf_attr(die, DW_AT_const_value, &value_attr);
	dwarf_formudata(&value_attr, &value);

	err = ctf_add_enumerator(ctf, parent_ctf_id, name, value);

	if (err != 0)
		return err;

	return parent_ctf_id;
}

/*
 * Assemble a typedef.
 */
static ctf_id_t assemble_ctf_typedef(const char *module_name,
				     const char *file_name,
				     Dwarf_Die *die,
				     Dwarf_Die *parent_die,
				     ulong_t parent_bias,
				     ctf_file_t *ctf,
				     ctf_id_t parent_ctf_id,
				     const char *locerrstr,
				     int top_level_type,
				     enum skip_type *skip,
				     int *override)
{
	const char *name = dwarf_diename(die);
	ctf_id_t type_ref;

	CTF_DW_ENFORCE(name);

	if ((type_ref = lookup_ctf_type(module_name, file_name, die, ctf,
					locerrstr)) < 0) {
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}

	return ctf_add_typedef(ctf, top_level_type ? CTF_ADD_ROOT : CTF_ADD_NONROOT,
			       name, type_ref);
}

/*
 * Assemble a const/volatile/restrict qualifier.
 */
static ctf_id_t assemble_ctf_cvr_qual(const char *module_name,
				      const char *file_name,
				      Dwarf_Die *die,
				      Dwarf_Die *parent_die,
				      ulong_t paretn_bias,
				      ctf_file_t *ctf,
				      ctf_id_t parent_ctf_id,
				      const char *locerrstr,
				      int top_level_type,
				      enum skip_type *skip,
				      int *override)
{
	ctf_id_t (*ctf_cvr_fun)(ctf_file_t *, uint_t, ctf_id_t);
	ctf_id_t type_ref;

	switch (dwarf_tag(die)) {
	case DW_TAG_const_type: ctf_cvr_fun = ctf_add_const; break;
	case DW_TAG_volatile_type: ctf_cvr_fun = ctf_add_volatile; break;
	case DW_TAG_restrict_type: ctf_cvr_fun = ctf_add_restrict; break;
	default:
		fprintf(stderr, "%s: internal error: assemble_ctf_cvr_qual() "
			"called with non-const/volatile/restrict: %i\n",
			locerrstr, dwarf_tag(die));
		exit(1);
	}

	if ((type_ref = lookup_ctf_type(module_name, file_name, die, ctf,
					locerrstr)) < 0) {
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}

	return ctf_cvr_fun(ctf, top_level_type ? CTF_ADD_ROOT : CTF_ADD_NONROOT,
			   type_ref);
}

/*
 * Assemble a structure or union type.  This assembles only the type itself, not
 * its constituent members: that is done by assemble_ctf_su_member().
 *
 * We assume that if a structure or union type is discovered with more members
 * than an earlier-discovered type, that it is compatible with that earlier type
 * and a superset of it.
 *
 * FIXME: in debug mode we should not assume this.
 */
static ctf_id_t assemble_ctf_struct_union(const char *module_name,
					  const char *file_name,
					  Dwarf_Die *die,
					  Dwarf_Die *parent_die,
					  ulong_t parent_bias,
					  ctf_file_t *ctf,
					  ctf_id_t parent_ctf_id,
					  const char *locerrstr,
					  int top_level_type,
					  enum skip_type *skip,
					  int *override)
{
	ctf_id_t (*ctf_add_sou)(ctf_file_t *, uint_t, const char *);

	const char *name = dwarf_diename(die);
	int is_union = (dwarf_tag(die) == DW_TAG_union_type);

	/*
	 * FIXME: these both need handling for DWARF4 support.
	 */
	CTF_DW_ENFORCE_NOT(specification);
	CTF_DW_ENFORCE_NOT(signature);

	/*
	 * Possibly we should ignore this entire structure, if we already know
	 * of one with the same name and at least as many members.  If we
	 * already know of one and it is shorter, we want to use its ID rather
	 * than creating a new one.
	 */

	if (name != NULL) {
		ctf_id_t existing;
		char *structized_name = NULL;

		structized_name = str_appendn(structized_name,
					      is_union ? "union " : "struct ",
					      name, NULL);

		existing = ctf_lookup_by_name(ctf, structized_name);
		free(structized_name);

		if (existing >= 0) {
			dw_ctf_trace("%s: already exists (with ID %li) with "
				     "%li members versus current %li members\n",
				     locerrstr, existing, count_ctf_members(ctf, existing),
				     count_dwarf_members(die));

			if (count_ctf_members(ctf, existing) <
			    count_dwarf_members(die))
				return existing;

			*skip = SKIP_SKIP;
			return existing;
		}
	}

	dw_ctf_trace("%s: adding structure %s\n", locerrstr, name);
	if (is_union)
		ctf_add_sou = ctf_add_union;
	else
		ctf_add_sou = ctf_add_struct;

	return ctf_add_sou(ctf, top_level_type ? CTF_ADD_ROOT : CTF_ADD_NONROOT,
			   name);
}

/*
 * Assemble a structure or union member.
 *
 * We only assemble a member of a given name if a member by that name does not
 * already exist, and if the member is not blacklisted.
 */
static ctf_id_t assemble_ctf_su_member(const char *module_name,
				       const char *file_name,
				       Dwarf_Die *die,
				       Dwarf_Die *parent_die,
				       ulong_t parent_bias,
				       ctf_file_t *ctf,
				       ctf_id_t parent_ctf_id,
				       const char *locerrstr,
				       int top_level_type,
				       enum skip_type *skip,
				       int *override)
{
	ulong_t offset;
	ctf_full_id_t *new_type;
	Dwarf_Attribute type_attr;
	Dwarf_Die type_die;
	Dwarf_Die cu_die;

	CTF_DW_ENFORCE(type);

	/*
	 * If this member is blacklisted, just skip it.
	 */
	if (member_blacklisted(die, parent_die)) {
		dw_ctf_trace("%s: blacklisted, skipping.\n", locerrstr);
		return parent_ctf_id;
	}

	/*
	 * Find the associated type so we can either add a member with that type
	 * (if it is named) or add its members directly (for unnamed types,
	 * which must be unnamed structs/unions).
	 */
	dwarf_attr(die, DW_AT_type, &type_attr);
	if (dwarf_formref_die(&type_attr, &type_die) == NULL) {
		fprintf(stderr, "%s: nonexistent type reference. "
			"Corrupted DWARF, cannot continue.\n", locerrstr);
		exit(1);
	}
	dwarf_diecu(&type_die, &cu_die, NULL, NULL);

	/*
	 * Figure out the offset of this type, in bits.
	 *
	 * DW_AT_data_bit_offset is the simple case.  DW_AT_data_member_location
	 * is trickier, and, alas, the DWARF2 variation is the complex one.
	 */
	if (dwarf_hasattr(die, DW_AT_data_bit_offset)) {
		Dwarf_Attribute bit_offset_attr;
		Dwarf_Word bit_offset;

		dwarf_attr(die, DW_AT_data_bit_offset, &bit_offset_attr);
		dwarf_formudata(&bit_offset_attr, &bit_offset);

		offset = bit_offset;
	} else if (dwarf_hasattr(die, DW_AT_data_member_location)) {
		Dwarf_Attribute location_attr;

		dwarf_attr(die, DW_AT_data_member_location, &location_attr);

		switch (dwarf_whatform(&location_attr)) {
		case DW_FORM_data2:
		case DW_FORM_data4:
		case DW_FORM_data8:
		case DW_FORM_udata:
		case DW_FORM_sdata:
		{
			/*
			 * Byte offset, with bit_offset of containing
			 * structure/union added, if present.
			 */
			if (dwarf_whatform(&location_attr) == DW_FORM_sdata) {
				Dwarf_Sword location;

				dwarf_formsdata(&location_attr, &location);
				offset = location * 8;
			} else {
				Dwarf_Word location;

				dwarf_formudata(&location_attr, &location);
				offset = location * 8;
			}

			if (dwarf_hasattr(parent_die, DW_AT_bit_offset)) {
				Dwarf_Attribute bit_attr;
				Dwarf_Word bit;

				dwarf_attr(parent_die, DW_AT_bit_offset,
					   &bit_attr);
				dwarf_formudata(&bit_attr, &bit);
				offset += bit;
			}
			break;
		}
		case DW_FORM_block1:
		case DW_FORM_block2:
		case DW_FORM_block4:
		{
			Dwarf_Op *location;
			size_t nlocs;

			/*
			 * DWARF 2 block-based data_member_location.  This can
			 * be quite complicated in some situations (notably C++
			 * virtual bases), but for normal structure members it
			 * is simple.  FIXME for userspace tracing of C++.
			 *
			 * This is thoroughly specific to the forms of DWARF2
			 * emitted by GCC.  We don't need to feel guilty about
			 * this because elfutils does just the same thing.
			 */

			if (dwarf_getlocation(&location_attr, &location,
					      &nlocs) < 0) {
				fprintf(stderr, "%s: offset not a valid "
					"location expression: %s\n", locerrstr,
					dwarf_errmsg(dwarf_errno()));
				*skip = SKIP_ABORT;
				return CTF_ERROR_REPORTED;
			}

			if ((nlocs != 1) ||
			    ((location[0].atom != DW_OP_plus_uconst) &&
			     (location[0].atom != DW_OP_constu))) {
				fprintf(stderr, "%s: complex location lists "
					"not supported: either C++ or non-GCC "
					"output: skipped\n", locerrstr);
				*skip = SKIP_ABORT;
				return CTF_ERROR_REPORTED;
			}

			offset = location[0].number * 8;
			break;
		}
		case DW_FORM_exprloc:
		{
			/*
			 * We need a full DWARF expression list interpreter to
			 * handle this.
			 */
			fprintf(stderr, "DWARF 4 expression location lists "
				"not supported.\n");
			exit(1);
		}
		default:
		{
			fprintf(stderr, "%s: expression location lists in "
				"form %u not supported.\n", locerrstr,
				dwarf_whatform(&location_attr));
			exit(1);
		}
		}
	} else { /* No offset.  */
		offset = 0;
	}

	offset += parent_bias;

	/*
	 * If this is an unnamed struct/union, call directly back to
	 * die_to_ctf() to add this struct's members to the current structure,
	 * merging it seamlessly with its parent (excepting only the member
	 * offsets).
	 */
	if (!dwarf_hasattr(die, DW_AT_name)) {
		Dwarf_Die child_die;
		int dummy = 0;

		if ((dwarf_tag(&type_die) != DW_TAG_structure_type) &&
		    (dwarf_tag(&type_die) != DW_TAG_union_type)) {
			fprintf(stderr, "%s:%lx: not supported: anonymous "
			    "structure member not a structure or union.\n",
			    locerrstr, (unsigned long) dwarf_dieoffset(die));
			*skip = SKIP_ABORT;
			return CTF_ERROR_REPORTED;
		}

		/*
		 * Anonymous structure or union with no members. Silently skip.
		 */
		if (dwarf_child(&type_die, &child_die) < 0)
			return parent_ctf_id;

		die_to_ctf(module_name, file_name, &child_die, parent_die, ctf,
		    parent_ctf_id, offset, 0, skip, &dummy, NULL);
		return parent_ctf_id;
	}

	/*
	 * Get the CTF ID of this member's type, by recursive lookup.
	 */
	new_type = construct_ctf_id(module_name, file_name, &type_die, &cu_die);

	if (new_type == NULL) {
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}

	if ((new_type->ctf_file != ctf) &&
	    (new_type->ctf_file != g_hash_table_lookup(module_to_ctf_file,
						       "shared_ctf"))) {
		fprintf(stderr, "%s:%s: internal error: referenced type lookup "
			"for member %s yields a different CTF file: %p versus "
			"%p\n", locerrstr, dwarf_diename(&cu_die),
			dwarf_diename(die), ctf, new_type->ctf_file);
		fprintf(stderr, "detect_duplicates() is probably buggy.\n");
		exit(1);
	}

	if (ctf_add_member_offset(ctf, parent_ctf_id, dwarf_diename(die),
				  new_type->ctf_id, offset) < 0) {
		/*
		 * If we have seen this member before, as part of another
		 * definition somewhere else, that's fine.  We cannot recurse
		 * from this point, so we can just return the parent CTF ID, the
		 * ID of the containing structure.
		 */
		if (ctf_errno(ctf) == ECTF_DUPLICATE)
			return parent_ctf_id;

		if (ctf_errno(ctf) == ECTF_BADID) {
#ifdef DEBUG
			fprintf(stderr, "%s: Internal error: bad ID %s:%s:%p:%i "
				"on member addition to ctf_file %p.\n",
				locerrstr, new_type->module_name,
				new_type->file_name, new_type->ctf_file,
				(int) new_type->ctf_id, ctf);
#else
			fprintf(stderr, "%s: Internal error: bad ID %p:%i on "
				"member addition to ctf_file %p.\n",
				locerrstr, new_type->ctf_file,
				(int) new_type->ctf_id, ctf);
#endif
			return CTF_ERROR_REPORTED;
		}

		/*
		 * Another error: not fine.
		 */
		return CTF_NO_ERROR_REPORTED;
	}

	return parent_ctf_id;
}

/*
 * Assemble a variable.
 */
static ctf_id_t assemble_ctf_variable(const char *module_name,
				      const char *file_name,
				      Dwarf_Die *die,
				      Dwarf_Die *parent_die,
				      ulong_t parent_bias,
				      ctf_file_t *ctf,
				      ctf_id_t parent_ctf_id,
				      const char *locerrstr,
				      int top_level_type,
				      enum skip_type *skip,
				      int *override)
{
	const char *name = dwarf_diename(die);
	ctf_id_t type_ref;
	int err;

	CTF_DW_ENFORCE(name);

	if ((type_ref = lookup_ctf_type(module_name, file_name, die, ctf,
					locerrstr)) < 0) {
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}

	/*
	 * This isn't a type: full DWARF child recursion and type-id addition is
	 * not called for.
	 */
	*skip = SKIP_SKIP;

	err = ctf_add_variable(ctf, name, type_ref);

	if (err == 0)
		dw_ctf_trace("%p: Added variable %s, type %i\n", ctf, name,
			     (int)type_ref);

	/*
	 * Variable references to opaque versus non-opaque structures could only
	 * get deduplicated with yet another deduplication pass.  This seems
	 * pointlessly expensive when nothing can refer to them: just skip
	 * duplicates instead.
	 */
	if ((err < 0) && (ctf_errno(ctf) == ECTF_DUPLICATE))
		return 0;

	return err;

}

/* Writeout.  */

static void write_types(char *output_dir)
{
	GHashTableIter module_iter;
	char *module;
	ctf_file_t *ctf_file;

	/*
	 * Work over all the modules and write their compressed CTF data out
	 * into the output directory.  Built-in modules get names ending in
	 * .builtin.ctf.new; others get names ending in .mod.ctf.new.  The
	 * makefile moves .ctf.new over the top of .ctf iff it has changed.
	 */

	if ((mkdir(output_dir, 0777) < 0) && errno != EEXIST) {
		fprintf(stderr, "Cannot create .ctf directory: %s\n",
			strerror(errno));
		exit(1);
	}

	g_hash_table_iter_init(&module_iter, module_to_ctf_file);
	while (g_hash_table_iter_next(&module_iter, (void **) &module,
				      (void **)&ctf_file)) {
		char *path = NULL;
		gzFile fd;
		int builtin_module = 0;

		dw_ctf_trace("Writing out %s\n", module);

		if ((strcmp(module, "shared_ctf") == 0) ||
		    (strcmp(module, "vmlinux") == 0))
			builtin_module = 1;
		else {
			size_t module_num;

			for (module_num = 0; module_num < builtin_modules_cnt;
			     module_num++) {
				char *module_name = fn_to_module(builtin_modules[module_num]);

				if (strcmp(module_name, module) == 0)
					builtin_module = 1;

				free(module_name);
			}
		}

		path = str_appendn(path, output_dir, "/", module,
				   builtin_module ? ".builtin" : ".mod",
				   ".ctf.new", NULL);

		dw_ctf_trace("Writeout path: %s\n", path);

		if ((fd = gzopen(path, "wb")) == NULL) {
			fprintf(stderr, "Cannot open CTF file %s for writing: "
				"%s\n", path, strerror(errno));
			exit(1);
		}
		if (ctf_gzwrite(ctf_file, fd) < 0) {
			fprintf(stderr, "Cannot write to CTF file %s: "
				"%s\n", path, ctf_errmsg(ctf_errno(ctf_file)));
			exit(1);
		}

		if (gzclose(fd) != Z_OK) {
			fprintf(stderr, "Cannot close CTF file %s: %s\n",
				path, strerror(errno));
			exit(1);
		}
		free(path);
	}
}

/* Utilities.  */

/*
 * Given a DIE that may contain a type attribute, look up the target of that
 * attribute and return it, or NULL if none.
 */
static Dwarf_Die *private_dwarf_type(Dwarf_Die *die, Dwarf_Die *target_die)
{
	Dwarf_Attribute type_ref_attr;

	if (dwarf_attr(die, DW_AT_type, &type_ref_attr) != NULL) {
		if (dwarf_formref_die(&type_ref_attr, target_die) == NULL) {
			fprintf(stderr, "Corrupt DWARF at offset %lx: ref with "
				"no target.\n",
				(unsigned long) dwarf_dieoffset(die));
			exit(1);
		}
		return target_die;
	}

	return NULL;
}

/*
 * Determine the dimensions of an array subrange, or 0 if variable.
 */
static Dwarf_Word private_subrange_dimensions(Dwarf_Die *die)
{
	int flexible_array = 0;
	Dwarf_Attribute nelem_attr;
	Dwarf_Word nelems;

	if (((dwarf_attr(die, DW_AT_upper_bound, &nelem_attr) == NULL) &&
	     (dwarf_attr(die, DW_AT_count, &nelem_attr) == NULL)) ||
	    (!dwarf_hasattr(die, DW_AT_type)))
		flexible_array = 1;

	if (!flexible_array)
		switch (dwarf_whatform(&nelem_attr)) {
		case DW_FORM_data1:
		case DW_FORM_data2:
		case DW_FORM_data4:
		case DW_FORM_data8:
		case DW_FORM_udata:
			break;
		default:
			flexible_array = 1;
		}

	if (flexible_array)
		return 0;

	dwarf_formudata(&nelem_attr, &nelems);

	/*
	 * Upper bounds indicate that we have one more element than that, since
	 * C starts counting at zero.
	 */
	if (dwarf_hasattr(die, DW_AT_upper_bound))
		nelems++;

	return nelems;
}

/*
 * An error checking strdup().
 */
static char *xstrdup(const char *s)
{
	char *s2 = strdup(s);

	if (s2 == NULL) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}

	return s2;
}

/*
 * A string appender working on dynamic strings.
 */
static char *str_append(char *s, const char *append)
{
	size_t s_len = 0;

	if (append == NULL)
		return s;

	if (s != NULL)
		s_len = strlen(s);

	size_t append_len = strlen(append);

	s = realloc(s, s_len + append_len + 1);

	if (s == NULL) {
		fprintf(stderr, "Out of memory appending a string of length "
			"%li to a string of length %li\n", strlen(append),
			s_len);
		exit(1);
	}

	memcpy(s + s_len, append, append_len);
	s[s_len+append_len]='\0';

	return s;
}

/*
 * A vararg string appender.
 */
static char *str_appendn(char *s, ...)
{
	va_list ap;
	const char *append;
	size_t len, s_len = 0;

	va_start(ap, s);
	if (s)
		s_len = strlen(s);
	len = s_len;

	append = va_arg(ap, const char *);
	while (append != NULL) {
		len += strlen(append);
		append = va_arg(ap, char *);
	}
	va_end(ap);

	s = realloc(s, len + 1);
	if (s == NULL) {
		fprintf(stderr, "Out of memory appending a string of length "
			"%li to a string of length %li\n", strlen(append),
			s_len);
		exit(1);
	}

	va_start(ap, s);
	append = va_arg(ap, const char *);
	while (append != NULL) {
		size_t append_len = strlen(append);

		memcpy(s + s_len, append, append_len);
		s_len += append_len;

		append = va_arg(ap, char *);
	}
	s[len] = '\0';
	va_end(ap);

	return s;
}

/*
 * Figure out the (pathless, suffixless) module name for a given module file (.o
 * or .ko), and return it in a new dynamically allocated string.
 */
static char *fn_to_module(const char *file_name)
{
	char *module_name;
	char *chop;

	if ((chop = strrchr(file_name, '/')) != NULL)
		module_name = xstrdup(++chop);
	else
		module_name = xstrdup(file_name);

	if ((chop = strrchr(module_name, '.')) != NULL)
		*chop = '\0';

	return module_name;
}

/*
 * Determine, and cache, absolute filenames.  This is called in very hot
 * paths, notably type_id(), and must be kept fast.
 */
static const char *abs_file_name(const char *file_name)
{
	static GHashTable *abs_file_names;
	const char *abs_name;

	if (abs_file_names == NULL)
		abs_file_names = g_hash_table_new_full(g_str_hash, g_str_equal,
		    free, free);

	abs_name = g_hash_table_lookup(abs_file_names, file_name);

	if (abs_name == NULL) {
		char abspath[PATH_MAX] = "";

		if (realpath(file_name, abspath) == NULL)
			strcpy(abspath, file_name);
		g_hash_table_replace(abs_file_names,
		    xstrdup(file_name), xstrdup(abspath));

		abs_name = g_hash_table_lookup(abs_file_names, file_name);
	}

	return abs_name;
}

/*
 * Given a type encoding table, and a size, return the CTF encoding for that
 * type, or 0 if none.
 */
static int find_ctf_encoding(struct type_encoding_tab *type_tab, size_t size)
{
	size_t i;

	for (i = 0; type_tab[i].size != 0; i++) {
		if (type_tab[i].size == size)
			return type_tab[i].ctf_encoding;
	}
	return 0;
}

/*
 * Count the number of members of a DWARF aggregate.
 */
static long count_dwarf_members(Dwarf_Die *d)
{
	const char *err;
	Dwarf_Die die;

	switch (dwarf_child(d, &die)) {
	case -1:
		err = "fetch first child of aggregate";
		goto fail;
	case 1: /* No DIEs at all in this aggregate */
		return 0;
	default: /* Child DIEs exist.  */
		break;
	}

	/*
	 * We are only interested in children of type DW_TAG_member.
	 */
	int sib_ret;
	long count = 0;

	do
		if (dwarf_tag(&die) == DW_TAG_member)
			count++;
	while ((sib_ret = dwarf_siblingof(&die, &die)) == 0);

	if (sib_ret == -1) {
		err = "count members";
		goto fail;
	}

	return count;

 fail:
	fprintf(stderr, "Cannot %s: %s\n", err, dwarf_errmsg(dwarf_errno()));
	exit(1);
}

 /*
 * Count the number of members of a CTF aggregate.
 */
static long count_ctf_members(ctf_file_t *fp, ctf_id_t souid)
{
	long count = 0;

	ctf_member_iter(fp, souid, count_ctf_members_internal, &count);

	return count;
}

/*
 * Increment said count.
 */
static int count_ctf_members_internal(const char *name, ctf_id_t member,
				      ulong_t offset, void *data)
{
	long *count = (long *) data;

	(*count)++;
	return 0;
}

/*
 * Trivial wrapper, avoid an incompatible pointer type warning.
 */
static void private_ctf_free(void *ctf_file)
{
	ctf_close((ctf_file_t *)ctf_file);
}
