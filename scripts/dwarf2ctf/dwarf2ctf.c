/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dwarf2ctf.c: Read in DWARF[23] debugging information from some set of ELF
 * files, and generate CTF in correspondingly-named files, or in a single
 * representation meant for mmapping.
 *
 * Copyright (c) 2011, 2019, Oracle and/or its affiliates. All rights reserved.
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
#include <fcntl.h>
#include <limits.h>
#include <endian.h>
#include <unistd.h>

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

#define __unused__ __attribute__((__unused__))

/*
 * If non-NULL, tracing is on.
 */
static const char *trace;

/*
 * Trace something.
 */
#ifdef DEBUG
#define dw_ctf_trace(format, ...) do {				\
	if (trace)						\
		fprintf(stderr, (format), ## __VA_ARGS__);	\
} while (0)
#else
#define dw_ctf_trace(format, ...)
#endif

/*
 * Run dwarf2ctf over a single object file or set thereof.
 *
 * output_dir is the directory into which the CTF goes, if 'standalone', or the
 * CTF archive file name otherwise.
 */
static void run(char *output, int standalone);

/*
 * Whether we are deduplicating.  We do not deduplicate if run over external
 * modules.
 */
static int deduplicating;

/*
 * A fully descriptive CTF type ID: both file and type ID in one place.
 */
struct ctf_full_id {
	ctf_file_t *ctf_file;
	ctf_id_t ctf_id;
#ifdef DEBUG
	char module_name[PATH_MAX];
	char file_name[PATH_MAX];
#endif
};

/*
 * A hash mapping 'atoms' (almost entirely type IDs) to nothing.
 */
static GHashTable *atoms;

/*
 * A mapping from the type ID of a DIE (see type_id()) to ctf_full_id_t's
 * describing the type with that ID.  The type ID is an atom.
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
 * A mapping from the type ID of a DIE (an atom) to the name of the module (and
 * thus CTF table) incorporating that type.  (Modules in this context, and
 * throughout dwarf2ctf, are DTrace modules: a name without suffix or path.)
 *
 * This is used to merge types identical across modules (e.g. those in global
 * header files).
 */
static GHashTable *id_to_module;

/*
 * Module-specific state.  The module named 'vmlinux' is that corresponding to
 * the types in always-built-in translation units; the module named 'shared_ctf'
 * (not appearing in this mapping) is that corresponding to types shared between
 * more than one module (even between two currently-built-in modules: we do not
 * distinguish at this level between built-in modules and non-built-in modules.)
 */
static GHashTable *per_module;

/*
 * The data structure that per_module maps module names to.
 */
struct per_module {
	/*
	 * The CTF file containing the types in this module.
	 */
	ctf_file_t *ctf_file;

	/*
	 * A hash from a "CTF-form" structure name (in the form 's/u NAME') to
	 * a struct ctf_memb_count (see below).
	 */
	GHashTable *member_counts;
};

/*
 * A count associating a type ID relating to a structure or union with a count
 * of members in that structure.
 */
struct ctf_memb_count {
	ctf_id_t ctf_id;
	size_t count;
};

/*
 * A mapping from the absolute pathname of a TU to a hashtable mapping
 * DIE offsets of child DIEs to DIE offsets of parents.  Populated on first
 * iteration.  Contains only those DIEs that we know are necessary for other
 * functions' use of this structure, to keep memory usage down.
 */
static GHashTable *fn_to_die_to_parent;

/*
 * Get a ctf_file out of the per_module hash for a given module.
 */
static ctf_file_t *lookup_ctf_file(const char *module_name);

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
 * Populate and object_to_module from the objects.builtin and modules.builtin
 * file.
 */
static void init_builtin(const char *builtin_objects_file,
			 const char *builtin_module_file);

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
static void init_member_blacklist(const char *member_blacklist_file,
				  const char *srcdir);

/*
 * Return 1 if a given DWARF DIE, which must be a DW_TAG_member, appears in the
 * member blacklist.
 */
static int member_blacklisted(Dwarf_Die *die, Dwarf_Die *parent_die);

/*
 * The variable blacklist, like the others, is an automatically-maintained
 * blacklist giving variables in specific modules which should not be emitted.
 * (These are variables whose names are ambiguous within a module, and may
 * appear multiple times in /proc/kallmodsyms, identical but for address and
 * thus indistinguishable.)
 *
 * The mapping is from module`variable to NULL (safe because variable names
 * cannot begin with a backtick, and even if they could DTrace's notation could
 * not reference such variables).
 */
static GHashTable *variable_blacklist;

/*
 * A mapping from object file name to the name of the module that translation
 * unit is part of.
 *
 * Actual, real, on-disk .ko modules do not appear here, because the translation
 * is trivial for them.
 */
static GHashTable *object_to_module;

/*
 * Initialize a CTF type table, and possibly fill it with those special types
 * that appear in CTF but not in DWARF (such as 'void').  (This filling happens
 * only for the type table named "shared_ctf", unless deduplication is turned
 * off.)
 *
 * If this is a local type table, and deduplication is active, make the global
 * type table its parent.
 */
static void init_ctf_table(const char *module_name);

/*
 * A few useful singleton CTF type IDs in the global type table: a void pointer
 * and a function pointer.  Constructed by init_ctf_table().
 */
static ctf_id_t ctf_void_type;
static ctf_id_t ctf_funcptr_type;

/*
 * Initialize the child->parent DIE mapping for a single file.
 */
static void init_parent_die(const char *file_name, Dwfl *dwfl);

/*
 * Initialize one layer of a child->parent mapping.
 */
static int init_parent_die_internal(const char *file_name,
				    GHashTable *offs, Dwarf_Die *parent,
				    int depth, int found_subprogram);

/*
 * Override the presence and value of FORM_u/sdata attributes on DWARF DIEs,
 * either adding to it, or replacing it.
 *
 * (Used so that a caller of construct_ctf_id() that wants a type to be created
 * can override aspects of that type.)
 *
 * The 'chain', if set, causes the various private_*() functions that handle
 * overrides to look back along the chain to find a suitable attribute.  The
 * chain must be set on the last element in the array.  The search for
 * attributes terminates at the first match.
 *
 * Note: this is not a particularly generic implementation: a better approach
 * would be to keep walking the chain on DIE_OVERRIDE_ADD, and keep adding until
 * we are done: but we have only one user of ADD, and it implements the addition
 * itself because it is adding to a value from a different DIE: so this added
 * generality is not needed yet.
 */
struct die_override {
	int tag;
	int attribute;
	enum { DIE_OVERRIDE_REPLACE, DIE_OVERRIDE_ADD } op;
	Dwarf_Sword value;
	struct die_override *chain;
};

/*
 * Compute the type ID of a DWARF DIE (with possibly-overridden attributes) and
 * return it in a new dynamically-allocated string.
 *
 * Optionally, call a callback with the computed ID once we know it (this is a
 * recursive process, so the callback can be called multiple times as the ID
 * is built up).
 *
 * An ID of NULL indicates that this DIE has no ID and need not be considered.
 */
static char *type_id(Dwarf_Die *die, struct die_override *overrides,
		     void (*fun)(Dwarf_Die *die,
				 const char *id,
				 struct die_override *overrides,
				 void *data),
		     void *data) __attribute__((__warn_unused_result__));

/*
 * Internal: allows flags to be passed to affect one (and only one) type ID
 * recursion, without affecting other type_id()s launched from the 'fun'.
 */
static char *type_id_internal(Dwarf_Die *die,
			      struct die_override *overrides,
			      void (*fun)(Dwarf_Die *die,
					  const char *id,
					  struct die_override *overrides,
					  void *data),
			      void *data,
			      int flags);

/*
 * Internal: generate the type ID for a type DIE.
 *
 * If there are no overrides, look for a bit_size and bit_offset and pass them
 * down as well.
 */
static char *type_id_type_die(Dwarf_Die *die,
			      Dwarf_Die *type_die,
			      struct die_override *overrides,
			      void (*fun)(Dwarf_Die *die,
					  const char *id,
					  struct die_override *overrides,
					  void *data),
			      void *data);

/*
 * Convert 'long unsigned int' to 'sizetype'.  Internal use within type_id().
 */
#define TI_COLLAPSE_SIZETYPE 0x1

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
 * process_file() helper, walking over the top level and picking up types
 * therein.
 */
static void process_tu_func(const char *module_name,
			    const char *file_name,
			    Dwarf *dwarf,
			    Dwarf_Die *parent_die,
			    Dwarf_Die *die,
			    void (*dwarf_process)(const char *module_name,
						  const char *file_name,
						  Dwarf_Die *die,
						  Dwarf_Die *parent_die,
						  void *data),
			    void *data);

/*
 * Records the type ID of interesting types, the files they are contained in,
 * and their DWARF offset, so they can be found rapidly.
 *
 * Used to avoid rescanning files that can contain no duplicates.
 */
struct dedup_id_file {
	char *file_name;
	char *id;
	Dwarf_Off dieoff;
};

/*
 * The structure used as the data argument for dedup() and
 * dedup_alias_fixup().
 *
 * structs_seen tracks the IDs of structures marked as duplicates within a given
 * translation unit, in order that recursion terminates if two such structures
 * have pointers to each other.
 *
 * vars_seen tracks variables seen in this module, mapping from unadorned name
 * to a non-NULL pointer (for static, non-'external') or NULL (for non-static or
 * 'extern').  If a static variable coexists with any other variable with the
 * same name, static or not, the variable is blacklisted.  (Non-static
 * coexistence is fine, because they are just different references to the same
 * variable).  Note that management of this variable is a little annoying
 * because it varies by module, not by TU, so we can't use tu_init/tu_done to
 * manage its lifetime.
 *
 * named_structs tracks type IDs and contained modules for every type that may
 * contain undetected duplicates and thus may require rescanning.
 *
 * dwfl and dwfl_file_name identify the opened DWARF file (if any) during the
 * second duplicates detection pass.
 *
 * repeat_detection is set by each phase if it considers that another round of
 * alias fixup detection is needed.
 */
struct dedup_state {
	const char *file_name;
	const char *module_name;
	GHashTable *structs_seen;
	GList *named_structs;
	GHashTable *vars_seen;
	char *dwfl_file_name;
	Dwarf *dwarf;
	Dwfl *dwfl;
	int repeat_detection;
};

/*
 * Scan and identify duplicates across the entire set of object files.
 */
static void scan_dups(void);

/*
 * Recursively detect duplicate types and types referenced by them, and
 * determine which CTF file they should be located in, and request a
 * dedup_alias_fixup() pass if any structures are shared.
 * Determine the mapping from translation unit name to module name.
 */
static void dedup(const char *module_name, const char *file_name,
		  Dwarf_Die *die, Dwarf_Die *parent_die, void *data);

/*
 * Do the underlying marking of a DIE as shared, iff need be.  (No variable
 * blacklisting, non-opaque structure checks, or anything else needed only by
 * top-level DIEs.)
 *
 * This function may be called multiple times for overridden DIEs that are
 * dependent types of bitfields.
 */
static void dedup_mark_inner_die(const char *module_name, Dwarf_Die *die,
				 const char *id,
				 struct die_override *overrides,
				 void *data);

/*
 * Note in the dedup_id_file list that we will rescan a DIE in a later duplicate
 * detection pass.
 *
 * A type_id() callback.
 */
static void dedup_will_rescan(Dwarf_Die *die, const char *id,
			      struct die_override *overrides, void *data);

/*
 * Note the variable referenced by this DIE in vars_seen: blacklist it if an
 * entry for this variable already exists in vars_seen and this instance is
 * static, or if a static entry already exists in vars_seen, whether this
 * instance is static or not.
 */
static void dedup_blacklist_var_dups(Dwarf_Die *die,
				     struct dedup_state *state);

/*
 * Detect duplicates and mark seen types for a given type, via a type_id()
 * callback: used to detect dependent types (particularly those at child-DIE
 * level) as duplicates.
 */
static void dedup_typeid(Dwarf_Die *die, const char *id,
			 struct die_override *overrides, void *data);

/*
 * Mark any aggregates contained within a particular type DIE as seen.  This is
 * needed since even nameless aggregates contained within other aggregates can
 * be used as the type of members of the outer aggregate (though they cannot
 * possibly be found in a module different from that of their containing
 * aggregate, any more than a structure member can).
 */
static void mark_seen_contained(Dwarf_Die *die, const char *module_name,
				struct die_override *overrides, void *data);

/*
 * Determine if some type (whose ultimate base type is an non-opaque structure,
 * alias, or enum) has an opaque equivalent which is shared, and mark it and
 * all its bases as shared too if so.
 *
 * A list_filter() filter function.
 */
static int dedup_alias_fixup(void *id_file_data, void *data);

/*
 * Mark a basic type shared by name and intern it in all relevant hashes.  (Used
 * for marking basic types we don't have a DIE for.)
 */
static void mark_shared_by_name(ctf_file_t *ctf, ctf_id_t ctf_id,
				const char *name);

/*
 * Determine if a type is a named struct, union, or enum.
 *
 * A type_id() callback.
 */
static void is_named_struct_union_enum(Dwarf_Die *die, const char *unused,
				       struct die_override *overrides,
				       void *data);

/*
 * Set up state for dedup().  A tu_init() callback.
 */
static void dedup_tu_init(const char *module_name, const char *file_name,
			  Dwarf_Die *tu_die, void *data);

/*
 * Free state for dedup().  A tu_done() callback.
 */
static void dedup_tu_done(const char *module_name, const char *file_name,
			  Dwarf_Die *tu_die, void *data);

/*
 * Free DWARF state for dedup().
 */
static void dedup_dwarf_free(struct dedup_state *state);

/*
 * Determine if a type is duplicated and needs sharing.
 */
enum needs_sharing { NS_NOT_SHARED, NS_NO_MARKING, NS_NEEDS_SHARING };
static enum needs_sharing type_needs_sharing(const char *module_name,
					     const char *id);

/*
 * Mark a type (optionally, with an already-known ID) as duplicated and located
 * in the shared CTF table.
 *
 * A type_id() callback (though also called directly).
 */
static void mark_shared(Dwarf_Die *die, const char *id,
			struct die_override *overrides, void *data);

/*
 * Construct CTF out of each type.
 */
static void construct_ctf(const char *module_name, const char *file_name,
			  Dwarf_Die *die,
			  Dwarf_Die *parent_die,
			  void *unused __unused__);

/*
 * Write out the CTF files from the per_module->ctf_file into files in the
 * output directory (if standalone), or into the output file (otherwise).
 */
static void write_types(char *output, int standalone);

/*
 * Construct CTF out of each type and return that type's ID and file.
 */
static struct ctf_full_id *construct_ctf_id(const char *module_name,
					    const char *file_name,
					    Dwarf_Die *die,
					    Dwarf_Die *parent_die,
					    struct die_override *overrides);

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
			   struct die_override *overrides, int top_level_type,
			   int backwards, enum skip_type *skip, int *replace,
			   const char *id);

/*
 * Return the next DIE, if that DIE needs to be emitted before this one.
 */
static Dwarf_Die *die_emit_next_backwards(Dwarf_Die *next, Dwarf_Die *die,
					  struct die_override *overrides);

/*
 * Look up a type through its reference: return its ctf_id_t, or
 * recursively construct it if need be.
 *
 * Must be called on a DIE with a type attribute.
 */
static ctf_id_t lookup_ctf_type(const char *module_name, const char *file_name,
				Dwarf_Die *die, ctf_file_t *ctf,
				struct die_override *overrides,
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
 * level have the CU as their parent.
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
 * Setting 'replace' to 1 in a child DIE indicates that this type should
 * entirely *replace* its parent's type (generally because it has wrapped it up
 * in something).  This replacemenu takes immediate effect for later children of
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
				     ctf_file_t *ctf,
				     ctf_id_t parent_ctf_id,
				     const char *locerrstr,
				     struct die_override *overrides,
				     int top_level_type,
				     enum skip_type *skip,
				     int *replace);

#define ASSEMBLY_FUN(name)							\
	static ctf_id_t assemble_ctf_##name(const char *module_name,		\
					    const char *file_name,		\
					    Dwarf_Die *die,			\
					    Dwarf_Die *parent_die,		\
					    ctf_file_t *ctf,			\
					    ctf_id_t parent_ctf_id,		\
					    const char *locerrstr,		\
					    struct die_override *overrides,	\
					    int top_level_type,			\
					    enum skip_type *skip,		\
					    int *replace)

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
typedef int (*ctf_assembly_filter_fun)(const char *file_name,
				       Dwarf *dwarf,
				       Dwarf_Die *die,
				       Dwarf_Die *parent_die);

/*
 * A CTF assembly filter function which excludes all types not at the global
 * scope (i.e. whose immediate parent is not a CU DIE) and which does not have a
 * structure or union as its ultimate dependent type.  (All structures and
 * unions and everything dependent on them must be recorded, even inside
 * functions, because GCC may emit references to the opaque variants of those
 * types from file scope.)
 */
static int filter_ctf_file_scope(const char *file_name,
				 Dwarf *dwarf,
				 Dwarf_Die *die,
				 Dwarf_Die *parent_die);

/*
 * A CTF assembly filter function which excludes all names not at the global
 * scope, all static symbols, and all names whose names are unlikely to be
 * interesting.  (DTrace userspace contains a similar list, but the two lists
 * need not be in sync.)
 */
static int filter_ctf_uninteresting(const char *file_name,
				    Dwarf *dwarf,
				    Dwarf_Die *die,
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
 * Given a DIE that may contain a type attribute, look up the target of that
 * attribute and return it, or NULL if none.
 */
static Dwarf_Die *private_dwarf_type(Dwarf_Die *die, Dwarf_Die *target_die);

/*
 * Check for existence of an attribute in a DIE, chasing through
 * DW_AT_specification if need be.
 */
static inline int private_dwarf_hasattr(Dwarf_Die *die,
					unsigned int search_name);

/*
 * Return a DIE attribute, chasing through DW_AT_specification if need be.
 */
static inline Dwarf_Attribute *private_dwarf_attr(Dwarf_Die *die,
						  unsigned int search_name,
						  Dwarf_Attribute *result);

/*
 * Given a DIE that contains a udata attribute, look up that attribute and
 * return its value (optionally overridden or modified by the die_overrides).
 */
static inline Dwarf_Word private_dwarf_udata(Dwarf_Die *die, int attribute,
					     struct die_override *overrides);

/*
 * Given a DIE, return its byte size, if known and interpretable, or -1
 * otherwise.
 */
static inline long long private_dwarf_size(Dwarf_Die *die);

/*
 * Find an override in an override list.
 */
static struct die_override *
private_find_override(Dwarf_Die *die,
		      int attribute,
		      struct die_override *overrides);

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
 * Filter a GList, calling a predicate on it and removing all elements for which
 * the predicate returns true, calling the free_func on them if set.
 */
typedef int (*filter_pred_fun) (void *element, void *data);
static GList *list_filter(GList *list, filter_pred_fun fun,
			  GDestroyNotify free_func, void *data);

/*
 * Intern an atom in the atoms table and return it, or free it and return the
 * existing atom if one is already interned.    (Despite the type signature, this
 * return value is constant and should not be freed.)
 */
static void *intern(char *atom);

/*
 * Figure out the (pathless, suffixless) module name for a given module file (.o
 * or .ko), and return it in a new dynamically allocated string.
 *
 * Takes the object_to_module mapping into account.
 */
static char *fn_to_module(const char *file_name);

/*
 * Determine, and cache, absolute filenames.
 */
static const char *abs_file_name(const char *file_name);

/*
 * Determine absolute filenames relative to some other directory: do not cache
 * them.  It is the caller's responsibility to free them.
 */
static char *rel_abs_file_name(const char *file_name, const char *relative_to);

/*
 * Free a per_module's contents.
 */
static void private_per_module_free(void *per_module);

/*
 * Free a dedup_id_file's contents.
 */
static void free_dups_id_file(void *id_file);

/*
 * Free a fn_to_die_to_parent subhash.
 */
static void private_fn_die_parent_free(void *ptr);

/*
 * dwarf_dieoffset() with a return type better for printf().
 */
#define DIEOFFSET(die) (unsigned long) dwarf_dieoffset((die))

/*
 * A line-shortener with a kernel-familiar name for fprintfing to stderr.
 */
#define pr_err(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__);

/* Initialization.  */

int main(int argc, char *argv[])
{
	char *output;

	trace = getenv("DWARF2CTF_TRACE");

	if ((argc != 4 && argc != 7) ||
	    (argc == 4 && strcmp(argv[2], "-e") != 0)) {
		pr_err("Syntax: dwarf2ctf output-file srcdir objects.builtin\n");
		pr_err("                  modules.builtin member.blacklist filelist\n");
		pr_err("    or dwarf2ctf output-dir -e filelist\n"
		       "for external module use\n");
		exit(1);
	}

	output = argv[1];

	elf_version(EV_CURRENT);

	if (elf_errno()) {
		pr_err("Version synchronization fault: %s\n",
		       elf_errmsg(elf_errno()));
		exit(1);
	}

	init_assembly_tab();
	object_to_module = g_hash_table_new_full(g_str_hash, g_str_equal,
						 free, free);

	/*
	 * When not building an external module, we run over all the arguments
	 * at once, deduplicating them.  In external-module mode, we act as if
	 * independently invoked with every argument.
	 */
	if (strcmp(argv[2], "-e") != 0) {
		const char *srcdir;
		char *builtin_objects_file;
		char *builtin_module_file;
		char *member_blacklist_file;

		srcdir = argv[2];
		builtin_objects_file = argv[3];
		builtin_module_file = argv[4];
		member_blacklist_file = argv[5];
		deduplicating = 1;

		init_builtin(builtin_objects_file, builtin_module_file);
		init_member_blacklist(member_blacklist_file, srcdir);
		init_object_names(argv[6]);

		run(output, 0);
	} else {
		char *single_object_name;
		char **all_object_names;
		size_t all_object_names_cnt;
		size_t i;

		deduplicating = 0;
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

			run(output, 1);
		}
	}

	g_hash_table_destroy(object_to_module);

	if (num_errors > 0)
		pr_err("%li CTF construction errors.\n", num_errors);

	return 0;
}

/*
 * Run dwarf2ctf over a single object file or set thereof.
 *
 * output is the directory into which the CTF goes, if 'standalone', or the
 * CTF archive file name otherwise.
 */
static void run(char *output, int standalone)
{
	size_t i;

	/*
	 * Create all the hashes, assemble the translation unit->module list for
	 * builtin modules, and create the shared CTF file if deduplicating.
	 */

	atoms = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
	id_to_type = g_hash_table_new_full(g_str_hash, g_str_equal,
					   NULL, free);
	id_to_module = g_hash_table_new_full(g_str_hash, g_str_equal,
					     NULL, free);
	per_module = g_hash_table_new_full(g_str_hash, g_str_equal, free,
					   private_per_module_free);
	variable_blacklist = g_hash_table_new_full(g_str_hash, g_str_equal,
						   free, free);
	fn_to_die_to_parent = g_hash_table_new_full(g_str_hash,
						    g_str_equal, free,
						    private_fn_die_parent_free);

	dw_ctf_trace("Initializing...\n");

	if (deduplicating)
		init_ctf_table("shared_ctf");

	scan_dups();

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
	write_types(output, standalone);

	g_hash_table_destroy(id_to_type);
	g_hash_table_destroy(id_to_module);
	g_hash_table_destroy(per_module);
	g_hash_table_destroy(variable_blacklist);
	g_hash_table_destroy(fn_to_die_to_parent);
	g_hash_table_destroy(atoms);
}

/*
 * Populate the object_names list from the module filelist.
 */
static void init_object_names(const char *object_names_file)
{
	FILE *f;
	char *line = NULL;
	size_t line_size = 0;

	f = fopen(object_names_file, "r");
	if (f == NULL) {
		pr_err("Cannot open object names file %s: %s\n",
			object_names_file, strerror(errno));
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
				       sizeof(char *));

		if (object_names == NULL) {
			pr_err("Out of memory reading %s\n", object_names_file);
			exit(1);
		}

		object_names[object_names_cnt-1] = xstrdup(line);
	}
	free(line);

	if (ferror(f)) {
		pr_err("Error reading from %s: %s\n", object_names_file,
		       strerror(errno));
		exit(1);
	}

	fclose(f);
}

/*
 * Populate object_to_module from the objects.builtin and modules.builtin file.
 */
static void init_builtin(const char *builtin_objects_file,
			 const char *builtin_module_file)
{
	FILE *f;
	struct modules_thick_iter *i;
	char *line = NULL;
	size_t line_size = 0;
	char *module_name = NULL;
	char **paths;

	/*
	 * Iterate over all modules in modules_thick.builtin and add each to
	 * object_to_module.
	 */
	i = modules_thick_iter_new(builtin_module_file);
	if (i == NULL) {
		pr_err("Cannot iterate over builtin module file.\n");
		exit(1);
	}

	while ((paths = modules_thick_iter_next(i, &module_name)) != NULL) {
		size_t j;

		for (j = 0; paths[j] != NULL; j++) {
			dw_ctf_trace("noting built-in module mapping %s -> %s\n",
				     module_name, paths[j]);
			g_hash_table_replace(object_to_module,
					     strdup(paths[j]),
					     xstrdup(module_name));
		}
		free(paths);
	}
	free(module_name);
	modules_thick_iter_free(i);

	f = fopen(builtin_objects_file, "r");
	if (f == NULL) {
		pr_err("Cannot open builtin objects file %s: %s\n",
		       builtin_objects_file, strerror(errno));
		exit(1);
	}

	/*
	 * Those entries in builtin.objects that are not already known are
	 * unconditionally-built-in object files.
	 */
	while (getline(&line, &line_size, f) >= 0) {
		size_t len = strlen(line);

		if (len == 0)
			continue;

		if (line[len-1] == '\n')
			line[len-1] = '\0';

		if (!g_hash_table_lookup(object_to_module, line))
			g_hash_table_replace(object_to_module, xstrdup(line),
					     xstrdup("vmlinux"));
	}

	if (ferror(f)) {
		pr_err("Error reading from %s: %s\n", builtin_objects_file,
		       strerror(errno));
		exit(1);
	}

	free(line);
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

	assembly_tab = calloc(sizeof(ctf_assembly_fun *), assembly_len + 1);
	assembly_filter_tab = calloc(sizeof(ctf_assembly_filter_fun *),
				     assembly_len + 1);
	if ((assembly_tab == NULL) || (assembly_filter_tab == NULL)) {
		pr_err("Out of memory allocating assembly table\n");
		exit(1);
	}

	for (walk = assembly_tab_init; walk->fun != NULL; walk++) {
		assembly_tab[walk->tag] = walk->fun;
		assembly_filter_tab[walk->tag] = walk->filter;
	}
}

/*
 * Populate the member blacklist from the member_blacklist file.
 */
static void init_member_blacklist(const char *member_blacklist_file,
				  const char *srcdir)
{
	FILE *f;
	char *line = NULL;
	size_t line_num = 0;
	size_t line_size = 0;

	/*
	 * Not having a member blacklist is not an error.
	 */
	f = fopen(member_blacklist_file, "r");
	if (f == NULL)
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
			pr_err("Syntax error on line %li of %s.\n"
			       "Syntax: filename:structure.member.\n",
			       line_num, member_blacklist_file);
			continue;
		}

		*last_colon = '\0';
		last_colon++;
		absolutized = rel_abs_file_name(line, srcdir);
		absolutized = str_appendn(absolutized, ":", last_colon, NULL);

		g_hash_table_insert(member_blacklist, absolutized, NULL);
	}
	free(line);

	if (ferror(f)) {
		pr_err("Error reading from %s: %s\n", member_blacklist_file,
		       strerror(errno));
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
	 * The compiler can define its own structures, which appear in no
	 * decl_file.
	 *
	 * We can't blacklist them with this mechanism, so skip them.
	 */
	if (__builtin_expect(fname == NULL, 0))
		return 0;

	fname = abs_file_name(fname);

	if (dwarf_tag(die) != DW_TAG_member ||
	    (dwarf_tag(parent_die) != DW_TAG_structure_type &&
		dwarf_tag(parent_die) != DW_TAG_union_type)) {
		pr_err("Warning: member_blacklisted() called on "
		       "%s:%s.%s at offset %li, which is not a structure member.\n",
		       fname, dwarf_diename(parent_die), dwarf_diename(die),
		       DIEOFFSET(die));
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
 * off.)
 *
 * If this is a local type table, and deduplication is active, make the global
 * type table its parent.
 */
static void init_ctf_table(const char *module_name)
{
	ctf_file_t *ctf_file;
	struct per_module *new_per_mod;
	int ctf_err;

	ctf_file = ctf_create(&ctf_err);
	if (ctf_file == NULL) {
		pr_err("Cannot create CTF file: %s\n", strerror(ctf_err));
		exit(1);
	}
	new_per_mod = malloc(sizeof(struct per_module));
	if (new_per_mod == NULL) {
		pr_err("Out of memory allocating per-module CTF info\n");
		exit(1);
	}

	new_per_mod->ctf_file = ctf_file;
	new_per_mod->member_counts = g_hash_table_new_full(g_str_hash,
							   g_str_equal,
							   free, free);
	g_hash_table_replace(per_module, xstrdup(module_name), new_per_mod);

	dw_ctf_trace("Initializing module: %s\n", module_name);
	if ((strcmp(module_name, "shared_ctf") == 0) ||
	    !deduplicating) {
		ctf_encoding_t void_encoding = { CTF_INT_SIGNED, 0, 0 };
		ctf_encoding_t int_encoding = { CTF_INT_SIGNED, 0,
						sizeof(int) * 8 };
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
		mark_shared_by_name(ctf_file, ctf_void_type, "void");
		mark_shared_by_name(ctf_file, int_type, "int");

		func_info.ctc_return = int_type;
		func_info.ctc_argc = 0;
		func_info.ctc_flags = 0;
		func_type = ctf_add_function(ctf_file, CTF_ADD_ROOT,
					     &func_info, NULL);
		ctf_funcptr_type = ctf_add_pointer(ctf_file, CTF_ADD_ROOT,
						   func_type);

		if (ctf_update(ctf_file) < 0) {
			pr_err("Cannot initialize shared CTF file: %s\n",
			       ctf_errmsg(ctf_errno(ctf_file)));
			exit(1);
		}
	} else {
		/*
		 * Local types module with deduplication enabled: point the
		 * parent at the global CTF file, which must exist by this
		 * point.
		 */
		if (ctf_import(ctf_file, lookup_ctf_file("shared_ctf")) < 0) {
			pr_err("Cannot set parent of CTF file for module %s: %s\n",
			       module_name, ctf_errmsg(ctf_errno(ctf_file)));
			exit(1);
		}
		ctf_parent_name_set(ctf_file, "shared_ctf");
	}

	dw_ctf_trace("Created CTF file for module %s: %p\n",
		     module_name, ctf_file);
}

/* DWARF walkers.  */

/*
 * Initialize the child->parent DIE mapping for a single file.
 */
static void init_parent_die(const char *file_name, Dwfl *dwfl)
{
	GHashTable *offs;
	Dwarf_Die *tu_die = NULL;
	Dwarf_Addr junk;

	offs = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (offs == NULL) {
		pr_err("Out of memory creating DIE offset hash\n");
		exit(1);
	}

	while ((tu_die = dwfl_nextcu(dwfl, tu_die, &junk)) != NULL) {
		init_parent_die_internal(file_name, offs, tu_die, 0, 0);
	}

	g_hash_table_insert(fn_to_die_to_parent,
			    strdup(abs_file_name(file_name)), offs);
}

/*
 * Initialize one layer of a child->parent mapping.
 *
 * We traverse children of top-level subprograms hunting for anything we know
 * how to emit, and record parent->child mappings for all intermediate DIEs.
 */
static int init_parent_die_internal(const char *file_name,
				    GHashTable *offs, Dwarf_Die *parent,
				    int depth, int found_subprogram)
{
	Dwarf_Die child;
	int sib_ret;
	Dwarf_Off parent_offset;
	const char *err;
	int add_parent = 0;

	if (dwarf_tag(parent) == DW_TAG_subprogram)
		found_subprogram = 1;

	switch (dwarf_child(parent, &child)) {
	case -1:
		err = "child DIEs";
		goto err;
	case 1: /* This DIE has no children */
		goto out;
	}

	parent_offset = dwarf_dieoffset(parent);

	do {
		int add_child = 0;

		/*
		 * Add links from the parent to all children for which a
		 * recursive call says they should be added, and note that we
		 * should add links to the parent too.  Always look down to
		 * depth 2, since the topmost level is always
		 * DW_TAG_compile_unit, and we are interested in
		 * DW_TAG_subprograms one level below that.
		 */
		if (found_subprogram || depth < 2)
			add_child = init_parent_die_internal(file_name, offs,
							     &child, depth+1,
							     found_subprogram);

		if (add_child) {
			g_hash_table_insert(offs,
					    GUINT_TO_POINTER(dwarf_dieoffset(&child)),
					    GUINT_TO_POINTER(parent_offset));
			add_parent = 1;
		}
	} while ((sib_ret = dwarf_siblingof (&child, &child)) == 0);

	if (sib_ret == -1) {
		err = "sibling DIEs";
		goto err;
	}

out:
	/*
	 * Emit a link for the next level up if we're under a subprogram and
	 * either we emitted a child link or the parent is itself something we
	 * know how to emit (and thus might possibly appear in a type DIE we
	 * care about).
	 */
	return (found_subprogram &&
		(add_parent ||
		 (dwarf_tag(parent) <= assembly_len &&
		  assembly_tab[dwarf_tag(parent)] != NULL)));
err:
	pr_err("Cannot fetch %s of DIE at offset %lu in %s: %s\n",
	       err, DIEOFFSET(parent), file_name,
	       dwarf_errmsg(dwarf_errno()));
	exit(1);
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
 * return the same ID, but for certain other DIEs (notably those representing
 * the members of structures or unions), it is expected that they return the
 * same ID as their type DIE.
 *
 * This function is the hottest hot spot in dwarf2ctf, so is somewhat
 * aggressively optimized.
 *
 * The "overrides" allow the overriding of DWARF attributes, so that the
 * machinery notices different DWARF from what actually appears in the
 * debuginfo, so that the CTF that is emitted is suitably modified (and possibly
 * duplicated).  This is mostly used by type_id() to generate different IDs for
 * dependent types of bitfields, but can be used for other purposes too, such as
 * adjusting the offsets of types in unnamed structures, etc.  Overrides are
 * passed down if provided: overrides relating to bitfields are only applied by
 * type_id() if no other overrides are provided.
 *
 * In general, you do not need to pass overrides down if you know you will only
 * be called directly on top-level DIEs, but otherwise, you should do so.
 */
static char *type_id(Dwarf_Die *die,
		     struct die_override *overrides,
		     void (*fun)(Dwarf_Die *die,
				 const char *id,
				 struct die_override *overrides,
				 void *data),
		     void *data)
{
	return type_id_internal(die, overrides, fun, data, 0);
}

/*
 * Internal: generate the type ID for a type DIE.
 *
 * If there are no overrides, look for a bit_size and bit_offset and pass them
 * down as well.
 */
static char *type_id_type_die(Dwarf_Die *die,
			      Dwarf_Die *type_die,
			      struct die_override *overrides,
			      void (*fun)(Dwarf_Die *die,
					  const char *id,
					  struct die_override *overrides,
					  void *data),
			      void *data)
{
	char *id;

	/*
	 * bit_size and bit_offset go together: we can assume that if a member
	 * has the one, it has the other.
	 */

	if (private_dwarf_hasattr(die, DW_AT_bit_size)) {
		Dwarf_Word size;
		Dwarf_Word offset;

		size = private_dwarf_udata(die, DW_AT_bit_size, NULL);
		offset = private_dwarf_udata(die, DW_AT_bit_offset, NULL);
		struct die_override o[] = {
			{ DW_TAG_base_type,
			  DW_AT_bit_size,
			  DIE_OVERRIDE_REPLACE,
			  size, NULL },
			{ DW_TAG_base_type,
			  DW_AT_bit_offset,
			  DIE_OVERRIDE_REPLACE,
			  offset, overrides },
			{0}
		};
		id = type_id(type_die, o, fun, data);
	} else
		id = type_id(type_die, overrides, fun, data);
	return id;
}

/*
 * Internal: allows flags to be passed to affect one (and only one) type ID
 * recursion, without affecting other type_id()s launched from the 'fun'.
 */
static char *type_id_internal(Dwarf_Die *die,
			      struct die_override *overrides,
			      void (*fun)(Dwarf_Die *die,
					  const char *id,
					  struct die_override *overrides,
					  void *data),
			      void *data,
			      int flags)
{
	char *id = NULL;
	int no_type_id = 0;
	int decorated = 1;

	/*
	 * The ID of a null pointer is NULL.
	 */
	if (die == NULL)
		return NULL;

	/*
	 * The ID of a function pointer is '//fp//', as a special case,
	 * with no location or overrides, ever.
	 */
	if (dwarf_tag(die) == DW_TAG_subroutine_type) {
		id = xstrdup("//fp//");
		if (fun)
			fun(die, id, NULL, data);
		return id;
	}

	/*
	 * If we have a type DIE, generate it first, passing any overrides down.
	 * (Base types and enumerations don't have a type DIE that CTF can
	 * encode the type of in any useful fashion.)
	 *
	 * Otherwise, note the location of this DIE, providing scoping
	 * information for all types based upon this one.  Location elements are
	 * separated by //, an element impossible in a Linux path.  The
	 * blacklist type prefix (if set) follows this (which is a name which,
	 * while not impossible in a Linux path, is very unlikely.)
	 *
	 * Array dimensions get none of this: they must be contained within
	 * another DIE, so will always have a location attached via that DIE,
	 * and get their type chased further down (so as to arrange that they
	 * appear inside an [].)
	 */
	if (dwarf_tag(die) != DW_TAG_subrange_type) {
		if ((dwarf_tag(die) != DW_TAG_base_type) &&
		    (dwarf_tag(die) != DW_TAG_enumeration_type)) {
			Dwarf_Die type_die;
			Dwarf_Die *diep = private_dwarf_type(die, &type_die);

			if (diep)
				id = type_id_type_die(die, diep, overrides,
						      fun, data);
		}

		/*
		 * Location information.  We use cached realpath() results, and
		 * call str_appendn() only once, minimizing the number of
		 * strlen()s.
		 */
		if (id == NULL) {
			const char *decl_file_name = dwarf_decl_file(die);
			int decl_line_num;
			const char *fname = "";
			char line_num[21] = "";	 /* > than 2^64's digit count */

			no_type_id = 1;
			if (decl_file_name != NULL)
				fname = abs_file_name(decl_file_name);

			if (dwarf_decl_line(die, &decl_line_num) >= 0) {
				snprintf(line_num, sizeof(line_num), "%i",
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
	 * adjust mark_shared_by_name and dedup_alias_fixup(), which
	 * construct the IDs of basic types, structures, and unions by hand.
	 */
	switch (dwarf_tag(die)) {
	case DW_TAG_base_type: {
		Dwarf_Word bit_size = -1;
		Dwarf_Word type_size = -1;
		Dwarf_Word bit_offset = -1;
		const char *diename = dwarf_diename(die);

		if ((flags & TI_COLLAPSE_SIZETYPE) &&
		    (strcmp(diename, "long unsigned int") == 0))
			diename = "sizetype";

		/*
		 * CTF encodes the size and bitwise-offset of bit-fields in the
		 * base type, so it must be stored once for each size, even if
		 * it only appears once for all sizes in the DWARF.
		 */
		if (private_dwarf_hasattr(die, DW_AT_bit_size) ||
		    private_find_override(die, DW_AT_bit_size,
					  overrides))
			bit_size = private_dwarf_udata(die, DW_AT_bit_size,
						       overrides);
		if (private_dwarf_hasattr(die, DW_AT_bit_offset) ||
		    private_find_override(die, DW_AT_bit_offset,
					  overrides))
			bit_offset = private_dwarf_udata(die, DW_AT_bit_offset,
							 overrides);

		/*
		 * Bitfields that occupy their entire containing type are not
		 * bitfields, but just redundant DWARF.  GCC emits these now and
		 * again, but the dups would trip CTF consistency checks, so
		 * must be skipped.
		 */
		if (bit_size > -1) {
			/*
			 * This "may be omitted" in DWARF, but GCC doesn't:
			 * bitfields always get both.  (See
			 * gcc/dwarf2out.c:gen_field_die().)
			 */
			type_size = private_dwarf_udata(die, DW_AT_bit_size,
							overrides);
		}
		if (bit_size != type_size) {
			char bitsize[22];	/* > 2^64's digit count */
			char bitoffset[22];	/* > 2^64's digit count */

			snprintf(bitsize, sizeof(bitsize), "%li", bit_size);
			id = str_appendn(id, diename, ":", bitsize, NULL);
			if (bit_offset != -1) {
				snprintf(bitoffset, sizeof(bitoffset), "%li",
					bit_offset);
				id = str_appendn(id, ":", bitoffset, NULL);
			}
			id = str_append(id, " ");
		} else {
			/*
			 * Ordinary (non-bit-field) base type.
			 */
			id = str_appendn(id, diename, " ", NULL);
		}
		break;
	}
	case DW_TAG_enumeration_type:
		id = str_appendn(id, "enum ", dwarf_diename(die), " ", NULL);
		break;
	case DW_TAG_structure_type:
	case DW_TAG_union_type: {
		/*
		 * Incorporate the unaligned sizeof() the structure, if
		 * statically known (the offset of the last member in the DWARF)
		 * so that most structures which are redefined on the fly by
		 * preprocessor defines are disambiguated despite being defined
		 * in the same place.
		 *
		 * Only do this if this is a non-opaque structure/union
		 * definition: opaque definitions cannot have a size, but if
		 * they do by some mischance get one, notating it will mess up
		 * the several other places that manually construct opaque
		 * structure identifiers (and cannot incorporate a size, since
		 * they don't know it).
		 */
		const char *sou;

		if (strncmp(id, "////", 4) != 0) {
			long long size;
			char byte_size[24];

			size = private_dwarf_size(die);
			if (size > -1) {
				sprintf(byte_size, "%lli", size);
				id = str_appendn(id, byte_size, "//", NULL);
			}
		}

		if (dwarf_tag(die) == DW_TAG_union_type)
			sou = "union ";
		else
			sou = "struct ";

		id = str_appendn(id, sou, dwarf_diename(die), " ", NULL);
		break;
	}
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
			pr_err("Corrupt DWARF: Cannot get array dimensions: %s\n",
			       dwarf_errmsg(dwarf_errno()));
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
			char *sub_id = type_id_internal(&dim_die, overrides,
							fun, data,
							TI_COLLAPSE_SIZETYPE);
			id = str_append(id, sub_id);
			free(sub_id);
		} while ((sib_ret = dwarf_siblingof(&dim_die, &dim_die)) == 0);

		if (sib_ret == -1) {
			pr_err("Corrupt DWARF: Cannot get array dimensions: %s\n",
			       dwarf_errmsg(dwarf_errno()));
			exit(1);
		}
		break;
	}
	case DW_TAG_subrange_type: {
		Dwarf_Word nelems = private_subrange_dimensions(die);

		id = str_append(id, "[");

		if (nelems > 0)	{
			Dwarf_Die type_die;
			char elems[22];	    /* bigger than 2^64's digit count */
			char *sub_id = type_id_internal(private_dwarf_type(die, &type_die),
							overrides, fun, data,
							TI_COLLAPSE_SIZETYPE);

			snprintf(elems, sizeof(elems), " %li", nelems);
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
		fun(die, id, overrides, data);

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

	Dwfl_Module *mod;
	Dwfl *dwfl;
	Dwarf *dwarf;
	GHashTable *seen_before = g_hash_table_new_full(g_str_hash, g_str_equal,
							free, free);
	Dwarf_Die *tu_die = NULL;
	Dwarf_Addr junk;

	if (seen_before == NULL) {
		pr_err("Out of memory creating seen_before hash\n");
		exit(1);
	}

	dwfl = simple_dwfl_new(file_name, &mod);
	dwarf = dwfl_module_getdwarf(mod, &junk);

	/*
	 * On first traversal, make sure the DIE parent mapping is populated,
	 * so that filter_ctf_file_scope can use it.
	 */
	if (!g_hash_table_lookup_extended(fn_to_die_to_parent,
					  abs_file_name(file_name),
					  NULL, NULL))
		init_parent_die(file_name, dwfl);

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
		 *
		 * This is purely an optimization: it breaks somewhat for
		 * multifile modules but this has no effect but a slight
		 * slowdown.
		 */
		if (g_hash_table_lookup_extended(seen_before, tu_name,
						 NULL, NULL))
			continue;

		g_hash_table_replace(seen_before, xstrdup(tu_name), NULL);

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

		process_tu_func(module_name, file_name, dwarf, tu_die, &die,
				dwarf_process, data);

		if (tu_done != NULL)
			tu_done(module_name, file_name, tu_die, data);
	}

	free(fn_module_name);
	simple_dwfl_free(dwfl);
	g_hash_table_destroy(seen_before);

	return;

 fail:
	pr_err("Cannot %s for %s: %s\n", err, module_name,
	       dwarf_errmsg(dwarf_errno()));
	exit(1);
}

/*
 * process_file() helper, walking over the top level and picking up types
 * therein.
 */
static void process_tu_func(const char *module_name,
			    const char *file_name,
			    Dwarf *dwarf,
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
	 * emit CTF: call the processing function for all such.
	 */
	do {
		if ((dwarf_tag(die) <= assembly_len) &&
		    (assembly_filter_tab[dwarf_tag(die)] == NULL ||
		     assembly_filter_tab[dwarf_tag(die)](file_name, dwarf, die,
							 parent_die)) &&
		    (assembly_tab[dwarf_tag(die)] != NULL))
			dwarf_process(module_name, file_name, die,
				      parent_die, data);
	} while ((sib_ret = dwarf_siblingof(die, die)) == 0);

	if (sib_ret == -1) {
		err = "fetch sibling";
		goto fail;
	}

	return;
 fail:
	pr_err("Cannot %s for %s: %s\n", err, module_name,
	       dwarf_errmsg(dwarf_errno()));
	exit(1);
}

/* Duplicate detection. */

/*
 * Scan and identify duplicates across the entire set of object files.
 */
static void scan_dups(void)
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

	struct dedup_state state = {0};

	dw_ctf_trace("Duplicate detection: primary pass.\n");

	/*
	 * This is merely flushed between TUs, not recreated: we create it here.
	 */
	state.vars_seen = g_hash_table_new_full(g_str_hash,
						g_str_equal,
						free, NULL);

	for (i = 0; i < object_names_cnt; i++)
		process_file(object_names[i], dedup,
			     dedup_tu_init, dedup_tu_done, &state);

	if ((!state.repeat_detection) || !deduplicating)
		goto out;

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
		state.named_structs = list_filter(state.named_structs,
						  dedup_alias_fixup,
						  free_dups_id_file, &state);
	} while (state.repeat_detection);
 out:
	g_hash_table_destroy(state.vars_seen);
	dedup_dwarf_free(&state);
	dw_ctf_trace("Duplicate detection: complete.\n");
	dw_ctf_trace("%llu distinct type IDs known.\n",
		     (unsigned long long) g_hash_table_size(id_to_module));
	dw_ctf_trace("%llu variables blacklisted for static/nonstatic conflicts.\n",
		     (unsigned long long) g_hash_table_size(variable_blacklist));
	g_list_free_full(state.named_structs, free_dups_id_file);
}

/*
 * Set up state for dedup().  A tu_init() callback.
 */
static void dedup_tu_init(const char *module_name, const char *file_name,
			  Dwarf_Die *tu_die, void *data)
{
	struct dedup_state *state = data;
	struct per_module *per_mod;

	/*
	 * Make sure that even if this module has no types in it we still end up
	 * generating a CTF file.  (Userspace depends on this, since a CTF file
	 * with no types in means the module is known and typeless, while no CTF
	 * file at all means the module is not known.)
	 */

	per_mod = g_hash_table_lookup(per_module, module_name);
	if (per_mod == NULL) {
		init_ctf_table(module_name);
		dw_ctf_trace("%s: initialized CTF file.\n", module_name);
	}

	state->structs_seen = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_remove_all(state->vars_seen);
	state->module_name = module_name;
}

/*
 * Free state for dedup().  A tu_done() callback.
 */
static void dedup_tu_done(const char *module_name, const char *file_name,
			  Dwarf_Die *tu_die, void *data)
{
	struct dedup_state *state = data;

	/*
	 * We have to annul module_name because it is freed between object files
	 * by process_file().  Since we use that to track whether vars_seen
	 * needs reconstructing, that means we have to destroy that as well.
	 */
	g_hash_table_destroy(state->structs_seen);
	state->structs_seen = NULL;
	state->module_name = NULL;
}

/*
 * Free DWARF state for dedup().
 */
static void dedup_dwarf_free(struct dedup_state *state)
{
	if (state->dwfl == NULL)
		return;
	simple_dwfl_free(state->dwfl);
	state->dwfl = NULL;
	state->dwarf = NULL;
	free(state->dwfl_file_name);
	state->dwfl_file_name = NULL;
	if (state->structs_seen)
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

static void dedup(const char *module_name, const char *file_name,
		  Dwarf_Die *die, Dwarf_Die *parent_die, void *data)
{
	struct dedup_state *state = data;
	int is_sou = 0;
	char *id = type_id(die, NULL, is_named_struct_union_enum, &is_sou);

	state->file_name = file_name;
	/*
	 * If a DWARF-4 type signature is found, abort.  While we can support
	 * DWARF-4 eventually, support in elfutils is insufficiently robust for
	 * now (elfutils 0.152).
	 */
	if (private_dwarf_hasattr(die, DW_AT_type)) {
		Dwarf_Attribute type_attr;

		if ((private_dwarf_attr(die, DW_AT_type, &type_attr) != NULL) &&
		    (dwarf_whatform(&type_attr) == DW_FORM_ref_sig8)) {
			pr_err("Sorry, not yet implemented: %s contains DWARF-4 debugging information.\n",
			       module_name);
			exit(1);
		}
	}

	/*
	 * Non-anonymous, non-opaque structure/union/enum types in
	 * non-dedup-blacklisted modules get their names and locations recorded
	 * for subsequent passes; all type_id()-descendant types are similarly
	 * noted.
	 */
	if (is_sou && strncmp(id, "////", strlen("////")) != 0)
		free(type_id(die, NULL, dedup_will_rescan, state));

	/*
	 * Handle static variable blacklisting.  (We still shuffle blacklisted
	 * variables into the right place in id_to_module because we check for
	 * blacklisting at the lowest level, by which point we have already
	 * depended on id_to_module being correctly populated.)
	 *
	 * Avoid calling this for recursive dependent-type scans: variables
	 * cannot be dependent types.
	 */
	if (parent_die != NULL && dwarf_tag(die) == DW_TAG_variable)
		dedup_blacklist_var_dups(die, state);

	dedup_mark_inner_die(module_name, die, id, NULL, data);
	free(id);
}

/*
 * Do the underlying marking of a DIE as shared, iff need be.  (No variable
 * blacklisting, non-opaque structure checks, or anything else needed only by
 * top-level DIEs.)
 *
 * This function may be called multiple times for overridden DIEs that are
 * dependent types of bitfields.  (On multiple calls for normal types, the
 * second call will enter the NS_NO_MARKING case block and terminate recursion.)
 */
static void dedup_mark_inner_die(const char *module_name, Dwarf_Die *die,
				 const char *id,
				 struct die_override *overrides,
				 void *data)
{
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
	switch (type_needs_sharing(module_name, id)) {
	case NS_NEEDS_SHARING:
		mark_shared(die, NULL, overrides, data);
		mark_seen_contained(die, "shared_ctf", overrides, data);
		/* Fall through */
	case NS_NO_MARKING:
		/*
		 * A duplicated type, but in the same module, or deduplication
		 * is disabled, so id_to_module is already correct.  (When
		 * deduplication is disabled, we will be running with only one
		 * module at a time, and id_to_module will be a trivial
		 * mapping.)
		 */
		return;
	case NS_NOT_SHARED:
		break;
	}

	/*
	 * Record that we have seen this type, and all its dependent types, in
	 * this module (or in the shared module if need be).
	 */

	dw_ctf_trace("Marking %s as seen in %s\n", id, module_name);
	g_hash_table_replace(id_to_module, intern(xstrdup(id)),
			     xstrdup(module_name));
	mark_seen_contained(die, module_name, overrides, data);
	free(type_id(die, overrides, dedup_typeid, data));
}

/*
 * Note in the dedup_id_file list that we will rescan a DIE in a later duplicate
 * detection pass.
 *
 * A type_id() callback.
 */
static void dedup_will_rescan(Dwarf_Die *die, const char *id,
			      struct die_override *overrides, void *data)
{
	struct dedup_state *state = data;
	struct dedup_id_file *id_file;

	/*
	 * We don't care about array index types, which will never be structures
	 * in C.
	 */
	if (id[0] == '[')
		return;

	id_file = calloc(1, sizeof(struct dedup_id_file));
	if (id_file == NULL) {
		pr_err("Out of memory allocating id_file\n");
		exit(1);
	}
	id_file->file_name = intern(xstrdup(state->file_name));
	id_file->id = intern(xstrdup(id));
	id_file->dieoff = dwarf_dieoffset(die);
	state->named_structs = g_list_prepend(state->named_structs, id_file);
}

/*
 * Note the variable referenced by this DIE in vars_seen: blacklist it if an
 * entry for this variable already exists in vars_seen and this instance is
 * static, or if a static entry already exists in vars_seen, whether this
 * instance is static or not.
 */
static void dedup_blacklist_var_dups(Dwarf_Die *die,
				     struct dedup_state *state)
{
	void *static_var;
	int blacklist = 0;

	if (g_hash_table_lookup_extended(state->vars_seen,
					 dwarf_diename(die),
					 NULL, &static_var)) {
		if (!private_dwarf_hasattr(die, DW_AT_external) &&
		    !private_dwarf_hasattr(die, DW_AT_declaration))
			blacklist = 1;
		if (static_var != NULL)
			blacklist = 1;
	} else
	  /*
	   * We need a non-NULL address here, but that is all we need.
	   * The address of a random variable will do.
	   */
		g_hash_table_insert(state->vars_seen,
				    xstrdup(dwarf_diename(die)),
				    (!private_dwarf_hasattr(die, DW_AT_external) &&
				     !private_dwarf_hasattr(die, DW_AT_declaration)) ?
				    &static_var : NULL);

	if (blacklist) {
		char *var = NULL;
		var = str_appendn(var, state->module_name, "`",
				  dwarf_diename(die), NULL);
		g_hash_table_replace(variable_blacklist, var, NULL);
	}
}

/*
 * Free a dedup_id_file's contents.
 */
static void free_dups_id_file(void *data)
{
	struct dedup_id_file *id_file = data;
	free(id_file);
}

/*
 * Determine if a type is duplicated and needs sharing.
 */
static enum needs_sharing type_needs_sharing(const char *module_name,
					     const char *id)
{
	const char *existing_type_module;
	existing_type_module = g_hash_table_lookup(id_to_module, id);

	/*
	 * Types not already known about do not need sharing.
	 *
	 * Types already in the current modules and any types in external-module
	 * mode do not even need marking.
	 */
	if (existing_type_module == NULL)
		return NS_NOT_SHARED;

	if ((strcmp(existing_type_module, module_name) == 0) ||
	    (strcmp(existing_type_module, "shared_ctf") == 0) ||
	    !deduplicating)
		return NS_NO_MARKING;

	return NS_NEEDS_SHARING;
}

/*
 * Detect duplicates and mark seen types for a given type, via a type_id()
 * callback: used to detect dependent types (particularly those at child-DIE
 * level) as duplicates.
 */
static void dedup_typeid(Dwarf_Die *die, const char *id,
			 struct die_override *overrides, void *data)
{
	struct dedup_state *state = data;

	dedup_mark_inner_die(state->module_name, die, id, overrides, data);
}

/*
 * Mark any types contained within a particular type DIE as seen.  This is
 * needed since even nameless types contained within other aggregates can be
 * used as the type of members in any of their enclosing aggregates (though they
 * cannot possibly be found in a module different from that of their containing
 * aggregate, any more than a structure member can).
 */
static void mark_seen_contained(Dwarf_Die *die, const char *module_name,
				struct die_override *overrides,
				void *data)
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
	 * We iterate over all immediate children and recursively call ourselves
	 * for all those of type DW_TAG_structure_type and DW_TAG_union_type.
	 *
	 * Further, everything with an entry in assembly_tab other than
	 * non-bitfield members needs marking, since these may be declared at
	 * structure scope rather than being confined to global scope.
	 * Non-bitfield members are skipped because they cannot be used as the
	 * type of another field.  These types cannot be duplicates if their
	 * containing type is not a duplicate, and typedefs cannot occur at this
	 * level so they cannot be aliased; thus we can mark them directly
	 * without going back into the top of dedup().
	 *
	 * (Bit-field members are not skipped: they use different CTF from their
	 * non-bitfield equivalents, even though they refer to the same
	 * top-level DIE.  The actual different CTF is handled by type_id()
	 * itself, but we do have to call it.)
	 */
	int sib_ret;

	do
		switch (dwarf_tag(&child)) {
		case DW_TAG_member: {
			/*
			 * bit_size and bit_offset go together: we can assume
			 * that if a member has the one, it has the other,
			 * is a bitfield, and needs recursive marking.
			 */
			if (dwarf_tag(&child) == DW_TAG_member &&
			    !private_dwarf_hasattr(&child, DW_AT_bit_size))
				break;

			free(type_id(&child, overrides, dedup_typeid, data));
			break;
		}
		case DW_TAG_structure_type:
		case DW_TAG_union_type:
			mark_seen_contained(&child, module_name, overrides, data);
			/* fall through */
		default:
			if (dwarf_tag(&child) <= assembly_len &&
			    assembly_tab[dwarf_tag(&child)] != NULL) {

				char *id = type_id(&child, overrides, NULL, NULL);

				dw_ctf_trace("Marking member %s as seen in "
					     "%s\n", id, module_name);
				g_hash_table_replace(id_to_module, intern(id),
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
	pr_err("Cannot %s while marking aggregates as seen: %s\n",
	       err, dwfl_errmsg(dwfl_errno()));
	exit(1);
}

/*
 * Mark a type as duplicated and located in the shared CTF table.  Recursive,
 * via the type_id() callback mechanism.
 *
 * A type_id() callback (though also called directly).
 */
static void mark_shared(Dwarf_Die *die, const char *id,
			struct die_override *overrides, void *data)
{
	struct dedup_state *state = data;
	const char *existing_module;

	/*
	 * Non-recursive call.  Trigger type_id for its recursive callback,
	 * throwing the result away.
	 */
	if (id == NULL) {
		free(type_id(die, overrides, mark_shared, state));
		return;
	}

	existing_module = g_hash_table_lookup(id_to_module, id);

	if ((existing_module == NULL) ||
	    (strcmp(existing_module, "shared_ctf") != 0)) {

		dw_ctf_trace("Marking %s as duplicate\n", id);
		g_hash_table_replace(id_to_module, intern(xstrdup(id)),
				     xstrdup("shared_ctf"));

		/*
		 * Newly-marked structures/unions/enums must trigger a new
		 * duplicate detection pass (even if they are opaque).
		 */

		if (((dwarf_tag(die) == DW_TAG_structure_type) ||
		     (dwarf_tag(die) == DW_TAG_union_type) ||
		     (dwarf_tag(die) == DW_TAG_enumeration_type)) &&
		    (!state->repeat_detection)) {
			dw_ctf_trace("Requesting another duplicate detection pass.\n");
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
		g_hash_table_replace(state->structs_seen, intern(xstrdup(id)),
				     NULL);

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
			if ((dwarf_tag(&child) == DW_TAG_member) &&
			    !member_blacklisted(&child, die))
				free(type_id(&child, overrides,
					     mark_shared, state));
		while ((sib_ret = dwarf_siblingof(&child, &child)) == 0);

		if (sib_ret == -1)
			goto fail;
	}

	return;

 fail:
	pr_err("Cannot mark aggregate %s members as duplicated: %s\n",
	       dwarf_diename(die), dwarf_errmsg(dwarf_errno()));
	exit(1);
}

/*
 * Determine if a type is a named struct, union, or enum.
 *
 * A type_id() callback.
 */
static void is_named_struct_union_enum(Dwarf_Die *die, const char *unused,
				       struct die_override *overrides,
				       void *data)
{
	int *is_sou = data;

	if (((dwarf_tag(die) == DW_TAG_structure_type) ||
	     (dwarf_tag(die) == DW_TAG_union_type) ||
	     (dwarf_tag(die) == DW_TAG_enumeration_type)) &&
	    (private_dwarf_hasattr(die, DW_AT_name)))
		*is_sou = 1;
}

/*
 * Duplicate detection alias fixup pass.  Once the first pass is complete, we
 * may have marked an opaque 'struct/union/enum foo' for sharing but not caught
 * the non-opaque instance, because no users of the non-opaque instance appeared
 * in the DWARF after the opaque copy was detected as a duplicate.  This pass
 * detects such cases, and marks their members as duplicates too.
 *
 * (The inverse case of a non-opaque structure/union/enum detected as a
 * duplicate after the last usage of its opaque alias will be caught by this
 * trap too.)
 *
 * Warning: this routine directly computes type_id()s without access to the
 * corresponding type DIE, and as such is dependent on the format of type_id()s.
 * (This is why it must run over non-opaque structures: given a non-opaque
 * structure, its opaque alias is easy to compute, but the converse is not
 * true.)
 *
 * As a list_filter() filter function, returns nonzero if this structure will
 * not need to be checked again (because both its opaque and transparent
 * variants are shared).
 */
static int dedup_alias_fixup(void *id_file_data, void *data)
{
	struct dedup_id_file *id_file = id_file_data;
	struct dedup_state *state = data;

	int transparent_shared = 0;
	int opaque_shared = 0;
	int made_shared = 0;

	char *opaque_id;
	const char *line_num;
	const char *type_size;
	const char *type_name;

	/*
	 * Compute the opaque variant corresponding to this transparent type,
	 * and check to see if either is marked shared, then find the DIE and
	 * mark both as shared if either is.  (Unfortunately this means a double
	 * recursion in such cases, but this is unavoidable.)
	 */

	line_num = strstr(id_file->id, "//");
	if (!line_num) {
		pr_err("Internal error: type ID %s is corrupt.\n",
		       id_file->id);
		exit(1);
	}

	type_size = strstr(line_num + 2, "//");
	if (!type_size) {
		pr_err("Internal error: type ID %s is corrupt.\n",
		       id_file->id);
		exit(1);
	}

	type_name = strstr(type_size + 2, "//");
	if (!type_name) {
		/*
		 * That's OK: the type size is optional, so what we thought was
		 * the type size is actually the type name.
		 */
		type_name = type_size;
	}
	type_name += 2;

	opaque_id = xstrdup("////");
	opaque_id = str_append(opaque_id, type_name);

	const char *transparent_module = g_hash_table_lookup(id_to_module,
							     id_file->id);
	const char *opaque_module = g_hash_table_lookup(id_to_module,
							opaque_id);

	transparent_shared = ((transparent_module != NULL) &&
			      (strcmp(transparent_module, "shared_ctf") == 0));

	opaque_shared = ((opaque_module != NULL) &&
			 (strcmp(opaque_module, "shared_ctf") == 0));

	/*
	 * Transparent type needs sharing.
	 */
	if (opaque_shared && !transparent_shared) {
		Dwarf_Die die;
		Dwfl_Module *mod;
		Dwarf_Addr dummy;

		/*
		 * Since we are not using process_file(), we must handle
		 * translation unit switches by hand, including resetting
		 * structs_seen.  We also need to open the DWARF file, since
		 * type_id() needs access to the DIE of this type and all its
		 * dependent types as well.
		 */

		if (state->dwfl != NULL &&
		    strcmp(state->dwfl_file_name, id_file->file_name) != 0)
			dedup_dwarf_free(state);

		if (state->dwfl_file_name == NULL) {
			state->dwfl = simple_dwfl_new(id_file->file_name, &mod);
			state->dwarf = dwfl_module_getdwarf(mod, &dummy);
			state->dwfl_file_name = xstrdup(id_file->file_name);
			if (state->structs_seen)
				g_hash_table_destroy(state->structs_seen);
			state->structs_seen = g_hash_table_new(g_str_hash,
							       g_str_equal);
		}
		if (!dwarf_offdie(state->dwarf, id_file->dieoff,
				  &die)) {
			pr_err("Cannot look up offset %li in %s for type with ID %s\n",
			       id_file->dieoff, id_file->file_name, id_file->id);
			exit(1);
		}
		mark_shared(&die, NULL, NULL, state);
		made_shared = 1;
	}

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
		g_hash_table_replace(id_to_module, intern(xstrdup(opaque_id)),
				     xstrdup("shared_ctf"));
		made_shared = 1;
	}

	free(opaque_id);

	return made_shared || (opaque_shared && transparent_shared);
}

/*
 * Mark a basic type shared by name and intern it in all relevant hashes.  (Used
 * for marking basic types we don't have a DIE for.)
 */
static void mark_shared_by_name(ctf_file_t *ctf, ctf_id_t ctf_id,
				const char *name)
{
	struct ctf_full_id static_ctf_id = { ctf, ctf_id };
	struct ctf_full_id *full_ctf_id;
	char *id = NULL;

	full_ctf_id = malloc(sizeof(struct ctf_full_id));
	if (full_ctf_id == NULL) {
		pr_err("%s: out of memory\n", __func__);
		exit(1);
	}
	*full_ctf_id = static_ctf_id;

	id = str_appendn(id, "////", name, " ", NULL);
#ifdef DEBUG
	strcpy(full_ctf_id->module_name, "shared_ctf");
	strcpy(full_ctf_id->file_name, "<built-in type>");
#endif
	g_hash_table_replace(id_to_module, intern(xstrdup(id)), xstrdup("shared_ctf"));
	g_hash_table_replace(id_to_type, intern(id), full_ctf_id);
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
 * most important function).  In such calls, the module_name may be 'shared_ctf'
 * if this type is in the shared CTF repository.
 *
 * Select properties of the DIE can be overridden via the overrides array, if
 * needed.
 */
static struct ctf_full_id *construct_ctf_id(const char *module_name,
					    const char *file_name,
					    Dwarf_Die *die,
					    Dwarf_Die *parent_die,
					    struct die_override *overrides)
{
	char *id = type_id(die, overrides, NULL, NULL);
	char *ctf_module;
	ctf_file_t *ctf;
	ctf_snapshot_id_t snapshot;

	dw_ctf_trace("    %p: %s: looking up %s: %s\n", &id,
		     module_name ? module_name : "(no module)",
		     dwarf_diename(die), id);
	/*
	 * Make sure this type does not already exist.  (Recursive chasing for
	 * referenced types can lead to construct_ctf() being called on them
	 * more than once.)
	 */
	struct ctf_full_id *ctf_id;

	ctf_id = g_hash_table_lookup(id_to_type, id);
	if (ctf_id != NULL) {
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
		pr_err("Internal error: within file %s, module %s, type at DIE offset %lx\n"
		       "with ID %s was not already noted by dedup().\n",
		       file_name, module_name, DIEOFFSET(die), id);
		pr_err("dedup() is probably buggy.\n");
		exit(1);
	}

	if ((strcmp(ctf_module, module_name) != 0) &&
	    (strcmp(ctf_module, "shared_ctf") != 0)) {
		pr_err("Internal error: within file %s, module %s, type at DIE offset %lx\n"
		       "with ID %s is in a different non-shared module, %s.\n",
		       file_name, module_name, DIEOFFSET(die), id, ctf_module);
		pr_err("dedup() is probably buggy.\n");
		exit(1);
	}

	ctf = lookup_ctf_file(ctf_module);

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

	snapshot = ctf_snapshot(ctf);

	enum skip_type skip = SKIP_CONTINUE;

	dw_ctf_trace("%p: into die_to_ctf() for %s\n", &id, id);
	ctf_id_t this_ctf_id = die_to_ctf(ctf_module, file_name, die,
					  parent_die, ctf, -1, overrides,
					  1, 0, &skip, NULL, id);
	dw_ctf_trace("%p: out of die_to_ctf()\n", &id);

	ctf_id = malloc(sizeof(struct ctf_full_id));
	if (ctf_id == NULL) {
		pr_err("Out of memory\n");
		exit(1);
	}

	if (skip != SKIP_ABORT) {
		ctf_id->ctf_file = ctf;
		ctf_id->ctf_id = this_ctf_id;
#ifdef DEBUG
		strcpy(ctf_id->module_name, ctf_module);
		strcpy(ctf_id->file_name, file_name);
#endif
		dw_ctf_trace("    %lx: %s: new type added, CTF ID %p:%li\n",
			     DIEOFFSET(die), id, ctf_id->ctf_file,
			     ctf_id->ctf_id);

                g_hash_table_replace(id_to_type, intern(id), ctf_id);
	} else {
		/*
		 * Failure.  Remove the type from the id_to_type mapping, if it
		 * is there, and discard any added types from the CTF.
		 *
		 * If we have had to ctf_update() due to a new type getting
		 * used, the rollback will fail: discard instead. It might leave
		 * some spurious types hanging around but it will clean up as
		 * much as we can at this point.  (This cannot happen when
		 * LIBDTRACE_CTF_OMISSIBLE_CTF_UPDATE, but it costs nothing to
		 * leave in: failure is a rare case.)
		 */

		if (ctf_rollback(ctf, snapshot) < 0)
			if (ctf_errno(ctf) == ECTF_OVERROLLBACK)
				ctf_discard(ctf);

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
 * struct die_override: Overrides for DWARF attributes (a NULL-terminated array,
 * or NULL).
 * top_level_type: 1 if this is a top-level type that can have a name and be
 * referred to by other types.
 * backwards: if 1, this is an internal call to process a series of bitfields
 *            with descending bit_offset and identical data_member_location.
 * skip: The error-handling / skipping enum.
 * replace: if 1, this type should replace its parent type entirely.
 * id: the ID of this type.
 *
 * Note: id is only defined when top_level_type is 1.  (We never use it
 * in other situations, and computing it is quite expensive.)
 */
static ctf_id_t die_to_ctf(const char *module_name, const char *file_name,
			   Dwarf_Die *die, Dwarf_Die *parent_die,
			   ctf_file_t *ctf, ctf_id_t parent_ctf_id,
			   struct die_override *overrides, int top_level_type,
			   int backwards, enum skip_type *skip, int *replace,
			   const char *id)
{
	int sib_ret = 0;
	ctf_id_t this_ctf_id;
	int dummy;

	do {
		const char *id_name;
		const char *decl_file_name = dwarf_decl_file(die);
		int decl_line_num;
		int emitted_backwards = 0;
		char locerrstr[1024];
		Dwarf_Die next_die;

		/*
		 * If the next DWARF DIE is at the same location as this one but
		 * with a lower bit_offset, we need to process the set of DIEs
		 * at this location in *reverse*, because DWARF has the DIEs in
		 * declaration order, while CTF wants them in in-memory order:
		 * so recurse to handle the next until we get to an element with
		 * a sibling at a different data_member_location (safe because
		 * there can't be that many of them per data_member_location),
		 * then (at the end of die_to_ctf()) exit the recursion and skip
		 * over the lot.
		 *
		 * We can ignore 'replace' and the return value of die_to_ctf
		 * because bitfields must be structure or union members and
		 * cannot be array dimensions.
		 */
		if (die_emit_next_backwards(&next_die, die,
					    overrides) != NULL) {
			ctf_id_t dummy;

			dw_ctf_trace("Emitting %s:%s:%lx backwards\n",
				     module_name, file_name,
				     DIEOFFSET(&next_die));

			dummy = die_to_ctf(module_name, file_name, &next_die,
					   parent_die, ctf, parent_ctf_id,
					   overrides, top_level_type, 1, skip,
					   replace, NULL);
			if (*skip == SKIP_ABORT)
				return dummy;
			emitted_backwards = 1;
		}

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

		snprintf(locerrstr, sizeof(locerrstr), "%s:%i:%s",
			 decl_file_name, decl_line_num, id_name);

		dw_ctf_trace("Working over %s:%s:%s:%lx:%x with CTF file %p\n",
			     module_name, file_name,
			     dwarf_diename(die)==NULL?"NULL":dwarf_diename(die),
			     DIEOFFSET(die), dwarf_tag(die), ctf);

		/*
		 * Only process a given node, or its children, if we know how to
		 * do so.
		 */
		if ((dwarf_tag(die) >= assembly_len) ||
		    (assembly_tab[dwarf_tag(die)] == NULL)) {
			pr_err("%s:%i: warning: skipping identifier "
			       "%s with unknown DWARF tag %lx.\n",
			       decl_file_name, decl_line_num, id_name,
			       (unsigned long) dwarf_tag(die));
			return -1;
		}

		*skip = SKIP_CONTINUE;

		this_ctf_id = assembly_tab[dwarf_tag(die)](module_name,
							   file_name,
							   die, parent_die,
							   ctf, parent_ctf_id,
							   locerrstr,
							   overrides,
							   top_level_type,
							   skip,
							   replace ? replace :
							   &dummy);
		dw_ctf_trace("%s: out of assembly function for tag %lx with type ID %li\n",
			     locerrstr, (unsigned long) dwarf_tag(die),
			     this_ctf_id);

		if (this_ctf_id < 0) {
			if ((this_ctf_id == CTF_NO_ERROR_REPORTED) &&
			    (ctf_errno(ctf) != 0))
				pr_err("%s: CTF error in assembly of item with tag %i: %s\n",
				       locerrstr, dwarf_tag(die),
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
			struct ctf_full_id full_ctf_id = { ctf, this_ctf_id };
			struct ctf_full_id *ctf_id;

#ifdef DEBUG
			strcpy(full_ctf_id.module_name, module_name);
			strcpy(full_ctf_id.file_name, file_name);
#endif

			ctf_id = malloc(sizeof(struct ctf_full_id));
			if (ctf_id == NULL) {
				fprintf(stderr,
					"Out of memory allocating type ID\n");
				exit(1);
			}

			dw_ctf_trace("    %s: immediate addition of %s, CTF ID "
				     "%p:%li in module %s, file %s\n", __func__,
				     id, full_ctf_id.ctf_file, full_ctf_id.ctf_id,
				     module_name, file_name);
			*ctf_id = full_ctf_id;

			g_hash_table_replace(id_to_type, intern(xstrdup(id)),
					     ctf_id);
		}

		/*
		 * Recurse to handle contained DIEs.
		 */

		if ((dwarf_haschildren(die)) && (*skip == SKIP_CONTINUE)) {
			Dwarf_Die child_die;
			ctf_id_t new_id;
			int replace = 0;

			if (dwarf_child(die, &child_die) < 0) {
				pr_err("%s: Cannot recurse to DWARF DIE children: %s\n",
				       locerrstr, dwarf_errmsg(dwarf_errno()));
				exit(1);
			}

			new_id = die_to_ctf(module_name, file_name, &child_die,
					    die, ctf, this_ctf_id, overrides, 0,
					    0, skip, &replace, NULL);
			if (replace)
				this_ctf_id = new_id;
		}

		/*
		 * If we are walking backwards over a bunch of bitfields, this
		 * is a recursive walk, not an iterative one: return.
		 */
		if (backwards)
			return this_ctf_id;

		/*
		 * We are not walking backwards, but this is the final stage of
		 * a bunch of backwards emissions: walk forwards until we hit
		 * the last one again.
		 */
		if (emitted_backwards)
			while (die_emit_next_backwards(&next_die, die,
						       overrides) != NULL)
				*die = next_die;

		/*
		 * Walk siblings of non-top-level types only: the sibling walk
		 * of top-level types is done by process_file(), so that
		 * construct_ctf_id() gets a chance to put each such type in the
		 * right CTF file.
		 */
	} while (*skip != SKIP_ABORT && !top_level_type &&
		 (sib_ret = dwarf_siblingof(die, die)) == 0);

	if (sib_ret == -1) {
		pr_err("In module %s, failure walking the sibling list: %s\n",
		       module_name, dwarf_errmsg(dwarf_errno()));
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
	construct_ctf_id(module_name, file_name, die, parent_die, NULL);
}

/*
 * Return the next DIE, if that DIE needs to be emitted before this one.
 */
static Dwarf_Die *die_emit_next_backwards(Dwarf_Die *next, Dwarf_Die *die,
					  struct die_override *overrides)
{
	if (dwarf_tag(die) == DW_TAG_member &&
	    dwarf_siblingof(die, next) == 0 &&
	    dwarf_tag(next) == DW_TAG_member &&
	    private_dwarf_hasattr(die, DW_AT_data_member_location) &&
	    private_dwarf_hasattr(next, DW_AT_data_member_location) &&
	    private_dwarf_udata(die, DW_AT_data_member_location, overrides) ==
	    private_dwarf_udata(next, DW_AT_data_member_location, overrides) &&
	    private_dwarf_hasattr(die, DW_AT_bit_offset) &&
	    private_dwarf_hasattr(next, DW_AT_bit_offset) &&
	    private_dwarf_udata(die, DW_AT_bit_offset, overrides) >
	    private_dwarf_udata(next, DW_AT_bit_offset, overrides))
		return next;
	return NULL;
}

/*
 * Look up a type through its reference: return its ctf_id, or recursively
 * construct it if need be.
 */
static ctf_id_t lookup_ctf_type(const char *module_name, const char *file_name,
				Dwarf_Die *die, ctf_file_t *ctf,
				struct die_override *overrides,
				const char *locerrstr)
{
	Dwarf_Die tmp;
	Dwarf_Die *type_die = private_dwarf_type(die, &tmp);
	Dwarf_Die cu_die;
	struct ctf_full_id *type_ref;

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

	dw_ctf_trace("    %s: Looking up dependent type at offset %lx for type %s at module %s, file %s\n",
		     locerrstr, DIEOFFSET(type_die),
		     dwarf_diename(die) ? dwarf_diename(die) : "NULL",
		     module_name, file_name);

	type_ref = construct_ctf_id(module_name, file_name,
				    type_die, &cu_die, overrides);

	/*
	 * Pass any error back up.
	 */
	if (type_ref == NULL) {
		pr_err("%s: type lookup failed.\n", locerrstr);
		return -1;
	}

	if ((type_ref->ctf_file != ctf) &&
	    type_ref->ctf_file != lookup_ctf_file("shared_ctf")) {
#ifdef DEBUG
		pr_err("%s: Internal error: lookup of %s found in different file: "
		       "%s/%s versus %s/%s.\n", locerrstr,
		       dwarf_diename(die) ? dwarf_diename(die) : "(unnamed)",
		       type_ref->module_name, type_ref->file_name,
		       module_name, file_name);
#else
		pr_err("%s: Internal error: lookup of %s found in different file.\n",
		       locerrstr, dwarf_diename(die) ? dwarf_diename(die) :
		       "(unnamed)");
#endif
		pr_err("dedup() is probably buggy.\n");
		exit(1);
	}

	return type_ref->ctf_id;
}

/* Assembly functions.  */

#define CTF_DW_ENFORCE(attribute) do					\
		if (!private_dwarf_hasattr(die, (DW_AT_##attribute))) {	\
			pr_err("%s: %s: %lx: skipping type, %s attribute not present.\n", \
			       locerrstr, __func__,  DIEOFFSET(die),	\
			       #attribute);				\
			*skip = SKIP_ABORT;				\
			return CTF_ERROR_REPORTED;			\
		}							\
	while (0)

#define CTF_DW_ENFORCE_NOT(attribute) do				\
		if (private_dwarf_hasattr(die, (DW_AT_##attribute))) {	\
			pr_err("%s: %s: %lx: skipping type, %s attribute not supported.\n", \
			       locerrstr, __func__, DIEOFFSET(die),	\
			       #attribute);				\
			*skip = SKIP_ABORT;				\
			return CTF_ERROR_REPORTED;			\
		}							\
	while (0)

#define ROOT_TYPE(x) (x) ? CTF_ADD_ROOT : CTF_ADD_NONROOT

/*
 * A CTF assembly filter function which excludes all types not at the global
 * scope (i.e. whose immediate parent is not a CU DIE), and all types which
 * reference a type which is not at the global scope (thus ruling out local type
 * definitions for which the compiler is not consistently emitting all
 * intermediate types at the local scope).
 */
static int filter_ctf_file_scope(const char *file_name, Dwarf *dwarf,
				 Dwarf_Die *die, Dwarf_Die *parent_die)
{
	Dwarf_Die type_die;
	GHashTable *parents;

	/*
	 * A type not dependent on another is acceptable iff it is at the global
	 * scope.
	 */
	if (private_dwarf_type(die, &type_die) == NULL)
		return (dwarf_tag(parent_die) == DW_TAG_compile_unit);

	/*
	 * No type we reference may have a subprogram DIE as any of its parents.
	 */
	parents = g_hash_table_lookup(fn_to_die_to_parent,
				      abs_file_name(file_name));

	do {
		Dwarf_Die parent = type_die;
		Dwarf_Off parent_off = 0;

		do {
			if (parent_off != 0 &&
			    !dwarf_offdie(dwarf, parent_off, &parent))
				break;
			if (dwarf_tag(&parent) == DW_TAG_subprogram)
				return 0;
		} while ((parent_off = GPOINTER_TO_UINT(g_hash_table_lookup(parents,
					  GUINT_TO_POINTER(dwarf_dieoffset(&parent)))))
			!= 0);
	} while (private_dwarf_type(&type_die, &type_die) != NULL);

	return 1;
}

/*
 * A CTF assembly filter function which excludes all names not at the global
 * scope, and all names whose names are unlikely to be interesting.  (DTrace
 * userspace contains a similar list, but the two lists need not be in sync.)
 */
static int filter_ctf_uninteresting(const char *file_name __unused__,
				    Dwarf *dwarf __unused__,
				    Dwarf_Die *die, Dwarf_Die *parent_die)
{
	const char *sym_name = dwarf_diename(die);

	/*
	 * 'Variables' with no name are not interesting.
	 */
	if (sym_name == NULL)
		return 0;

#define strstarts(var, x) (strncmp(var, x, strlen(x)) == 0)
	return ((dwarf_tag(parent_die) == DW_TAG_compile_unit) &&
		!((strcmp(sym_name, "__per_cpu_start") == 0) ||
		  (strcmp(sym_name, "__per_cpu_end") == 0) ||
		  (strcmp(sym_name, "_sdt_probes") == 0) ||
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
				  Dwarf_Die *parent_die, ctf_file_t *ctf,
				  ctf_id_t parent_ctf_id, const char *locerrstr,
				  struct die_override *overrides,
				  int top_level_type, enum skip_type *skip,
				  int *replace)
{
	typedef ctf_id_t (*ctf_add_fun)(ctf_file_t *, uint_t,
					const char *, const ctf_encoding_t *);

	const char *name = dwarf_diename(die);
	Dwarf_Word encoding, size;
	ctf_add_fun ctf_add_func;
	ctf_encoding_t ctf_encoding;
	size_t encoding_search;
	struct die_override *bit_size_override, *bit_offset_override;

	struct dwarf_encoding_tab {
		Dwarf_Word encoding;
		ctf_add_fun func;
		uint_t encoding_fixed;
		struct type_encoding_tab *size_lookup;
	};

	struct type_encoding_tab float_encoding[] = {
		{sizeof(float), CTF_FP_SINGLE },
		{sizeof(double), CTF_FP_DOUBLE },
		{sizeof(long double), CTF_FP_LDOUBLE },
		{0, 0}
	};

	struct type_encoding_tab float_cplx_encoding[] = {
		{sizeof(float), CTF_FP_CPLX },
		{sizeof(double), CTF_FP_DCPLX },
		{sizeof(long double), CTF_FP_LDCPLX },
		{0, 0}
	};

	struct type_encoding_tab float_imagry_encoding[] = {
		{sizeof(float), CTF_FP_IMAGRY },
		{sizeof(double), CTF_FP_DIMAGRY },
		{sizeof(long double), CTF_FP_LDIMAGRY },
		{0, 0}
	};

	struct dwarf_encoding_tab all_encodings[] = {
		{DW_ATE_boolean, ctf_add_integer, CTF_INT_BOOL, NULL},
		{DW_ATE_signed, ctf_add_integer, CTF_INT_SIGNED, NULL},
		{DW_ATE_signed_char, ctf_add_integer,
		 CTF_INT_SIGNED | CTF_INT_CHAR, NULL},
		{DW_ATE_unsigned, ctf_add_integer, 0, NULL},
		{DW_ATE_unsigned_char, ctf_add_integer, CTF_INT_CHAR, NULL},
		{DW_ATE_float, ctf_add_float, 0, float_encoding},
		{DW_ATE_complex_float, ctf_add_float, 0, float_cplx_encoding},
		{DW_ATE_imaginary_float, ctf_add_float, 0,
		 float_imagry_encoding},
		{0, 0, 0, 0}
	};

	CTF_DW_ENFORCE(name);
	CTF_DW_ENFORCE(encoding);
	CTF_DW_ENFORCE(byte_size);
	CTF_DW_ENFORCE_NOT(endianity);

	encoding = private_dwarf_udata(die, DW_AT_encoding, overrides);
	size = private_dwarf_udata(die, DW_AT_byte_size, overrides);

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
		pr_err("%s: skipping type, base type %li not yet implemented.\n",
		       locerrstr, (long) encoding);
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}

	/*
	 * Handle bitfields.  Only look at overrides, since bitfields can only
	 * be members of structures in C, thus derived from the referencing DIE.
	 * Bitfields are never top-level types in C, even though they are in
	 * DWARF.
	 */
	bit_size_override = private_find_override(die, DW_AT_bit_size,
						  overrides);
	bit_offset_override = private_find_override(die, DW_AT_bit_offset,
						    overrides);
	if (bit_size_override) {
		ctf_encoding.cte_bits = bit_size_override->value;
		top_level_type = 0;
	} else
		ctf_encoding.cte_bits = size * 8;

	if (bit_offset_override) {
#if __BYTE_ORDER == __BIG_ENDIAN
		ctf_encoding.cte_offset = bit_offset_override->value;
#else
		/*
		 * The figure here counts from the left to the leftmost edge of
		 * the bitfield: we want to count from the right to the
		 * rightmost edge.
		 */
		ctf_encoding.cte_offset = (size * 8) -
			bit_offset_override->value - ctf_encoding.cte_bits;
		dw_ctf_trace("Endianizing cte_offset from %x to %x\n",
			     (unsigned int) bit_offset_override->value,
			     ctf_encoding.cte_offset);
#endif
	} else
		ctf_encoding.cte_offset = 0;

#ifdef DEBUG
	if (bit_size_override || bit_offset_override)
		dw_ctf_trace("Bitfield overrides: bit size %i; bit offset %i\n",
			     ctf_encoding.cte_bits, ctf_encoding.cte_offset);
#endif

	return ctf_add_func(ctf, ROOT_TYPE(top_level_type), name,
			    &ctf_encoding);
}

/*
 * Assemble pointer types.
 */
static ctf_id_t assemble_ctf_pointer(const char *module_name,
				     const char *file_name,
				     Dwarf_Die *die, Dwarf_Die *parent_die,
				     ctf_file_t *ctf, ctf_id_t parent_ctf_id,
				     const char *locerrstr,
				     struct die_override *overrides,
				     int top_level_type,
				     enum skip_type *skip, int *replace)
{
	ctf_id_t type_ref;

	type_ref = lookup_ctf_type(module_name, file_name, die, ctf,
				   overrides, locerrstr);
	if (type_ref < 0) {
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}

	/*
	 * Pointers to functions are all the same type in CTF: don't bother
	 * adding it over again.
	 */
	if (type_ref == ctf_funcptr_type)
		return type_ref;

	return ctf_add_pointer(ctf, ROOT_TYPE(top_level_type), type_ref);
}

/*
 * Assemble array types.  This function looks up the array type, but does not do
 * any array construction: that is left to assemble_ctf_array_dimension().
 */
static ctf_id_t assemble_ctf_array(const char *module_name,
				   const char *file_name, Dwarf_Die *die,
				   Dwarf_Die *parent_die, ctf_file_t *ctf,
				   ctf_id_t parent_ctf_id,
				   const char *locerrstr,
				   struct die_override *overrides,
				   int top_level_type,
				   enum skip_type *skip, int *replace)
{
	ctf_id_t type_ref;

	CTF_DW_ENFORCE_NOT(ordering);
	CTF_DW_ENFORCE_NOT(bit_stride);
	CTF_DW_ENFORCE_NOT(byte_stride);

	type_ref = lookup_ctf_type(module_name, file_name, die, ctf,
				   overrides, locerrstr);
	if (type_ref < 0) {
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
					     ctf_file_t *ctf,
					     ctf_id_t parent_ctf_id,
					     const char *locerrstr,
					     struct die_override *overrides,
					     int top_level_type,
					     enum skip_type *skip,
					     int *replace)
{
	ctf_arinfo_t arinfo;

	CTF_DW_ENFORCE_NOT(bit_size);
	CTF_DW_ENFORCE_NOT(byte_size);
	CTF_DW_ENFORCE_NOT(bit_stride);
	CTF_DW_ENFORCE_NOT(byte_stride);
	CTF_DW_ENFORCE_NOT(lower_bound);
	CTF_DW_ENFORCE_NOT(threads_scaled);

	arinfo.ctr_contents = parent_ctf_id;

	arinfo.ctr_index = lookup_ctf_type(module_name, file_name,
					   die, ctf, overrides, locerrstr);
	if (arinfo.ctr_index < 0) {
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}

	arinfo.ctr_nelems = private_subrange_dimensions(die);

	/*
	 * For each array dimension, construct an appropriate array of the
	 * type-so-far, overriding the parent type.
	 */

	*replace = 1;
	return ctf_add_array(ctf, ROOT_TYPE(top_level_type), &arinfo);
}

/*
 * Assemble an enumeration.
 */
static ctf_id_t assemble_ctf_enumeration(const char *module_name,
					 const char *file_name,
					 Dwarf_Die *die,
					 Dwarf_Die *parent_die,
					 ctf_file_t *ctf,
					 ctf_id_t parent_ctf_id,
					 const char *locerrstr,
					 struct die_override *overrides,
					 int top_level_type,
					 enum skip_type *skip,
					 int *replace)
{
	const char *name = dwarf_diename(die);

	return ctf_add_enum(ctf, ROOT_TYPE(top_level_type), name);
}

/*
 * Assemble an enumeration value.
 */
static ctf_id_t assemble_ctf_enumerator(const char *module_name,
					const char *file_name,
					Dwarf_Die *die,
					Dwarf_Die *parent_die,
					ctf_file_t *ctf,
					ctf_id_t parent_ctf_id,
					const char *locerrstr,
					struct die_override *overrides,
					int top_level_type,
					enum skip_type *skip,
					int *replace)
{
	const char *name = dwarf_diename(die);
	Dwarf_Word value;
	int err;

	CTF_DW_ENFORCE(name);
	CTF_DW_ENFORCE(const_value);
	CTF_DW_ENFORCE_NOT(bit_stride);
	CTF_DW_ENFORCE_NOT(byte_stride);

	value = private_dwarf_udata(die, DW_AT_const_value, overrides);
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
				     ctf_file_t *ctf,
				     ctf_id_t parent_ctf_id,
				     const char *locerrstr,
				     struct die_override *overrides,
				     int top_level_type,
				     enum skip_type *skip,
				     int *replace)
{
	const char *name = dwarf_diename(die);
	ctf_id_t type_ref;

	CTF_DW_ENFORCE(name);

	type_ref = lookup_ctf_type(module_name, file_name, die, ctf,
				   overrides, locerrstr);
	if (type_ref < 0) {
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}

	return ctf_add_typedef(ctf, ROOT_TYPE(top_level_type), name, type_ref);
}

/*
 * Assemble a const/volatile/restrict qualifier.
 */
static ctf_id_t assemble_ctf_cvr_qual(const char *module_name,
				      const char *file_name,
				      Dwarf_Die *die,
				      Dwarf_Die *parent_die,
				      ctf_file_t *ctf,
				      ctf_id_t parent_ctf_id,
				      const char *locerrstr,
				      struct die_override *overrides,
				      int top_level_type,
				      enum skip_type *skip,
				      int *replace)
{
	ctf_id_t (*ctf_cvr_fun)(ctf_file_t *fp, uint_t flag, ctf_id_t ref);
	ctf_id_t type_ref;

	switch (dwarf_tag(die)) {
	case DW_TAG_const_type: ctf_cvr_fun = ctf_add_const; break;
	case DW_TAG_volatile_type: ctf_cvr_fun = ctf_add_volatile; break;
	case DW_TAG_restrict_type: ctf_cvr_fun = ctf_add_restrict; break;
	default:
		pr_err("%s: internal error: assemble_ctf_cvr_qual() called with\n"
		       "non-const/volatile/restrict: %i\n", locerrstr, dwarf_tag(die));
		exit(1);
	}

	type_ref = lookup_ctf_type(module_name, file_name, die, ctf,
				   overrides, locerrstr);
	if (type_ref < 0) {
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}

	return ctf_cvr_fun(ctf, ROOT_TYPE(top_level_type), type_ref);
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
					  ctf_file_t *ctf,
					  ctf_id_t parent_ctf_id,
					  const char *locerrstr,
					  struct die_override *overrides,
					  int top_level_type,
					  enum skip_type *skip,
					  int *replace)
{
	ctf_id_t (*ctf_add_sou)(ctf_file_t *fp, uint_t flag, const char *name,
				size_t size);

	const char *name = dwarf_diename(die);
	int is_union = (dwarf_tag(die) == DW_TAG_union_type);
	struct ctf_memb_count *member_count = NULL;
	ctf_id_t id;
	long long size;

	/*
	 * FIXME: these both need handling for DWARF4 support.
	 */
	CTF_DW_ENFORCE_NOT(specification);
	CTF_DW_ENFORCE_NOT(signature);

	/*
	 * Figure out the size of the type (if possible) and force it into the
	 * CTF to ensure that struct/union padding is added appropriately.
	 *
	 * If we don't know it, force a size of zero, which is interpreted as
	 * being equivalent to a call to the unsized struct/union addition
	 * function, letting libdtrace-ctf figure out a likely size as best it
	 * can.
	 */
	size = private_dwarf_size(die);
	if (size < 0)
		size = 0;

	/*
	 * Possibly we should ignore this entire structure, if we already know
	 * of one with the same name and at least as many members.  If we
	 * already know of one and it is shorter, we want to use its ID rather
	 * than creating a new one.
	 *
	 * Note; by this point, the deduplicator has long run: thus we know for
	 * sure what module a potentially-shared type will end up in, and
	 * there's no need to double-check the shared CTF repository for types.
	 * We also know that the module must exist in the per_module hash.
	 */

	if (name != NULL) {
		char *structized_name = NULL;
		struct per_module *ctf_pm;

		structized_name = str_appendn(structized_name,
					      is_union ? "u " : "s ",
					      name, NULL);

		ctf_pm = g_hash_table_lookup(per_module, module_name);
		member_count = g_hash_table_lookup(ctf_pm->member_counts,
						   structized_name);

		if (member_count) {
			free(structized_name);
			dw_ctf_trace("%s: already exists (with ID %li) with %zi members\n"
				     "versus current %li members\n",
				     locerrstr, member_count->ctf_id,
				     member_count->count,
				     count_dwarf_members(die));

			if (member_count->count < count_dwarf_members(die))
				return member_count->ctf_id;

			*skip = SKIP_SKIP;
			return member_count->ctf_id;
		}

		/*
		 * Not in existence yet.  Create it.
		 */
		member_count = malloc(sizeof(struct ctf_memb_count));
		if (member_count == NULL) {
			pr_err("Out of memory allocating structure/union member count\n");
			exit(1);
		}
		member_count->count = 0;
		g_hash_table_insert(ctf_pm->member_counts,
				    structized_name, member_count);
	}

	dw_ctf_trace("%s: adding structure %s\n", locerrstr, name);

	if (is_union)
		ctf_add_sou = ctf_add_union_sized;
	else
		ctf_add_sou = ctf_add_struct_sized;

	id = ctf_add_sou(ctf, ROOT_TYPE(top_level_type), name, size);

	if (member_count != NULL)
		member_count->ctf_id = id;

	return id;
}

/*
 * Figure out the offset of this type, in bits.  (This is split in two
 * for bitfields, where the bitfield itself gets represented elsewhere,
 * in the CTF type of the member itself.)
 *
 * DW_AT_data_bit_offset is the simple case.  DW_AT_data_member_location
 * is trickier, and, alas, the DWARF2 variation is the complex one.
 */
static int ctf_su_offset(Dwarf_Die *die, const char *locerrstr,
			 struct die_override *overrides, ulong_t *offset,
			 ulong_t *bit_offset)
{
	struct die_override *o;

	if (private_dwarf_hasattr(die, DW_AT_data_bit_offset))
		*offset = private_dwarf_udata(die, DW_AT_data_bit_offset, NULL);
	else if (private_dwarf_hasattr(die, DW_AT_data_member_location)) {
		Dwarf_Attribute location_attr;

		private_dwarf_attr(die, DW_AT_data_member_location,
				   &location_attr);

		switch (dwarf_whatform(&location_attr)) {
		case DW_FORM_data1:
		case DW_FORM_data2:
		case DW_FORM_data4:
		case DW_FORM_data8:
		case DW_FORM_udata:
		case DW_FORM_sdata:
		{
			/*
			 * Byte offset, with bit_offset of containing
			 * structure/union added, if present.
			 *
			 * (No overrides supported here, yet, due to lack of
			 * sdata overrides and the desire for consistency.
			 * We can add them if we start passing down
			 * DW_AT_data_member_location overrides.)
			 */
			if (dwarf_whatform(&location_attr) == DW_FORM_sdata) {
				Dwarf_Sword location;

				dwarf_formsdata(&location_attr, &location);
				*offset = location * 8;
			} else {
				Dwarf_Word location;

				dwarf_formudata(&location_attr, &location);
				*offset = location * 8;
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
				pr_err("%s: offset not a valid location expression: %s\n",
				       locerrstr, dwarf_errmsg(dwarf_errno()));
				return CTF_ERROR_REPORTED;
			}

			if ((nlocs != 1) ||
			    ((location[0].atom != DW_OP_plus_uconst) &&
			     (location[0].atom != DW_OP_constu))) {
				pr_err("%s: complex location lists not supported:\n"
				       "either C++ or non-GCC output: skipped\n", locerrstr);
				return CTF_ERROR_REPORTED;
			}

			*offset = location[0].number * 8;
			break;
		}
		case DW_FORM_exprloc:
		{
			/*
			 * We need a full DWARF expression list interpreter to
			 * handle this.
			 */
			pr_err("DWARF 4 expression location lists not supported.\n");
			exit(1);
		}
		default:
		{
			pr_err("%s: expression location lists in form %u not supported.\n",
			       locerrstr, dwarf_whatform(&location_attr));
			exit(1);
		}
		}
	}

	/*
	 * Handle the bit offset.
	 */
	if (private_dwarf_hasattr(die, DW_AT_bit_offset)) {
	  Dwarf_Attribute bit_attr;
	  Dwarf_Word bit;

	  private_dwarf_attr(die, DW_AT_bit_offset,
			     &bit_attr);
	  dwarf_formudata(&bit_attr, &bit);
	  *bit_offset = bit;
	}

	/*
	 * Handle the offset value override.  It does not matter which method
	 * has been used to get the value.  At this point offset is always
	 * the bit distance of the member from the structure/union start.
	 *
	 * The DW_AT_data_bit_offset override is always used to pass the offset
	 * around, so that we don't need to add special override handling for
	 * various forms of the DW_AT_data_member_location as a special case.
	 * This is safe as it is not possible to have both attributes attached
	 * to the same DIE per the DWARF4 standard, and if we have one attached
	 * as an override to a DIE that has the other, we will only ever need to
	 * use one (since no DIE can be both an unnamed struct/union and a
	 * bitfield at the same time).
	 */
	o = private_find_override(die, DW_AT_data_bit_offset, overrides);
	if (o != NULL) {
		if (o->op == DIE_OVERRIDE_REPLACE)
			*offset = o->value;
		else
			*offset += o->value;
	}

	return 0;
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
				       ctf_file_t *ctf,
				       ctf_id_t parent_ctf_id,
				       const char *locerrstr,
				       struct die_override *overrides,
				       int top_level_type,
				       enum skip_type *skip,
				       int *replace)
{
	ulong_t offset = 0;
	ulong_t bit_offset = 0;
	struct ctf_full_id *new_type;
	Dwarf_Attribute type_attr;
	Dwarf_Die type_die;
	Dwarf_Die cu_die;
	int err;
	struct ctf_memb_count *member_count;
	const char *struct_name = dwarf_diename(parent_die);

	CTF_DW_ENFORCE(type);

	/*
	 * Increment the member count of named structures.  This is the number
	 * of members in the DWARF, not in the CTF: blacklisted members are
	 * counted too.
	 */
	if (struct_name != NULL) {
		int is_union = (dwarf_tag(parent_die) == DW_TAG_union_type);
		char *structized_name = NULL;
		struct per_module *ctf_pm;

		structized_name = str_appendn(structized_name,
					      is_union ? "u " : "s ",
					      struct_name, NULL);

		ctf_pm = g_hash_table_lookup(per_module, module_name);
		member_count = g_hash_table_lookup(ctf_pm->member_counts,
						   structized_name);
		member_count->count++;
		free(structized_name);
	}

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
	 * which must be unnamed structs/unions): then figure out the member's
	 * offset.
	 */
	private_dwarf_attr(die, DW_AT_type, &type_attr);
	if (dwarf_formref_die(&type_attr, &type_die) == NULL) {
		pr_err("%s: nonexistent type reference.\n"
		       "Corrupted DWARF, cannot continue.\n", locerrstr);
		exit(1);
	}
	dwarf_diecu(&type_die, &cu_die, NULL, NULL);

	err = ctf_su_offset(die, locerrstr, overrides, &offset, &bit_offset);
	if (err < 0) {
		*skip = SKIP_ABORT;
		return err;
	}

	/*
	 * If this is an unnamed struct/union, call directly back to
	 * die_to_ctf() to add this struct's members to the current structure,
	 * merging it seamlessly with its parent (excepting only the member
	 * offsets).  Use DW_AT_data_bit_offset because it does not require
	 * the complexity of DW_AT_data_member_location to be faked.
	 */
	if (!private_dwarf_hasattr(die, DW_AT_name)) {
		Dwarf_Die child_die;
		int dummy = 0;

		if ((dwarf_tag(&type_die) != DW_TAG_structure_type) &&
		    (dwarf_tag(&type_die) != DW_TAG_union_type)) {
			pr_err("%s:%lx: not supported: anonymous structure member\n"
			       "not a structure or union.\n", locerrstr,
			       DIEOFFSET(die));
			*skip = SKIP_ABORT;
			return CTF_ERROR_REPORTED;
		}

		/*
		 * Anonymous structure or union with no members. Silently skip.
		 */
		switch (dwarf_child(&type_die, &child_die)) {
		case -1:
			*skip = SKIP_ABORT;
			return CTF_ERROR_REPORTED;
		case 1: /* No DIEs at all in this aggregate */
			return parent_ctf_id;
		default: /* Child DIEs exist.  */
			break;
		}

		/*
		 * Add override that will adjust offset of the anonymous
		 * struct/union members during inlining.  The bit_offset is
		 * ignored here as it is not expected that a nested
		 * structure/union will start on a non-byte-aligned boundary.
		 */
		struct die_override o[] = {{ dwarf_tag(&child_die),
					     DW_AT_data_bit_offset,
					     DIE_OVERRIDE_ADD,
					     offset, overrides }, {0}};

		die_to_ctf(module_name, file_name, &child_die, parent_die, ctf,
			   parent_ctf_id, o, 0, 0, skip, &dummy, NULL);

		return parent_ctf_id;
	}

	/*
	 * Get the CTF ID of this member's type, by recursive lookup.
	 *
	 * If this is a bitfield, we want to note that said type's size and
	 * bit-offset should be adjusted.
	 */
	if (private_dwarf_hasattr(die, DW_AT_bit_size)) {
		struct die_override o[] = {
			{ DW_TAG_base_type,
			  DW_AT_bit_size,
			  DIE_OVERRIDE_REPLACE,
			  private_dwarf_udata(die, DW_AT_bit_size,
					      NULL),
			  NULL },
			{ DW_TAG_base_type,
			  DW_AT_bit_offset,
			  DIE_OVERRIDE_REPLACE,
			  bit_offset,
			  overrides },
			{0}
		};

		new_type = construct_ctf_id(module_name, file_name, &type_die,
					    &cu_die, o);
	} else {
		if (bit_offset != 0) {
			pr_err("%s:%s: error in member %s: No DW_AT_bit_size, but nonzero bit offset\n"
			       "of %lx in overall offset of %lx\n", locerrstr,
			       dwarf_diename(&cu_die), dwarf_diename(die),
			       bit_offset, offset);
			return CTF_ERROR_REPORTED;
		}
		new_type = construct_ctf_id(module_name, file_name, &type_die,
					    &cu_die, NULL);
	}

	if (new_type == NULL) {
		*skip = SKIP_ABORT;
		return CTF_ERROR_REPORTED;
	}

	if ((new_type->ctf_file != ctf) &&
	    (new_type->ctf_file != lookup_ctf_file("shared_ctf"))) {
		pr_err("%s:%s: internal error: referenced type lookup for member %s\n"
		       "yields a different CTF file: %p versus %p\n",
		       locerrstr, dwarf_diename(&cu_die), dwarf_diename(die),
		       ctf, new_type->ctf_file);
		pr_err("dedup() is probably buggy.\n");
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

		/*
		 * We have special handling for cases where CTF doesn't know of
		 * either this member's type or the enclosing structure: when
		 * libdtrace-ctf is old enough to need it, we try a ctf_update()
		 * in case this is recently added, but no special handling for
		 * other errors, which the caller must report.
		 */

		if (ctf_errno(ctf) != ECTF_BADID &&
		    ctf_errno(ctf) != ECTF_NOTSOU)
			return CTF_NO_ERROR_REPORTED;

#ifndef LIBDTRACE_CTF_OMISSIBLE_CTF_UPDATE
		ctf_file_t *shared_ctf;

		/*
		 * Try an update of the current CTF file first, to bring the
		 * type ID table up to date: if that doesn't work, try an update
		 * of the shared table.  (If none is needed, this is cheap.)
		 */

		if (ctf_update(new_type->ctf_file) < 0) {
			pr_err("Cannot update CTF file: %s\n",
			       ctf_errmsg(ctf_errno(ctf)));
			exit(1);
		}

		if (ctf_add_member_offset(ctf, parent_ctf_id,
					  dwarf_diename(die),
					  new_type->ctf_id,
					  offset) == 0)
			return parent_ctf_id;

		shared_ctf = lookup_ctf_file("shared_ctf");
		if (ctf_update(shared_ctf) < 0) {
			pr_err("Cannot update shared CTF: %s\n",
			       ctf_errmsg(ctf_errno(shared_ctf)));
			exit(1);
		}

		if (ctf_add_member_offset(ctf, parent_ctf_id,
					  dwarf_diename(die),
					  new_type->ctf_id,
					  offset) == 0)
			return parent_ctf_id;
#endif
#ifdef DEBUG
		pr_err("%s: Internal error: %s %s:%s:%p:%i\n"
		       "on member addition to ctf_file %p.\n",
		       locerrstr, ctf_errmsg(ctf_errno(ctf)),
		       new_type->module_name, new_type->file_name,
		       new_type->ctf_file, (int) new_type->ctf_id, ctf);
#else
		pr_err("%s: Internal error: %s %p:%i\n"
		       "on member addition to ctf_file %p.\n",
		       locerrstr, ctf_errmsg(ctf_errno(ctf)),
		       new_type->ctf_file, (int) new_type->ctf_id,
		       ctf);
#endif
		return CTF_ERROR_REPORTED;
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
				      ctf_file_t *ctf,
				      ctf_id_t parent_ctf_id,
				      const char *locerrstr,
				      struct die_override *overrides,
				      int top_level_type,
				      enum skip_type *skip,
				      int *replace)
{
	const char *name = dwarf_diename(die);
	char *blacklist_name = NULL;
	ctf_id_t type_ref;
	int err;

	CTF_DW_ENFORCE(name);

	/*
	 * If blacklisted, just skip it.
	 */
	blacklist_name = str_appendn(blacklist_name, module_name, "`",
				     dwarf_diename(die), NULL);
	if (g_hash_table_lookup_extended(variable_blacklist, blacklist_name,
					 NULL, NULL)) {
		dw_ctf_trace("%s: variable %s is blacklisted for static/non-static ambiguity.\n",
			     file_name, blacklist_name);
		free(blacklist_name);
		return 0;
	}
	free(blacklist_name);

	type_ref = lookup_ctf_type(module_name, file_name, die, ctf,
				   overrides, locerrstr);
	if (type_ref < 0) {
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

static void write_types(char *output, int standalone)
{
	GHashTableIter module_iter;
	char *module;
	struct per_module *per_mod;
	ctf_file_t **ctfs;
	const char **names;
	size_t i = 0;
	size_t ctf_count = g_hash_table_size(per_module);

	/*
	 * Work over all the modules and write their compressed CTF data out.
	 * Standalone modules get placed in files in the output directory named
	 * with names ending in .mod.ctf.new, and the makefile moves .ctf.new
	 * over the top of .ctf iff it has changed; built-in modules and the
	 * core kernel and shared type repository are placed into a CTF archive.
	 */
	if (standalone) {
		if ((mkdir(output, 0777) < 0) && errno != EEXIST) {
			perror("Cannot create .ctf directory");
			exit(1);
		}
	} else {
		ctfs = calloc(ctf_count, sizeof(ctf_file_t *));
		names = calloc(ctf_count, sizeof(char *));
		if (!ctfs || !names)
			pr_err("Out of memory in CTF writeout\n");
	}

	/*
	 * Write the files out (in standalone mode), or construct the arrays of
	 * module names and files to put in the archive (otherwise).
	 */
	g_hash_table_iter_init(&module_iter, per_module);
	while (g_hash_table_iter_next(&module_iter, (void **) &module,
				      (void **)&per_mod)) {
		int fd;

		dw_ctf_trace("Writing out %s\n", module);

		if (ctf_update(per_mod->ctf_file) < 0) {
			pr_err("Cannot serialize CTF file %s: %s\n",
			       module, ctf_errmsg(ctf_errno(per_mod->ctf_file)));
			exit(1);
		}

		if (!standalone) {
			names[i] = module;
			ctfs[i] = per_mod->ctf_file;
			i++;
		} else {
			char *path = NULL;

			path = str_appendn(path, output, "/", module,
					   ".mod.ctf.new", NULL);

			fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
				  0666);
			if (fd < 0) {
				pr_err("Cannot open CTF file %s for writing: %s\n",
				       path, strerror(errno));
				exit(1);
			}
			if (ctf_compress_write(per_mod->ctf_file, fd) < 0) {
				pr_err("Cannot write to CTF file %s: "
				       "%s\n", path,
				       ctf_errmsg(ctf_errno(per_mod->ctf_file)));
				exit(1);
			}
			if (close(fd) != 0) {
				pr_err("Cannot close CTF file %s: %s\n",
				       path, strerror(errno));
				exit(1);
			}
			free(path);
		}
	}

	if (!standalone) {
		int err;

		err = ctf_arc_write(output, ctfs, ctf_count, names, 4096);
		if (err != 0) {
			pr_err("Cannot write to CTF archive %s: %s\n",
			       output, err < ECTF_BASE ? strerror(err) :
			       ctf_errmsg(err));
			exit(1);
		}
		free(names);
		free(ctfs);
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

	if (private_dwarf_attr(die, DW_AT_type, &type_ref_attr) != NULL) {
		if (dwarf_formref_die(&type_ref_attr, target_die) == NULL) {
			pr_err("Corrupt DWARF at offset %lx: ref with no target.\n",
			       DIEOFFSET(die));
			exit(1);
		}
		return target_die;
	}

	return NULL;
}

/*
 * Check for existence of an attribute in a DIE, chasing through
 * DW_AT_specification if need be.
 */
static inline int private_dwarf_hasattr(Dwarf_Die *die,
					unsigned int search_name)
{
	int hasattr = 0;
	Dwarf_Attribute spec_ref_attr;
	Dwarf_Die spec_die;

	/*
	 * DW_AT_declaration is not forwarded, because non-declarations can
	 * reference declarations via DW_AT_specification, without implying that
	 * the referencing DIE is a declaration.
	 */
	hasattr = dwarf_hasattr(die, search_name);
	if (hasattr || (search_name == DW_AT_declaration))
		return hasattr;

	if (dwarf_attr(die, DW_AT_specification, &spec_ref_attr) != NULL) {
		if (dwarf_formref_die(&spec_ref_attr, &spec_die) == NULL) {
			pr_err("Corrupt DWARF at offset %lx: ref with no target.\n",
			       DIEOFFSET(die));
			exit(1);
		}
		return dwarf_hasattr(&spec_die, search_name);
	}
	return hasattr;
}

/*
 * Return a DIE attribute, chasing through DW_AT_specification if need be.
 */
static inline Dwarf_Attribute *private_dwarf_attr(Dwarf_Die *die,
						  unsigned int search_name,
						  Dwarf_Attribute *result)
{
	Dwarf_Attribute spec_ref_attr;
	Dwarf_Die spec_die;
	Dwarf_Attribute *ret;

	ret = dwarf_attr(die, search_name, result);
	if (ret != NULL || (search_name == DW_AT_declaration))
		return ret;

	if (dwarf_attr(die, DW_AT_specification, &spec_ref_attr) != NULL) {
		if (dwarf_formref_die(&spec_ref_attr, &spec_die) == NULL) {
			pr_err("Corrupt DWARF at offset %lx: ref with no target.\n",
			       DIEOFFSET(die));
			exit(1);
		}
		return dwarf_attr(&spec_die, search_name, result);
	}

	return NULL;
}

/*
 * Given a DIE that contains a udata attribute, look up that attribute and
 * return its value (optionally overridden or modified by the die_overrides).
 */
static inline Dwarf_Word private_dwarf_udata(Dwarf_Die *die, int attribute,
					     struct die_override *overrides)
{
	Dwarf_Attribute attr;
	Dwarf_Word value;
	struct die_override *override;

	override = private_find_override(die, attribute, overrides);

	if (override && override->op == DIE_OVERRIDE_REPLACE)
		return override->value;

	private_dwarf_attr(die, attribute, &attr);
	dwarf_formudata(&attr, &value);

	if (override)
		value += override->value;

	return value;
}

/*
 * Given a DIE, return its byte size, if known and interpretable, or -1
 * otherwise.
 */
static inline long long
private_dwarf_size(Dwarf_Die *die)
{
	Dwarf_Attribute size_attr;

	if (private_dwarf_hasattr(die, DW_AT_byte_size)) {
		private_dwarf_attr(die, DW_AT_byte_size, &size_attr);

		switch (dwarf_whatform(&size_attr)) {
		case DW_FORM_data1:
		case DW_FORM_data2:
		case DW_FORM_data4:
		case DW_FORM_data8:
		case DW_FORM_udata: {
			Dwarf_Word dw_size;

			dwarf_formudata(&size_attr, &dw_size);
			return dw_size;
		}
		case DW_FORM_sdata: {
			Dwarf_Sword dw_size;

			dwarf_formsdata(&size_attr, &dw_size);
			return dw_size;
		}
		}
	}

	/*
	 * exprloc or other type we don't know how to interpret yet.
	 */
	return -1;
}

/*
 * Find an override in an override list, walking up the chained overrides if
 * need be, until one is found.
 */
static struct die_override *
private_find_override(Dwarf_Die *die,
		      int attribute,
		      struct die_override *overrides)
{
	size_t i;

	if (overrides == NULL)
		return NULL;

	while (overrides) {
		struct die_override *chain = NULL;
		for (i = 0; overrides[i].tag != 0; i++) {
			chain = overrides[i].chain;
			if ((overrides[i].tag == dwarf_tag(die)) &&
			    (overrides[i].attribute == attribute))
				return &overrides[i];
		}
		overrides = chain;
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

	if (((private_dwarf_attr(die, DW_AT_upper_bound,
				 &nelem_attr) == NULL) &&
	     (private_dwarf_attr(die, DW_AT_count,
				 &nelem_attr) == NULL)) ||
	    (!private_dwarf_hasattr(die, DW_AT_type)))
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
	if (private_dwarf_hasattr(die, DW_AT_upper_bound))
		nelems++;

	return nelems;
}

/*
 * Intern an atom in the atoms table and return it, or free it and return the
 * existing atom if one is already interned.  (Despite the type signature, this
 * return value is constant and should not be freed.)
 */
static void *intern(char *atom)
{
	void *foo;

	if (!g_hash_table_lookup_extended(atoms, atom, &foo, NULL)) {
		g_hash_table_insert(atoms, atom, NULL);
		foo = atom;
	} else
		free(atom);

	return foo;
}

/*
 * An error checking strdup().
 */
static char *xstrdup(const char *s)
{
	char *s2 = strdup(s);

	if (s2 == NULL) {
		pr_err("%s: Out of memory\n", __func__);
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
		pr_err("Out of memory appending a string of length %li to one of length %li\n",
		       strlen(append), s_len);
		exit(1);
	}

	memcpy(s + s_len, append, append_len);
	s[s_len+append_len] = '\0';

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
		pr_err("Out of memory appending a string of length %li to one of length %li\n",
		       len - s_len, s_len);
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
 * Filter a GList, calling a predicate on it and removing all elements for which
 * the predicate returns true, calling the free_func on them if set.
 */
static GList *list_filter(GList *list, filter_pred_fun fun,
			  GDestroyNotify free_func, void *data)
{
	GList *cur = list;

	while (cur) {
		GList *next = cur->next;

		if (fun(cur->data, data)) {
			if (free_func)
				free_func(cur->data);
			list = g_list_delete_link(list, cur);
		}
		cur = next;
	}

	return list;
}

/*
 * Figure out the (pathless, suffixless) module name for a given module file (.o
 * or .ko), and return it in a new dynamically allocated string.
 *
 * Takes the object_to_module mapping into account.
 */
static char *fn_to_module(const char *file_name)
{
	char *module_name;
	char *chop, *dash;

	module_name = g_hash_table_lookup(object_to_module, file_name);
	if (module_name != NULL)
		return xstrdup(module_name);

	chop = strrchr(file_name, '/');
	if (chop != NULL)
		module_name = xstrdup(++chop);
	else
		module_name = xstrdup(file_name);

	chop = strrchr(module_name, '.');
	if (chop != NULL)
		*chop = '\0';

	dash = module_name;
	while (dash != NULL) {
		dash = strchr(dash, '-');
		if (dash != NULL)
			*dash = '_';
	}

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
 * Determine absolute filenames relative to some other directory.  This does not
 * need to be fast.  The returned name is dynamically allocated, and must be
 * freed by the caller.
 */
static char *rel_abs_file_name(const char *file_name, const char *relative_to)
{
	int dir = -1;
	static int warned = 0;
	char *abspath;
	/*
	 * If we can't get this name relatively, we might as well *try* to do it
	 * absolutely: but print a warning.
	 */
	dir = open(".", O_RDONLY | O_DIRECTORY);
	if (dir < 0) {
		if (!warned) {
			perror("Cannot open current directory");
			warned = 1;
		}
	} else {
		if (chdir(relative_to) < 0)
			if (!warned) {
				pr_err("Cannot change directory to "
				       "%s: %s\n", relative_to,
				       strerror(errno));
				warned = 1;
			}
	}

	abspath = realpath(file_name, NULL);
	if (abspath == NULL)
		abspath = xstrdup(file_name);

	if ((dir > -1) && (fchdir(dir) < 0)) {
		perror("Cannot return to original directory after relative realpath()");
		exit(1);
	}

	close(dir);

	return abspath;
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
	pr_err("Cannot %s: %s\n", err, dwarf_errmsg(dwarf_errno()));
	exit(1);
}

/*
 * Free a per_module's contents.
 */
static void private_per_module_free(void *per_module)
{
	struct per_module *per_mod = per_module;

	ctf_close(per_mod->ctf_file);
	g_hash_table_destroy(per_mod->member_counts);
	free(per_module);
}

/*
 * Free a fn_to_die_to_parent subhash.
 */
static void private_fn_die_parent_free(void *ptr)
{
	g_hash_table_destroy((GHashTable *) ptr);
}

/*
 * Get a ctf_file out of the per_module hash for a given module.
 */
static ctf_file_t *lookup_ctf_file(const char *module_name)
{
	struct per_module *per_mod;

	per_mod = g_hash_table_lookup(per_module, module_name);
	if (per_mod == NULL)
		return NULL;
	return per_mod->ctf_file;
}
