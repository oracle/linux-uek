/*
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 *
 * Copyright (c) 2009, 2013, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

#ifndef _LINUX_DTRACE_DOF_H
#define _LINUX_DTRACE_DOF_H

#include <linux/dtrace/universal.h>
#include <linux/dtrace/dif.h>
#include <linux/dtrace/dof_defines.h>

/*
 * DTrace programs can be persistently encoded in the DOF format so that they
 * may be embedded in other programs (for example, in an ELF file) or in the
 * dtrace driver configuration file for use in anonymous tracing.  The DOF
 * format is versioned and extensible so that it can be revised and so that
 * internal data structures can be modified or extended compatibly.  All DOF
 * structures use fixed-size types, so the 32-bit and 64-bit representations
 * are identical and consumers can use either data model transparently.
 *
 * The file layout is structured as follows:
 *
 * +---------------+-------------------+----- ... ----+---- ... ------+
 * |   dof_hdr_t   |  dof_sec_t[ ... ] |   loadable   | non-loadable  |
 * | (file header) | (section headers) | section data | section data  |
 * +---------------+-------------------+----- ... ----+---- ... ------+
 * |<------------ dof_hdr.dofh_loadsz --------------->|               |
 * |<------------ dof_hdr.dofh_filesz ------------------------------->|
 *
 * The file header stores meta-data including a magic number, data model for
 * the instrumentation, data encoding, and properties of the DIF code within.
 * The header describes its own size and the size of the section headers.  By
 * convention, an array of section headers follows the file header, and then
 * the data for all loadable sections and unloadable sections.  This permits
 * consumer code to easily download the headers and all loadable data into the
 * DTrace driver in one contiguous chunk, omitting other extraneous sections.
 *
 * The section headers describe the size, offset, alignment, and section type
 * for each section.  Sections are described using a set of #defines that tell
 * the consumer what kind of data is expected.  Sections can contain links to
 * other sections by storing a dof_secidx_t, an index into the section header
 * array, inside of the section data structures.  The section header includes
 * an entry size so that sections with data arrays can grow their structures.
 *
 * The DOF data itself can contain many snippets of DIF (i.e. >1 DIFOs), which
 * are represented themselves as a collection of related DOF sections.  This
 * permits us to change the set of sections associated with a DIFO over time,
 * and also permits us to encode DIFOs that contain different sets of sections.
 * When a DOF section wants to refer to a DIFO, it stores the dof_secidx_t of a
 * section of type DOF_SECT_DIFOHDR.  This section's data is then an array of
 * dof_secidx_t's which in turn denote the sections associated with this DIFO.
 *
 * This loose coupling of the file structure (header and sections) to the
 * structure of the DTrace program itself (ECB descriptions, action
 * descriptions, and DIFOs) permits activities such as relocation processing
 * to occur in a single pass without having to understand D program structure.
 *
 * Finally, strings are always stored in ELF-style string tables along with a
 * string table section index and string table offset.  Therefore strings in
 * DOF are always arbitrary-length and not bound to the current implementation.
 */

typedef struct dof_hdr {
	uint8_t dofh_ident[DOF_ID_SIZE]; /* identification bytes (see defines) */
	uint32_t dofh_flags;		/* file attribute flags (if any) */
	uint32_t dofh_hdrsize;		/* size of file header in bytes */
	uint32_t dofh_secsize;		/* size of section header in bytes */
	uint32_t dofh_secnum;		/* number of section headers */
	uint64_t dofh_secoff;		/* file offset of section headers */
	uint64_t dofh_loadsz;		/* file size of loadable portion */
	uint64_t dofh_filesz;		/* file size of entire DOF file */
	uint64_t dofh_pad;		/* reserved for future use */
} dof_hdr_t;

typedef struct dof_sec {
	uint32_t dofs_type;	/* section type (see defines) */
	uint32_t dofs_align;	/* section data memory alignment */
	uint32_t dofs_flags;	/* section flags (if any) */
	uint32_t dofs_entsize;	/* size of section entry (if table) */
	uint64_t dofs_offset;	/* offset of section data within file */
	uint64_t dofs_size;	/* size of section data in bytes */
} dof_sec_t;


typedef struct dof_ecbdesc {
	dof_secidx_t dofe_probes;	/* link to DOF_SECT_PROBEDESC */
	dof_secidx_t dofe_pred;		/* link to DOF_SECT_DIFOHDR */
	dof_secidx_t dofe_actions;	/* link to DOF_SECT_ACTDESC */
	uint32_t dofe_pad;		/* reserved for future use */
	uint64_t dofe_uarg;		/* user-supplied library argument */
} dof_ecbdesc_t;

typedef struct dof_probedesc {
	dof_secidx_t dofp_strtab;	/* link to DOF_SECT_STRTAB section */
	dof_stridx_t dofp_provider;	/* provider string */
	dof_stridx_t dofp_mod;		/* module string */
	dof_stridx_t dofp_func;		/* function string */
	dof_stridx_t dofp_name;		/* name string */
	uint32_t dofp_id;		/* probe identifier (or zero) */
} dof_probedesc_t;

typedef struct dof_actdesc {
	dof_secidx_t dofa_difo;		/* link to DOF_SECT_DIFOHDR */
	dof_secidx_t dofa_strtab;	/* link to DOF_SECT_STRTAB section */
	uint32_t dofa_kind;		/* action kind (DTRACEACT_* constant) */
	uint32_t dofa_ntuple;		/* number of subsequent tuple actions */
	uint64_t dofa_arg;		/* kind-specific argument */
	uint64_t dofa_uarg;		/* user-supplied argument */
} dof_actdesc_t;

typedef struct dof_difohdr {
	dtrace_diftype_t dofd_rtype;	/* return type for this fragment */
	dof_secidx_t dofd_links[1];	/* variable length array of indices */
} dof_difohdr_t;

typedef struct dof_relohdr {
	dof_secidx_t dofr_strtab;	/* link to DOF_SECT_STRTAB for names */
	dof_secidx_t dofr_relsec;	/* link to DOF_SECT_RELTAB for relos */
	dof_secidx_t dofr_tgtsec;	/* link to section we are relocating */
} dof_relohdr_t;

typedef struct dof_relodesc {
	dof_stridx_t dofr_name;		/* string name of relocation symbol */
	uint32_t dofr_type;		/* relo type (DOF_RELO_* constant) */
	uint64_t dofr_offset;		/* byte offset for relocation */
	uint64_t dofr_data;		/* additional type-specific data */
} dof_relodesc_t;

typedef struct dof_optdesc {
	uint32_t dofo_option;		/* option identifier */
	dof_secidx_t dofo_strtab;	/* string table, if string option */
	uint64_t dofo_value;		/* option value or string index */
} dof_optdesc_t;

typedef struct dof_provider {
	dof_secidx_t dofpv_strtab;	/* link to DOF_SECT_STRTAB section */
	dof_secidx_t dofpv_probes;	/* link to DOF_SECT_PROBES section */
	dof_secidx_t dofpv_prargs;	/* link to DOF_SECT_PRARGS section */
	dof_secidx_t dofpv_proffs;	/* link to DOF_SECT_PROFFS section */
	dof_stridx_t dofpv_name;	/* provider name string */
	dof_attr_t dofpv_provattr;	/* provider attributes */
	dof_attr_t dofpv_modattr;	/* module attributes */
	dof_attr_t dofpv_funcattr;	/* function attributes */
	dof_attr_t dofpv_nameattr;	/* name attributes */
	dof_attr_t dofpv_argsattr;	/* args attributes */
	dof_secidx_t dofpv_prenoffs;	/* link to DOF_SECT_PRENOFFS section */
} dof_provider_t;

typedef struct dof_probe {
	uint64_t dofpr_addr;		/* probe base address or offset */
	dof_stridx_t dofpr_func;	/* probe function string */
	dof_stridx_t dofpr_name;	/* probe name string */
	dof_stridx_t dofpr_nargv;	/* native argument type strings */
	dof_stridx_t dofpr_xargv;	/* translated argument type strings */
	uint32_t dofpr_argidx;		/* index of first argument mapping */
	uint32_t dofpr_offidx;		/* index of first offset entry */
	uint8_t dofpr_nargc;		/* native argument count */
	uint8_t dofpr_xargc;		/* translated argument count */
	uint16_t dofpr_noffs;		/* number of offset entries for probe */
	uint32_t dofpr_enoffidx;	/* index of first is-enabled offset */
	uint16_t dofpr_nenoffs;		/* number of is-enabled offsets */
	uint16_t dofpr_pad1;		/* reserved for future use */
	uint32_t dofpr_pad2;		/* reserved for future use */
} dof_probe_t;

typedef struct dof_xlator {
	dof_secidx_t dofxl_members;	/* link to DOF_SECT_XLMEMBERS section */
	dof_secidx_t dofxl_strtab;	/* link to DOF_SECT_STRTAB section */
	dof_stridx_t dofxl_argv;	/* input parameter type strings */
	uint32_t dofxl_argc;		/* input parameter list length */
	dof_stridx_t dofxl_type;	/* output type string name */
	dof_attr_t dofxl_attr;		/* output stability attributes */
} dof_xlator_t;

typedef struct dof_xlmember {
	dof_secidx_t dofxm_difo;	/* member link to DOF_SECT_DIFOHDR */
	dof_stridx_t dofxm_name;	/* member name */
	dtrace_diftype_t dofxm_type;	/* member type */
} dof_xlmember_t;

typedef struct dof_xlref {
	dof_secidx_t dofxr_xlator;	/* link to DOF_SECT_XLATORS section */
	uint32_t dofxr_member;		/* index of referenced dof_xlmember */
	uint32_t dofxr_argn;		/* index of argument for DIF_OP_XLARG */
} dof_xlref_t;

#endif /* _LINUX_DTRACE_DOF_H */
