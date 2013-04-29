#ifndef _LINUX_DTRACE_DOF_DEFINES_H
#define _LINUX_DTRACE_DOF_DEFINES_H

/* 
 * DTrace Dynamic Tracing Software: DTrace Object Format (DOF) defines
 * 
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2009 -- 2013 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/dtrace/universal.h>

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

#define DOF_ID_SIZE     16      /* total size of dofh_ident[] in bytes */

#define DOF_ID_MAG0	0
#define DOF_ID_MAG1	1
#define DOF_ID_MAG2	2
#define DOF_ID_MAG3	3
#define DOF_ID_MODEL	4
#define DOF_ID_ENCODING	5
#define DOF_ID_VERSION	6
#define DOF_ID_DIFVERS	7
#define	DOF_ID_DIFIREG	8	/* DIF integer registers used by compiler */
#define	DOF_ID_DIFTREG	9	/* DIF tuple registers used by compiler */
#define	DOF_ID_PAD	10	/* start of padding bytes (all zeroes) */

#define DOF_MAG_MAG0	0x7F	/* DOF_ID_MAG[0-3] */
#define DOF_MAG_MAG1	'D'
#define DOF_MAG_MAG2	'O'
#define DOF_MAG_MAG3	'F'

#define DOF_MAG_STRING	"\177DOF"
#define DOF_MAG_STRLEN	4

#define DOF_MODEL_NONE	0	/* DOF_ID_MODEL */
#define DOF_MODEL_ILP32	1
#define DOF_MODEL_LP64	2

#ifdef _LP64
#define DOF_MODEL_NATIVE	DOF_MODEL_LP64
#else
#define DOF_MODEL_NATIVE	DOF_MODEL_ILP32
#endif

#define DOF_ENCODE_NONE	0	/* DOF_ID_ENCODING */
#define DOF_ENCODE_LSB	1
#define DOF_ENCODE_MSB	2

#ifndef _LITTLE_ENDIAN
#define DOF_ENCODE_NATIVE	DOF_ENCODE_MSB
#else
#define DOF_ENCODE_NATIVE	DOF_ENCODE_LSB
#endif

#define DOF_VERSION_1	1
#define DOF_VERSION_2	2
#define DOF_VERSION	DOF_VERSION_2

#define DOF_FL_VALID	0	/* mask of all valid dofh_flags bits */

typedef uint32_t dof_secidx_t;	/* section header table index type */
typedef uint32_t dof_stridx_t;	/* string table index type */

#define	DOF_SECIDX_NONE	-1U	/* null value for section indices */
#define	DOF_STRIDX_NONE	-1U	/* null value for string indices */

#define	DOF_SECT_NONE		0	/* null section */
#define	DOF_SECT_COMMENTS	1	/* compiler comments */
#define	DOF_SECT_SOURCE		2	/* D program source code */
#define	DOF_SECT_ECBDESC	3	/* dof_ecbdesc_t */
#define	DOF_SECT_PROBEDESC	4	/* dof_probedesc_t */
#define	DOF_SECT_ACTDESC	5	/* dof_actdesc_t array */
#define	DOF_SECT_DIFOHDR	6	/* dof_difohdr_t (variable length) */
#define	DOF_SECT_DIF		7	/* uint32_t array of byte code */
#define	DOF_SECT_STRTAB		8	/* string table */
#define	DOF_SECT_VARTAB		9	/* dtrace_difv_t array */
#define	DOF_SECT_RELTAB		10	/* dof_relodesc_t array */
#define	DOF_SECT_TYPTAB		11	/* dtrace_diftype_t array */
#define	DOF_SECT_URELHDR	12	/* dof_relohdr_t (user relocations) */
#define	DOF_SECT_KRELHDR	13	/* dof_relohdr_t (kernel relocations) */
#define	DOF_SECT_OPTDESC	14	/* dof_optdesc_t array */
#define	DOF_SECT_PROVIDER	15	/* dof_provider_t */
#define	DOF_SECT_PROBES		16	/* dof_probe_t array */
#define	DOF_SECT_PRARGS		17	/* uint8_t array (probe arg mappings) */
#define	DOF_SECT_PROFFS		18	/* uint32_t array (probe arg offsets) */
#define	DOF_SECT_INTTAB		19	/* uint64_t array */
#define	DOF_SECT_UTSNAME	20	/* struct utsname */
#define	DOF_SECT_XLTAB		21	/* dof_xlref_t array */
#define	DOF_SECT_XLMEMBERS	22	/* dof_xlmember_t array */
#define	DOF_SECT_XLIMPORT	23	/* dof_xlator_t */
#define	DOF_SECT_XLEXPORT	24	/* dof_xlator_t */
#define	DOF_SECT_PREXPORT	25	/* dof_secidx_t array (exported objs) */
#define	DOF_SECT_PRENOFFS	26	/* uint32_t array (enabled offsets) */

#define	DOF_SECF_LOAD		1	/* section should be loaded */

#define DOF_SEC_ISLOADABLE(x)						      \
		(((x) == DOF_SECT_ECBDESC) || ((x) == DOF_SECT_PROBEDESC) ||  \
		((x) == DOF_SECT_ACTDESC) || ((x) == DOF_SECT_DIFOHDR) ||     \
		((x) == DOF_SECT_DIF) || ((x) == DOF_SECT_STRTAB) ||	      \
		((x) == DOF_SECT_VARTAB) || ((x) == DOF_SECT_RELTAB) ||	      \
		((x) == DOF_SECT_TYPTAB) || ((x) == DOF_SECT_URELHDR) ||      \
		((x) == DOF_SECT_KRELHDR) || ((x) == DOF_SECT_OPTDESC) ||     \
		((x) == DOF_SECT_PROVIDER) || ((x) == DOF_SECT_PROBES) ||     \
		((x) == DOF_SECT_PRARGS) || ((x) == DOF_SECT_PROFFS) ||	      \
		((x) == DOF_SECT_INTTAB) || ((x) == DOF_SECT_XLTAB) ||	      \
		((x) == DOF_SECT_XLMEMBERS) || ((x) == DOF_SECT_XLIMPORT) ||  \
		((x) == DOF_SECT_XLIMPORT) || ((x) == DOF_SECT_XLEXPORT) ||   \
		((x) == DOF_SECT_PREXPORT) || ((x) == DOF_SECT_PRENOFFS))

#define	DOF_RELO_NONE	0		/* empty relocation entry */
#define	DOF_RELO_SETX	1		/* relocate setx value */

typedef uint32_t dof_attr_t;		/* encoded stability attributes */

#define DOF_ATTR(n, d, c)	(((n) << 24) | ((d) << 16) | ((c) << 8))
#define DOF_ATTR_NAME(a)	(((a) >> 24) & 0xff)
#define DOF_ATTR_DATA(a)	(((a) >> 16) & 0xff)
#define DOF_ATTR_CLASS(a)	(((a) >>  8) & 0xff)

struct dof_hdr;
struct dof_sec;
struct dof_ecbdesc;
struct dof_probedesc;
struct dof_actdesc;
struct dof_difohdr;
struct dof_relohdr;
struct dof_relodesc;
struct dof_optdesc;
struct dof_provider;
struct dof_xlator;
struct dof_xlmember;
struct dof_xlref;

#endif /* _LINUX_DTRACE_DOF_DEFINES_H */
