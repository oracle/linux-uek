/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Google, Inc.
 *
 * Author:
 *	Sami Tolvanen <samitolvanen@google.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _PGO_H
#define _PGO_H

/*
 * Note: These internal LLVM definitions must match the compiler version.
 * See llvm/include/llvm/ProfileData/InstrProfData.inc in LLVM's source code.
 */

#define LLVM_INSTR_PROF_RAW_MAGIC_64	\
		((u64)255 << 56 |	\
		 (u64)'l' << 48 |	\
		 (u64)'p' << 40 |	\
		 (u64)'r' << 32 |	\
		 (u64)'o' << 24 |	\
		 (u64)'f' << 16 |	\
		 (u64)'r' << 8  |	\
		 (u64)129)
#define LLVM_INSTR_PROF_RAW_MAGIC_32	\
		((u64)255 << 56 |	\
		 (u64)'l' << 48 |	\
		 (u64)'p' << 40 |	\
		 (u64)'r' << 32 |	\
		 (u64)'o' << 24 |	\
		 (u64)'f' << 16 |	\
		 (u64)'R' << 8  |	\
		 (u64)129)

#define LLVM_INSTR_PROF_RAW_VERSION		5
#define LLVM_INSTR_PROF_DATA_ALIGNMENT		8
#define LLVM_INSTR_PROF_IPVK_FIRST		0
#define LLVM_INSTR_PROF_IPVK_LAST		1
#define LLVM_INSTR_PROF_MAX_NUM_VAL_PER_SITE	255

#define LLVM_VARIANT_MASK_IR_PROF	(0x1ULL << 56)
#define LLVM_VARIANT_MASK_CSIR_PROF	(0x1ULL << 57)

/**
 * struct llvm_prf_header - represents the raw profile header data structure.
 * @magic: the magic token for the file format.
 * @version: the version of the file format.
 * @data_size: the number of entries in the profile data section.
 * @padding_bytes_before_counters: the number of padding bytes before the
 *   counters.
 * @counters_size: the size in bytes of the LLVM profile section containing the
 *   counters.
 * @padding_bytes_after_counters: the number of padding bytes after the
 *   counters.
 * @names_size: the size in bytes of the LLVM profile section containing the
 *   counters' names.
 * @counters_delta: the beginning of the LLMV profile counters section.
 * @names_delta: the beginning of the LLMV profile names section.
 * @value_kind_last: the last profile value kind.
 */
struct llvm_prf_header {
	u64 magic;
	u64 version;
	u64 data_size;
	u64 padding_bytes_before_counters;
	u64 counters_size;
	u64 padding_bytes_after_counters;
	u64 names_size;
	u64 counters_delta;
	u64 names_delta;
	u64 value_kind_last;
};

/**
 * struct llvm_prf_data - represents the per-function control structure.
 * @name_ref: the reference to the function's name.
 * @func_hash: the hash value of the function.
 * @counter_ptr: a pointer to the profile counter.
 * @function_ptr: a pointer to the function.
 * @values: the profiling values associated with this function.
 * @num_counters: the number of counters in the function.
 * @num_value_sites: the number of value profile sites.
 */
struct llvm_prf_data {
	const u64 name_ref;
	const u64 func_hash;
	const void *counter_ptr;
	const void *function_ptr;
	void *values;
	const u32 num_counters;
	const u16 num_value_sites[LLVM_INSTR_PROF_IPVK_LAST + 1];
} __aligned(LLVM_INSTR_PROF_DATA_ALIGNMENT);

/**
 * structure llvm_prf_value_node_data - represents the data part of the struct
 *   llvm_prf_value_node data structure.
 * @value: the value counters.
 * @count: the counters' count.
 */
struct llvm_prf_value_node_data {
	u64 value;
	u64 count;
};

/**
 * struct llvm_prf_value_node - represents an internal data structure used by
 *   the value profiler.
 * @value: the value counters.
 * @count: the counters' count.
 * @next: the next value node.
 */
struct llvm_prf_value_node {
	u64 value;
	u64 count;
	struct llvm_prf_value_node *next;
};

/**
 * struct llvm_prf_value_data - represents the value profiling data in indexed
 *   format.
 * @total_size: the total size in bytes including this field.
 * @num_value_kinds: the number of value profile kinds that has value profile
 *   data.
 */
struct llvm_prf_value_data {
	u32 total_size;
	u32 num_value_kinds;
};

/**
 * struct llvm_prf_value_record - represents the on-disk layout of the value
 *   profile data of a particular kind for one function.
 * @kind: the kind of the value profile record.
 * @num_value_sites: the number of value profile sites.
 * @site_count_array: the first element of the array that stores the number
 *   of profiled values for each value site.
 */
struct llvm_prf_value_record {
	u32 kind;
	u32 num_value_sites;
	u8 site_count_array[];
};

#define prf_get_value_record_header_size()		\
	offsetof(struct llvm_prf_value_record, site_count_array)
#define prf_get_value_record_site_count_size(sites)	\
	roundup((sites), 8)
#define prf_get_value_record_size(sites)		\
	(prf_get_value_record_header_size() +		\
	 prf_get_value_record_site_count_size((sites)))

/* Data sections */
extern struct llvm_prf_data __llvm_prf_data_start[];
extern struct llvm_prf_data __llvm_prf_data_end[];

extern u64 __llvm_prf_cnts_start[];
extern u64 __llvm_prf_cnts_end[];

extern char __llvm_prf_names_start[];
extern char __llvm_prf_names_end[];

extern struct llvm_prf_value_node __llvm_prf_vnds_start[];
extern struct llvm_prf_value_node __llvm_prf_vnds_end[];

/* Locking for vnodes */
extern unsigned long prf_lock(void);
extern void prf_unlock(unsigned long flags);

/* Declarations for LLVM instrumentation. */
void __llvm_profile_instrument_target(u64 target_value, void *data, u32 index);
void __llvm_profile_instrument_range(u64 target_value, void *data,
				     u32 index, s64 precise_start,
				     s64 precise_last, s64 large_value);
void __llvm_profile_instrument_memop(u64 target_value, void *data,
				     u32 counter_index);

#define __DEFINE_PRF_SIZE(s) \
	static inline unsigned long prf_ ## s ## _size(void)		\
	{								\
		unsigned long start =					\
			(unsigned long)__llvm_prf_ ## s ## _start;	\
		unsigned long end =					\
			(unsigned long)__llvm_prf_ ## s ## _end;	\
		return roundup(end - start,				\
				sizeof(__llvm_prf_ ## s ## _start[0]));	\
	}								\
	static inline unsigned long prf_ ## s ## _count(void)		\
	{								\
		return prf_ ## s ## _size() /				\
			sizeof(__llvm_prf_ ## s ## _start[0]);		\
	}

__DEFINE_PRF_SIZE(data);
__DEFINE_PRF_SIZE(cnts);
__DEFINE_PRF_SIZE(names);
__DEFINE_PRF_SIZE(vnds);

#undef __DEFINE_PRF_SIZE

#endif /* _PGO_H */
