/* Copyright (C) 2011, 2012, 2013 Oracle, Inc. */

#ifndef _FASTTRAP_H_
#define	_FASTTRAP_H_

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(CONFIG_DTRACE) || defined(CONFIG_DTRACE_MODULE)

#define FASTTRAPIOC		(('m' << 24) | ('r' << 16) | ('f' << 8))
#define FASTTRAPIOC_MAKEPROBE	(FASTTRAPIOC | 1)
#define FASTTRAPIOC_GETINSTR	(FASTTRAPIOC | 2)

typedef enum fasttrap_probe_type {
	DTFTP_NONE = 0,
	DTFTP_ENTRY,
	DTFTP_RETURN,
	DTFTP_OFFSETS,
	DTFTP_POST_OFFSETS,
	DTFTP_IS_ENABLED
} fasttrap_probe_type_t;

typedef struct fasttrap_probe_spec {
	pid_t ftps_pid;
	fasttrap_probe_type_t ftps_type;
	char ftps_func[DTRACE_FUNCNAMELEN];
	char ftps_mod[DTRACE_MODNAMELEN];
	uint64_t ftps_pc;
	uint64_t ftps_size;
	uint64_t ftps_noffs;
	uint64_t ftps_offs[1];
} fasttrap_probe_spec_t;

typedef uint8_t		fasttrap_instr_t;

typedef struct fasttrap_instr_query {
	uint64_t ftiq_pc;
	pid_t ftiq_pid;
	fasttrap_instr_t ftiq_instr;
} fasttrap_instr_query_t;

#endif /* CONFIG_DTRACE */

#ifdef	__cplusplus
}
#endif

#endif	/* _FASTTRAP_H_ */
