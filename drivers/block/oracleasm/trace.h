#undef TRACE_SYSTEM
#define TRACE_SYSTEM oracleasm

#if !defined(_TRACE_ORACLEASM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ORACLEASM_H

#include <linux/tracepoint.h>

struct asm_disk_info;
struct asm_ioc64;

#define show_status(flags) \
	__print_flags(flags, "|", \
		{ ASM_BUSY		, "BUSY"	}, \
		{ ASM_SUBMITTED		, "SUBM"	}, \
		{ ASM_COMPLETED		, "COMP"	}, \
		{ ASM_FREE		, "FREE"	}, \
		{ ASM_CANCELLED		, "CANCEL"	}, \
		{ ASM_ERROR		, "ERR"		}, \
		{ ASM_WARN		, "WARN"	}, \
		{ ASM_PARTIAL		, "PARTIAL"	}, \
		{ ASM_BADKEY		, "BADKEY"	}, \
		{ ASM_BAD_DATA		, "DATA"	}, \
		{ ASM_LOCAL_ERROR	, "LOCAL"	})

#define show_op(flags) \
	__print_flags(flags, "|", \
		{ ASM_READ		, "READ"	}, \
		{ ASM_WRITE		, "WRITE"	})

#define show_iflags(flags) \
	__print_flags(flags, "|", \
		{ ASM_IFLAG_REMAPPED	, "REMAP"	}, \
		{ ASM_IFLAG_IP_CHECKSUM	, "IP"		}, \
		{ ASM_IFLAG_CTRL_NOCHECK, "!CTRL"	}, \
		{ ASM_IFLAG_DISK_NOCHECK, "!DISK"	})

#define show_ifmt(flags) \
	__print_flags(flags, "|", \
		{ ASM_IMODE_512_512	, "512N"	}, \
		{ ASM_IMODE_512_4K	, "512E"	}, \
		{ ASM_IMODE_4K_4K	, "4KN"		}, \
		{ ASM_IFMT_IP_CHECKSUM	, "IP"		}, \
		{ ASM_IFMT_DISK		, "DISK"	}, \
		{ ASM_IFMT_ATO		, "ATO"		})

TRACE_EVENT(disk,

	TP_PROTO(struct asm_disk_info *d, char *action),

	TP_ARGS(d, action),

	TP_STRUCT__entry(
		__string(action		, action	)
		__field(void *		, disk		)
		__field(dev_t		, dev		)
	),

	TP_fast_assign(
		__assign_str(action, action);
		__entry->disk		= d;
		__entry->dev		= d->d_bdev ? d->d_bdev->bd_dev : 0;
	),

	TP_printk("%-9s dsk=%p dev=%u:%u", __get_str(action), __entry->disk,
		  MAJOR(__entry->dev), MINOR(__entry->dev))
);

TRACE_EVENT(req,

	TP_PROTO(struct asm_request *r, unsigned int done, int error, char *action),

	TP_ARGS(r, done, error, action),

	TP_STRUCT__entry(
		__string(action		, action	)
		__field(void *		, req		)
		__field(dev_t		, dev		)
		__field(void *		, ioc		)
		__field(unsigned int	, bytes		)
		__field(unsigned int	, done		)
		__field(int		, error		)
	),

	TP_fast_assign(
		__assign_str(action, action);
		__entry->req		= r;
		__entry->dev		= r->r_disk ? r->r_disk->d_bdev->bd_dev : 0;
		__entry->ioc		= r->r_ioc;
		__entry->bytes		= r->r_count;
		__entry->done		= done;
		__entry->error		= error;
	),

	TP_printk("%-10s req=%p dev=%u:%u ioc=%p bytes=%u done=%u error=%d",
		  __get_str(action), __entry->req, MAJOR(__entry->dev),
		  MINOR(__entry->dev), __entry->ioc, __entry->bytes,
		  __entry->done, __entry->error)
);

TRACE_EVENT(bio,

	TP_PROTO(struct bio *bio, char *action),

	TP_ARGS(bio, action),

	TP_STRUCT__entry(
		__string(action		, action	)
		__field(void *		, bio		)
		__field(dev_t		, dev		)
		__field(void *		, req		)
		__field(int		, status	)
	),

	TP_fast_assign(
		__assign_str(action, action);
		__entry->bio		= bio;
		__entry->dev		= bio_dev(bio) ?: 0;
		__entry->req		= bio->bi_private;
		__entry->status	        = bio->bi_status;
	),

	TP_printk("%-10s bio=%p dev=%u:%u req=%p status=%d",
		  __get_str(action), __entry->bio, MAJOR(__entry->dev),
		  MINOR(__entry->dev), __entry->req, __entry->status)
);

TRACE_EVENT(ioc,

	TP_PROTO(struct _asm_ioc64 *ioc, int ret, char *action),

	TP_ARGS(ioc, ret, action),

	TP_STRUCT__entry(
		__string(action		, action	)
		__field(void *		, ioc		)
		__field(u8		, op		)
		__field(sector_t	, block		)
		__field(unsigned int	, count		)
		__field(u16		, status	)
		__field(s32		, error		)
		__field(s32		, warn		)
		__field(bool		, integrity	)
		__field(int		, ret		)
	),

	TP_fast_assign(
		__assign_str(action, action);
		__entry->ioc		= ioc;
		__entry->op		= ioc->operation_asm_ioc;
		__entry->block		= ioc->first_asm_ioc;
		__entry->count		= ioc->rcount_asm_ioc;
		__entry->status		= ioc->status_asm_ioc;
		__entry->error		= ioc->error_asm_ioc;
		__entry->warn		= ioc->warn_asm_ioc;
		__entry->integrity	= ioc->check_asm_ioc  ? true : false;
		__entry->ret		= ret;
	),

	TP_printk("%-10s ioc=%p op=%s block=%llu bytes=%u status=%s "
		  "error=%d warn=%d integrity=%u ret=%d",
		  __get_str(action), __entry->ioc, show_op(__entry->op),
		  (unsigned long long)__entry->block, __entry->count,
		  show_status(__entry->status), __entry->error, __entry->warn,
		  __entry->integrity, __entry->ret)
);

TRACE_EVENT(querydisk,

	TP_PROTO(struct block_device *bdev, struct oracleasm_query_disk_v2 *qd),

	TP_ARGS(bdev, qd),

	TP_STRUCT__entry(
		__field(void *		, bdev		)
		__field(void *		, qd		)
		__field(dev_t		, dev		)
		__field(sector_t	, max		)
		__field(unsigned int	, pbs		)
		__field(unsigned int	, lbs		)
		__field(unsigned char	, integrity	)
	),

	TP_fast_assign(
		__entry->bdev		= bdev;
		__entry->qd		= qd;
		__entry->dev		= bdev->bd_dev ? bdev->bd_dev : 0;
		__entry->max		= qd->qd_max_sectors;
		__entry->pbs		= qd->qd_hardsect_size;
		__entry->lbs		= 1 << (qd->qd_feature >> ASM_LSECSZ_SHIFT);
		__entry->integrity	= qd->qd_feature & ASM_INTEGRITY_QDF_MASK;
	),

	TP_printk("     dev=%u:%u max_blocks=%llu pbs=%u lbs=%u integrity=%s",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long long)__entry->max, __entry->pbs, __entry->lbs,
		  show_ifmt(__entry->integrity))
);

TRACE_EVENT(queryhandle,

	TP_PROTO(struct block_device *bdev, struct oracleasm_query_handle_v2 *qh),

	TP_ARGS(bdev, qh),

	TP_STRUCT__entry(
		__field(void *		, bdev		)
		__field(void *		, qh		)
		__field(dev_t		, dev		)
		__field(sector_t	, max		)
		__field(unsigned int	, pbs		)
		__field(unsigned int	, lbs		)
		__field(unsigned char	, integrity	)
	),

	TP_fast_assign(
		__entry->bdev		= bdev;
		__entry->qh		= qh;
		__entry->dev		= bdev->bd_dev ? bdev->bd_dev : 0;
		__entry->max		= qh->qh_max_sectors;
		__entry->pbs		= qh->qh_hardsect_size;
		__entry->lbs		= 1 << (qh->qh_feature >> ASM_LSECSZ_SHIFT);
		__entry->integrity	= qh->qh_feature & ASM_INTEGRITY_QDF_MASK;
	),

	TP_printk("   dev=%u:%u max_blocks=%llu pbs=%u lbs=%u integrity=%s",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  (unsigned long long)__entry->max, __entry->pbs, __entry->lbs,
		  show_ifmt(__entry->integrity))
);

TRACE_EVENT(integrity,

	TP_PROTO(struct oracleasm_integrity_v2 *it,
		 struct asm_request *r,
		 unsigned int nr_pages),

	TP_ARGS(it, r, nr_pages),

	TP_STRUCT__entry(
		__field(void *		, ioc		)
		__field(unsigned int	, bytes		)
		__field(unsigned int	, pages		)
		__field(unsigned int	, format	)
		__field(unsigned int	, flags		)
		__field(void *		, buf		)
	),

	TP_fast_assign(
		__entry->ioc		= r->r_ioc;
		__entry->bytes		= it->it_bytes;
		__entry->pages		= nr_pages;
		__entry->format		= it->it_format;
		__entry->flags		= it->it_flags;
		__entry->buf		= (void *)it->it_buf;
	),

	TP_printk("     ioc=%p prot_bytes=%u nr_pages=%u format=%s flags=%s buf=%p",
		  __entry->ioc, __entry->bytes, __entry->pages,
		  show_ifmt(__entry->format), show_iflags(__entry->flags),
		  __entry->buf)
);

#endif	/* _TRACE_ORACLEASM_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace
#include <trace/define_trace.h>
