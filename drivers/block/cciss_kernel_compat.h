/*
 *    Disk Array driver for HP Smart Array controllers.
 *    (C) Copyright 2000, 2010, 2012 Hewlett-Packard Development Company, L.P.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; version 2 of the License.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *    General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *    02111-1307, USA.
 *
 *    Questions/Comments/Bugfixes to iss_storagedev@hp.com
 *
 */

/* Kernel compat file for the cciss_4_6_xx branch */

/* #define SLES11sp2plus */
/* #define SLES11sp1 */
/* #define SLES11sp2plus */
/* #define RHEL6 */
/* Default is kernel.org */

#ifdef SLES11sp1
#	define KFEATURE_HAS_LOCKED_IOCTL 1
#	define KFEATURE_HAS_BLK_QUEUE_MAX_SEGMENTS 0
#	define KFEATURE_HAS_SMP_LOCK_H 1
#	define KFEATURE_HAS_BLK_QUEUE_PLUGGED 1
#	define KFEATURE_HAS_LOCK_KERNEL 1
#  define SA_CONTROLLERS_GEN8 0
#  define SA_CONTROLLERS_GEN6 1
#  define SA_CONTROLLERS_LEGACY 1
#	define KFEATURE_HAS_2011_03_QUEUECOMMAND 0
#else
#ifdef SLES11sp2plus
#	define KFEATURE_HAS_LOCKED_IOCTL 0
#	define KFEATURE_HAS_BLK_QUEUE_MAX_SEGMENTS 1
#	define KFEATURE_HAS_SMP_LOCK_H 0
#	define KFEATURE_HAS_BLK_QUEUE_PLUGGED 0
#	define KFEATURE_HAS_LOCK_KERNEL 0
#  define SA_CONTROLLERS_GEN8 0
#  define SA_CONTROLLERS_GEN6 1
#  define SA_CONTROLLERS_LEGACY 1
#	define KFEATURE_HAS_2011_03_QUEUECOMMAND 1
#else
#ifdef RHEL6
#	define KFEATURE_HAS_LOCKED_IOCTL 0
#	define KFEATURE_HAS_BLK_QUEUE_MAX_SEGMENTS 1
#	define KFEATURE_HAS_SMP_LOCK_H 1
#	define KFEATURE_HAS_BLK_QUEUE_PLUGGED 1
#	define KFEATURE_HAS_LOCK_KERNEL 1
#  define SA_CONTROLLERS_GEN8 0
#  define SA_CONTROLLERS_GEN6 0
#  define SA_CONTROLLERS_LEGACY 1
#	define KFEATURE_HAS_2011_03_QUEUECOMMAND 0
#else /* kernel.org */
#	define KFEATURE_HAS_LOCKED_IOCTL 0
#	define KFEATURE_HAS_BLK_QUEUE_MAX_SEGMENTS 1
#	define KFEATURE_HAS_SMP_LOCK_H 0
#	define KFEATURE_HAS_BLK_QUEUE_PLUGGED 0
#	define KFEATURE_HAS_LOCK_KERNEL 0
#  define SA_CONTROLLERS_GEN8 0
#  define SA_CONTROLLERS_GEN6 0
#  define SA_CONTROLLERS_LEGACY 1
#	define KFEATURE_HAS_2011_03_QUEUECOMMAND 1
#endif
#endif
#endif

/* Some kernels have a .locked_ioctl while some have a .ioctl in the fops */
#if KFEATURE_HAS_LOCKED_IOCTL
#	define SET_IOCTL_FUNCTION(locked_function, unlocked_function) .locked_ioctl = locked_function,
#else
#	define SET_IOCTL_FUNCTION(locked_function, unlocked_function) .ioctl = unlocked_function,
#endif /* KFEATURE_HAS_LOCKED_IOCTL */

#if KFEATURE_HAS_BLK_QUEUE_MAX_SEGMENTS
#else
/*
 * Some kernels don't have blk_queue_max_segments(), instead it has the older
 * blk_queue_max_hw_segments() and blk_queue_max_phys_segments()
 */
static inline void blk_queue_max_segments(struct request_queue *queue,
	int nsegments)
{
	blk_queue_max_hw_segments(queue, nsegments);
	blk_queue_max_phys_segments(queue, nsegments);
}
#endif /* KFEATURE_HAS_BLK_QUEUE_MAX_SEGMENTS */

#if KFEATURE_HAS_SMP_LOCK_H
#include <linux/smp_lock.h>
#endif

#if KFEATURE_HAS_BLK_QUEUE_PLUGGED
#	define BLK_QUEUE_PLUGGED(x) blk_queue_plugged(x)
#else
	/* No such thing as blk_queue_plugged, so always return
	 * false, compiler will optimize away
	 */
#	define BLK_QUEUE_PLUGGED(x) (0)
#endif

#if KFEATURE_HAS_LOCK_KERNEL
#else
#	define lock_kernel() do { } while (0)
#	define unlock_kernel() do { } while (0)
#endif

#if KFEATURE_HAS_2011_03_QUEUECOMMAND
#       define DECLARE_QUEUECOMMAND(func) \
                static int func##_lck(struct scsi_cmnd *cmd, \
                        void (*done)(struct scsi_cmnd *))
#       define DECLARE_QUEUECOMMAND_WRAPPER(func) static DEF_SCSI_QCMD(func)
#else
#       define DECLARE_QUEUECOMMAND(func) \
        static int func(struct scsi_cmnd *cmd, void (*done)(struct scsi_cmnd *))
#       define DECLARE_QUEUECOMMAND_WRAPPER(func)
#endif
