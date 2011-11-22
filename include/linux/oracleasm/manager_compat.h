/*
 * NAME
 *	manager_compat.h - Older ASM management device specification.
 *
 * AUTHOR
 * 	Joel Becker <joel.becker@oracle.com>
 *
 * DESCRIPTION
 *      This file contains routines for managing the ASM kernel manager
 *      device.  The library communicates to the kernel driver through
 *      this device.
 *
 * MODIFIED   (YYYY/MM/DD)
 *      2004/01/02 - Joel Becker <joel.becker@oracle.com>
 *              Initial LGPL header.
 *
 * Copyright (c) 2002-2004 Oracle Corporation.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *      - Neither the name of Oracle Corporation nor the names of its
 *        contributors may be used to endorse or promote products
 *        derived from this software without specific prior written
 *        permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Alternatively, the contents of this file may be used under the terms
 * of the GNU General Public License version 2 (the "GPL") distributed
 * with this softwarere in the file COPYING.GPL, in which case the
 * provisions of the GPL are applicable instead of the above. 
 *
 * If you wish to allow the use of your version of this file only under
 * the terms of the GPL and not to allow others to use your version of
 * this file under the license above, indicate your decision by deleting
 * the provisions above and replace them with the notice and other
 * provisions required by the GPL.  If you do not delete the provisions
 * above, a recipient may use your version of this file under the above
 * license or the GPL.
 */

/*
 * This file is an internal header to the asmlib implementation on
 * Linux.
 */


#ifndef _ORACLEASM_MANAGER_H
#define _ORACLEASM_MANAGER_H

/*
 * Defines
 */

/*
 * Path-fu for the ASM manager device.  This is where a particular
 * oracleasmfs is mounted.  Default is ASM_MANAGER_DEFAULT
 */
#define ASM_MANAGER_DEFAULT		"/dev/oracleasm"
#define ASM_MANAGER_DISKS		"disks"
#define ASM_MANAGER_INSTANCES		"iid"

#ifndef __KERNEL__
static inline char *asm_disk_path(const char *manager, const char *disk)
{
	size_t len;
	char *asm_disk;

	if (!manager || !*manager || !disk)
		return NULL;

	len = strlen(manager) + strlen("/") +
		strlen(ASM_MANAGER_DISKS) + strlen("/") + strlen(disk);
	asm_disk = (char *)malloc(sizeof(char) * (len + 1));
	if (!asm_disk)
		return NULL;
	snprintf(asm_disk, len + 1, "%s/%s/%s", manager,
		 ASM_MANAGER_DISKS, disk);

	return asm_disk;
}


static inline char *asm_disk_name(const char *manager,
				  const char *disk_path)
{
	size_t len;
	char *asm_disk_base, *disk;

	if (!manager || !*manager || !disk_path)
		return NULL;

	asm_disk_base = asm_disk_path(manager, "");
	if (!asm_disk_base)
		return NULL;

	if (strncmp(disk_path, asm_disk_base,
		    strlen(asm_disk_base)))
	{
		free(asm_disk_base);
		return NULL;
	}
	disk_path = disk_path + strlen(asm_disk_base);
	free(asm_disk_base);

	for (; (*disk_path != '\0') && (*disk_path == '/'); disk_path++)
		;

	len = strlen(disk_path);
	disk = (char *)malloc(sizeof(char) * (len + 1));
	if (!disk)
		return NULL;
	strncpy(disk, disk_path, len + 1);

	return disk;
}


static inline char *asm_manage_path(const char *manager)
{
	size_t len;
	char *asm_manage;

	if (!manager || !*manager)
		return NULL;
	len = strlen(manager) + strlen("/") +
		strlen(ASM_MANAGER_INSTANCES);
	asm_manage = (char *)malloc(sizeof(char) * (len + 1));
	if (!asm_manage)
		return NULL;
	snprintf(asm_manage, len + 1, "%s/%s", manager,
		 ASM_MANAGER_INSTANCES);

	return asm_manage;
}


#define ASM_MANAGER_IID_FORMAT		"%.8lX%.8lX"
static inline char *asm_iid_path(const char *manager,
				 unsigned long iid_high,
				 unsigned long iid_low)
{
	size_t len;
	char *asm_iid;

	if (!manager || !*manager)
		return NULL;
	len = strlen(manager) + strlen("/") +
		strlen(ASM_MANAGER_INSTANCES) + strlen("/") +
		(8 + 8 + 1);  /* 8 chars per u32, 1 char for '.' */
	asm_iid = (char *)malloc(sizeof(char) * (len + 1));
	if (!asm_iid)
		return NULL;
	snprintf(asm_iid, len + 1, "%s/%s/" ASM_MANAGER_IID_FORMAT,
		 manager, ASM_MANAGER_INSTANCES, iid_high, iid_low);

	return asm_iid;
}
#endif  /* __KERNEL__ */
#endif  /* _ORACLEASM_MANAGER_H */
