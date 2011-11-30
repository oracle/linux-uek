/*
 * NAME
 *	disk.h - ASM library disk tag.
 *
 * AUTHOR
 * 	Joel Becker <joel.becker@oracle.com>
 *
 * DESCRIPTION
 *      This file contains the definition of the ASM library's disk
 *      tag.  This tag allows recognition of ASM disks.
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


#ifndef _ORACLEASM_DISK_H
#define _ORACLEASM_DISK_H

/*
 * Defines
 */

/*
 * Disk label.  This is a 32 byte quantity at offset 32 (0x20) on the 
 * disk.  The first 8 bytes are "ORCLDISK".  The remaining 24 bytes
 * are a unique device label determined by the administrator.
 */
#define ASM_DISK_LABEL_MARKED   "ORCLDISK"
#define ASM_DISK_LABEL_CLEAR    "ORCLCLRD"
#define ASM_DISK_LABEL_OFFSET   32

struct asm_disk_label {
	char dl_tag[8];
	char dl_id[24];
};

#ifndef __KERNEL__
/* 
 * Why?
 * label_asm_name is defined as a SQL identifier.  That is, it is
 * case insensitive.  It is also defined as ASCII only.  Disk names
 * are what become label_asm_name.  So for the user's convenience (sic),
 * we blatantly promote to uppercase.
 */
static inline int asmdisk_toupper(unsigned char *str, ssize_t len,
				  int glob)
{
	int count, c;

	if (len < 0)
		len = INT_MAX;
	count = 0;
	for (count = 0; (count < len) && str[count]; count++)
	{
		c = str[count];
		if (!isascii(c))
			return -ERANGE;
		/* This is super-ASCII-specific */
		if (c == '_')
			continue;
		if (glob &&
		    ((c == '*') || (c == '?') ||
		     (c == '[') || (c == ']') ||
		     (c == '\\') || (c == '-') ||
		     (c == '!')))
			continue;
		if (c < '0')
			return c;
		if (c <= '9')
			continue;
		if (c < 'A')
			return c;
		if (c <= 'Z')
			continue;
		if (c < '_')
			return c;
		if ((c < 'a') || (c > 'z'))
			return c;
		str[count] = (unsigned char)(c - ('a' - 'A'));
	}

	if (!glob && count && ((str[0] < 'A') || (str[0] > 'Z')))
		return str[0];

	return 0;
}
#endif  /* __KERNEL__ */

#endif  /* _ORACLEASM_DISK_H */
