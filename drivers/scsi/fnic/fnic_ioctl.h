/*
 * Copyright 2012 Cisco Systems, Inc.  All rights reserved.
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * [Insert appropriate license here when releasing outside of Cisco]
 * $Id: fnic_ioctl.h 95328 2012-02-09 01:42:58Z hiralpat $
 */

#ifndef __FNIC_IOCTL_H__
#define __FNIC_IOCTL_H__

/*
 * ioctl commands are defined statically to support calls between
 * 32-bit user program and 64-bit kernel module
 */

#define FNIC_SET_TRACE_ENABLE           0xfc490701
#define FNIC_GET_TRACE_ENABLE           0xfc490702
#define FNIC_GET_TRACE_BUF_SIZE         0xfc490703
#define FNIC_GET_TRACE_DATA             0xfc490704
#define FNIC_GET_HOST_STATS             0xfc490705
#define FNIC_RESET_HOST_STATS           0xfc490706
#define FNIC_GET_STATS_SIZE           	0xfc490707
#define FNIC_GET_HBAS_INFO           	0xfc490708

extern struct list_head fnic_list;

struct fnic_trace_get {
	void __user 	*tb_ptr;
	size_t		snd_buf_len;
	size_t  	rcv_buf_len;
} __attribute__((aligned(8)));

struct fnic_stats_get {
	char host_name[16];
	void __user 	*stats_ptr;
	size_t		snd_buf_len;
	size_t  	rcv_buf_len;
} __attribute__((aligned(8)));

int fnic_reg_char_dev(void);
void fnic_unreg_char_dev(void);
int fnic_ioctl_init(void);
int fnic_ioctl_exit(void);

#endif
