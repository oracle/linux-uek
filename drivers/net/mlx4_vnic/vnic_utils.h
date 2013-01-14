/*
 * Copyright (c) 2009 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _VNIC_UTILS_H
#define _VNIC_UTILS_H

/*#define CONFIG_MLX4_VNIC_DEBUG  */     /* comment out in RELEASE and PERFORMANCE modes */
/* #define VNIC_PROFILLNG */  		/* comment out in RELEASE and PERFORMANCE modes */
#define VNIC_EXTRA_STATS 		/* comment out in PERFORMANCE mode */

enum {
	VNIC_DEBUG_GENERAL	= 1 << 0,  /* 0x1    */
	VNIC_DEBUG_MCAST	= 1 << 1,  /* 0x2    */
	VNIC_DEBUG_MCAST_V	= 1 << 2,  /* 0x4    */
	VNIC_DEBUG_DATA		= 1 << 3,  /* 0x8    */
	VNIC_DEBUG_DATA_V	= 1 << 4,  /* 0x10   */
	VNIC_DEBUG_FIP		= 1 << 5,  /* 0x20   */
	VNIC_DEBUG_FIP_V	= 1 << 6,  /* 0x40   */
	VNIC_DEBUG_SKB		= 1 << 7,  /* 0x80   */
	VNIC_DEBUG_SKB_V	= 1 << 8,  /* 0x100  */
	VNIC_DEBUG_VHUB		= 1 << 9,  /* 0x200  */
	VNIC_DEBUG_VHUB_V	= 1 << 10, /* 0x400  */
	VNIC_DEBUG_ETHTOOL	= 1 << 11, /* 0x800  */
	VNIC_DEBUG_ETHTOOL_V	= 1 << 12, /* 0x1000 */
	VNIC_DEBUG_FUNC		= 1 << 13, /* 0x2000 */
	VNIC_DEBUG_MARK		= 1 << 14, /* 0x4000 */
	VNIC_DEBUG_MODER	= 1 << 15, /* 0x8000 */
	VNIC_DEBUG_MODER_v	= 1 << 16, /* 0x10000 */
	VNIC_DEBUG_PKT_DUMP	= 1 << 17, /* 0x20000 */
	VNIC_DEBUG_FIP_P0	= 1 << 18, /* 0x40000 */
	VNIC_DEBUG_SYSFS	= 1 << 19, /* 0x80000 */
	VNIC_DEBUG_MAC		= 1 << 20, /* 0x100000 */
	VNIC_DEBUG_TSTAMP	= 1 << 21, /* 0x200000 */
	VNIC_DEBUG_PARSER	= 1 << 19, /* 0x400000 */
	VNIC_DEBUG_LAG		= 1 << 20, /* 0x800000 */
	VNIC_DEBUG_LAG_V	= 1 << 21, /* 0x1000000 */
	VNIC_DEBUG_MCAST_VV	= 1 << 22, /* 0x2000000 */
	VNIC_DEBUG_DEBUG	= 1 << 31, /* 0x80000000 */
};

/* always defined */
#define vnic_printk(level, prefix, format, arg...)			\
	do {   printk(level "T%.4ld [%s] %s:%s:%d: " format,		\
		jiffies * 1000 / HZ,  					\
	       DRV_NAME, prefix ? prefix : "", __func__, __LINE__ ,	\
	       ## arg);							\
} while(0)

#define vnic_info(format, arg...)					\
do {	printk(KERN_INFO "[%s] " format, DRV_NAME, ## arg); }		\
while (0)

#define vnic_warn(prefix, format, arg...)				\
do { vnic_printk(KERN_WARNING, prefix, format, ## arg); }		\
while (0)

#define vnic_err(prefix, format, arg...)				\
do { vnic_printk(KERN_ERR, prefix, format, ## arg); }			\
while (0)

#define _sprintf(p, buf, format, arg...)				\
	(PAGE_SIZE - (int)(p - buf)) <= 0 ? 0 :				\
	scnprintf(p, PAGE_SIZE - (int)(p - buf), format, ## arg)

/* debug functions */
#ifndef CONFIG_MLX4_VNIC_DEBUG
#define ASSERT(x) 			         do { (void)(x);      } while (0)
#define vnic_dbg_mark(void)		         do {                 } while (0)
#define vnic_dbg_func(prefix)		         do {                 } while (0)
#define vnic_dbg(prefix, format, arg...)         do { (void)(prefix); } while (0)
#define vnic_dbg_mcast(prefix, format, arg...)   do { (void)(prefix); } while (0)
#define vnic_dbg_mcast_v(prefix, format, arg...) do { (void)(prefix); } while (0)
#define vnic_dbg_mcast_vv(prefix, format, arg...) do { (void)(prefix); } while (0)
#define vnic_dbg_debug(prefix, format, arg...) do { (void)(prefix); } while (0)
#define vnic_dbg_ethtool(prefix, format, arg...) do { (void)(prefix); } while (0)
#define vnic_dbg_ethtool_v(prefix, format, arg...) \
					         do { (void)(prefix); } while (0)
#define vnic_dbg_data(prefix, format, arg...)    do { (void)(prefix); } while (0)
#define vnic_dbg_data_v(prefix, format, arg...)  do { (void)(prefix); } while (0)
#define vnic_dbg_fip(prefix, format, arg...)     do { (void)(prefix); } while (0)
#define vnic_dbg_parse(prefix, format, arg...)     do { (void)(prefix); } while (0)
#define vnic_dbg_lag(prefix, format, arg...)     do { (void)(prefix); } while (0)
#define vnic_dbg_lag_v(prefix, format, arg...)     do { (void)(prefix); } while (0)
#define vnic_dbg_fip_p0(prefix, format, arg...)  do { (void)(prefix); } while (0)
#define vnic_dbg_sysfs(prefix, format, arg...)   do { (void)(prefix); } while (0)
#define vnic_dbg_mac(prefix, format, arg...)     do { (void)(prefix); } while (0)
#define vnic_dbg_fip_v(prefix, format, arg...)   do { (void)(prefix); } while (0)
#define vnic_dbg_vhub(prefix, format, arg...)    do { (void)(prefix); } while (0)
#define vnic_dbg_vhub_v(prefix, format, arg...)  do { (void)(prefix); } while (0)
#define vnic_dbg_moder(prefix, format, arg...)   do { (void)(prefix); } while (0)
#define vnic_dbg_moder_v(prefix, format, arg...) do { (void)(prefix); } while (0)
#define vnic_printk_skb(prefix, skb, o1, o2)     do { (void)(prefix); } while (0)
#define vnic_dbg_skb(prefix, skb, o1, o2)        do { (void)(prefix); } while (0)
#else
#define ASSERT(x)  							\
do {	if (x) break;							\
	printk(KERN_EMERG "### ASSERTION FAILED %s: %s: %d: %s\n",	\
	       __FILE__, __func__, __LINE__, #x); dump_stack(); BUG();	\
} while (0)

#define vnic_dbg(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_GENERAL)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_mcast(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_MCAST)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_mcast_v(prefix, format, arg...)			\
do {	if (!(vnic_msglvl & VNIC_DEBUG_MCAST_V)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_mcast_vv(prefix, format, arg...)			\
do {	if (!(vnic_msglvl & VNIC_DEBUG_MCAST_VV)) break;		\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_debug(prefix, format, arg...)			\
do {	if (!(vnic_msglvl & VNIC_DEBUG_DEBUG)) break;			\
	vnic_printk(KERN_WARNING, prefix, format, ## arg);		\
} while (0)


#define vnic_dbg_data(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_DATA)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_data_v(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_DATA_V)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_fip_p0(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_FIP_P0)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_sysfs(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_SYSFS)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_mac(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_MAC)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_fip(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_FIP)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_parse(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_PARSER)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_lag(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_LAG)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_lag_v(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_LAG_V)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_fip_v(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_FIP_V)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_vhub(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_VHUB)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_vhub_v(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_VHUB_V)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_moder(prefix, format, arg...)				\
do {	if (!(vnic_msglvl & VNIC_DEBUG_MODER)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_moder_v(prefix, format, arg...)			\
do {	if (!(vnic_msglvl & VNIC_DEBUG_MODER_V)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_ethtool(prefix, format, arg...)			\
do {	if (!(vnic_msglvl & VNIC_DEBUG_ETHTOOL)) break;			\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_ethtool_v(prefix, format, arg...)			\
do {	if (!(vnic_msglvl & VNIC_DEBUG_ETHTOOL_V)) break;		\
	vnic_printk(KERN_DEBUG, prefix, format, ## arg);		\
} while (0)

#define vnic_dbg_mark(void)						\
do {	if (!(vnic_msglvl & VNIC_DEBUG_MARK)) break;			\
	vnic_printk(KERN_DEBUG, NULL, "###\n");				\
} while (0)

#define vnic_dbg_func(prefix)						\
do {	if (!(vnic_msglvl & VNIC_DEBUG_FUNC)) break;			\
	vnic_printk(KERN_DEBUG, prefix, "function called\n");		\
} while (0)

#define ethp2str(p, str)						\
do { 									\
	switch (ntohs(p)) {						\
	case ETH_P_RARP: sprintf(str, "%s", "ETH_P_RARP"); break;	\
	case ETH_P_ARP:  sprintf(str, "%s", "ETH_P_ARP");  break;	\
	case ETH_P_IP:   sprintf(str, "%s", "ETH_P_IP");   break;	\
	case ETH_P_IPV6: sprintf(str, "%s", "ETH_P_IPV6"); break;	\
	case ETH_P_8021Q:sprintf(str, "%s", "ETH_P_8021Q");break;	\
	default:         sprintf(str, "0x%x", p);	   break;	\
	}								\
} while (0)

#define skb_printk(prefix, format, arg...)				\
	printk(KERN_DEBUG "[%s] " format, prefix, ## arg)

#define vnic_dbg_skb(_prefix, skb, eoib_off, eth_off)			\
do {	if (!(vnic_msglvl & VNIC_DEBUG_SKB)) break;			\
	vnic_printk_skb(_prefix, skb, eoib_off, eth_off);		\
} while (0)

#define VNIC_SYSLOG_LLEN 64
#define vnic_printk_skb(_prefix, skb, eoib_off, eth_off)		\
do { 									\
	char pr[VNIC_SYSLOG_LLEN];					\
	char h_proto_str[VNIC_SYSLOG_LLEN];				\
	struct eoibhdr *eoib_hdr = (struct eoibhdr *)			\
			(skb->data + eoib_off);				\
	struct ethhdr *ethh = (struct ethhdr *)				\
			(skb->data + eth_off);				\
	struct net_device *dev = skb->dev;				\
	ASSERT(dev);							\
	snprintf(pr, VNIC_SYSLOG_LLEN, "%s:skb-%s", dev->name, _prefix);\
	skb_printk(pr, "\n");						\
	skb_printk(pr, "--- skb dump ---\n");				\
	skb_printk(pr, "len          : %d\n", skb->len);		\
	skb_printk(pr, "data_len     : %d\n", skb->data_len);		\
	skb_printk(pr, "frags        : %d\n",				\
		skb_shinfo(skb)->nr_frags);				\
	skb_printk(pr, "gso          : %d\n", skb_is_gso(skb));		\
	skb_printk(pr, "head_len     : %d\n", (int)skb_headlen(skb));	\
	skb_printk(pr, "data         : %p\n", skb->data);		\
	skb_printk(pr, "head         : %p\n", skb->head);		\
	skb_printk(pr, "tail         : %lu\n",				\
		   (unsigned long)(skb->tail));				\
	skb_printk(pr, "end          : %lu\n",				\
		   (unsigned long)(skb->end));				\
	skb_printk(pr, "eoib_off     : %lu\n", eoib_off);		\
	skb_printk(pr, "eth_off      : %lu\n", eth_off);		\
	if (eth_off < 0 || !skb_headlen(skb))				\
		break;							\
	ethp2str(ethh->h_proto, h_proto_str);				\
	skb_printk(pr, "eth_proto    : %s\n", h_proto_str);		\
	skb_printk(pr, "eth_dest     : "MAC_6_PRINT_FMT"\n",		\
		   MAC_6_PRINT_ARG(ethh->h_dest));			\
	skb_printk(pr, "eth_source   : "MAC_6_PRINT_FMT"\n",		\
		   MAC_6_PRINT_ARG(ethh->h_source));			\
	if (eoib_off < 0)						\
		break;							\
	skb_printk(pr, "eoib_seg_id  : 0x%04x\n", eoib_hdr->seg_id);	\
	skb_printk(pr, "eoib_seg_off : 0x%02x\n", eoib_hdr->seg_off);	\
	skb_printk(pr, "eoib_ip_chk  : 0x%02x\n",			\
		   VNIC_EOIB_HDR_GET_IP_CHK(eoib_hdr));			\
	skb_printk(pr, "eoib_tcp_chk : 0x%02x\n",			\
		   VNIC_EOIB_HDR_GET_TCP_UDP_CHK(eoib_hdr));		\
	skb_printk(pr, "eoib_ver     : 0x%02x\n",			\
		   VNIC_EOIB_HDR_GET_VER(eoib_hdr));			\
	skb_printk(pr, "eoib_sig     : 0x%02x\n",			\
		   VNIC_EOIB_HDR_GET_SIG(eoib_hdr));			\
} while (0)

#endif /* CONFIG_MLX4_VNIC_DEBUG */
#endif /* _VNIC_UTILS_H */
