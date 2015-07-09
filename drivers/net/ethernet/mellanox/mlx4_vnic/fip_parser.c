/*
 * Copyright (c) 2010 Mellanox Technologies. All rights reserved.
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
 
#include "vnic.h"
#include "vnic_fip.h"
#include "vnic_fip_pkt.h"

static const struct subcode_rules {
	u64	req_mask;
	u64	opt_mask;
} subcodes_array[FIP_MAX_SUBCODES] = {
	[FIP_HOST_SOL_SUB_OPCODE] = {
		.req_mask = FIP_MASK(VENDOR_ID) |
			    FIP_MASK(ADDRESS),
		.opt_mask = FIP_MASK(EXT_DESC),
	},
	[FIP_GW_ADV_SUB_OPCODE] = {
		.req_mask = FIP_MASK(VENDOR_ID) |
			    FIP_MASK(ADDRESS) |
			    FIP_MASK(GW_INFORMATION) |
			    FIP_MASK(GW_IDENTIFIER) |
			    FIP_MASK(KA_PARAMS),
		.opt_mask = FIP_MASK(EXT_DESC),
	},
	[FIP_HOST_LOGIN_SUB_OPCODE] = {
		.req_mask = FIP_MASK(VENDOR_ID) |
			    FIP_MASK(ADDRESS) |
			    FIP_MASK(LOGIN) |
			    FIP_MASK(PARTITION),
		.opt_mask = FIP_MASK(EXT_DESC),
	},
	[FIP_GW_LOGIN_SUB_OPCODE] = {
		.req_mask = FIP_MASK(VENDOR_ID) |
			    FIP_MASK(ADDRESS) |
			    FIP_MASK(LOGIN) |
			    FIP_MASK(PARTITION),
		.opt_mask = FIP_MASK(EXT_DESC),
	},
	[FIP_HOST_LOGOUT_SUB_OPCODE] = {
		.req_mask = FIP_MASK(VENDOR_ID) |
			    FIP_MASK(VNIC_IDENTITY),
	},
	[FIP_GW_UPDATE_SUB_OPCODE] = {
		.req_mask = FIP_MASK(VENDOR_ID) |
			    FIP_MASK(VHUB_UPDATE),
		.opt_mask = FIP_MASK(EXT_DESC),
	},
	[FIP_GW_TABLE_SUB_OPCODE] = {
		.req_mask = FIP_MASK(VENDOR_ID) |
			    FIP_MASK(VHUB_TABLE),
	},
	[FIP_HOST_ALIVE_SUB_OPCODE] = {
		.req_mask = FIP_MASK(VENDOR_ID) |
			    FIP_MASK(VNIC_IDENTITY),
	},
};

static int type2idx(struct fip_content *fc, struct fip_fip_type *ft)
{
	void *p = ft;

	switch (ft->type) {
	case FIP_TYPE(VENDOR_ID):
		fc->fvend = p;
		return FIP_TYPE_IDX(VENDOR_ID);
	case FIP_TYPE(ADDRESS):
		fc->fa.fa[fc->fa.num++] = p;
		return FIP_TYPE_IDX(ADDRESS);
	case FIP_TYPE(GW_INFORMATION):
		fc->fgwi = p;
		return FIP_TYPE_IDX(GW_INFORMATION);
	case FIP_TYPE(LOGIN):
		fc->fl = p;
		return FIP_TYPE_IDX(LOGIN);
	case FIP_TYPE(VHUB_UPDATE):
		fc->fvu = p;
		return FIP_TYPE_IDX(VHUB_UPDATE);
	case FIP_TYPE(VHUB_TABLE):
		fc->fvt = p;
		return FIP_TYPE_IDX(VHUB_TABLE);
	case FIP_TYPE(VNIC_IDENTITY):
		fc->fvi = p;
		return FIP_TYPE_IDX(VNIC_IDENTITY);
	case FIP_TYPE(PARTITION):
		fc->fp = p;
		return FIP_TYPE_IDX(PARTITION);
	case FIP_TYPE(GW_IDENTIFIER):
		fc->fgid = p;
		return FIP_TYPE_IDX(GW_IDENTIFIER);
	case FIP_TYPE(KA_PARAMS):
		fc->fka = p;
		return FIP_TYPE_IDX(KA_PARAMS);
	case FIP_TYPE(EXT_DESC):
		fc->fed.fed[fc->fed.num++] = p;
		return FIP_TYPE_IDX(EXT_DESC);
	default:
		return -1;
	}
}

#ifdef CONFIG_MLX4_VNIC_DEBUG
static const char *fip_type_str(int type)
{
	switch (type) {
	FIP_CASE_STR(VENDOR_ID);
	FIP_CASE_STR(ADDRESS);
	FIP_CASE_STR(GW_INFORMATION);
	FIP_CASE_STR(LOGIN);
	FIP_CASE_STR(VHUB_UPDATE);
	FIP_CASE_STR(VHUB_TABLE);
	FIP_CASE_STR(VNIC_IDENTITY);
	FIP_CASE_STR(PARTITION);
	FIP_CASE_STR(GW_IDENTIFIER);
	FIP_CASE_STR(KA_PARAMS);
	FIP_CASE_STR(EXT_DESC);
	default:
		return "Unknown";
	}
}

static const char *fip_subcode_str(int subcode)
{
	switch (subcode) {
	FIP_SUBCODE_CASE_STR(FIP_HOST_SOL_SUB_OPCODE);
	FIP_SUBCODE_CASE_STR(FIP_GW_ADV_SUB_OPCODE);
	FIP_SUBCODE_CASE_STR(FIP_HOST_LOGIN_SUB_OPCODE);
	FIP_SUBCODE_CASE_STR(FIP_GW_LOGIN_SUB_OPCODE);
	FIP_SUBCODE_CASE_STR(FIP_HOST_LOGOUT_SUB_OPCODE);
	FIP_SUBCODE_CASE_STR(FIP_GW_UPDATE_SUB_OPCODE);
	FIP_SUBCODE_CASE_STR(FIP_GW_TABLE_SUB_OPCODE);
	FIP_SUBCODE_CASE_STR(FIP_HOST_ALIVE_SUB_OPCODE);
	default:
		return "Unknown";
	}
}
#endif

static int verify_mlx_sig(void *p)
{
	static const char *mlx4_str = "mellanox";
	__be64 mlx_str_64 = *(__be64 *)mlx4_str;
	__be64 *sig = p;

	return *sig != mlx_str_64;
}

static int next_type(struct vnic_port *port, void *tlv, int len,
		     struct fip_content *fc, int *sz, int *idx)
{
        struct fip_fip_type *ft;

	if (sizeof *ft > len) {
		vnic_dbg_parse(port->name, "message too short\n");
		return -1;
	}
	ft = tlv
		;
        vnic_dbg_parse(port->name, "TLV: type %s(%d)\n", fip_type_str(ft->type),
		     ft->type);

	if (!ft->length || (ft->length << 2 > len)) {
		vnic_dbg_parse(port->name, "TLV does not fit in message: %s(%d) "
			     "tlv->len %d, remaining %d\n", fip_type_str(ft->type),
			     ft->type, ft->length << 2, len);
		return -1;
	}

	*sz = (ft->length << 2);

	*idx = type2idx(fc, ft);
	if (*idx < 0) {
		vnic_dbg_parse(port->name, "unkown type %d\n", ft->type);
		return -1;
	}

	if (ft->type == FIP_TYPE(VENDOR_ID) && verify_mlx_sig(fc->fvend->vendor_id)) {
                vnic_dbg_parse(port->name, "mellanox signature check failed\n");
		return -1;
	}

        if (ft->type == FIP_TYPE(VHUB_TABLE) || ft->type == FIP_TYPE(VHUB_UPDATE)) {
		int cte_list_sz;
		struct context_table_entry *cte_start;

		if (ft->type == FIP_TYPE(VHUB_TABLE)) {
			unsigned hdr = be16_to_cpu(fc->fvt->hdr) >> 14;

			if (hdr > FIP_TABLE_HDR_ONLY) {
				vnic_dbg_parse(port->name, "invalid table header %d\n", hdr);
				return -1;
			}
			cte_list_sz = *sz - sizeof(struct fip_vhub_table_tlv);
			/* Todo, the next 2 lines are comented because the size of the tbl tlv is
			   miscomputed in BXM versions 1.3.6-5 and it causes tables to be discarded.
			   In reality the size should be used with the lines in tact. */
			/*if (hdr == FIP_TABLE_HDR_LAST)
				cte_list_sz -= 4;
			*/

			cte_start = (struct context_table_entry *)(fc->fvt + 1);
		} else {
			cte_list_sz = *sz - sizeof(struct fip_vhub_update_tlv);
			cte_start = (struct context_table_entry *)(fc->fvu + 1);
		}


		fc->cte.num = cte_list_sz / sizeof(struct context_table_entry);
		fc->cte.cte = cte_start;
	}


	return 0;
}

static inline int check_eoib_ver(struct vnic_port *port,
				 struct fip_eoib_ver *eoib_ver, int sz, int *len)
{
	if (unlikely(sz < sizeof *eoib_ver)) {
		vnic_dbg_parse(port->name, "message too short\n");
		*len = sz;
		return -ENOMEM;
	}
	*len = sizeof *eoib_ver;
	if (unlikely(eoib_ver->version >> 4)) {
		vnic_dbg_parse(port->name, "eoib version check failed: %d\n", eoib_ver->version >> 4);
		return -EINVAL;
	}
	return 0;
}

static void dump_raw(struct vnic_port *port, void *buf, int len)
{
	int i;

	for (i = 0; i < len / 4; ++i)
		vnic_dbg_parse(port->name, "0x%08x\n", be32_to_cpu(((__be32 *)(buf))[i]));
}

static inline int check_fip_hdr(struct vnic_port *port,
				struct fip_header_simple *fh, int sz, int *len)
{
	if (unlikely(sizeof *fh > sz)) {
		vnic_dbg_parse(port->name, "message too short\n");
		return -1;
	}

	if (unlikely(fh->opcode != cpu_to_be16(EOIB_FIP_OPCODE))) {
		vnic_dbg_parse(port->name, "not fip opcode\n");
		return -1;
	}

	if (unlikely((be16_to_cpu(fh->list_length) << 2) > (sz - sizeof *fh))) {
		vnic_dbg_parse(port->name, "message too short: header length = %u, "
			       "left length = %lu\n",
			       be16_to_cpu(fh->list_length) << 2, sz - sizeof *fh);
		return -1;
	}

        *len = sizeof *fh;

	return 0;
}

static int check_fip_mask(struct vnic_port *port, struct fip_content *fc)
{
	u64 req_mask = subcodes_array[fc->fh->subcode].req_mask;
	u64 opt_mask = subcodes_array[fc->fh->subcode].opt_mask;

	if (((fc->mask & req_mask) != req_mask) ||
	    ((fc->mask & ~opt_mask) & ~req_mask)) {
		vnic_dbg_parse(port->name, "%s: mask check failed: mask 0x%llx,"
			     "req_mask 0x%llx, opt_mask 0x%llx\n",
			     fip_subcode_str(fc->fh->subcode), fc->mask, req_mask, opt_mask);
		return -1;
	}

	return 0;
}

static void dump_cte(struct vnic_port *port, struct context_table_entry *cte)
{
        vnic_dbg_parse(port->name, "CTE: V(%d) RSS(%d) type(%d) MAC(%pM) QPN(0x%06x) SL(%d) LID(0x%04x)\n",
		       (0x1 & (cte->v_rss_type >> 7)),
		       (0x1 & (cte->v_rss_type >> 6)),
		       (cte->v_rss_type & 0xf),
		       cte->mac, be32_to_cpu(cte->qpn) & 0xffffff,
		       (cte->sl & 0xf), be16_to_cpu(cte->lid));
}

static void dump_vnic_identity(struct vnic_port *port,
			       struct fip_vnic_identity_tlv *fvi)
{
#define VHUB_ID	be32_to_cpu(fvi->flags_vhub_id)

        vnic_dbg_parse(port->name, "%s: U(%d) R(%d) VP(%d) VHUBID(x%x) TUSN(0x%x) VNIC_ID(0x%x)"
		       "MAC(%pM) GUID("GUID_FORMAT") VNIC NAME (%s)\n",
		       fip_type_str(fvi->ft.type), (VHUB_ID >> 31), (0x01 & (VHUB_ID >> 30)),
		       (0x01 & (VHUB_ID >> 24)), VHUB_ID & 0xffffff, be32_to_cpu(fvi->tusn),
		       be16_to_cpu(fvi->vnic_id), fvi->mac, GUID_ARG(fvi->port_guid), fvi->vnic_name);
}

static void dump_vnic_partition(struct vnic_port *port, struct fip_partition_tlv *fp)
{
	vnic_dbg_parse(port->name, "%s: PKEY(0x%x)\n", fip_type_str(fp->ft.type),
		       be16_to_cpu(fp->pkey));
}


static void dump_gw_identifier(struct vnic_port *port, struct fip_gw_identifier_tlv *fgid)
{
	vnic_dbg_parse(port->name, "%s: SYS GUID("GUID_FORMAT") SYS NAME(%s) GW PORT NAME(%s)\n",
		     fip_type_str(fgid->ft.type), GUID_ARG(fgid->sys_guid), fgid->sys_name, fgid->sys_name);
}

static void dump_ka_params(struct vnic_port *port, struct fip_ka_params_tlv *fka)
{
	vnic_dbg_parse(port->name, "%s: GW_ADV_PERIOD(%d) GW_KA_PERIOD(%d) VNIC_KA_PERIOD(%d)\n",
		       fip_type_str(fka->ft.type), be32_to_cpu(fka->adv_period),
		       be32_to_cpu(fka->ka_period), be32_to_cpu(fka->vnic_ka_period));
}

static void dump_vhub_table(struct vnic_port *port, struct fip_content *fc)
{
	int i;

	vnic_dbg_parse(port->name, "%s: VP(%d) vhub id(0x%x) TUSN(0x%x) HDR(%d) table size (%d)\n",
		       fip_type_str(fc->fvt->ft.type), be32_to_cpu(fc->fvt->vp_vhub_id) >> 24 & 1,
		       be32_to_cpu(fc->fvt->vp_vhub_id) & 0xffffff, be32_to_cpu(fc->fvt->tusn),
		       be16_to_cpu(fc->fvt->hdr) >> 14, be16_to_cpu(fc->fvt->table_size));
	for (i = 0; i < fc->cte.num; ++i)
		dump_cte(port, &fc->cte.cte[i]);
}

static void dump_fip_login(struct vnic_port *port, struct fip_login_tlv *p)
{
	vnic_dbg_parse(port->name, "%s: mtu(%d) vnic_id(0x%x) v_m_vp_h(0x%x) vlan(0x%x) mac(%pM)"
		       "mgid_prefix("MGID_PREFIX_FMT") vfields(0x%0x) syndrom(%d) QPN(0x%x)"
		       " vnic_name(%s)\n", fip_type_str(p->ft.type), be16_to_cpu(p->mtu),
		       be16_to_cpu(p->vnic_id), be16_to_cpu(p->flags_vlan) >> 12,
		       be16_to_cpu(p->flags_vlan) & 0xfff, p->mac, MGID_PRE_ARG(p->eth_gid_prefix),
		       be16_to_cpu(p->vfields), be32_to_cpu(p->syndrom_ctrl_qpn) >> 24,
		       be32_to_cpu(p->syndrom_ctrl_qpn) & 0xffffff, p->vnic_name);
}

static void dump_fip_address(struct vnic_port *port, struct fip_address_tlv *fa)
{
	vnic_dbg_parse(port->name, "%s: GW_TYPE(%d) QPN(0x%x)  SL(%d), GW_PORT_ID(0x%x),"
		       " LID(0x%x) GUID(" GUID_FORMAT ")\n", fip_type_str(fa->ft.type),
		       be32_to_cpu(fa->gwtype_qpn) >> 24, be32_to_cpu(fa->gwtype_qpn) & 0xffffff,
		       be16_to_cpu(fa->sl_gwportid) >> 12, be16_to_cpu(fa->sl_gwportid) & 0xfff,
		       be16_to_cpu(fa->lid), GUID_ARG(fa->guid));
}

static void dump_vhub_update(struct vnic_port *port, struct fip_content *fc)
{
#define VHUB_ID_1 	be32_to_cpu(fc->fvu->state_vhub_id)
	int i;

	vnic_dbg_parse((port->name), "%s: eport_state(%s) vp(%d) vhub_id(0x%x) tusn(0x%x)\n",
		       fip_type_str(fc->fvu->ft.type), eport_state_str(VHUB_ID_1 >> 28 & 3),
		       VHUB_ID_1 >> 24 & 1, VHUB_ID_1 & 0xffffff, be32_to_cpu(fc->fvu->tusn));
	for (i = 0; i < fc->cte.num; ++i)
		dump_cte(port, &fc->cte.cte[i]);
}

static void dump_gateway_information(struct vnic_port *port,
				     struct fip_gw_information_tlv *fgwi)
{
	vnic_dbg_parse(port->name, "%s: accept host administered(%s) nmac_mgid(%d) "
		       "nrss_mgid(%d) ntss_qpn(%d), n_rss(%d), num_net_vnics(%d)\n",
		       fip_type_str(fgwi->ft.type), (fgwi->h_nmac_mgid >> 7) ? "Yes" : "No",
		       fgwi->h_nmac_mgid & 0x3f, fgwi->n_rss_mgid_tss_qpn >> 4,
		       fgwi->n_rss_mgid_tss_qpn & 0xf, be16_to_cpu(fgwi->n_rss_qpn_vnics) >> 12,
		       be16_to_cpu(fgwi->n_rss_qpn_vnics) & 0xfff);
}

static void dump_fip_packet(struct vnic_port *port, struct fip_content *fc)
{
	int i;

	for (i = 0; i < fc->fa.num; ++i)
		dump_fip_address(port, fc->fa.fa[i]);

	if (fc->fgwi)
		dump_gateway_information(port, fc->fgwi);

	if (fc->fvu)
		dump_vhub_update(port, fc);

	if (fc->fl)
		dump_fip_login(port, fc->fl);

	if (fc->fvt)
		dump_vhub_table(port, fc);

	if (fc->fvi)
		dump_vnic_identity(port, fc->fvi);

	if (fc->fp)
		dump_vnic_partition(port, fc->fp);

	if (fc->fgid)
                dump_gw_identifier(port, fc->fgid);

	if (fc->fka)
                dump_ka_params(port, fc->fka);
}

int fip_packet_parse(struct vnic_port *port, void *packet, int pkt_size, struct fip_content *fc)
{
	void *ptr = packet;
	int len;
	int err;
	int idx;
	u16 offset = 0;
	int size = pkt_size;

	vnic_dbg_parse(port->name, "size = %d\n", size);
	err = check_eoib_ver(port, ptr, size, &len);
	if (err) {
		if (err != -EINVAL)
			goto out_err;
		else
			vnic_dbg_parse(port->name, "version check failed\n");
	}

	fc->eoib_ver = ptr;
	size -= len;
	ptr += len;
	offset += len;
	fc->fh = ptr;

	err = check_fip_hdr(port, ptr, size, &len);
	if (err)
		goto out_err;

	ptr += len;
	offset += len;

	fc->fa.num = 0;
	fc->num = 0;
	fc->mask = 0;

	/* workaround a BXM bug not reporting the correct descriptor length */
	if (fc->fh->subcode != FIP_GW_ADV_SUB_OPCODE)
		size = be16_to_cpu(fc->fh->list_length) << 2;
	else
		size -= len;

	vnic_dbg_parse(port->name, "subcode = %s, size %d\n",
		     fip_subcode_str(fc->fh->subcode), size);
	while (size > 0) {
		err = next_type(port, ptr, size, fc, &len, &idx);
		if (err)
			break;

		fc->offsets[fc->num] = offset;
		fc->mask |= ((u64)1 << idx);
		ptr += len;
		size -= len;
		offset += len;
		fc->num++;
	}

	if (err)
		goto out_err;

	err = check_fip_mask(port, fc);
	if (err) {
		vnic_dbg_parse(port->name, "check mask: failed\n");
		goto out_err;
	}

	dump_fip_packet(port, fc);

	return 0;

out_err:
       	dump_raw(port, packet, pkt_size);
	return err;
}
