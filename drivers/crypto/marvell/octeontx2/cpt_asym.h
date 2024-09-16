/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2018 Marvell.
 */

#ifndef __CPT_ASYM_H
#define __CPT_ASYM_H

#include <crypto/akcipher.h>
#include <crypto/ecdh.h>
#include <crypto/rng.h>
#include <crypto/ecc_curve.h>
#include <crypto/internal/akcipher.h>
#include <crypto/internal/ecc.h>
#include <crypto/internal/ecdsa.h>
#include <crypto/internal/kpp.h>
#include <crypto/internal/rsa.h>
#include <crypto/kpp.h>
#include <crypto/scatterwalk.h>
#include <linux/module.h>
#include <linux/asn1_decoder.h>
#include "otx2_cptvf.h"
#include "otx2_cptvf_algs.h"
#include "otx2_cpt_reqmgr.h"

#define CPT_EGRP_AE   2

#define CPT_AE_EC_ID_P192  0
#define CPT_AE_EC_ID_P224  1
#define CPT_AE_EC_ID_P256  2
#define CPT_AE_EC_ID_P384  3
#define CPT_AE_EC_ID_P521  4
#define CPT_AE_EC_ID_PMAX  5

struct cpt_rsa_ctx {
	char *pubkey;
	char *prikey;
	/* low address: dq->dp->q->p->qinv */
	char *crt_prikey;
	u32 e_sz;
	u32 d_sz;
	bool crt_mode;
	bool pkcs1;
};

struct cpt_ecdh_ctx {
	/* low address: x->y->k->p->a->b */
	unsigned char *c;
	u32 curve_id;
	u32 curve_sz;
	u16 dlen;
};

struct cpt_asym_ctx {
	u32 key_sz;
	u32 max_dst_len;
	struct device *dev;
	struct pci_dev *pdev;
	union {
		struct cpt_rsa_ctx rsa;
		struct cpt_ecdh_ctx ecdh;
		struct ecc_ctx ecdsa;
	};
	struct cn10k_cpt_errata_ctx er_ctx;
};

struct cpt_asym_req_ctx {
	struct otx2_cpt_req_info cpt_req;
	struct cpt_asym_ctx *ctx;
	bool verify;
};

static inline u32 cpt_uc_ecc_id_get(u32 id)
{
	switch (id) {
	case ECC_CURVE_NIST_P192:
		return CPT_AE_EC_ID_P192;
	case ECC_CURVE_NIST_P256:
		return CPT_AE_EC_ID_P256;
	case ECC_CURVE_NIST_P384:
		return CPT_AE_EC_ID_P384;
	default:
		break;
	}

	return 0;
}

static inline void cpt_key_to_big_end(u8 *data, int len)
{
	int i, j;

	for (i = 0; i < len / 2; i++) {
		j = len - i - 1;
		swap(data[j], data[i]);
	}
}

static inline bool cpt_key_is_zero(char *key, u32 key_sz)
{
	int i;

	for (i = 0; i < key_sz; i++)
		if (key[i])
			return false;

	return true;
}

static inline void fill_curve_param(void *addr, u64 *param, u32 cur_sz, u8 ndigits)
{
	unsigned int sz = cur_sz - (ndigits - 1) * sizeof(u64);
	u8 i = 0;

	while (i < ndigits - 1) {
		memcpy(addr + sizeof(u64) * i, &param[i], sizeof(u64));
		i++;
	}
	if (sz)
		memcpy(addr + sizeof(u64) * i, &param[ndigits - 1], sz);
	cpt_key_to_big_end((u8 *)addr, cur_sz);
}

static inline int cpt_asym_enqueue(struct crypto_async_request *areq,
				   struct otx2_cpt_req_info *req_info)
{
	struct pci_dev *pdev;
	int cpu_num, ret;

	ret = otx2_cpt_dev_get(&pdev, &cpu_num);
	if (ret)
		return ret;

	req_info->ctrl.s.grp = CPT_EGRP_AE;
	req_info->areq = areq;
	/*
	 * We perform an asynchronous send and once
	 * the request is completed the driver would
	 * intimate through registered call back functions
	 */
	return otx2_cpt_do_request(pdev, req_info, cpu_num);
}

int cpt_ae_fpm_tbl_get(struct pci_dev *pdev, struct cpt_ae_fpm_tbl *tbl);
void cpt_ae_fpm_tbl_free(struct pci_dev *pdev, struct cpt_ae_fpm_tbl *tbl);
int cpt_register_ecdsa(void);
void cpt_unregister_ecdsa(void);

#endif /* __CPT_ASYM_H */
