/* SPDX-License-Identifier: GPL-2.0
 * Marvell CPT common code
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT_ALGS_H_
#define __CPT_ALGS_H_

struct algs_ops {
	int (*cpt_do_request)(struct pci_dev *pdev,
			      struct cpt_request_info *req, int cpu_num);
	int (*cpt_get_kcrypto_eng_grp_num)(struct pci_dev *pdev);
};

int cvm_crypto_init(struct pci_dev *pdev, struct module *mod,
		    struct algs_ops ops, enum cpt_pf_type pf_type,
		    enum cpt_eng_type engine_type, int num_queues,
		    int num_devices);
void cvm_crypto_exit(struct pci_dev *pdev, struct module *mod,
		     enum cpt_eng_type engine_type);
void cvm_callback(int status, void *arg, void *req);

#endif /* __CPT_ALGS_H_*/
