/*
 * Copyright (C) 2017 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */
#ifndef ZIP_H
#define ZIP_H

#include <linux/pci.h>
#include <linux/types.h>

#include "octeontx.h"

struct zippf_com_s {
	u64 (*create_domain)(u32 id, u16 domain_id, u32 num_vfs,
			     void *master, void *master_data,
			     struct kobject *kobj);
	int (*destroy_domain)(u32 id, u16 domain_id, struct kobject *kobj);
	int (*reset_domain)(u32 id, u16 domain_id);
	int (*receive_message)(u32 id, u16 domain_id, struct mbox_hdr *hdr,
			       union mbox_data *req, union mbox_data *resp,
			       void *mdata);
};

extern struct zippf_com_s zippf_com;


#endif
