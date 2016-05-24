/*
 * Copyright (c) 2014, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * version.h: Detailed version info data structure
 */
#ifndef SIF_VERSION_H
#define SIF_VERSION_H

struct sif_version {
	const char *git_repo;
	const char *last_commit;
	const char *git_status;
	const char *build_user;
	const char *build_git_time;
	const char *git_psifapi_repo;
	const char *last_psifapi_commit;
	const char *git_psifapi_status;
};

extern struct sif_version sif_version;

#endif /* SIF_VERSION_H */
