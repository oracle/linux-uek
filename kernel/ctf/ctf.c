/*
 * FILE:	ctf.c
 * DESCRIPTION:	Dynamic Tracing: CTF container module
 *
 * Copyright (C) 2012 Oracle Corporation
 */

#include <linux/module.h>

MODULE_AUTHOR("Nick Alcock <nick.alcock@oracle.com>");
MODULE_DESCRIPTION("CTF container module, not for modprobing");
MODULE_VERSION("v0.2");
MODULE_LICENSE("GPL");

void ctf_forceload(void) {
	/* nothing doing */
}

EXPORT_SYMBOL(ctf_forceload);
