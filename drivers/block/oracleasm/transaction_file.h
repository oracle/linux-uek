/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * transaction_file.h - Functions for transaction files.
 *
 * This header contains initialization routines for transaction files.
 *
 * Copyright (c) 2004 Oracle Corporation.  All rights reserved.
 */


#ifndef _TRANSACTION_FILE_H
#define _TRANSACTION_FILE_H

/* 
 * A transaction context is attached to a transaction file's inode.  It
 * holds the transaction service operation.
 */
struct transaction_context {
	ssize_t (*write_op)(struct file *, char *, size_t);
};

int init_transaction_inode(struct inode *inode,
			   struct transaction_context *tctxt);
struct inode *new_transaction_inode(struct super_block *sb, int mode,
				    struct transaction_context *tctxt);

#endif  /* _TRANSACTION_FILE_H */
