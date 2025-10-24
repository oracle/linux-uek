/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Asymmetric public-key cryptography data parser
 *
 * See Documentation/crypto/asymmetric-keys.rst
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _KEYS_ASYMMETRIC_PARSER_H
#define _KEYS_ASYMMETRIC_PARSER_H

struct key_preparsed_payload;

/*
 * Key data parser.  Called during key instantiation.
 */
struct asymmetric_key_parser {
	struct list_head	link;
	struct module		*owner;
	const char		*name;

	/* Attempt to parse a key from the data blob passed to add_key() or
	 * keyctl_instantiate().  Should also generate a proposed description
	 * that the caller can optionally use for the key.
	 *
	 * Return EBADMSG if not recognised.
	 */
	int (*parse)(struct key_preparsed_payload *prep);
};
DECLARE_CRYPTO_API(register_asymmetric_key_parser, int, (struct asymmetric_key_parser *i), (i));
DECLARE_CRYPTO_API(unregister_asymmetric_key_parser, void, (struct asymmetric_key_parser *i), (i));

#endif /* _KEYS_ASYMMETRIC_PARSER_H */
