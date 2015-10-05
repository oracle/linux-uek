/* System keyring containing trusted public keys.
 *
 * Copyright (C) 2013 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _KEYS_SYSTEM_KEYRING_H
#define _KEYS_SYSTEM_KEYRING_H

#ifdef CONFIG_SYSTEM_TRUSTED_KEYRING

#include <linux/key.h>

extern struct key *system_trusted_keyring;
static inline struct key *get_system_trusted_keyring(void)
{
	return system_trusted_keyring;
}

#ifdef CONFIG_SYSTEM_BLACKLIST_KEYRING
extern struct key *system_blacklist_keyring;
#endif

#else /* CONFIG_SYSTEM_TRUSTED_KEYRING */
static inline struct key *get_system_trusted_keyring(void)
{
	return NULL;
}
#endif /* CONFIG_SYSTEM_TRUSTED_KEYRING */

#endif /* _KEYS_SYSTEM_KEYRING_H */
