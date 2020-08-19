#include <linux/kernel.h>
#include <linux/errno.h>
#include <crypto/pkcs7.h>

extern const char __initconst *const blacklist_hashes[];

#ifdef CONFIG_INTEGRITY_PLATFORM_KEYRING
#define validate_trust pkcs7_validate_trust
#else
static inline int validate_trust(struct pkcs7_message *pkcs7,
				 struct key *trust_keyring)
{
	return -ENOKEY;
}
#endif
