#ifndef _CRYPTO_API_H
#define _CRYPTO_API_H

#include <linux/static_call.h>

struct crypto_api_key {
	struct static_call_key *key;
	void *tramp;
	void *func;
};

#ifndef FIPS_MODULE

/*
 * These are the definitions that get used for vmlinux and in-tree
 * kernel modules.
 *
 * In this case, all references to the kernel crypto API functions will
 * be replaced by wrappers that perform a call using the kernel's static_call
 * functionality.
 */

#define CRYPTO_API(name) nonfips_##name

#define DECLARE_CRYPTO_API0(name, ret_type) \
	ret_type nonfips_##name(void); \
	DECLARE_STATIC_CALL(crypto_##name##_key, nonfips_##name); \
	static inline ret_type name(void) { \
		return static_call(crypto_##name##_key)(); \
	}

#define DECLARE_CRYPTO_API1(name, ret_type, arg0_type, arg0) \
	ret_type nonfips_##name(arg0_type arg0); \
	DECLARE_STATIC_CALL(crypto_##name##_key, nonfips_##name); \
	static inline ret_type name(arg0_type arg0) { \
		return static_call(crypto_##name##_key)(arg0); \
	}

#define DECLARE_CRYPTO_API2(name, ret_type, arg0_type, arg0, arg1_type, arg1) \
	ret_type nonfips_##name(arg0_type arg0, arg1_type arg1); \
	DECLARE_STATIC_CALL(crypto_##name##_key, nonfips_##name); \
	static inline ret_type name(arg0_type arg0, arg1_type arg1) { \
		return static_call(crypto_##name##_key)(arg0, arg1); \
	}

#define DECLARE_CRYPTO_API3(name, ret_type, arg0_type, arg0, arg1_type, arg1, arg2_type, arg2) \
	ret_type nonfips_##name(arg0_type arg0, arg1_type arg1, arg2_type arg2); \
	DECLARE_STATIC_CALL(crypto_##name##_key, nonfips_##name); \
	static inline ret_type name(arg0_type arg0, arg1_type arg1, arg2_type arg2) { \
		return static_call(crypto_##name##_key)(arg0, arg1, arg2); \
	}

#define DECLARE_CRYPTO_API4(name, ret_type, arg0_type, arg0, arg1_type, arg1, arg2_type, arg2, arg3_type, arg3) \
	ret_type nonfips_##name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3); \
	DECLARE_STATIC_CALL(crypto_##name##_key, nonfips_##name); \
	static inline ret_type name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3) { \
		return static_call(crypto_##name##_key)(arg0, arg1, arg2, arg3); \
	}

#define DECLARE_CRYPTO_API5(name, ret_type, arg0_type, arg0, arg1_type, arg1, arg2_type, arg2, arg3_type, arg3, arg4_type, arg4) \
	ret_type nonfips_##name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4); \
	DECLARE_STATIC_CALL(crypto_##name##_key, nonfips_##name); \
	static inline ret_type name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4) { \
		return static_call(crypto_##name##_key)(arg0, arg1, arg2, arg3, arg4); \
	}

#define DEFINE_CRYPTO_API(name) \
	DEFINE_STATIC_CALL(crypto_##name##_key, nonfips_##name); \
	EXPORT_STATIC_CALL(crypto_##name##_key)

#else

/*
 * These are the definitions that get used for the FIPS module and
 * its kernel modules.
 *
 * In this case, all crypto API functions resolve directly to their
 * implementations, since they are all part of the FIPS module.
 *
 * We still need to declare the static call keys so we can update
 * them when the FIPS modules have all been loaded.
 */

#define CRYPTO_API(name) fips_##name

#define DECLARE_CRYPTO_API0(name, ret_type) \
	ret_type fips_##name(void); \
	DECLARE_STATIC_CALL(crypto_##name##_key, fips_##name); \
	static inline ret_type name(void) { \
		return fips_##name(); \
	}

#define DECLARE_CRYPTO_API1(name, ret_type, arg0_type, arg0) \
	ret_type fips_##name(arg0_type arg0); \
	DECLARE_STATIC_CALL(crypto_##name##_key, fips_##name); \
	static inline ret_type name(arg0_type arg0) { \
		return fips_##name(arg0); \
	}

#define DECLARE_CRYPTO_API2(name, ret_type, arg0_type, arg0, arg1_type, arg1) \
	ret_type fips_##name(arg0_type arg0, arg1_type arg1); \
	DECLARE_STATIC_CALL(crypto_##name##_key, fips_##name); \
	static inline ret_type name(arg0_type arg0, arg1_type arg1) { \
		return fips_##name(arg0, arg1); \
	}

#define DECLARE_CRYPTO_API3(name, ret_type, arg0_type, arg0, arg1_type, arg1, arg2_type, arg2) \
	ret_type fips_##name(arg0_type arg0, arg1_type arg1, arg2_type arg2); \
	DECLARE_STATIC_CALL(crypto_##name##_key, fips_##name); \
	static inline ret_type name(arg0_type arg0, arg1_type arg1, arg2_type arg2) { \
		return fips_##name(arg0, arg1, arg2); \
	}

#define DECLARE_CRYPTO_API4(name, ret_type, arg0_type, arg0, arg1_type, arg1, arg2_type, arg2, arg3_type, arg3) \
	ret_type fips_##name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3); \
	DECLARE_STATIC_CALL(crypto_##name##_key, fips_##name); \
	static inline ret_type name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3) { \
		return fips_##name(arg0, arg1, arg2, arg3); \
	}

#define DECLARE_CRYPTO_API5(name, ret_type, arg0_type, arg0, arg1_type, arg1, arg2_type, arg2, arg3_type, arg3, arg4_type, arg4) \
	ret_type fips_##name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4); \
	DECLARE_STATIC_CALL(crypto_##name##_key, fips_##name); \
	static inline ret_type name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4) { \
		return fips_##name(arg0, arg1, arg2, arg3, arg4); \
	}

/*
 * Create an entry for the static call key so we can initialize it
 * in the FIPS module.
 */
// TODO: make this const initdata, probably
#define DEFINE_CRYPTO_API(name) \
	EXPORT_SYMBOL_GPL(fips_##name); \
	static struct crypto_api_key __##name##_key \
		__used \
		__section("__crypto_api_keys") \
		__aligned(__alignof__(struct crypto_api_key)) = \
	{ \
		.key = &STATIC_CALL_KEY(crypto_##name##_key), \
		.tramp = STATIC_CALL_TRAMP_ADDR(crypto_##name##_key), \
		.func = &fips_##name, \
	};

#endif

#endif
