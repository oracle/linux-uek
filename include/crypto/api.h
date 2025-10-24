#ifndef _CRYPTO_API_H
#define _CRYPTO_API_H

#include <linux/static_call.h>

#if !defined(CONFIG_CRYPTO_FIPS140_EXTMOD)

#define CRYPTO_API(name) name

/*
 * These are the definitions that get used when no standalone FIPS module
 * is used: we simply forward everything to normal functions and function
 * calls.
 */

#define DECLARE_CRYPTO_API(name, ret_type, args_decl, args_call) \
	ret_type name args_decl;

#define DECLARE_CRYPTO_API0(name, ret_type) \
	ret_type name(void);

#define DECLARE_CRYPTO_API1(name, ret_type, arg0_type, arg0) \
	ret_type name(arg0_type arg0);

#define DECLARE_CRYPTO_API2(name, ret_type, arg0_type, arg0, arg1_type, arg1) \
	ret_type name(arg0_type arg0, arg1_type arg1);

#define DECLARE_CRYPTO_API3(name, ret_type, arg0_type, arg0, arg1_type, arg1, arg2_type, arg2) \
	ret_type name(arg0_type arg0, arg1_type arg1, arg2_type arg2);

#define DECLARE_CRYPTO_API4(name, ret_type, arg0_type, arg0, arg1_type, arg1, arg2_type, arg2, arg3_type, arg3) \
	ret_type name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3);

#define DECLARE_CRYPTO_API5(name, ret_type, arg0_type, arg0, arg1_type, arg1, arg2_type, arg2, arg3_type, arg3, arg4_type, arg4) \
	ret_type name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4);

#define DECLARE_CRYPTO_API6(name, ret_type, arg0_type, arg0, arg1_type, arg1, arg2_type, arg2, arg3_type, arg3, arg4_type, arg4, arg5_type, arg5) \
	ret_type name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, arg5_type arg5);

#define DEFINE_CRYPTO_API(name) \
	EXPORT_SYMBOL_GPL(name)

#define crypto_module_init(fn) module_init(fn)
#define crypto_module_exit(fn) module_exit(fn)

#define crypto_arch_initcall(fn)	arch_initcall(fn)
#define crypto_subsys_initcall(fn)	subsys_initcall(fn)
#define crypto_late_initcall(fn)	late_initcall(fn)

#define CRYPTO_MODULE_DEVICE_TABLE(type, name) MODULE_DEVICE_TABLE(type, name)

#define crypto_module_cpu_feature_match(x, __initfunc) \
	module_cpu_feature_match(x, __initfunc)

#else

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

/* Consolidated version of different DECLARE_CRYPTO_API versions */
#define DECLARE_CRYPTO_API(name, ret_type, args_decl, args_call)	\
	ret_type nonfips_##name args_decl;				\
	DECLARE_STATIC_CALL(crypto_##name##_key, nonfips_##name);	\
	static inline ret_type name args_decl				\
	{								\
		return static_call(crypto_##name##_key) args_call;	\
	}

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

#define DECLARE_CRYPTO_API6(name, ret_type, arg0_type, arg0, arg1_type, arg1, arg2_type, arg2, arg3_type, arg3, arg4_type, arg4, arg5_type, arg5) \
	ret_type nonfips_##name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, arg5_type arg5); \
	DECLARE_STATIC_CALL(crypto_##name##_key, nonfips_##name); \
	static inline ret_type name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, arg5_type arg5) { \
		return static_call(crypto_##name##_key)(arg0, arg1, arg2, arg3, arg4, arg5); \
	}

#define DEFINE_CRYPTO_API(name) \
	DEFINE_STATIC_CALL(crypto_##name##_key, nonfips_##name); \
	EXPORT_STATIC_CALL(crypto_##name##_key)

#define crypto_module_init(fn) module_init(fn)
#define crypto_module_exit(fn) module_exit(fn)

#define crypto_arch_initcall(fn)	arch_initcall(fn)
#define crypto_subsys_initcall(fn)	subsys_initcall(fn)
#define crypto_late_initcall(fn)	late_initcall(fn)

#define CRYPTO_MODULE_DEVICE_TABLE(type, name) MODULE_DEVICE_TABLE(type, name)

#define crypto_module_cpu_feature_match(x, __initfunc) \
	module_cpu_feature_match(x, __initfunc)

#else /* defined(FIPS_MODULE) */

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

/* Consolidated version of different DECLARE_CRYPTO_API versions */
#define DECLARE_CRYPTO_API(name, ret_type, args_decl, args_call)	\
	ret_type fips_##name args_decl;					\
	DECLARE_STATIC_CALL(crypto_##name##_key, fips_##name);		\
	static inline ret_type name args_decl				\
	{								\
		return fips_##name args_call;				\
	}

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

#define DECLARE_CRYPTO_API6(name, ret_type, arg0_type, arg0, arg1_type, arg1, arg2_type, arg2, arg3_type, arg3, arg4_type, arg4, arg5_type, arg5) \
	ret_type fips_##name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, arg5_type arg5); \
	DECLARE_STATIC_CALL(crypto_##name##_key, fips_##name); \
	static inline ret_type name(arg0_type arg0, arg1_type arg1, arg2_type arg2, arg3_type arg3, arg4_type arg4, arg5_type arg5) { \
		return fips_##name(arg0, arg1, arg2, arg3, arg4, arg5); \
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

#define crypto_module_init(fn) \
	static unsigned long __used __section(".fips_initcall") \
		__fips_##fn = (unsigned long) &fn;
#define crypto_module_exit(fn) \
	static unsigned long __used __section(".fips_exitcall") \
		__fips_##fn = (unsigned long) &fn;

#define crypto_arch_initcall(fn)	crypto_module_init(fn)
#define crypto_subsys_initcall(fn)	crypto_module_init(fn)
#define crypto_late_initcall(fn)	crypto_module_init(fn)

/*
 * We don't need to emit device tables or module aliases for the FIPS module,
 * since it will all be loaded at once anyway.
 */
#define CRYPTO_MODULE_DEVICE_TABLE(type, name)

#define crypto_module_cpu_feature_match(x, __initfunc) \
static int __init cpu_feature_match_ ## x ## _init(void)	\
{								\
	if (!cpu_have_feature(cpu_feature(x)))			\
		return -ENODEV;					\
	return __initfunc();					\
}								\
crypto_module_init(cpu_feature_match_ ## x ## _init)

#endif /* defined(FIPS_MODULE) */
#endif /* defined(CONFIG_CRYPTO_FIPS140_EXTMOD) */

#endif /* !_CRYPTO_API_H */
