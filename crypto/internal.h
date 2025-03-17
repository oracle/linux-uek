/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Cryptographic API.
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2005 Herbert Xu <herbert@gondor.apana.org.au>
 */
#ifndef _CRYPTO_INTERNAL_H
#define _CRYPTO_INTERNAL_H

#include <crypto/algapi.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/jump_label.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/numa.h>
#include <linux/refcount.h>
#include <linux/rwsem.h>
#include <linux/scatterlist.h>
#include <linux/sched.h>
#include <linux/types.h>

struct akcipher_request;
struct crypto_akcipher;
struct crypto_instance;
struct crypto_template;

struct crypto_larval {
	struct crypto_alg alg;
	struct crypto_alg *adult;
	struct completion completion;
	u32 mask;
	bool test_started;
};

struct crypto_akcipher_sync_data {
	struct crypto_akcipher *tfm;
	const void *src;
	void *dst;
	unsigned int slen;
	unsigned int dlen;

	struct akcipher_request *req;
	struct crypto_wait cwait;
	struct scatterlist sg;
	u8 *buf;
};

enum {
	CRYPTOA_UNSPEC,
	CRYPTOA_ALG,
	CRYPTOA_TYPE,
	__CRYPTOA_MAX,
};

#define CRYPTOA_MAX (__CRYPTOA_MAX - 1)

/* Maximum number of (rtattr) parameters for each template. */
#define CRYPTO_MAX_ATTRS 32

#ifndef FIPS_MODULE
#define crypto_alg_list nonfips_crypto_alg_list
#define crypto_alg_sem nonfips_crypto_alg_sem
#define crypto_chain nonfips_crypto_chain
#else
#define crypto_alg_list fips_crypto_alg_list
#define crypto_alg_sem fips_crypto_alg_sem
#define crypto_chain fips_crypto_chain
#endif

extern struct list_head crypto_alg_list;
extern struct rw_semaphore crypto_alg_sem;
extern struct blocking_notifier_head crypto_chain;

int alg_test(struct crypto_alg *alg, const char *driver, const char *alg, u32 type, u32 mask);

#if !IS_BUILTIN(CONFIG_CRYPTO_ALGAPI) || \
    IS_ENABLED(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
static inline bool crypto_boot_test_finished(void)
{
	return true;
}
static inline void set_crypto_boot_test_finished(void)
{
}
#else
DECLARE_STATIC_KEY_FALSE(__crypto_boot_test_finished);
static inline bool crypto_boot_test_finished(void)
{
	return static_branch_likely(&__crypto_boot_test_finished);
}
static inline void set_crypto_boot_test_finished(void)
{
	static_branch_enable(&__crypto_boot_test_finished);
}
#endif /* !IS_BUILTIN(CONFIG_CRYPTO_ALGAPI) ||
	* IS_ENABLED(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
	*/

#ifdef CONFIG_PROC_FS
void __init crypto_init_proc(void);
void __exit crypto_exit_proc(void);
#else
static inline void crypto_init_proc(void)
{ }
static inline void crypto_exit_proc(void)
{ }
#endif

static inline unsigned int crypto_cipher_ctxsize(struct crypto_alg *alg)
{
	return alg->cra_ctxsize;
}

static inline unsigned int crypto_compress_ctxsize(struct crypto_alg *alg)
{
	return alg->cra_ctxsize;
}

DECLARE_CRYPTO_API1(crypto_mod_get, struct crypto_alg *, struct crypto_alg *, alg);
DECLARE_CRYPTO_API3(crypto_alg_mod_lookup, struct crypto_alg *, const char *, name, u32, type, u32, mask);

DECLARE_CRYPTO_API3(crypto_larval_alloc, struct crypto_larval *, const char *, name, u32, type, u32, mask);
DECLARE_CRYPTO_API1(crypto_schedule_test, void, struct crypto_larval *, larval);
DECLARE_CRYPTO_API2(crypto_alg_tested, void, struct crypto_alg *, alg, int, err);

void crypto_remove_spawns(struct crypto_alg *alg, struct list_head *list,
			  struct crypto_alg *nalg);
void crypto_remove_final(struct list_head *list);
DECLARE_CRYPTO_API1(crypto_shoot_alg, void, struct crypto_alg *, alg);
DECLARE_CRYPTO_API4(__crypto_alloc_tfmgfp, struct crypto_tfm *, struct crypto_alg *, alg, u32, type, u32, mask, gfp_t, gfp);
DECLARE_CRYPTO_API3(__crypto_alloc_tfm, struct crypto_tfm *, struct crypto_alg *, alg, u32, type, u32, mask);
DECLARE_CRYPTO_API3(crypto_create_tfm_node, void *, struct crypto_alg *, alg, const struct crypto_type *, frontend, int, node);
DECLARE_CRYPTO_API2(crypto_clone_tfm, void *, const struct crypto_type *, frontend, struct crypto_tfm *, otfm);

int crypto_akcipher_sync_prep(struct crypto_akcipher_sync_data *data);
int crypto_akcipher_sync_post(struct crypto_akcipher_sync_data *data, int err);
int crypto_init_akcipher_ops_sig(struct crypto_tfm *tfm);

static inline void *crypto_create_tfm(struct crypto_alg *alg,
			const struct crypto_type *frontend)
{
	return crypto_create_tfm_node(alg, frontend, NUMA_NO_NODE);
}

DECLARE_CRYPTO_API4(crypto_find_alg, struct crypto_alg *, const char *, alg_name, const struct crypto_type *, frontend, u32, type, u32, mask);

DECLARE_CRYPTO_API5(crypto_alloc_tfm_node, void *, const char *, alg_name, const struct crypto_type *, frontend, u32, type, u32, mask, int, node);

static inline void *crypto_alloc_tfm(const char *alg_name,
		       const struct crypto_type *frontend, u32 type, u32 mask)
{
	return crypto_alloc_tfm_node(alg_name, frontend, type, mask, NUMA_NO_NODE);
}

DECLARE_CRYPTO_API2(crypto_probing_notify, int, unsigned long, val, void *, v);

unsigned int crypto_alg_extsize(struct crypto_alg *alg);

int crypto_type_has_alg(const char *name, const struct crypto_type *frontend,
			u32 type, u32 mask);

static inline struct crypto_alg *crypto_alg_get(struct crypto_alg *alg)
{
	refcount_inc(&alg->cra_refcnt);
	return alg;
}

static inline void crypto_alg_put(struct crypto_alg *alg)
{
	if (refcount_dec_and_test(&alg->cra_refcnt) && alg->cra_destroy)
		alg->cra_destroy(alg);
}

static inline int crypto_tmpl_get(struct crypto_template *tmpl)
{
	return try_module_get(tmpl->module);
}

static inline void crypto_tmpl_put(struct crypto_template *tmpl)
{
	module_put(tmpl->module);
}

static inline int crypto_is_larval(struct crypto_alg *alg)
{
	return alg->cra_flags & CRYPTO_ALG_LARVAL;
}

static inline int crypto_is_dead(struct crypto_alg *alg)
{
	return alg->cra_flags & CRYPTO_ALG_DEAD;
}

static inline int crypto_is_moribund(struct crypto_alg *alg)
{
	return alg->cra_flags & (CRYPTO_ALG_DEAD | CRYPTO_ALG_DYING);
}

static inline void crypto_notify(unsigned long val, void *v)
{
	blocking_notifier_call_chain(&crypto_chain, val, v);
}

static inline void crypto_yield(u32 flags)
{
	if (flags & CRYPTO_TFM_REQ_MAY_SLEEP)
		cond_resched();
}

static inline int crypto_is_test_larval(struct crypto_larval *larval)
{
	return larval->alg.cra_driver_name[0];
}

static inline struct crypto_tfm *crypto_tfm_get(struct crypto_tfm *tfm)
{
	return refcount_inc_not_zero(&tfm->refcnt) ? tfm : ERR_PTR(-EOVERFLOW);
}

#endif	/* _CRYPTO_INTERNAL_H */

