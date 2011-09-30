/*
 * FILE:	dtrace_match.c
 * DESCRIPTION:	Dynamic Tracing: matching functions
 *
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2010, 2011 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "dtrace.h"

dtrace_hash_t	*dtrace_bymod;
dtrace_hash_t	*dtrace_byfunc;
dtrace_hash_t	*dtrace_byname;

int dtrace_match_priv(const dtrace_probe_t *prp, uint32_t priv, uid_t uid)
{
	if (priv != DTRACE_PRIV_ALL) {
		uint32_t	ppriv =
				prp->dtpr_provider->dtpv_priv.dtpp_flags;
		uint32_t	match = priv & ppriv;

		if ((priv & (DTRACE_PRIV_PROC | DTRACE_PRIV_USER |
		    DTRACE_PRIV_KERNEL)) == 0)
			return 0;

		if (match == 0 && ppriv != 0)
			return 0;

		if (((ppriv & ~match) & DTRACE_PRIV_OWNER) != 0 &&
		    uid != prp->dtpr_provider->dtpv_priv.dtpp_uid)
			return 0;
	}

	return 1;
}

int dtrace_match_probe(const dtrace_probe_t *prp, const dtrace_probekey_t *pkp,
		       uint32_t priv, uid_t uid)
{
	dtrace_provider_t	*pvp = prp->dtpr_provider;
	int			rv;

	if (pvp->dtpv_defunct)
		return 0;

	if ((rv = pkp->dtpk_pmatch(pvp->dtpv_name, pkp->dtpk_prov, 0)) <= 0)
		return rv;

	if ((rv = pkp->dtpk_mmatch(prp->dtpr_mod, pkp->dtpk_mod, 0)) <= 0)
		return rv;

	if ((rv = pkp->dtpk_fmatch(prp->dtpr_func, pkp->dtpk_func, 0)) <= 0)
		return rv;

	if ((rv = pkp->dtpk_nmatch(prp->dtpr_name, pkp->dtpk_name, 0)) <= 0)
		return rv;

	if (dtrace_match_priv(prp, priv, uid) == 0)
		return 0;

        return rv;
}

int dtrace_match_glob(const char *s, const char *p, int depth)
{
	const char	*olds;
	char		s1, c;
	int		gs;

	if (depth > DTRACE_PROBEKEY_MAXDEPTH)
		return -1;

	if (s == NULL)
		s = "";

top:
	olds = s;
	s1 = *s++;

	if (p == NULL)
		return 0;

	if ((c = *p++) == '\0')
		return s1 == '\0';

	switch (c) {
	case '[':
		{
			int	ok = 0, notflag = 0;
			char	lc = '\0';

			if (s1 == '\0')
				return 0;

			if (*p == '!') {
				notflag = 1;
				p++;
			}

			if ((c = *p++) == '\0')
				return 0;

			do {
				if (c == '-' && lc != '\0' && *p != ']') {
					if ((c = *p++) == '\0')
						return 0;
					if (c == '\\' && (c = *p++) == '\0')
						return 0;

					if (notflag) {
						if (s1 < lc || s1 > c)
							ok++;
						else
							return 0;
					} else if (lc <= s1 && s1 <= c)
						ok++;
				} else if (c == '\\' && (c = *p++) == '\0')
					return 0;

				lc = c;

				if (notflag) {
					if (s1 != c)
						ok++;
					else
						return 0;
				} else if (s1 == c)
					ok++;

				if ((c = *p++) == '\0')
					return 0;
			} while (c != ']');

			if (ok)
				goto top;

			return 0;
		}

	case '\\':
		if ((c = *p++) == '\0')
			return 0;

	default:
		if (c != s1)
			return 0;

	case '?':
		if (s1 != '\0')
			goto top;

		return 0;

	case '*':
		while (*p == '*')
			p++;

		if (*p == '\0')
			return 1;

		for (s = olds; *s != '\0'; s++) {
			if ((gs = dtrace_match_glob(s, p, depth + 1)) != 0)
				return gs;
		}

		return 0;
	}
}

int dtrace_match_string(const char *s, const char *p, int depth)
{
	return s != NULL && strcmp(s, p) == 0;
}

int dtrace_match_nul(const char *s, const char *p, int depth)
{
	return 1;
}

int dtrace_match_nonzero(const char *s, const char *p, int depth)
{
	return s != NULL && s[0] != '\0';
}

struct probe_match {
	const dtrace_probekey_t *pkp;
	uint32_t		priv;
	uid_t			uid;
	int			(*matched)(dtrace_probe_t *, void *);
	void			*arg;
	int			nmatched;
};

static int dtrace_match_one(int id, void *p, void *data)
{
	struct probe_match	*pbm	= (struct probe_match *)data;
	dtrace_probe_t		*probe	= (dtrace_probe_t *)p;
	int			rc;

	if (dtrace_match_probe(probe, pbm->pkp, pbm->priv, pbm->uid) <= 0)
		return 0;

	pbm->nmatched++;

	if ((rc = (pbm->matched)(probe, pbm->arg)) != DTRACE_MATCH_NEXT) {
		if (rc == DTRACE_MATCH_FAIL)
			return DTRACE_MATCH_FAIL;
	}

	return 0;
}

int dtrace_match(const dtrace_probekey_t *pkp, uint32_t priv, uid_t uid,
		 int (*matched)(dtrace_probe_t *, void *), void *arg)
{
	dtrace_probe_t	template, *probe;
	dtrace_hash_t	*hash = NULL;
	int		len, rc, best = INT_MAX, nmatched = 0;

	if (pkp->dtpk_id != DTRACE_IDNONE) {
		if ((probe = dtrace_probe_lookup_id(pkp->dtpk_id)) != NULL &&
		    dtrace_match_probe(probe, pkp, priv, uid) > 0) {
			if ((*matched)(probe, arg) == DTRACE_MATCH_FAIL)
				return DTRACE_MATCH_FAIL;

			nmatched++;
		}

		return nmatched;
	}

	template.dtpr_mod = (char *)pkp->dtpk_mod;
	template.dtpr_func = (char *)pkp->dtpk_func;
	template.dtpr_name = (char *)pkp->dtpk_name;

	if (pkp->dtpk_mmatch == &dtrace_match_string &&
	    (len = dtrace_hash_collisions(dtrace_bymod, &template)) < best) {
		best = len;
		hash = dtrace_bymod;
	}

	if (pkp->dtpk_fmatch == &dtrace_match_string &&
	    (len = dtrace_hash_collisions(dtrace_byfunc, &template)) < best) {
		best = len;
		hash = dtrace_byfunc;
	}

	if (pkp->dtpk_nmatch == &dtrace_match_string &&
	    (len = dtrace_hash_collisions(dtrace_byname, &template)) < best) {
		best = len;
		hash = dtrace_byname;
	}

	if (hash == NULL) {
		struct probe_match	pbm;

		pbm.pkp = pkp;
		pbm.priv = priv;
		pbm.uid = uid;
		pbm.matched = matched;
		pbm.arg = arg;
		pbm.nmatched = 0;

		rc = dtrace_probe_for_each(dtrace_match_one, &pbm);
		if (rc == DTRACE_MATCH_FAIL)
			return DTRACE_MATCH_FAIL;

		return pbm.nmatched;
	}

	for (probe = dtrace_hash_lookup(hash, &template); probe != NULL;
	     probe = *(DTRACE_HASHNEXT(hash, probe))) {
		if (dtrace_match_probe(probe, pkp, priv, uid) <= 0)
			continue;

		nmatched++;

		if ((rc = (*matched)(probe, arg)) != DTRACE_MATCH_NEXT) {
			if (rc == DTRACE_MATCH_FAIL)
				return DTRACE_MATCH_FAIL;

			break;
		}
	}

	return nmatched;
}

static dtrace_probekey_f *dtrace_probekey_func(const char *p)
{
	char	c;

	if (p == NULL || *p == '\0')
		return &dtrace_match_nul;

	while ((c = *p++) != '\0') {
		if (c == '[' || c == '?' || c == '*' || c == '\\')
			return &dtrace_match_glob;
	}

	return &dtrace_match_string;
}

void dtrace_probekey(const dtrace_probedesc_t *pdp, dtrace_probekey_t *pkp)
{
	pkp->dtpk_prov = pdp->dtpd_provider;
	pkp->dtpk_pmatch = dtrace_probekey_func(pdp->dtpd_provider);

	pkp->dtpk_mod = pdp->dtpd_mod;
	pkp->dtpk_mmatch = dtrace_probekey_func(pdp->dtpd_mod);

	pkp->dtpk_func = pdp->dtpd_func;
	pkp->dtpk_fmatch = dtrace_probekey_func(pdp->dtpd_func);

	pkp->dtpk_name = pdp->dtpd_name;
	pkp->dtpk_nmatch = dtrace_probekey_func(pdp->dtpd_name);

	pkp->dtpk_id = pdp->dtpd_id;

	if (pkp->dtpk_id == DTRACE_IDNONE &&
	    pkp->dtpk_pmatch == &dtrace_match_nul &&
	    pkp->dtpk_mmatch == &dtrace_match_nul &&
	    pkp->dtpk_fmatch == &dtrace_match_nul &&
	    pkp->dtpk_nmatch == &dtrace_match_nul)
		pkp->dtpk_fmatch = &dtrace_match_nonzero;
}
