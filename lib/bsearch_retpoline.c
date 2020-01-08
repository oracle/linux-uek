// SPDX-License-Identifier: GPL-2.0-only

/* bsearch() built with inlined retpolines */
#define bsearch bsearch_retpoline
#include "bsearch.c"
