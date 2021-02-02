// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include "util/evsel.h"

void arch_evsel__set_sample_weight(struct evsel *evsel)
{
	perf_evsel__set_sample_bit(evsel, WEIGHT_STRUCT);
}
