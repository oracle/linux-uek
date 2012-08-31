/*******************************************************************************

  Intel(R) 82576 Virtual Function Linux driver
  Copyright(c) 1999 - 2012 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#include <linux/netdevice.h>

#include "igbvf.h"

/*
 * This is the only thing that needs to be changed to adjust the
 * maximum number of ports that the driver can manage.
 */

#define IGBVF_MAX_NIC 7

#define OPTION_UNSET   -1
#define OPTION_DISABLED 0
#define OPTION_ENABLED  1

/*
 * All parameters are treated the same, as an integer array of values.
 * This macro just reduces the need to repeat the same declaration code
 * over and over (plus this helps to avoid typo bugs).
 */

#define IGBVF_PARAM_INIT { [0 ... IGBVF_MAX_NIC] = OPTION_UNSET }
#ifndef module_param_array
/* Module Parameters are always initialized to -1, so that the driver
 * can tell the difference between no user specified value or the
 * user asking for the default value.
 * The true default values are loaded in when igbvf_check_options is called.
 *
 * This is a GCC extension to ANSI C.
 * See the item "Labeled Elements in Initializers" in the section
 * "Extensions to the C Language Family" of the GCC documentation.
 */
#define IGBVF_PARAM(X, desc) \
	static const int __devinitdata X[IGBVF_MAX_NIC+1] = IGBVF_PARAM_INIT; \
	static unsigned int num_##X;				 \
	MODULE_PARM(X, "1-" __MODULE_STRING(IGBVF_MAX_NIC) "i"); \
	MODULE_PARM_DESC(X, desc);
#else
#define IGBVF_PARAM(X, desc)					\
	static int __devinitdata X[IGBVF_MAX_NIC+1]		\
		= IGBVF_PARAM_INIT;				\
	static unsigned int num_##X;				\
	module_param_array_named(X, X, int, &num_##X, 0);	\
	MODULE_PARM_DESC(X, desc);
#endif

/*
 * Interrupt Throttle Rate (interrupts/sec)
 *
 * Valid Range: 100-100000 (0=off, 1=dynamic, 3=dynamic conservative)
 */
IGBVF_PARAM(InterruptThrottleRate, "Interrupt Throttling Rate");
#define DEFAULT_ITR 3
#define MAX_ITR 100000
#define MIN_ITR 100

struct igbvf_option {
	enum { enable_option, range_option, list_option } type;
	const char *name;
	const char *err;
	int def;
	union {
		struct { /* range_option info */
			int min;
			int max;
		} r;
		struct { /* list_option info */
			int nr;
			struct igbvf_opt_list { int i; char *str; } *p;
		} l;
	} arg;
};

static int __devinit igbvf_validate_option(unsigned int *value,
					   const struct igbvf_option *opt,
					   struct igbvf_adapter *adapter)
{
	if (((int)(*value)) == OPTION_UNSET) {
		*value = opt->def;
		return 0;
	}

	switch (opt->type) {
	case enable_option:
		switch (*value) {
		case OPTION_ENABLED:
			e_early_info("%s Enabled\n", opt->name);
			return 0;
		case OPTION_DISABLED:
			e_early_info("%s Disabled\n", opt->name);
			return 0;
		}
		break;
	case range_option:
		if (*value >= opt->arg.r.min && *value <= opt->arg.r.max) {
			e_early_info("%s set to %i\n", opt->name, *value);
			return 0;
		}
		break;
	case list_option: {
		int i;
		struct igbvf_opt_list *ent;

		for (i = 0; i < opt->arg.l.nr; i++) {
			ent = &opt->arg.l.p[i];
			if (*value == ent->i) {
				if (ent->str[0] != '\0')
					e_early_info("%s\n", ent->str);
				return 0;
			}
		}
	}
		break;
	default:
		BUG();
	}

	e_early_info("Invalid %s value specified (%i) %s\n", opt->name, *value,
	       opt->err);
	*value = opt->def;
	return -1;
}

/**
 * igbvf_check_options - Range Checking for Command Line Parameters
 * @adapter: board private structure
 *
 * This routine checks all command line parameters for valid user
 * input.  If an invalid value is given, or if no user specified
 * value exists, a default value is used.  The final value is stored
 * in a variable in the adapter structure.
 **/
void __devinit igbvf_check_options(struct igbvf_adapter *adapter)
{
	int bd = adapter->bd_number;

	if (bd >= IGBVF_MAX_NIC) {
		e_early_notice("Warning: no configuration for board #%i\n", bd);
		e_early_notice("Using defaults for all values\n");
	}

	{ /* Interrupt Throttling Rate */
		const struct igbvf_option opt = {
			.type = range_option,
			.name = "Interrupt Throttling Rate (ints/sec)",
			.err  = "using default of "
				__MODULE_STRING(DEFAULT_ITR),
			.def  = DEFAULT_ITR,
			.arg  = { .r = { .min = MIN_ITR,
					 .max = MAX_ITR } }
		};

		if (num_InterruptThrottleRate > bd) {
			adapter->requested_itr = InterruptThrottleRate[bd];
			switch (adapter->requested_itr) {
			case 0:
				e_early_info("%s turned off\n", opt.name);
				break;
			case 1:
				e_early_info("%s set to dynamic mode\n",
					     opt.name);
				adapter->current_itr = IGBVF_START_ITR;
				break;
			case 3:
				e_early_info("%s set to dynamic conservative mode\n",
					opt.name);
				adapter->current_itr = IGBVF_START_ITR;
				break;
			default:
				igbvf_validate_option(&adapter->requested_itr,
						      &opt, adapter);
				adapter->current_itr = 1000000000 /
						(adapter->requested_itr * 256);
				/* lower two bits used as control */
				adapter->requested_itr &= ~3;
				break;
			}
		} else {
			adapter->requested_itr = opt.def;
			adapter->current_itr = IGBVF_START_ITR;
		}
	}
}
