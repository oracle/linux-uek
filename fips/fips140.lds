/* SPDX-License-Identifier: GPL-2.0-only */

SECTIONS {
	.init.data : {
		__fips_initcalls_start = .;
		*(.fips_initcall)
		__fips_initcalls_end = .;
       }
}
