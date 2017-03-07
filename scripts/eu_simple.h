/*
 * Simplifying wrappers for functions in elfutils.
 *
 * (C) 2014, 2017 Oracle, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LINUX_EU_SIMPLE_H
#define _LINUX_EU_SIMPLE_H

/*
 * Wrap up dwfl_new() complexities.
 */
Dwfl *simple_dwfl_new(const char *file_name, Dwfl_Module **module);

/*
 * The converse of simple_dwfl_new().
 */
void simple_dwfl_free(Dwfl *dwfl);

#endif
