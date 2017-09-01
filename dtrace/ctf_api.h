/*
 * Compact C Type format
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __CTF_API_H_
#define __CTF_API_H_

/*
 * The CTF data model is inferred to be the caller's data model or the data
 * model of the given object, unless ctf_setmodel() is explicitly called.
 */
#define CTF_MODEL_ILP32		1	/* object data model is ILP32 */
#define CTF_MODEL_LP64		2	/* object data model is LP64 */
#ifdef CONFIG_64BIT
# define CTF_MODEL_NATIVE	CTF_MODEL_LP64
#else
# define CTF_MODEL_NATIVE	CTF_MODEL_ILP32
#endif

#endif /* __CTF_API_H_ */
