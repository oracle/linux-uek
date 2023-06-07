/*
 * uek_abi.h - Oracle kabi abstraction header
 *
 * Copyright (c) 2018, 2023, Oracle and/or its affiliates.
 *
 * This file is released under the GPLv2 license.
 * See the file COPYING for more details.
 */

#ifndef _LINUX_UEK_KABI_H
#define _LINUX_UEK_KABI_H

#include <linux/compiler.h>

/*
 * The UEK_KABI_REPLACE* macros attempt to add the ability to use the '_new'
 * element while preserving size alignment and kabi agreement with the '_orig'
 * element.
 *
 * The #ifdef __GENKSYMS__ preserves the kabi agreement, while the anonymous
 * union structure preserves the size alignment (assuming the '_new' element is
 * not bigger than the '_orig' element).
 *
 * UEK_KABI_REPLACE - simple replacement of _orig with a union of _orig and _new
 * UEK_KABI_DEPRECATE - mark the element as deprecated and make it unusable
 *			by modules while preserving KABI checksums
 *
 * UEK_KABI_EXTEND - simple macro for adding a new element to a struct while
 *		  preserving the kabi agreement (by wrapping with GENKSYMS).
 * UEK_KABI_FILL_HOLE - simple macro for filling a hole in a struct while
 *		     preserving the kabi agreement (by wrapping with GENKSYMS).
 * UEK_KABI_RENAME - simple macro for renaming an element without changing its type
 *		  while preserving thi kabi agreement (by wrapping with GENKSYMS).
 *		  This macro can be used in bitfields, for example.
 *		  NOTE: does not include the final ';'
 * UEK_KABI_REPLACE_UNSAFE - unsafe version of UEK_KABI_REPLACE. Only use for typedefs.
 *
 * NOTE NOTE NOTE
 * Don't use ';' after these macros as it messes up the kabi checker by
 * changing what the resulting token string looks like.
 * Instead let this macro add the ';' so it can be properly hidden from
 * the kabi checker (mainly for UEK_KABI_EXTEND, but applied to all macros for
 * uniformity).
 * NOTE NOTE NOTE
 *
 * UEK_KABI_DEPRECATE_ENUM
 * 	 Mark the element in enum as deprecated and make it unusable by modules while
 *   preserving kABI checksums.
 *
 */
#ifdef __GENKSYMS__

#define _UEK_KABI_REPLACE(_orig, _new)		_orig
#define _UEK_KABI_REPLACE_UNSAFE(_orig, _new)	_orig
#define _UEK_KABI_DEPRECATE(_type, _orig)	_type _orig

#define UEK_KABI_EXTEND(_new)
#define UEK_KABI_FILL_HOLE(_new)
#define UEK_KABI_RENAME(_orig, _new)		_orig

# define _UEK_KABI_DEPRECATE_ENUM(_orig) _orig

#else

#if IS_BUILTIN(CONFIG_UEK_KABI_SIZE_ALIGN_CHECKS)
#define __UEK_KABI_CHECK_SIZE_ALIGN(_orig, _new)						\
	union {											\
		_Static_assert(sizeof(struct{_new;}) <= sizeof(struct{_orig;}),			\
				"kabi sizeof test panic");					\
		_Static_assert(__alignof__(struct{_new;}) <= __alignof__(struct{_orig;}),	\
				"kabi alignof test panic");					\
	}
#else
#define __UEK_KABI_CHECK_SIZE_ALIGN(_orig, _new)
#endif

#define _UEK_KABI_REPLACE(_orig, _new)				\
	union {							\
		_new;						\
		struct {					\
			_orig;					\
		} __UNIQUE_ID(uek_kabi_hide);			\
		__UEK_KABI_CHECK_SIZE_ALIGN(_orig, _new);	\
	}

#define _UEK_KABI_REPLACE_UNSAFE(_orig, _new)	_new

#define _UEK_KABI_DEPRECATE(_type, _orig)	_type uek_reserved_##_orig

#define UEK_KABI_EXTEND(_new)			_new;

/* Warning, only use if a hole exists for _all_ arches. Use pahole to verify */
#define UEK_KABI_FILL_HOLE(_new)		_new;
#define UEK_KABI_RENAME(_orig, _new)		_new

# define _UEK_KABI_DEPRECATE_ENUM(_orig) uek_reserved_##_orig

#endif /* __GENKSYMS__ */

/* colon added wrappers for the UEK_KABI_REPLACE macros */
#define UEK_KABI_REPLACE(_orig, _new)		_UEK_KABI_REPLACE(_orig, _new);
#define UEK_KABI_REPLACE_UNSAFE(_orig, _new)	_UEK_KABI_REPLACE_UNSAFE(_orig, _new);
#define UEK_KABI_DEPRECATE(_type, _orig)	_UEK_KABI_DEPRECATE(_type, _orig);

/*
 * Standardization on Oracle reserved names.  These wrappers leverage
 * those common names making it easier to read and find in the code.
 */
#define _UEK_KABI_RESERVED(n)		unsigned long uek_reserved##n
#define _UEK_KABI_RESERVED_P(n)		void (*uek_reserved##n)(void)
#define UEK_KABI_RESERVED(n)		_UEK_KABI_RESERVED(n);
#define UEK_KABI_RESERVED_P(n)		_UEK_KABI_RESERVED_P(n);

/*
 * Simple wrappers to replace standard Oracle inc reserved elements.
 */
#define UEK_KABI_USE(n, _new)		UEK_KABI_REPLACE(_UEK_KABI_RESERVED(n), _new)
#define UEK_KABI_USE_P(n, _new)		UEK_KABI_REPLACE(_UEK_KABI_RESERVED_P(n), _new)

/*
 * Macros for breaking up a reserved element into two smaller chunks using an
 * anonymous struct inside an anonymous union.
 */
#define UEK_KABI_USE2(n, _new1, _new2) \
	UEK_KABI_REPLACE(_UEK_KABI_RESERVED(n), struct{ _new1; _new2; })
#define UEK_KABI_USE2_P(n, _new1, _new2) \
	UEK_KABI_REPLACE(_UEK_KABI_RESERVED_P(n), struct{ _new1; _new2;})

#define UEK_KABI_DEPRECATE_ENUM(_orig) _UEK_KABI_DEPRECATE_ENUM(_orig),

#endif /* _LINUX_UEK_KABI_H */
