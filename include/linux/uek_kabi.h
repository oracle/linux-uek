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
 * UEK_KABI_EXTEND_WITH_SIZE
 *  Adds a new element (usually a struct) to a struct and reserves extra
 *  space for the new element.  The provided 'size' is the total space to
 *  be added in longs (i.e. it's 8 * 'size' bytes), including the size of
 *  the added element.  It is automatically checked that the new element
 *  does not overflow the reserved space, now nor in the future. However,
 *  no attempt is done to check the content of the added element (struct)
 *  for kABI conformance - kABI checking inside the added element is
 *  effectively switched off.
 *  For any struct being added by UEK_KABI_EXTEND_WITH_SIZE, it is
 *  recommended its content to be documented as not covered by kABI
 *  guarantee.
 *
 * UEK_KABI_FILL_HOLE - simple macro for filling a hole in a struct while
 *		     preserving the kabi agreement (by wrapping with GENKSYMS).
 * UEK_KABI_RENAME - simple macro for renaming an element without changing its type
 *		  while preserving thi kabi agreement (by wrapping with GENKSYMS).
 *		  This macro can be used in bitfields, for example.
 *		  NOTE: does not include the final ';'
 * UEK_KABI_REPLACE_UNSAFE - unsafe version of UEK_KABI_REPLACE. Only use for typedefs.
 *
 * UEK_KABI_REPLACE_UNSAFE_SIZE
 *   Similar to UEK_KABI_REPLACE_UNSAFE but preserves the size.
 *
 * UEK_KABI_EXCLUDE
 *  !!! WARNING: DANGEROUS, DO NOT USE unless you are aware of all the !!!
 *  !!! implications. This should be used ONLY EXCEPTIONALLY and only  !!!
 *  !!! under specific circumstances. Very likely, this macro does not !!!
 *  !!! do what you expect it to do. Note that any usage of this macro !!!
 *  !!! MUST be paired with a UEK_KABI_FORCE_CHANGE annotation of       !!!
 *  !!! a suitable symbol (or an equivalent safeguard) and the commit  !!!
 *  !!! log MUST explain why the chosen solution is appropriate.       !!!
 *
 *  Exclude the element from checksum generation.  Any such element is
 *  considered not to be part of the kABI whitelist and may be changed at
 *  will.  Note however that it's the responsibility of the developer
 *  changing the element to ensure 3rd party drivers using this element
 *  won't panic, for example by not allowing them to be loaded.  That can
 *  be achieved by changing another, non-whitelisted symbol they use,
 *  either by nature of the change or by using UEK_KABI_FORCE_CHANGE.
 *
 *  Also note that any change to the element must preserve its size. Change
 *  of the size is not allowed and would constitute a silent kABI breakage.
 *  Beware that the UEK_KABI_EXCLUDE macro does not do any size checks.
 *
 * UEK_KABI_EXCLUDE_WITH_SIZE
 *  Like UEK_KABI_EXCLUDE, this macro excludes the element from
 *  checksum generation.  The same warnings as for UEK_KABI_EXCLUDE
 *  apply: use UEK_KABI_FORCE_CHANGE.
 *
 *  This macro is intended to be used for elements embedded inside
 *  kABI-protected structures (struct, array). In contrast with
 *  UEK_KABI_EXCLUDE, this macro reserves extra space, so that the
 *  embedded element can grow without changing the offsets of the
 *  fields that follow. The provided 'size' is the total space to be
 *  added in longs (i.e. it's 8 * 'size' bytes), including the size
 *  of the added element.  It is automatically checked that the new
 *  element does not overflow the reserved space, now nor in the
 *  future. The size is also included in the checksum via the
 *  reserved space, to ensure that we don't accidentally change it,
 *  which would change the offsets of the fields that follow.
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
# define _UEK_KABI_REPLACE_UNSAFE_SIZE(_orig, _new, _size)      _orig
#define _UEK_KABI_DEPRECATE(_type, _orig)	_type _orig

#define UEK_KABI_EXTEND(_new)
#define UEK_KABI_FILL_HOLE(_new)
#define UEK_KABI_RENAME(_orig, _new)		_orig

# define _UEK_KABI_DEPRECATE_ENUM(_orig) _orig

# define __UEK_KABI_CHECK_SIZE(_item, _size)

#else

# define UEK_KABI_ALIGN_WARNING ".  Disable CONFIG_UEK_KABI_SIZE_ALIGN_CHECKS if debugging."

#if IS_BUILTIN(CONFIG_UEK_KABI_SIZE_ALIGN_CHECKS)
# define __UEK_KABI_CHECK_SIZE_ALIGN(_orig, _new)			\
	union {								\
		_Static_assert(sizeof(struct{_new; }) <= sizeof(struct{_orig; }), \
			       __FILE__ ":" __stringify(__LINE__) ": "  __stringify(_new) " is larger than " __stringify(_orig) UEK_KABI_ALIGN_WARNING); \
		_Static_assert(__alignof__(struct{_new; }) <= __alignof__(struct{_orig; }), \
			       __FILE__ ":" __stringify(__LINE__) ": "  __stringify(_orig) " is not aligned the same as " __stringify(_new) UEK_KABI_ALIGN_WARNING); \
	}
# define __UEK_KABI_CHECK_SIZE(_item, _size)				\
	_Static_assert(sizeof(struct{_item; }) <= _size,		\
		       __FILE__ ":" __stringify(__LINE__) ": " __stringify(_item) " is larger than the reserved size (" __stringify(_size) " bytes)" UEK_KABI_ALIGN_WARNING);
#else
# define __UEK_KABI_CHECK_SIZE_ALIGN(_orig, _new)
# define __UEK_KABI_CHECK_SIZE(_item, _size)
#endif

# define UEK_KABI_UNIQUE_ID			__PASTE(uek_kabi_hidden, \
							__LINE__)

#define _UEK_KABI_REPLACE(_orig, _new)				\
	union {							\
		_new;						\
		struct {					\
			_orig;					\
		} __UNIQUE_ID(uek_kabi_hide);			\
		__UEK_KABI_CHECK_SIZE_ALIGN(_orig, _new);	\
	}

#define _UEK_KABI_REPLACE_UNSAFE(_orig, _new)	_new
# define _UEK_KABI_REPLACE_UNSAFE_SIZE(_orig, _new, _size)	\
	union {							\
		_new;						\
		struct {					\
			_orig;					\
		} UEK_KABI_UNIQUE_ID;				\
		__UEK_KABI_CHECK_SIZE(_new, 8 * (_size))	\
	};

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
# define UEK_KABI_REPLACE_UNSAFE_SIZE(_orig, _new, _size)	\
	_UEK_KABI_REPLACE_UNSAFE_SIZE(_orig, _new, _size);
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

#define UEK_KABI_EXCLUDE(_elem)		_UEK_KABI_EXCLUDE(_elem);

#define UEK_KABI_EXCLUDE_WITH_SIZE(_new, _size)				\
	union {								\
		UEK_KABI_EXCLUDE(_new)					\
		unsigned long UEK_KABI_UNIQUE_ID[_size];		\
		__UEK_KABI_CHECK_SIZE(_new, 8 * (_size))		\
	};

#define UEK_KABI_EXTEND_WITH_SIZE(_new, _size)				\
	UEK_KABI_EXTEND(union {						\
		_new;							\
		unsigned long UEK_KABI_UNIQUE_ID[_size];		\
		__UEK_KABI_CHECK_SIZE(_new, 8 * (_size))		\
	})
#endif /* _LINUX_UEK_KABI_H */
