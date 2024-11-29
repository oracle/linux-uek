/* SPDX-License-Identifier: GPL-2.0 */
/*
 * uek_kabi.h - kABI abstraction header
 *
 * Copyright (c) 2021, 2023, Oracle and/or its affiliates.
 * Copyright (c) 2014 Don Zickus
 * Copyright (c) 2015-2018 Jiri Benc
 * Copyright (c) 2015 Sabrina Dubroca, Hannes Frederic Sowa
 * Copyright (c) 2016-2018 Prarit Bhargava
 * Copyright (c) 2017 Paolo Abeni, Larry Woodman
 *
 * This file is released under the GPLv2.
 * See the file COPYING for more details.
 *
 * These kabi macros hide the changes from the kabi checker and from the
 * process that computes the exported symbols' checksums.
 * They have 2 variants: one (defined under __GENKSYMS__) used when
 * generating the checksums, and the other used when building the kernel's
 * binaries.
 *
 */

#ifndef _LINUX_UEK_KABI_H
#define _LINUX_UEK_KABI_H

#include <linux/compiler.h>
#include <linux/kconfig.h>
#include <linux/stringify.h>

/*
 * UEK_KABI_CONST
 *   Adds a new const modifier to a function parameter preserving the old
 *   checksum.
 *
 * UEK_KABI_DEPRECATE
 *   Mark the element as deprecated and make it unusable by modules while
 *   preserving kABI checksums.
 *
 * UEK_KABI_DEPRECATE_FN
 *   Mark the function pointer as deprecated and make it unusable by modules
 *   while preserving kABI checksums.
 *
 * UEK_KABI_EXTEND
 *   Simple macro for adding a new element to a struct.
 *
 * UEK_KABI_EXTEND_WITH_SIZE
 *   Adds a new element (usually a struct) to a struct and reserves extra
 *   space for the new element.  The provided 'size' is the total space to
 *   be added in longs (i.e. it's 8 * 'size' bytes), including the size of
 *   the added element.  It is automatically checked that the new element
 *   does not overflow the reserved space, now nor in the future. However,
 *   no attempt is done to check the content of the added element (struct)
 *   for kABI conformance - kABI checking inside the added element is
 *   effectively switched off.
 *   For any struct being added by UEK_KABI_EXTEND_WITH_SIZE, it is
 *   recommended its content to be documented as not covered by kABI
 *   guarantee.
 *
 * UEK_KABI_FILL_HOLE
 *   Simple macro for filling a hole in a struct.
 *
 * UEK_KABI_RENAME
 *   Simple macro for renaming an element without changing its type.  This
 *   macro can be used in bitfields, for example.
 *
 *   NOTE: does not include the final ';'
 *
 * UEK_KABI_REPLACE
 *   Simple replacement of _orig with a union of _orig and _new.
 *
 *   The UEK_KABI_REPLACE* macros attempt to add the ability to use the '_new'
 *   element while preserving size alignment with the '_orig' element.
 *
 *   The #ifdef __GENKSYMS__ preserves the kABI agreement, while the anonymous
 *   union structure preserves the size alignment (assuming the '_new' element
 *   is not bigger than the '_orig' element).
 *
 * UEK_KABI_REPLACE_UNSAFE
 *   Unsafe version of UEK_KABI_REPLACE.  Only use for typedefs.
 *
 * UEK_KABI_REPLACE_UNSAFE_SIZE
 *   Similar to UEK_KABI_REPLACE_UNSAFE but preserves the size.
 *
 * UEK_KABI_FORCE_CHANGE
 *   Force change of the symbol checksum.  The argument of the macro is a
 *   version for cases we need to do this more than once.
 *
 *   This macro does the opposite: it changes the symbol checksum without
 *   actually changing anything about the exported symbol.  It is useful for
 *   symbols that are not whitelisted, we're changing them in an
 *   incompatible way and want to prevent 3rd party modules to silently
 *   corrupt memory.  Instead, by changing the symbol checksum, such modules
 *   won't be loaded by the kernel.  This macro should only be used as a
 *   last resort when all other KABI workarounds have failed.
 *
 * UEK_KABI_EXCLUDE
 *   !!! WARNING: DANGEROUS, DO NOT USE unless you are aware of all the !!!
 *   !!! implications. This should be used ONLY EXCEPTIONALLY and only  !!!
 *   !!! under specific circumstances. Very likely, this macro does not !!!
 *   !!! do what you expect it to do. Note that any usage of this macro !!!
 *   !!! MUST be paired with a UEK_KABI_FORCE_CHANGE annotation of       !!!
 *   !!! a suitable symbol (or an equivalent safeguard) and the commit  !!!
 *   !!! log MUST explain why the chosen solution is appropriate.       !!!
 *
 *   Exclude the element from checksum generation.  Any such element is
 *   considered not to be part of the kABI whitelist and may be changed at
 *   will.  Note however that it's the responsibility of the developer
 *   changing the element to ensure 3rd party drivers using this element
 *   won't panic, for example by not allowing them to be loaded.  That can
 *   be achieved by changing another, non-whitelisted symbol they use,
 *   either by nature of the change or by using UEK_KABI_FORCE_CHANGE.
 *
 *   Also note that any change to the element must preserve its size. Change
 *   of the size is not allowed and would constitute a silent kABI breakage.
 *   Beware that the UEK_KABI_EXCLUDE macro does not do any size checks.
 *
 * UEK_KABI_EXCLUDE_WITH_SIZE
 *   Like UEK_KABI_EXCLUDE, this macro excludes the element from
 *   checksum generation.  The same warnings as for UEK_KABI_EXCLUDE
 *   apply: use UEK_KABI_FORCE_CHANGE.
 *
 *   This macro is intended to be used for elements embedded inside
 *   kABI-protected structures (struct, array). In contrast with
 *   UEK_KABI_EXCLUDE, this macro reserves extra space, so that the
 *   embedded element can grow without changing the offsets of the
 *   fields that follow. The provided 'size' is the total space to be
 *   added in longs (i.e. it's 8 * 'size' bytes), including the size
 *   of the added element.  It is automatically checked that the new
 *   element does not overflow the reserved space, now nor in the
 *   future. The size is also included in the checksum via the
 *   reserved space, to ensure that we don't accidentally change it,
 *   which would change the offsets of the fields that follow.
 *
 *  UEK_KABI_HIDE_INCLUDE
 *   Hides the given include file from kABI checksum computations.  This is
 *   used when a newly added #include makes a previously opaque struct
 *   visible.
 *
 *   Example usage:
 *   #include UEK_KABI_HIDE_INCLUDE(<linux/poll.h>)
 *
 * UEK_KABI_FAKE_INCLUDE
 *   Pretends inclusion of the given file for kABI checksum computations.
 *   This is used when upstream removed a particular #include but that made
 *   some structures opaque that were previously visible and is causing kABI
 *   checker failures.
 *
 *   Example usage:
 *   #include UEK_KABI_FAKE_INCLUDE(<linux/rhashtable.h>)
 *
 * NOTE
 *   Don't use ';' after these macros as it messes up the kABI checker by
 *   changing what the resulting token string looks like.  Instead let this
 *   macro add the ';' so it can be properly hidden from the kABI checker
 *   (mainly for UEK_KABI_EXTEND, but applied to all macros for uniformity).
 *
 * UEK_KABI_DEPRECATE_ENUM
 *   Mark the element in enum as deprecated and make it unusable by
 *   modules while preserving kABI checksums.
 *
 */
#ifdef __GENKSYMS__

# define UEK_KABI_CONST
# define UEK_KABI_EXTEND(_new)
# define UEK_KABI_FILL_HOLE(_new)
# define UEK_KABI_FORCE_CHANGE(ver)		__attribute__((uek_kabi_change ## ver))
# define UEK_KABI_RENAME(_orig, _new)		_orig

# define _UEK_KABI_DEPRECATE(_type, _orig)	_type _orig
# define _UEK_KABI_DEPRECATE_FN(_type, _orig, _args...)	_type (*_orig)(_args)
# define _UEK_KABI_REPLACE(_orig, _new)		_orig
# define _UEK_KABI_REPLACE_UNSAFE(_orig, _new)	_orig
# define _UEK_KABI_REPLACE_UNSAFE_SIZE(_orig, _new, _size)	_orig
# define _UEK_KABI_EXCLUDE(_elem)
# define _UEK_KABI_DEPRECATE_ENUM(_orig)	_orig
# define UEK_KABI_HIDE_INCLUDE(_file)		<linux/uek_kabi.h>
# define UEK_KABI_FAKE_INCLUDE(_file)		_file

# define __UEK_KABI_CHECK_SIZE(_item, _size)

#else

# define UEK_KABI_ALIGN_WARNING ".  Disable CONFIG_UEK_KABI_SIZE_ALIGN_CHECKS if debugging."

# define UEK_KABI_CONST				const
# define UEK_KABI_EXTEND(_new)			_new;
# define UEK_KABI_FILL_HOLE(_new)		_new;
# define UEK_KABI_FORCE_CHANGE(ver)
# define UEK_KABI_RENAME(_orig, _new)		_new
# define UEK_KABI_HIDE_INCLUDE(_file)		_file
# define UEK_KABI_FAKE_INCLUDE(_file)		<linux/uek_kabi.h>

#if IS_BUILTIN(CONFIG_UEK_KABI_SIZE_ALIGN_CHECKS)
# define __UEK_KABI_CHECK_SIZE_ALIGN(_orig, _new)			\
	union {								\
		_Static_assert(sizeof(struct{_new;}) <= sizeof(struct{_orig;}), \
			       __FILE__ ":" __stringify(__LINE__) ": "  __stringify(_new) " is larger than " __stringify(_orig) UEK_KABI_ALIGN_WARNING); \
		_Static_assert(__alignof__(struct{_new;}) <= __alignof__(struct{_orig;}), \
			       __FILE__ ":" __stringify(__LINE__) ": "  __stringify(_orig) " is not aligned the same as " __stringify(_new) UEK_KABI_ALIGN_WARNING); \
	}
# define __UEK_KABI_CHECK_SIZE(_item, _size)				\
	_Static_assert(sizeof(struct{_item;}) <= _size,			\
		       __FILE__ ":" __stringify(__LINE__) ": " __stringify(_item) " is larger than the reserved size (" __stringify(_size) " bytes)" UEK_KABI_ALIGN_WARNING);
#else
# define __UEK_KABI_CHECK_SIZE_ALIGN(_orig, _new)
# define __UEK_KABI_CHECK_SIZE(_item, _size)
#endif

# define UEK_KABI_UNIQUE_ID			__PASTE(uek_kabi_hidden, \
							__LINE__)
# define _UEK_KABI_DEPRECATE(_type, _orig)	_type uek_reserved_##_orig
# define _UEK_KABI_DEPRECATE_FN(_type, _orig, _args...)  \
	_type (* uek_reserved_##_orig)(_args)
# define _UEK_KABI_REPLACE(_orig, _new)			  \
	union {						  \
		_new;					  \
		struct {				  \
			_orig;				  \
		} UEK_KABI_UNIQUE_ID;			  \
		__UEK_KABI_CHECK_SIZE_ALIGN(_orig, _new);  \
	}
# define _UEK_KABI_REPLACE_UNSAFE(_orig, _new)	_new
# define _UEK_KABI_REPLACE_UNSAFE_SIZE(_orig, _new, _size) \
	union {						\
		_new;					  \
		struct {				  \
			_orig;				  \
		} UEK_KABI_UNIQUE_ID;			  \
		__UEK_KABI_CHECK_SIZE(_new, 8 * (_size))	\
	};


# define _UEK_KABI_EXCLUDE(_elem)		_elem

# define _UEK_KABI_DEPRECATE_ENUM(_orig) uek_reserved_##_orig

#endif /* __GENKSYMS__ */

/* semicolon added wrappers for the UEK_KABI_REPLACE macros */
# define UEK_KABI_DEPRECATE(_type, _orig)	_UEK_KABI_DEPRECATE(_type, _orig);
# define UEK_KABI_DEPRECATE_FN(_type, _orig, _args...)  \
	_UEK_KABI_DEPRECATE_FN(_type, _orig, _args);
# define UEK_KABI_REPLACE(_orig, _new)		_UEK_KABI_REPLACE(_orig, _new);
# define UEK_KABI_REPLACE_UNSAFE(_orig, _new)	_UEK_KABI_REPLACE_UNSAFE(_orig, _new);
# define UEK_KABI_REPLACE_UNSAFE_SIZE(_orig, _new, _size)	_UEK_KABI_REPLACE_UNSAFE_SIZE(_orig, _new, _size);

/*
 * Macro for breaking up a random element into two smaller chunks using an
 * anonymous struct inside an anonymous union.
 */
# define UEK_KABI_REPLACE2(orig, _new1, _new2)	UEK_KABI_REPLACE(orig, struct{ _new1; _new2;})

# define UEK_KABI_RESERVE(n)		_UEK_KABI_RESERVE(n);
/*
 * Simple wrappers to replace standard reserved elements.
 */
# define UEK_KABI_USE(n, _new)		UEK_KABI_REPLACE(_UEK_KABI_RESERVE(n), _new)
/*
 * Macros for breaking up a reserved element into two smaller chunks using
 * an anonymous struct inside an anonymous union.
 */
# define UEK_KABI_USE2(n, _new1, _new2)	UEK_KABI_REPLACE(_UEK_KABI_RESERVE(n), struct{ _new1; _new2; })

/*
 * We tried to standardize on reserved names.  These wrappers
 * leverage those common names making it easier to read and find in the
 * code.
 */
# define _UEK_KABI_RESERVE(n)		unsigned long uek_reserved##n

#define UEK_KABI_EXCLUDE(_elem)		_UEK_KABI_EXCLUDE(_elem);

#define UEK_KABI_EXCLUDE_WITH_SIZE(_new, _size)				\
	union {								\
		UEK_KABI_EXCLUDE(_new)					\
		unsigned long UEK_KABI_UNIQUE_ID[_size];			\
		__UEK_KABI_CHECK_SIZE(_new, 8 * (_size))			\
	};

#define UEK_KABI_DEPRECATE_ENUM(_orig) _UEK_KABI_DEPRECATE_ENUM(_orig),

/*
 * Macros to extend structs.
 *
 * base struct: The struct being extended.  For example, pci_dev.
 * extended struct: The struct being added to the base struct.
 *		    For example, pci_dev_uek.
 *
 * These macros should be used to extend structs before KABI freeze.
 * They can be used post-KABI freeze in the limited case of the base
 * struct not being embedded in another struct.
 *
 * Extended structs cannot be shrunk in size as changes will break
 * the size & offset comparison.
 *
 * Extended struct elements are not guaranteed for access by modules unless
 * explicitly commented as such in the declaration of the extended struct or
 * the element in the extended struct.
 */

/*
 * UEK_KABI_SIZE_AND_EXTEND|_PTR() extends a struct by embedding or adding
 * a pointer in a base struct.  The name of the new struct is the name
 * of the base struct appended with _uek.
 */
#define UEK_KABI_SIZE_AND_EXTEND_PTR(_struct)				\
	size_t _struct##_size_uek;					\
	UEK_KABI_EXCLUDE(struct _struct##_uek *_struct##_uek)

#define UEK_KABI_SIZE_AND_EXTEND(_struct)				\
	size_t _struct##_size_uek;					\
	UEK_KABI_EXCLUDE(struct _struct##_uek _struct##_uek)

#define UEK_KABI_EXTEND_WITH_SIZE(_new, _size)                           \
        UEK_KABI_EXTEND(union {                                          \
                _new;                                                   \
                unsigned long UEK_KABI_UNIQUE_ID[_size];                 \
                __UEK_KABI_CHECK_SIZE(_new, 8 * (_size))                 \
        })
/*
 * UEK_KABI_SET_SIZE calculates and sets the size of the extended struct and
 * stores it in the size_uek field for structs that are dynamically allocated.
 * This macro MUST be called when expanding a base struct with
 * UEK_KABI_SIZE_AND_EXTEND, and it MUST be called from the allocation site
 * regardless of being allocated in the kernel or a module.
 */
#define UEK_KABI_SET_SIZE(_name, _struct) ({				\
	_name._struct##_size_uek = sizeof(struct _struct##_uek);		\
})

/*
 * UEK_KABI_INIT_SIZE calculates and sets the size of the extended struct and
 * stores it in the size_uek field for structs that are statically allocated.
 * This macro MUST be called when expanding a base struct with
 * UEK_KABI_SIZE_AND_EXTEND, and it MUST be called from the declaration site
 * regardless of being allocated in the kernel or a module.
 */
#define UEK_KABI_INIT_SIZE(_struct)					\
	._struct##_size_uek = sizeof(struct _struct##_uek),

/*
 * UEK_KABI_CHECK_EXT verifies allocated memory exists.  This MUST be called to
 * verify that memory in the _uek struct is valid, and can be called
 * regardless if UEK_KABI_SIZE_AND_EXTEND or UEK_KABI_SIZE_AND_EXTEND_PTR is
 * used.
 */
#define UEK_KABI_CHECK_EXT(_ptr, _struct, _field) ({			\
	size_t __off = offsetof(struct _struct##_uek, _field);		\
	_ptr->_struct##_size_uek > __off ? true : false;			\
})

#endif /* _LINUX_UEK_KABI_H */
