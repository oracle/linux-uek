/*
 * Copyright (c) 2015, 2016, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_PSIF_ENDIAN_H
#define	_PSIF_ENDIAN_H

#if defined(__arm__)
#undef HOST_BIG_ENDIAN
#define HOST_LITTLE_ENDIAN
#else /* __arm__ */
#  if defined(__BIG_ENDIAN) || defined(_BIG_ENDIAN)
#    define HOST_BIG_ENDIAN
#  elif defined(__LITTLE_ENDIAN) || defined(_LITTLE_ENDIAN)
#    define HOST_LITTLE_ENDIAN
#  else
#    error "could not determine byte order"
#  endif
#endif

#endif	/* _PSIF_ENDIAN_H */
