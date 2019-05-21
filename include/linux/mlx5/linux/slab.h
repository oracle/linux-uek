#ifndef COMPAT_LINUX_SLAB_H
#define COMPAT_LINUX_SLAB_H

#include "linux/mlx5/compat/config.h"

#include <linux/mlx5/linux/overflow.h>

#ifndef HAVE_KMALLOC_ARRAY
/**
 * kmalloc_array - allocate memory for an array.
 * @n: number of elements.
 * @size: element size.
 * @flags: the type of memory to allocate (see kmalloc).
 */
static inline void *kmalloc_array(size_t n, size_t size, gfp_t flags)
{
        if (size != 0 && n > SIZE_MAX / size)
                return NULL;
        return __kmalloc(n * size, flags);
}
#endif

#ifndef HAVE_KMALLOC_ARRAY_NODE
static inline void *kmalloc_array_node(size_t n, size_t size, gfp_t flags,
				       int node)
{
	if (size != 0 && n > SIZE_MAX / size)
		return NULL;
	if (__builtin_constant_p(n) && __builtin_constant_p(size))
		return kmalloc_node(n * size, flags, node);
	return __kmalloc_node(n * size, flags, node);
}
#endif

#ifndef HAVE_KCALLOC_NODE
static inline void *kcalloc_node(size_t n, size_t size, gfp_t flags, int node)
{
	return kmalloc_array_node(n, size, flags | __GFP_ZERO, node);
}
#endif

/*
 * W/A for old kernels that do not have this fix.
 *
 * commit 3942d29918522ba6a393c19388301ec04df429cd
 * Author: Sergey Senozhatsky <sergey.senozhatsky@gmail.com>
 * Date:   Tue Sep 8 15:00:50 2015 -0700
 *
 *     mm/slab_common: allow NULL cache pointer in kmem_cache_destroy()
 *
*/
static inline void compat_kmem_cache_destroy(struct kmem_cache *s)
{
	if (unlikely(!s))
		return;

	kmem_cache_destroy(s);
}
#define kmem_cache_destroy compat_kmem_cache_destroy

#endif /* COMPAT_LINUX_SLAB_H */
