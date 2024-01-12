#ifndef _LINUX_LFSTACK_H
#define _LINUX_LFSTACK_H

#include <linux/stddef.h>
#include <linux/slab.h>

#ifdef CONFIG_HAVE_CMPXCHG_DOUBLE
#define LFSTACK_LOCKFREE
#else
#include <linux/llist.h>
#endif

struct lfstack_el {
	struct lfstack_el *next;
};

#ifdef LFSTACK_LOCKFREE
union lfstack {
	u128 full;
	struct  {
		__aligned_largest struct lfstack_el *first;
		uintptr_t seq;
	};
};

#else
#include <linux/llist.h>
union  lfstack {
	struct {
		struct lfstack_el *first;
		spinlock_t lfs_lock;	/* protect stack pops */
	};
};
#endif

static inline void lfstack_init(union lfstack *stack)
{
#ifdef LFSTACK_LOCKFREE
	stack->first = NULL;
	stack->seq = 0;
#else
	init_llist_head((struct llist_head *)&stack->first);
	spin_lock_init(&stack->lfs_lock);
#endif
}

static inline void lfstack_free(union lfstack *stack)
{
}

static inline void lfstack_push(union lfstack *stack, struct lfstack_el *el)
{
#ifdef LFSTACK_LOCKFREE
	union lfstack old_v, new_v;

	while (true) {
		old_v.first = READ_ONCE(stack->first);
		old_v.seq   = READ_ONCE(stack->seq);
		el->next = old_v.first;
		new_v.first = el;
		new_v.seq   = old_v.seq + 1;
		if (try_cmpxchg128(&stack->full, &old_v.full, new_v.full))
			break;
	}
#else
	llist_add((struct llist_node *)el, (struct llist_head *)stack);
#endif
}

static inline void lfstack_push_many(union lfstack *stack, struct lfstack_el *el_first, struct lfstack_el *el_last)
{
#ifdef LFSTACK_LOCKFREE
	union lfstack old_v, new_v;

	while (true) {
		old_v.first = READ_ONCE(stack->first);
		old_v.seq   = READ_ONCE(stack->seq);
		el_last->next = old_v.first;
		new_v.first = el_first;
		new_v.seq = old_v.seq + 1;
		if (try_cmpxchg128(&stack->full, &old_v.full, new_v.full))
			break;
	}
#else
	llist_add_batch((struct llist_node *)el_first, (struct llist_node *)el_last, (struct llist_head *)stack);
#endif
}

static inline struct lfstack_el *lfstack_pop(union lfstack *stack)
{
#ifdef LFSTACK_LOCKFREE
	union lfstack old_v, new_v;

	while (true) {
		old_v.first = READ_ONCE(stack->first);
		if (!old_v.first)
			break;
		old_v.seq   = READ_ONCE(stack->seq);
		new_v.first = old_v.first->next;
		new_v.seq   = old_v.seq + 1;
		if (try_cmpxchg128(&stack->full, &old_v.full, new_v.full))
			break;
	}
	return old_v.first;
#else
	struct lfstack_el *el;
	unsigned long flags;

	spin_lock_irqsave(&stack->lfs_lock, flags);
	el = (struct lfstack_el *)llist_del_first((struct llist_head *)stack);
	spin_unlock_irqrestore(&stack->lfs_lock, flags);
	return el;
#endif
}

static inline struct lfstack_el *lfstack_pop_all(union lfstack *stack)
{
#ifdef LFSTACK_LOCKFREE
	union lfstack old_v, new_v;

	new_v.first = NULL;
	new_v.seq   = 0;
	do {
		old_v.first = READ_ONCE(stack->first);
		old_v.seq   = READ_ONCE(stack->seq);
	} while (!try_cmpxchg128(&stack->full, &old_v.full, new_v.full));
	return old_v.first;
#else
	struct lfstack_el *el;
	unsigned long flags;

	spin_lock_irqsave(&stack->lfs_lock, flags);
	el = (struct lfstack_el *)llist_del_all((struct llist_head *)stack);
	spin_unlock_irqrestore(&stack->lfs_lock, flags);
	return el;
#endif
}

static inline void lfstack_link(struct lfstack_el *first, struct lfstack_el *next)
{
	/* Ensure prior memory ops get executed before updating first->next */
	smp_store_release(&first->next, next);
}

static inline struct lfstack_el *lfstack_next(struct lfstack_el *el)
{
	return READ_ONCE(el->next);
}

#endif
