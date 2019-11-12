#ifndef _LINUX_LFSTACK_H
#define _LINUX_LFSTACK_H

#include <linux/stddef.h>
#include <linux/slab.h>

#ifdef CONFIG_HAVE_CMPXCHG_DOUBLE
#define LFSTACK_LOCKFREE
#else
#include <linux/llist.h>
#endif
#ifdef LFSTACK_LOCKFREE
struct lfstack {
	__aligned_largest struct lfstack_el *first;
	uintptr_t seq;
};
#else
#include <linux/llist.h>
struct lfstack {
	struct lfstack_el *first;
	spinlock_t lfs_lock;	/* protect stack pops */
};
#endif

struct lfstack_el {
	struct lfstack_el *next;
};

static inline void lfstack_init(struct lfstack *stack)
{
#ifdef LFSTACK_LOCKFREE
	stack->first = NULL;
	stack->seq = 0;
#else
	init_llist_head((struct llist_head *)&stack->first);
	spin_lock_init(&stack->lfs_lock);
#endif
}

static inline void lfstack_free(struct lfstack *stack)
{
}

static inline void lfstack_push(struct lfstack *stack, struct lfstack_el *el)
{
#ifdef LFSTACK_LOCKFREE
	struct lfstack_el *first;
	uintptr_t seq, nseq;

	while (true) {
		first = stack->first;
		seq = stack->seq;
		el->next = first;
		nseq = seq + 1;
		if (cmpxchg_double(&stack->first, &stack->seq, first, seq, el, nseq))
			break;
	}
#else
	llist_add((struct llist_node *)el, (struct llist_head *)stack);
#endif
}

static inline void lfstack_push_many(struct lfstack *stack, struct lfstack_el *el_first, struct lfstack_el *el_last)
{
#ifdef LFSTACK_LOCKFREE
	struct lfstack_el *first;
	uintptr_t seq, nseq;

	while (true) {
		first = stack->first;
		seq = stack->seq;
		el_last->next = first;
		nseq = seq + 1;
		if (cmpxchg_double(&stack->first, &stack->seq, first, seq, el_first, nseq))
			break;
	}
#else
	llist_add_batch((struct llist_node *)el_first, (struct llist_node *)el_last, (struct llist_head *)stack);
#endif
}

static inline struct lfstack_el *lfstack_pop(struct lfstack *stack)
{
#ifdef LFSTACK_LOCKFREE
	struct lfstack_el *first, *next;
	uintptr_t seq, nseq;

	while (true) {
		first = stack->first;
		if (!first)
			goto out;
		seq = stack->seq;
		next = first->next;
		nseq = seq + 1;
		if (cmpxchg_double(&stack->first, &stack->seq, first, seq, next, nseq))
			goto out;
	}
out:
	return first;
#else
	struct lfstack_el *el;
	unsigned long flags;

	spin_lock_irqsave(&stack->lfs_lock, flags);
	el = (struct lfstack_el *)llist_del_first((struct llist_head *)stack);
	spin_unlock_irqrestore(&stack->lfs_lock, flags);
	return el;
#endif
}

static inline void lfstack_link(struct lfstack_el *first, struct lfstack_el *next)
{
	first->next = next;
}

#endif
