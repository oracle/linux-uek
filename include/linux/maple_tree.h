/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _LINUX_MAPLE_TREE_H
#define _LINUX_MAPLE_TREE_H
/*
 * Maple Tree - An RCU-safe adaptive tree for storing ranges
 * Copyright (c) 2018 Oracle
 * Authors:     Liam R. Howlett <Liam.Howlett@Oracle.com>
 *              Matthew Wilcox <willy@infradead.org>
 */

#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#define CONFIG_MAPLE_RCU_DISABLED
//#define CONFIG_DEBUG_MAPLE_TREE
//#define CONFIG_DEBUG_MAPLE_TREE_VERBOSE

/*
 * Allocated nodes are mutable until they have been inserted into the tree,
 * at which time they cannot change their type until they have been removed
 * from the tree and an RCU grace period has passed.
 *
 * Removed nodes have their ->parent set to point to themselves.  RCU readers
 * check ->parent before relying on the value that they loaded from the
 * slots array.  This lets us reuse the slots array for the RCU head.
 *
 * Nodes in the tree point to their parent unless bit 0 is set.
 */
#define NODE256
#if defined(CONFIG_64BIT) || defined(BUILD_VDSO32_64)
#if defined(NODE256)
#define MAPLE_NODE_SLOTS	31	/* 256 bytes including ->parent */
#define MAPLE_RANGE64_SLOTS	16	/* 256 bytes */
#define MAPLE_ARANGE64_SLOTS	10	/* 240 bytes */
#else
#define MAPLE_NODE_SLOTS       15      /* 128 bytes including ->parent */
#define MAPLE_RANGE64_SLOTS    8       /* 128 bytes */
#define MAPLE_ARANGE64_SLOTS   5       /* 120 bytes */
#endif // End NODE256

#define MA_MAX_ALLOC		127
#else
/* Need to do corresponding calculations for 32-bit kernels */
#endif

typedef struct maple_enode *maple_enode; // encoded node.
typedef struct maple_pnode *maple_pnode; // parent node.


/**
 * maple_tree node explained
 *
 * Each node type has a number of slots for entries and a number of slots for
 * pivots.  In the case of dense nodes, the pivots are implied by the position
 * and are simply the slot index + the minimum of the node.
 *
 * In regular B-Tree terms, pivots are called keys.  The term pivot is used to
 * indicate that the tree is specifying ranges,  Pivots may appear in the
 * subtree with an entry attached to the value where as keys are unique to a
 * specific position of a B-tree.  Pivot values are inclusive of the slot with
 * the same index.
 *
 *
 * The following illustrates the layout of a range64 nodes slots and pivots.
 *
 *           _________________________________
 *  Slots -> | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
 *           ┬   ┬   ┬   ┬   ┬   ┬   ┬   ┬   ┬
 *           │   │   │   │   │   │   │   │   └─ Implied maximum
 *           │   │   │   │   │   │   │   └─ Pivot 6
 *           │   │   │   │   │   │   └─ Pivot 5
 *           │   │   │   │   │   └─ Pivot 4
 *           │   │   │   │   └─ Pivot 3
 *           │   │   │   └─ Pivot 2
 *           │   │   └─ Pivot 1
 *           │   └─ Pivot 0
 *           └─  Implied minimum
 *
 * Slot contents:
 *  Internal (non-leaf) nodes contain pointers to other nodes.
 *  Leaf nodes contain entries.
 *
 *
 */
struct maple_range_64 {
	struct maple_pnode *parent;
	unsigned long pivot[MAPLE_RANGE64_SLOTS - 1];
	void __rcu *slot[MAPLE_RANGE64_SLOTS];
};

struct maple_arange_64 {
	struct maple_pnode *parent;
	unsigned long pivot[MAPLE_ARANGE64_SLOTS - 1];
	void __rcu *slot[MAPLE_ARANGE64_SLOTS];
	unsigned long gap[MAPLE_ARANGE64_SLOTS];
};

struct maple_topiary {
	struct maple_pnode *parent;
	struct maple_enode *next; /* Overlaps the pivot */
};

enum maple_type {
	maple_dense,
	maple_leaf_64,
	maple_range_64,
	maple_arange_64,
};


/* Flags:
 * MAPLE_ALLOC_RANGE	Use allocation ranges (tracks gaps) in this tree
 * MAPLE_USE_RCU	Operate in read/copy/update mode for multi-readers.
 * MAPLE_HEIGHT_OFFSET	The position of the tree height in the flags
 * MAPLE_HEIGHT_MASK	The mask for the maple tree height value.
 */
#define MAPLE_ALLOC_RANGE	1	// Bit 0
#define MAPLE_USE_RCU		2	// Bit 1
#define	MAPLE_HEIGHT_OFFSET	2	// Bit 2
#define	MAPLE_HEIGHT_MASK	60	// Bits 2-5
struct maple_tree {
	spinlock_t	ma_lock;
	unsigned int	ma_flags;
	void __rcu      *ma_root;
};


#define MTREE_INIT(name, flags) {					\
	.ma_lock = __SPIN_LOCK_UNLOCKED(name.ma_lock),			\
	.ma_flags = flags,						\
	.ma_root = NULL,						\
}

#define DEFINE_MTREE(name)						\
	struct maple_tree name = MTREE_INIT(name, 0)

#define mtree_lock(mt)		spin_lock((&(mt)->ma_lock))
#define mtree_unlock(mt)	spin_unlock((&(mt)->ma_lock))

struct maple_node {
	union {
		struct {
			struct maple_pnode *parent;
			void __rcu *slot[MAPLE_NODE_SLOTS];
		};
		struct {
			void *pad;
			struct rcu_head rcu;
			enum maple_type type;
			struct maple_tree mt;
		};
		struct maple_range_64 mr64;
		struct maple_arange_64 ma64;
	};
};

struct ma_topiary {
	struct maple_enode *head;
	struct maple_enode *tail;
	struct maple_tree *mtree;
};

void mtree_init(struct maple_tree *mt, unsigned int ma_flags);
void *mtree_load(struct maple_tree *mt, unsigned long index);
int mtree_insert(struct maple_tree *mt, unsigned long index,
		void *entry, gfp_t gfp);
int mtree_insert_range(struct maple_tree *mt, unsigned long first,
		unsigned long last, void *entry, gfp_t gfp);
void *mtree_erase(struct maple_tree *mt, unsigned long index);
void mtree_destroy(struct maple_tree *mt);
int mtree_store_range(struct maple_tree *mt, unsigned long first,
		unsigned long last, void *entry, gfp_t gfp);

/**
 * mtree_empty() - Determine if a tree has any present entries.
 * @mt: Maple Tree.
 *
 * Context: Any context.
 * Return: %true if the tree contains only NULL pointers.
 */
static inline bool mtree_empty(const struct maple_tree *mt)
{
	return mt->ma_root == NULL;
}

/* Advanced API */

struct ma_state {
	struct maple_tree *tree;	/* The tree we're operating in */
	unsigned long index;		/* The index we're operating on - range start */
	unsigned long last;		/* The last index we're operating on - range end */
	struct maple_enode *node;	/* The node containing this entry */
	unsigned long min;		/* The minimum index of this node - implied pivot min */
	unsigned long max;		/* The maximum index of this node - implied pivot max */
	struct maple_node *alloc;	/* Allocated nodes for this operation */
	struct maple_enode *span_enode;	/* Pointer to maple parent/slot that set the max */
	unsigned char depth;		/* depth of tree descent during write */
};

#define mas_lock(mas)           spin_lock(&((mas)->tree->ma_lock))
#define mas_unlock(mas)         spin_unlock(&((mas)->tree->ma_lock))


/*
 * Special values for ma_state.node.
 * MAS_START means we have not searched the tree.
 * MAS_ROOT means we have searched the tree and the entry we found lives in
 * the root of the tree (ie it has index 0, length 1 and is the only entry in
 * the tree).
 * MAS_NONE means we have searched the tree and there is no node in the
 * tree for this entry.  For example, we searched for index 1 in an empty
 * tree.  Or we have a tree which points to a full leaf node and we
 * searched for an entry which is larger than can be contained in that
 * leaf node.
 * MA_ERROR represents an errno.  After dropping the lock and attempting
 * to resolve the error, the walk would have to be restarted from the
 * top of the tree as the tree may have been modified.
 */
#define MAS_START	((struct maple_enode *)1UL)
#define MAS_ROOT	((struct maple_enode *)5UL)
#define MAS_NONE	((struct maple_enode *)9UL)
#define MA_ERROR(err) \
		((struct maple_enode *)(((unsigned long)err << 2) | 2UL))

#define MA_STATE(name, mt, first, end)					\
	struct ma_state name = {					\
		.tree = mt,						\
		.index = first,						\
		.last = end,						\
		.node = MAS_START,					\
		.min = 0,						\
		.max = ULONG_MAX,					\
	}

#define MA_TOPIARY(name, tree)						\
	struct ma_topiary name = {					\
		.head = NULL,						\
		.tail = NULL,						\
		.mtree = tree,						\
	}

void *mas_walk(struct ma_state *mas);
void *mas_store(struct ma_state *mas, void *entry);
void *mas_find(struct ma_state *mas, unsigned long max);

bool mas_nomem(struct ma_state *mas, gfp_t gfp);
void mas_pause(struct ma_state *mas);
void maple_tree_init(void);

void *mas_prev(struct ma_state *mas, unsigned long min);
void *mas_next(struct ma_state *mas, unsigned long max);

/* Finds a sufficient hole */
int mas_get_empty_area(struct ma_state *mas, unsigned long min,
		unsigned long max, unsigned long size);

/* Checks if a mas has not found anything */
static inline bool mas_is_none(struct ma_state *mas)
{
	return mas->node == MAS_NONE;
}

void mas_dup_tree(struct ma_state *oldmas, struct ma_state *mas);
void mas_dup_store(struct ma_state *mas, void *entry);
/* This finds an empty area from the highest address to the lowest.
 * AKA "Topdown" version,
 */
int mas_get_empty_area_rev(struct ma_state *mas, unsigned long min,
		unsigned long max, unsigned long size);
/**
 * mas_reset() - Reset a Maple Tree operation state.
 * @mas: Maple Tree operation state.
 *
 * Resets the error or walk state of the @mas so future walks of the
 * array will start from the root.  Use this if you have dropped the
 * lock and want to reuse the ma_state.
 *
 * Context: Any context.
 */
static inline void mas_reset(struct ma_state *mas)
{
	mas->node = MAS_START;
}

/**
 * mas_for_each() - Iterate over a range of the maple tree.
 * @mas: Maple Tree operation state (maple_state)
 * @entry: Entry retrieved from the tree
 * @max: maximum index to retrieve from the tree
 *
 * When returned, mas->index and mas->last will hold the entire range for the
 * entry.
 *
 * Note: may return the zero entry.
 *
 */
#define mas_for_each(mas, entry, max) \
	while (((entry) = mas_find((mas), (max))) != NULL)


/**
 * mas_set_range() - Set up Maple Tree operation state for a different index.
 * @mas: Maple Tree operation state.
 * @start: New start of range in the Maple Tree.
 * @last: New end of range in the Maple Tree.
 *
 * Move the operation state to refer to a different range.  This will
 * have the effect of starting a walk from the top; see mas_next()
 * to move to an adjacent index.
 */
static inline void mas_set_range(struct ma_state *mas, unsigned long start,
		unsigned long last)
{
	       mas->index = start;
	       mas->last = last;
	       mas->node = MAS_START;
}

/**
 * mas_set() - Set up Maple Tree operation state for a different index.
 * @mas: Maple Tree operation state.
 * @index: New index into the Maple Tree.
 *
 * Move the operation state to refer to a different index.  This will
 * have the effect of starting a walk from the top; see mas_next()
 * to move to an adjacent index.
 */
static inline void mas_set(struct ma_state *mas, unsigned long index)
{

	mas_set_range(mas, index, index);
}

/**
 * mt_init_flags() - Initialise an empty maple tree with flags.
 * @mt: Maple Tree
 * @flags: maple tree flags.
 *
 * If you need to initialise a Maple Tree with special falgs (eg, an
 * allocation tree), use this function.
 *
 * Context: Any context.
 *
 */
static inline void mt_init_flags(struct maple_tree *mt, unsigned int flags)
{
	spin_lock_init(&mt->ma_lock);
	mt->ma_flags = flags;
	mt->ma_root = NULL;
}

/**
 * mt_init() - Initialise an empty maple tree.
 * @mt: Maple Tree
 *
 * An empty Maple Tree.
 *
 * Context: Any context.
 */
static inline void mt_init(struct maple_tree *mt)
{
	mt_init_flags(mt, 0);
}

static inline bool mt_in_rcu(struct maple_tree *mt)
{
#ifdef CONFIG_MAPLE_RCU_DISABLED
	return false;
#endif
	return !!(mt->ma_flags & MAPLE_USE_RCU);
}
/**
 * mt_clear_in_rcu() - Switch the tree to non-RCU mode.
 */
static inline void mt_clear_in_rcu(struct maple_tree *mt)
{
	if (!mt_in_rcu(mt))
		return;

	mtree_lock(mt);
	mt->ma_flags &= ~MAPLE_USE_RCU;
	mtree_unlock(mt);
}

/**
 * mt_set_in_rcu() - Switch the tree to RCU safe mode.
 */
static inline void mt_set_in_rcu(struct maple_tree *mt)
{
	if (mt_in_rcu(mt))
		return;

	mtree_lock(mt);
	mt->ma_flags |= MAPLE_USE_RCU;
	mtree_unlock(mt);
}

int mas_entry_cnt(struct ma_state *mas, unsigned long nr_leaves);

void *mt_find(struct maple_tree *mt, unsigned long *index, unsigned long max);
void *_mt_find(struct maple_tree *mt, unsigned long *index, unsigned long max,
		bool start);
/**
 * mt_for_each - Searches for an entry starting at index until max.
 *
 * Note: Will not return the zero entry.
 */
#define mt_for_each(tree, entry, index, max) \
	for (entry = _mt_find(tree, &index, max, true); \
		entry; entry = _mt_find(tree, &index, max, false))


#ifdef CONFIG_DEBUG_MAPLE_TREE
extern unsigned int maple_tree_tests_run;
extern unsigned int maple_tree_tests_passed;

void mt_dump(const struct maple_tree *mt);
#define MT_BUG_ON(tree, x) do {						\
	maple_tree_tests_run++;						\
	if (x) {							\
		pr_info("BUG at %s:%d (%u)\n",				\
		__func__, __LINE__, x);					\
		mt_dump(tree);						\
		pr_info("Pass: %u Run:%u\n", maple_tree_tests_passed,	\
			maple_tree_tests_run);				\
		dump_stack();						\
	} else {							\
		maple_tree_tests_passed++;				\
	}								\
} while (0)
#else
#define MT_BUG_ON(tree, x) BUG_ON(x)
#endif /* CONFIG_DEBUG_MAPLE_TREE */

#endif /*_LINUX_MAPLE_TREE_H */
