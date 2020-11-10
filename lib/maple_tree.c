// SPDX-License-Identifier: GPL-2.0+
/*
 * Maple Tree implementation
 * Copyright (c) 2018 Oracle Corporation
 * Authors: Liam R. Howlett <Liam.Howlett@oracle.com>
 *	    Matthew Wilcox <willy@infradead.org>
 */

#include <linux/maple_tree.h>
#include <linux/xarray.h>
#include <linux/types.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <asm/barrier.h>

#define CREATE_TRACE_POINTS
#include <trace/events/maple_tree.h>

#define MA_ROOT_PARENT 1

/* Maple state flags */
#define MA_STATE_BULK		1
#define MA_STATE_REBALANCE	2

#define ma_parent_ptr(x) ((struct maple_pnode *)(x))
#define ma_mnode_ptr(x) ((struct maple_node *)(x))
#define ma_enode_ptr(x) ((struct maple_enode *)(x))
static struct kmem_cache *maple_node_cache;

static const unsigned long mt_max[] = {
	[maple_dense]		= MAPLE_NODE_SLOTS,
	[maple_leaf_64]		= ULONG_MAX,
	[maple_range_64]	= ULONG_MAX,
	[maple_arange_64]	= ULONG_MAX,
};
#define mt_node_max(x) mt_max[mte_node_type(x)]

static const unsigned char mt_slots[] = {
	[maple_dense]		= MAPLE_NODE_SLOTS,
	[maple_leaf_64]		= MAPLE_RANGE64_SLOTS,
	[maple_range_64]	= MAPLE_RANGE64_SLOTS,
	[maple_arange_64]	= MAPLE_ARANGE64_SLOTS,
};
#define mt_slot_count(x) mt_slots[mte_node_type(x)]

static const unsigned char mt_pivots[] = {
	[maple_dense]		= 0,
	[maple_leaf_64]		= MAPLE_RANGE64_SLOTS - 1,
	[maple_range_64]	= MAPLE_RANGE64_SLOTS - 1,
	[maple_arange_64]	= MAPLE_ARANGE64_SLOTS - 1,
};
#define mt_pivot_count(x) mt_pivots[mte_node_type(x)]

static const unsigned char mt_min_slots[] = {
	[maple_dense]		= MAPLE_NODE_SLOTS / 2,
	[maple_leaf_64]		= (MAPLE_RANGE64_SLOTS / 2) - 2,
	[maple_range_64]	= (MAPLE_RANGE64_SLOTS / 2) - 2,
	[maple_arange_64]	= (MAPLE_ARANGE64_SLOTS / 2) - 1,
};
#define mt_min_slot_count(x) mt_min_slots[mte_node_type(x)]

#define MAPLE_BIG_NODE_SLOTS	(MAPLE_RANGE64_SLOTS* 2 + 2)

struct maple_big_node {
	struct maple_pnode *parent;
	struct maple_enode *slot[MAPLE_BIG_NODE_SLOTS];
	unsigned long pivot[MAPLE_BIG_NODE_SLOTS - 1];
	unsigned long gap[MAPLE_BIG_NODE_SLOTS];
	unsigned long min;
	unsigned char b_end;
	enum maple_type type;
};

struct maple_subtree_state {
	struct ma_state *orig_l;	/* Original left side of subtree */
	struct ma_state *orig_r;	/* Original rigth side of subtree */
	struct ma_state *l;		/* New left side of subtree */
	struct ma_state *m;		/* New middle of subtree (rare) */
	struct ma_state *r;		/* New right side of subtree */
	struct ma_topiary *free;	/* nodes to be freed */
	struct ma_topiary *destroy;	/* Nodes to be destroyed (walked and freed) */
	struct maple_big_node *bn;
};

// Functions
static inline struct maple_node *mt_alloc_one(gfp_t gfp)
{
	return kmem_cache_alloc(maple_node_cache, gfp | __GFP_ZERO);
}

static inline int mt_alloc_bulk(gfp_t gfp, size_t size, void **nodes)
{
	return kmem_cache_alloc_bulk(maple_node_cache, gfp | __GFP_ZERO, size,
				     nodes);
}


static inline void mt_free_bulk(size_t size, void **nodes)
{
	kmem_cache_free_bulk(maple_node_cache, size, nodes);
}

static void mt_free_rcu(struct rcu_head *head)
{
	struct maple_node *node = container_of(head, struct maple_node, rcu);

	kmem_cache_free(maple_node_cache, node);
}

static void ma_free_rcu(struct maple_node *node)
{
	node->parent = ma_parent_ptr(node);
	call_rcu(&node->rcu, mt_free_rcu);
}

static unsigned int mt_height(const struct maple_tree *mt)
{
	return (mt->ma_flags & MAPLE_HEIGHT_MASK) >> MAPLE_HEIGHT_OFFSET;
}


static void mas_set_height(struct ma_state *mas)
{
	unsigned int new_flags = mas->tree->ma_flags;
	new_flags &= ~MAPLE_HEIGHT_MASK;
	new_flags |= mas->depth << MAPLE_HEIGHT_OFFSET;
	mas->tree->ma_flags = new_flags;
}

static unsigned int mas_mt_height(struct ma_state *mas)
{
	return mt_height(mas->tree);
}

static inline enum maple_type mte_node_type(const struct maple_enode *entry)
{
	return ((unsigned long)entry >> 3) & 15;
}

static inline bool ma_is_dense(const enum maple_type type)
{
	return type < maple_leaf_64;
}

static inline bool ma_is_leaf(const enum maple_type type)
{
	return type < maple_range_64;
}

static inline bool mte_is_leaf(const struct maple_enode *entry)
{
	return ma_is_leaf(mte_node_type(entry));
}

/*
 * We also reserve values with the bottom two bits set to '10' which are
 * below 4096
 */
static inline bool mt_is_reserved(const void *entry)
{
	return ((unsigned long)entry < 4096) && xa_is_internal(entry);
}

static inline void mas_set_err(struct ma_state *mas, long err)
{
	mas->node = MA_ERROR(err);
}

static inline bool mas_is_ptr(struct ma_state *mas)
{
	return mas->node == MAS_ROOT;
}

static inline bool mas_is_start(struct ma_state *mas)
{
	return mas->node == MAS_START;
}

static inline bool mas_is_err(struct ma_state *mas)
{
	return xa_is_err(mas->node);
}

static inline bool mas_searchable(struct ma_state *mas)
{
	if (mas_is_none(mas))
		return false;

	if (mas_is_ptr(mas))
		return false;

	return true;
}

static inline struct maple_node *mte_to_node(const struct maple_enode *entry)
{
	return (struct maple_node *)((unsigned long)entry & ~127);
}

static inline struct maple_topiary *mte_to_mat(const struct maple_enode *entry)
{
	return (struct maple_topiary *)((unsigned long)entry & ~127);
}

static inline struct maple_node *mas_mn(const struct ma_state *mas)
{
	return mte_to_node(mas->node);
}

static inline void mte_set_node_dead(struct maple_enode *mn)
{
	mte_to_node(mn)->parent = ma_parent_ptr(mte_to_node(mn));
}

static inline void mte_free(struct maple_enode *enode)
{
	ma_free_rcu(mte_to_node(enode));
}

static inline struct maple_enode *mt_mk_node(const struct maple_node *node,
		enum maple_type type) {
	return (void *)((unsigned long)node | (type << 3) | 4);
}

static inline void *mte_mk_root(const struct maple_enode *node)
{
	return (void *)((unsigned long)node | 2);
}

static inline void *mte_safe_root(const struct maple_enode *node)
{
	return (void *)((unsigned long)node & ~2);
}

static inline void mte_set_full(const struct maple_enode *node)
{
	node = (void *)((unsigned long)node | 4);
}

static inline bool ma_is_root(struct maple_node *node)
{
	return ((unsigned long)node->parent & MA_ROOT_PARENT);
}

static inline bool mte_is_root(const struct maple_enode *node)
{
	return ma_is_root(mte_to_node(node));
}

static inline bool mas_is_root_limits(const struct ma_state *mas)
{
	return !mas->min && mas->max == ULONG_MAX;
}

static inline bool mt_is_alloc(struct maple_tree *mt)
{
	return (mt->ma_flags & MAPLE_ALLOC_RANGE);
}


static inline unsigned int mte_parent_shift(unsigned long parent)
{
	if (!(parent & 2))
		return 2; // maple_range_16
	return 3;
}

static inline enum maple_type mte_parent_range_enum(unsigned long parent)
{
	if (parent)
		return maple_range_64;

	return maple_dense;
}

static inline enum maple_type mte_parent_alloc_enum(unsigned long parent)
{
	if (parent)
		return maple_arange_64;

	return maple_dense;
}

static inline enum maple_type mas_parent_enum(struct ma_state *mas,
		struct maple_enode *node)
{
	unsigned long parent = 6;
	unsigned long slot_shift;

	if (!mte_is_root(mas->node)) {
		parent = (unsigned long) mte_to_node(node)->parent;
		slot_shift = mte_parent_shift(parent);
		parent &= (1 << slot_shift) - 1;
	}

	if (mt_is_alloc(mas->tree))
		return mte_parent_alloc_enum(parent);

	return mte_parent_range_enum(parent);
}

/*
 * mte_set_parent() - Set the parent node and encode the slot.
 * @enode: The encoded maple node.
 * @parent: The encoded maple node that is the parent of @enode.
 * @slot: The slot that @enode resides in @parent.
 *
 * Type is encoded in the enode->parent
 * bit 0: 1 = root, 0 otherwise
 * bit 1: Reserved.
 * bit 2: 0 = range 32, 1 = [a]range 64 | lowest bit of range_16's slot.
 *
 * Slot number is encoded in the enode->parent
 * range_32, slot number is encoded in bits 3-6
 * [a]range_64, slot number is encoded in bits 3-6
 */
static inline void mte_set_parent(struct maple_enode *enode,
				 const struct maple_enode *parent,
				 unsigned char slot)
{
	unsigned long bitmask = 0x78;
	unsigned long slot_shift = 3;
	unsigned long val = (unsigned long) parent;
	unsigned long type = 0;

	switch (mte_node_type(parent)) {
	case maple_range_64:
	case maple_arange_64:
		type |= 4;
		type |= 2;
		break;
	default:
		break;
	}

	val &= ~bitmask; // Remove any old slot number.
	val |= (slot << slot_shift); // Set the slot.
	val |= type;
	mte_to_node(enode)->parent = ma_parent_ptr(val);
}

/*
 * mte_parent_slot() - get the parent slot of @enode.
 * @enode: The encoded maple node.
 *
 * Returns: The slot in the parent node where @enode resides.
 */
static inline unsigned int mte_parent_slot(const struct maple_enode *enode)
{
	unsigned long bitmask = 0x7C;
	unsigned long val = (unsigned long) mte_to_node(enode)->parent;
	unsigned long slot_shift = mte_parent_shift(val);

	if (val & 1)
		return 0; // Root.

	return (val & bitmask) >> slot_shift;
}

/*
 * mte_parent() - Get the parent of @node.
 * @node: The encoded maple node.
 *
 * Returns: The parent maple node.
 */
static inline struct maple_node *mte_parent(const struct maple_enode *enode)
{
	return (void *)((unsigned long)
			(mte_to_node(enode)->parent) & ~MAPLE_NODE_MASK);
}

/*
 * mte_dead_node() - check if the @enode is dead.
 * Returns: true if dead, false otherwise.
 */
static inline bool mte_dead_node(const struct maple_enode *enode)
{
	struct maple_node *parent, *node = mte_to_node(enode);

	parent = mte_parent(enode);
	return (parent == node);
}

/*
 * mas_allocated() - Get the number of nodes allocated in a maple state.
 * @mas: The maple state
 *
 * Walks through the allocated nodes and returns the number allocated.
 *
 * Returns: The total number of nodes allocated
 *
 */
static inline unsigned long mas_allocated(const struct ma_state *mas)
{
	if (!mas->alloc || ((unsigned long)mas->alloc & 0x1))
		return 0;

	return mas->alloc->total;
}

/*
 * mas_set_alloc_req() - Set the requested number of allocations.
 * @mas: the maple state
 * @count: the number of allocations.
 */
static inline void mas_set_alloc_req(struct ma_state *mas, unsigned long count)
{
	if (!mas->alloc || ((unsigned long)mas->alloc & 0x1)) {
		if (!count)
			mas->alloc = NULL;
		else
			mas->alloc = (struct maple_alloc *)(((count) << 1U) | 1U);
		return;
	}

	mas->alloc->request_count = count;
}

/*
 * mas_alloc_req() - get the requested number of allocations.
 * @mas: The maple state.
 *
 * Returns: The allocation request count.
 */
static inline unsigned int mas_alloc_req(const struct ma_state *mas)
{
	if ((unsigned long)mas->alloc & 0x1)
		return (unsigned long)(mas->alloc) >> 1;
	else if (mas->alloc)
		return mas->alloc->request_count;
	return 0;
}

/*
 * ma_pivots() - Get the pivot of a node.
 * @node - the maple node.
 * @type - the node type.
 *
 * Returns: The value of the @piv in the @node.
 */
static inline unsigned long *ma_pivots(struct maple_node *node,
					   enum maple_type type)
{
	switch (type) {
	case maple_arange_64:
		return node->ma64.pivot;
	case maple_range_64:
	case maple_leaf_64:
		return node->mr64.pivot;
	case maple_dense:
	default:
		return NULL;
	}
}

static inline unsigned long *ma_gaps(struct maple_node *node,
				     enum maple_type type)
{
	switch (type) {
	case maple_arange_64:
		return node->ma64.gap;
	case maple_range_64:
	case maple_leaf_64:
	case maple_dense:
	default:
		return NULL;
	}
}

static inline unsigned long mte_pivot(const struct maple_enode *mn,
				 unsigned char piv)
{
	struct maple_node *node = mte_to_node(mn);

	switch (mte_node_type(mn)) {
	case maple_arange_64:
		return node->ma64.pivot[piv];
	case maple_range_64:
	case maple_leaf_64:
		return node->mr64.pivot[piv];
	case maple_dense:
	default:
		return 0;
	}
}

static inline unsigned long
_mas_safe_pivot(const struct ma_state *mas, unsigned long *pivots,
		unsigned char piv, enum maple_type type)
{
	if (piv >= mt_pivots[type])
		return mas->max;

	return pivots[piv];
}

/*
 * mas_safe_pivot() - Return pivot, implied or otherwise.
 * @mas: The maple state.
 * @piv:  the pivot location.
 *
 * Return: The pivot (including mas->max for the final piv)
 */
static inline unsigned long
mas_safe_pivot(const struct ma_state *mas, unsigned char piv)
{
	enum maple_type type = mte_node_type(mas->node);
	unsigned long *pivots = ma_pivots(mas_mn(mas), type);

	return _mas_safe_pivot(mas, pivots, piv, type);
}

/*
 * mas_safe_min() - Return the minimum for a given offset.
 *
 */
static inline unsigned long
mas_safe_min(struct ma_state *mas, unsigned long *pivots, unsigned char piv)
{
	if (!piv)
		return mas->min;

	return pivots[piv - 1] + 1;
}


// Check what the maximum value the pivot could represent.
static inline unsigned long
mas_logical_pivot(struct ma_state *mas, unsigned long *pivots,
		  unsigned char piv, enum maple_type type)
{
	unsigned long lpiv = _mas_safe_pivot(mas, pivots, piv, type);

	if (!lpiv && piv)
		return mas->max;
	return lpiv;
}
static inline void ma_set_pivot(struct maple_node *mn, unsigned char piv,
		enum maple_type type, unsigned long val)
{
	BUG_ON(piv >= mt_pivots[type]);

	switch (type) {
	default:
	case maple_range_64:
	case maple_leaf_64:
		(&mn->mr64)->pivot[piv] = val;
		break;
	case maple_arange_64:
		(&mn->ma64)->pivot[piv] = val;
	case maple_dense:
		break;
	}
}

static inline void mte_set_pivot(struct maple_enode *mn, unsigned char piv,
				unsigned long val)
{
	return ma_set_pivot(mte_to_node(mn), piv, mte_node_type(mn), val);
}

static inline void __rcu **ma_slots(struct maple_node *mn, enum maple_type mt)
{
	switch (mt) {
	default:
	case maple_arange_64:
		return mn->ma64.slot;
	case maple_range_64:
	case maple_leaf_64:
		return mn->mr64.slot;
	case maple_dense:
		return mn->slot;
	}
}

static inline void *mas_slot_locked(struct ma_state *mas, void **slots,
				       unsigned char offset)
{
	if (mt_in_rcu(mas->tree))
		return rcu_dereference_protected(slots[offset],
					lockdep_is_held(&mas->tree->ma_lock));
	return slots[offset];
}

static inline void *mas_slot(struct ma_state *mas, void **slots,
			     unsigned char offset)
{
	if (mt_in_rcu(mas->tree))
		return rcu_dereference(slots[offset]);

	return slots[offset];
}

static inline struct maple_enode *mas_get_slot(struct ma_state *mas,
		unsigned char offset)
{
	return mas_slot(mas, ma_slots(mas_mn(mas), mte_node_type(mas->node)),
		       offset);
}

static inline void *mas_root(struct ma_state *mas)
{
	if (mt_in_rcu(mas->tree))
		return rcu_dereference(mas->tree->ma_root);

	return mas->tree->ma_root;
}

static inline void *mas_root_locked(struct ma_state *mas)
{
	if (mt_in_rcu(mas->tree))
		return rcu_dereference_protected(mas->tree->ma_root,
					lockdep_is_held(&mas->tree->ma_lock));

	return mas->tree->ma_root;
}
/*
 * ma_set_slot() - Set a nodes rcu slot.
 *
 * @mn - the maple node for the operation
 * @slot - the slot number to set
 * @type - the maple node type
 * @val - the value to store
 */
static inline void ma_set_slot(struct maple_node *mn,
		unsigned char slot, enum maple_type type, void *val)
{
	BUG_ON(slot >= mt_slots[type]);

	switch (type) {
	default:
	case maple_range_64:
	case maple_leaf_64:
		rcu_assign_pointer(mn->mr64.slot[slot], val);
		break;
	case maple_arange_64:
		rcu_assign_pointer(mn->ma64.slot[slot], val);
		break;
	case maple_dense:
		rcu_assign_pointer(mn->slot[slot], val);
		break;
	}
}

/*
 * mte_set_slot() - Set an encoded nodes rcu slot.
 */
static inline void mte_set_slot(const struct maple_enode *mn,
				 unsigned char slot, void *val)
{
	ma_set_slot(mte_to_node(mn), slot, mte_node_type(mn), val);
}

#define MA_META_END_MASK	0b1111
#define MA_META_GAP_SHIFT	4
static inline void ma_set_meta(struct maple_node *mn, enum maple_type mt,
			       unsigned char offset, unsigned char end)
{

	BUG_ON(mt != maple_arange_64);
	mn->ma64.meta = (offset << MA_META_GAP_SHIFT) | end;
}
static inline unsigned char ma_meta_end(struct maple_node *mn,
					enum maple_type mt)
{

	BUG_ON(mt != maple_arange_64);
	return mn->ma64.meta & MA_META_END_MASK;
}
static inline unsigned char ma_meta_gap(struct maple_node *mn,
					enum maple_type mt)
{

	BUG_ON(mt != maple_arange_64);
	return mn->ma64.meta >> MA_META_GAP_SHIFT;
}
static inline void ma_set_meta_gap(struct maple_node *mn, enum maple_type mt,
				   unsigned char offset)
{

	BUG_ON(mt != maple_arange_64);
	mn->ma64.meta = (offset << MA_META_GAP_SHIFT) |
		(mn->ma64.meta & MA_META_END_MASK);
}
/*
 * mat_add() - Add a @dead_enode to the ma_topiary of a list of dead nodes.
 *
 * Add the %dead_enode to the linked list in %mat.
 *
 * @mat - the ma_topiary, a linked list of dead nodes.
 * @dead_enode - the node to be marked as dead and added to the tail of the list
 */
static inline void mat_add(struct ma_topiary *mat,
			   struct maple_enode *dead_enode)
{
	mte_set_node_dead(dead_enode);
	mte_to_mat(dead_enode)->next = NULL;
	if (!mat->tail) {
		mat->tail = mat->head = dead_enode;
		return;
	}

	mte_to_mat(mat->tail)->next = dead_enode;
	mat->tail = dead_enode;
}

static void mte_destroy_walk(struct maple_enode *, struct maple_tree *);
/*
 * mat_free() - Free all nodes in a dead list.
 *
 * Free or destroy walk a dead list.
 *
 * @mat - the ma_topiary linked list of dead nodes to free.
 * @recursive - specifies if this sub-tree is to be freed or just the single
 * node.
 */
static inline void mas_free(struct ma_state *mas, struct maple_enode *used);
static inline void mas_mat_free(struct ma_state *mas, struct ma_topiary *mat,
				bool recursive)
{
	struct maple_enode *next;

	while (mat->head) {
		next = mte_to_mat(mat->head)->next;
		if (recursive)
			mte_destroy_walk(mat->head, mat->mtree);
		else
			mas_free(mas, mat->head);
		mat->head = next;
	}
}

/*
 * mas_dup_state() - duplicate the internal state of a ma_state.
 *
 * @dst - the destination to store the state information
 * @src - the source of the state information
 */
static inline void mas_dup_state(struct ma_state *dst, struct ma_state *src)
{
	dst->tree = src->tree;
	dst->index = src->index;
	dst->last = src->last;
	dst->node = src->node;
	dst->max = src->max;
	dst->min = src->min;
	dst->offset = src->offset;
	dst->mas_flags = src->mas_flags;
}

/*
 * mas_descend() - Descend into the slot stored in the ma_state.
 *
 * @mas - the maple state.
 */
static inline void mas_descend(struct ma_state *mas)
{
	if (mas->offset)
		mas->min = mas_safe_pivot(mas, mas->offset - 1) + 1;
	mas->max = mas_safe_pivot(mas, mas->offset);
	mas->node = mas_get_slot(mas, mas->offset);
}

static inline void mte_set_gap(const struct maple_enode *mn,
				 unsigned char gap, unsigned long val)
{
	switch (mte_node_type(mn)) {
	default:
		break;
	case maple_arange_64:
		mte_to_node(mn)->ma64.gap[gap] = val;
		break;
	}
}

static inline void mas_ascend(struct ma_state *mas)
{
	struct maple_enode *p_enode = mas->node; // parent enode.
	struct maple_enode *a_enode = mas->node; // ancestor enode.
	struct maple_node *a_node = mas_mn(mas); // ancestor node.
	unsigned char a_slot = 0;
	enum maple_type a_type = mte_node_type(mas->node);
	unsigned long max = 0, min = ULONG_MAX;
	bool set_max = false, set_min = false;

	if (ma_is_root(a_node))
		goto no_parent;

	p_enode = mt_mk_node(mte_parent(mas->node),
			mas_parent_enum(mas, mas->node));
	a_type = mas_parent_enum(mas, mas->node);
	a_enode = p_enode;
	if (mte_is_root(a_enode))
		goto parent_is_root;

	mas->node = p_enode;
ascend:
	a_type = mas_parent_enum(mas, mas->node);
	a_node = mte_parent(mas->node);
	a_slot = mte_parent_slot(mas->node);
	a_enode = mt_mk_node(a_node, a_type);
	if (!set_min && a_slot) {
		set_min = true;
		min = mte_pivot(a_enode, a_slot - 1) + 1;
	}

	if (!set_max && a_slot < mt_pivots[a_type]) {
		set_max = true;
		max = mte_pivot(a_enode, a_slot);
	}

no_parent:
	if (ma_is_root(a_node)) {
parent_is_root:
		if (!set_min)
			min = 0;
		if (!set_max)
			max = mt_max[a_type];
	}

	if (!max || min == ULONG_MAX) {
		if (mas->node == a_enode) {
			printk("Failed on node %p (%p)\n", mas_mn(mas), a_enode);
			//FIXME: Restart and retry if the lock is held.
			MT_BUG_ON(mas->tree, mas->node == a_enode);
		}
		mas->node = a_enode;
		goto ascend;
	}

	mas->max = max;
	mas->min = min;
	mas->node = p_enode;
}

static inline struct maple_node *mas_pop_node(struct ma_state *mas)
{
	struct maple_alloc *ret, *node = mas->alloc;
	unsigned long total = mas_allocated(mas);

	if (!total) // nothing or a request pending.
		return NULL;

	if (total == 1) { // single allocation in this ma_state
		mas->alloc = NULL;
		ret = node;
		goto single_node;
	}

	if (!node->node_count) { // Single allocation in this node.
		BUG_ON(!node->slot[0]);
		mas->alloc = node->slot[0];
		mas->alloc->total = node->total - 1;
		ret = node;
		goto new_head;
	}

	node->total--;
	ret = node->slot[node->node_count];
	node->slot[node->node_count--] = NULL;

single_node:
new_head:
	ret->total = 0;
	ret->node_count = 0;
	if (ret->request_count)
		mas_set_alloc_req(mas, ret->request_count + 1);
	ret->request_count = 0;
	return (struct maple_node *)ret;
}
static inline void mas_push_node(struct ma_state *mas, struct maple_enode *used)
{
	struct maple_alloc *reuse = (struct maple_alloc *)mte_to_node(used);
	struct maple_alloc *head = mas->alloc;
	unsigned long count;
	unsigned int requested = mas_alloc_req(mas);

	memset(reuse, 0, sizeof(*reuse));
	count = mas_allocated(mas);

	if (count && (head->node_count < MAPLE_ALLOC_SLOTS - 1)) {
		if (head->slot[0])
			head->node_count++;
		head->slot[head->node_count] = reuse;

		head->total++;
		goto done;
	}

	reuse->total = 1;
	if ((head) && !(((unsigned long)head & 0x1))) {
		reuse->slot[0] = head;
		reuse->total += head->total;
	}

	reuse->node_count = 0;
	mas->alloc = reuse;
done:
	if (requested)
		mas_set_alloc_req(mas, requested - 1);
}

static inline void mas_alloc_nodes(struct ma_state *mas, gfp_t gfp)
{
	struct maple_alloc *node;
	struct maple_alloc **nodep = &mas->alloc;
	unsigned long allocated = mas_allocated(mas);
	unsigned long success = allocated;
	unsigned int requested = mas_alloc_req(mas);
	unsigned int count;

	if (!requested)
		return;

	mas_set_alloc_req(mas, 0);
	if (!allocated || mas->alloc->node_count == MAPLE_ALLOC_SLOTS - 1) {
		node = (struct maple_alloc *)mt_alloc_one(gfp);
		if (!node)
			goto nomem;

		if (allocated)
			node->slot[0] = mas->alloc;

		success++;
		mas->alloc = node;
		requested--;
	}

	node = mas->alloc;
	while (requested) {
		void **slots = (void**)&node->slot;
		unsigned int max_req = MAPLE_NODE_SLOTS - 1;

		if (node->slot[0]) {
			unsigned int offset = node->node_count + 1;
			slots = (void**)&node->slot[offset];
			max_req -= offset;
		}

		count = min(requested, max_req);
		count = mt_alloc_bulk(gfp, count, slots);
		if (!count)
			goto nomem;

		node->node_count += count;
		if (slots == (void**)&node->slot)
			node->node_count--; // zero indexed.

		success += count;
		nodep = &node->slot[0];
		node = *nodep;
		// decrement.
		requested -= count;
	}
	mas->alloc->total = success;
	return;
nomem:
	mas_set_alloc_req(mas, requested);
	if (mas->alloc && !(((unsigned long)mas->alloc & 0x1)))
		mas->alloc->total = success;
	mas_set_err(mas, -ENOMEM);
	return;

}

static inline void mas_free(struct ma_state *mas, struct maple_enode *used)
{
	if (mt_in_rcu(mas->tree))
		mte_free(used);
	else
		mas_push_node(mas, used);
}

static void mas_node_count(struct ma_state *mas, int count)
{
	unsigned long allocated = mas_allocated(mas);

	if (allocated < count) {
		mas_set_alloc_req(mas, count - allocated);
		mas_alloc_nodes(mas, GFP_NOWAIT | __GFP_NOWARN);
	}
}

/*
 * Sets up maple state for operations by setting mas->min = 0 & mas->node to
 * certain values.
 * returns:
 * - If mas->node is an error or MAS_START, return NULL.
 * - If it's an empty tree:     NULL & mas->node == MAS_NONE
 * - If it's a single entry:    The entry & mas->node == MAS_ROOT
 * - If it's a tree:            NULL & mas->node == safe root node.
 */
static inline struct maple_enode *mas_start(struct ma_state *mas)
{
	void *entry = NULL;

	if (mas_is_err(mas))
		return NULL;

	if (mas_is_start(mas)) {
		struct maple_enode *root;

		mas->node = MAS_NONE;
		mas->min = 0;
		mas->max = ULONG_MAX;
		mas->depth = 0;
		mas->offset = 0;
		if (!mas_root(mas)) // empty tree.
			goto done;

		root = mte_safe_root(mas_root(mas));

		if (xa_is_node(mas_root(mas))) {
			mas->node = root;
		} else {
			// Single entry tree.
			if (mas->index > 0)
				goto done;

			entry = mas_root(mas);
			mas->node = MAS_ROOT;
			mas->offset = MAPLE_NODE_SLOTS;
		}
	}

done:
	return entry;
}

/*
 * mas_data_end() - Find the end of the data (slot).
 * @mas: the maple state
 * @type: the type of maple node
 *
 * Returns: The zero indexed last slot with data (may be null).
 */
static inline unsigned char mas_data_end(struct ma_state *mas)
{
	enum maple_type type = mte_node_type(mas->node);
	unsigned char offset = mt_min_slots[type];
	unsigned long *pivots = ma_pivots(mas_mn(mas), type);

	if (type == maple_arange_64)
		return ma_meta_end(mte_to_node(mas->node), type);

	if (!pivots[offset])
		goto decrement;

	// Higher than the min.
	offset = mt_pivots[type] - 1;
	// Check exceptions outside of the loop.
	if (pivots[offset]) { // almost full.
		if (pivots[offset] != mas->max) // Totally full.
			return offset + 1;
		return offset;
	}

decrement:
	while (--offset) {
		if (pivots[offset])
			break;
	};
	if (pivots[offset] < mas->max)
		offset++;

	return offset;
}

/*
 * mas_leaf_max_gap() - Returns the largest gap in a leaf node
 *
 * @mas - the maple state
 */
static inline unsigned long mas_leaf_max_gap(struct ma_state *mas)
{
	enum maple_type mt = mte_node_type(mas->node);
	unsigned long pstart, pend, gap = 0, max_gap = 0;
	struct maple_node *mn = mas_mn(mas);
	unsigned long *pivots = ma_pivots(mn, mt);
	void **slots = ma_slots(mn, mt);
	unsigned char i;
	unsigned char max_piv;

	if (ma_is_dense(mt)) {
		for (i = 0; i < mt_slots[mt]; i++) {
			if (slots[i]) {
				if (gap > max_gap)
					max_gap = gap;
				gap = 0;
			} else {
				gap++;
			}
		}
		if (gap > max_gap)
			max_gap = gap;
		return max_gap;
	}

	// Removing the pivot overflow optimizes the loop below.
	max_piv = mt_pivots[mt] - 1;
	if (pivots[max_piv] && pivots[max_piv] != mas->max &&
	    !slots[max_piv + 1])
		max_gap = mas->max - pivots[max_piv];

	pstart = mas->min;
	for (i = 0; i < mt_pivots[mt]; i++) {
		pend = pivots[i];
		if (!pend && i)
			pend = mas->max;

		if (slots[i])
			goto next;

		gap = pend - pstart + 1;
		if (gap > max_gap)
			max_gap = gap;

next:
		if (pend >= mas->max)
			break;
		pstart = pend + 1;
	}
	return max_gap;
}
static inline unsigned long
ma_max_gap(struct maple_node *node, unsigned long *gaps, enum maple_type mt,
	    unsigned char *offset)
{
	unsigned char i = ma_meta_end(node, mt);
	unsigned long max_gap = 0;

	do {
		if (gaps[i] > max_gap) {
			max_gap = gaps[i];
			*offset = i;
		}
	} while(i--);

	return max_gap;
}

/*
 * mas_max_gap() - find the largest gap in a non-leaf node and set the slot.
 */
static inline unsigned long mas_max_gap(struct ma_state *mas)
{
	unsigned long *gaps;//, *pivots;
	unsigned char offset;
	enum maple_type mt;
	if (mte_is_leaf(mas->node))
		return mas_leaf_max_gap(mas);

	mt = mte_node_type(mas->node);
	gaps = ma_gaps(mas_mn(mas), mt);
	offset = ma_meta_gap(mas_mn(mas), mt);
	if (offset == 15)
		return 0;

	return gaps[offset];
}
static inline unsigned long mas_tree_gap(struct ma_state *mas)
{
	struct maple_node *pnode;
	unsigned long *gaps;
	enum maple_type mt;

	if (!mte_is_root(mas->node)) {

		pnode = mte_parent(mas->node);
		mt = mas_parent_enum(mas, mas->node);
		gaps = ma_gaps(pnode, mt);
		return gaps[mte_parent_slot(mas->node)];

	}
	return mas_max_gap(mas);
}
static inline void mas_parent_gap(struct ma_state *mas, unsigned char offset,
		unsigned long new)
{
	unsigned long meta_gap = 0;
	struct maple_node *pnode;
	struct maple_enode *penode;
	unsigned long *pgaps;
	unsigned char meta_offset;
	enum maple_type pmt;

	pnode = mte_parent(mas->node);
	pmt = mas_parent_enum(mas, mas->node);
	penode = mt_mk_node(pnode, pmt);
	pgaps = ma_gaps(pnode, pmt);

ascend:
	meta_offset = ma_meta_gap(pnode, pmt);
	if (meta_offset == 15)
		meta_gap = 0;
	else
		meta_gap = pgaps[meta_offset];

	pgaps[offset] = new;

	if (meta_gap == new)
		return;

	if (offset != meta_offset) {
	    if (meta_gap > new)
		return;

	    ma_set_meta_gap(pnode, pmt, offset);
	} else if (new < meta_gap) {
		meta_offset = 15;
		new = ma_max_gap(pnode, pgaps, pmt, &meta_offset);
		ma_set_meta_gap(pnode, pmt, meta_offset);
	}

	if (ma_is_root(pnode))
		return;

	/* Go to the parent node. */
	pnode = mte_parent(penode);
	pmt = mas_parent_enum(mas, penode);
	pgaps = ma_gaps(pnode, pmt);
	offset = mte_parent_slot(penode);
	penode = mt_mk_node(pnode, pmt);
	goto ascend;
}

/*
 * mas_update_gap() - Update a nodes gaps and propagate up if necessary.
 *
 * @mas - the maple state.
 */
static inline void mas_update_gap(struct ma_state *mas)
{
	unsigned char pslot;
	unsigned long p_gap, max_gap = 0;

	if (!mt_is_alloc(mas->tree))
		return;

	if (mte_is_root(mas->node))
		return;

	max_gap = mas_max_gap(mas);

	pslot = mte_parent_slot(mas->node);
	p_gap = ma_gaps(mte_parent(mas->node),
			mas_parent_enum(mas, mas->node))[pslot];

	if (p_gap != max_gap)
		mas_parent_gap(mas, pslot, max_gap);
}

/*
 * mas_first_entry() - Go the first leaf and find the first entry.
 *
 * @mas: the maple state.
 * @limit: the maximum index to check.
 * Returns: The start of the range.
 */
static inline unsigned long mas_first_entry(struct ma_state *mas,
		unsigned long limit)
{
	void **slots, *entry;
	unsigned long range_start = mas->min;

	while (!mte_is_leaf(mas->node)) {
		mas->max = mte_pivot(mas->node, 0);
		slots = ma_slots(mte_to_node(mas->node),
				     mte_node_type(mas->node));
		mas->node = slots[0];
	}

	slots = ma_slots(mte_to_node(mas->node), mte_node_type(mas->node));

	mas->offset = 0;
	while ((range_start < limit) && (mas->offset < mt_slot_count(mas->node))) {
		entry = mas_slot(mas, slots, mas->offset);
		if (entry)
			return range_start;
		range_start = mas_safe_pivot(mas, mas->offset) + 1;
		mas->offset++;
	}

	mas->node = MAS_NONE;
	return range_start;
}

/*
 * mas_adopt_children() - Set the parent pointer of all nodes in @parent to
 * @parent with the slot encoded.
 *
 * @mas - the maple state (for the tree)
 * @parent - the maple encoded node containing the children.
 */
static inline void mas_adopt_children(struct ma_state *mas,
		struct maple_enode *parent)
{

	enum maple_type type = mte_node_type(parent);
	void **slots = ma_slots(mte_to_node(mas->node), type);
	struct maple_enode *child;
	unsigned char offset;

	for (offset = 0; offset < mt_slots[type]; offset++) {
		child = slots[offset];
		if (!child)
			break;
		mte_set_parent(child, parent, offset);
	}
}

/*
 * mas_replace() - Replace a maple node in the tree with mas->node.  Uses the
 * parent encoding to locate the maple node in the tree.
 *
 * @mas - the ma_state to use for operations.
 * @advanced - boolean to adopt the child nodes and free the old node (false) or
 * leave the node (true) and handle the adoption and free elsewhere.
 */
static inline void mas_replace(struct ma_state *mas, bool advanced)
{
	struct maple_node *parent, *mn = mas_mn(mas);
	struct maple_enode *prev, *eparent = NULL;
	unsigned char offset = 0;
	void **slots;


	if (mte_is_root(mas->node)) {
		prev = mas_root_locked(mas);
	} else {
		enum maple_type ptype = mas_parent_enum(mas, mas->node);

		parent = mte_parent(mas->node);
		eparent = mt_mk_node(parent, ptype);
		offset = mte_parent_slot(mas->node);
		slots = ma_slots(parent, ptype);
		prev = slots[offset];
	}

	if (mte_to_node(prev) == mn)
		return;

	if (!advanced && !mte_is_leaf(mas->node))
		mas_adopt_children(mas, mas->node);

	if (mte_is_root(mas->node)) {
		mn->parent = ma_parent_ptr(
			      ((unsigned long)mas->tree | MA_ROOT_PARENT));
		rcu_assign_pointer(mas->tree->ma_root, mte_mk_root(mas->node));
		mas_set_height(mas);
	} else {
		mte_set_slot(eparent, offset, mas->node);
	}

	if (!advanced)
		mas_free(mas, prev);
}

/*
 * mas_new_child() - Find the new child of a node.
 * @mas: the maple state
 * @child: the maple state to store the child.
 *
 */
static inline bool mas_new_child(struct ma_state *mas, struct ma_state *child)
{
	enum maple_type mt = mte_node_type(mas->node);
	unsigned char offset;
	struct maple_enode *entry;
	void **slots = ma_slots(mte_to_node(mas->node), mt);

	for (offset = mas->offset; offset < mt_slots[mt]; offset++) {
		entry = slots[offset];
		if (!entry) // end of node data.
			break;

		if (mte_parent(entry) == mas_mn(mas)) {
			mas->offset = offset;
			mas_dup_state(child, mas);
			mas->offset = offset + 1;
			mas_descend(child);
			return true;
		}
	}
	return false;
}

/*
 * mab_shift_right() - Shift the data in mab right. Note, does not clean out the
 * old data or set b_node->b_end.
 *
 * @b_node: the maple_big_node
 * @shift: the shift count
 */
static inline void mab_shift_right(struct maple_big_node *b_node,
				 unsigned char shift)
{
	unsigned long size = b_node->b_end * sizeof(unsigned long);

	memmove(b_node->pivot + shift, b_node->pivot, size);
	memmove(b_node->slot + shift, b_node->slot, size);
	memmove(b_node->gap + shift, b_node->gap, size);
}

/*
 * mab_middle_node() - Check if a middle node is needed (unlikely)
 *
 * @b_node: the maple_big_node that contains the data.
 * @size: the amount of data in the b_node
 * @split: the potential split location
 * @slot_count: the size that can be stored in a single node being considered.
 * Returns: true if a middle node is required.
 */
static inline bool mab_middle_node(struct maple_big_node *b_node, int split,
				   unsigned char slot_count)
{
	unsigned char size = b_node->b_end;

	if (size >= 2 * slot_count)
		return true;

	if (!b_node->slot[split] && (size >= 2 * slot_count - 1))
		return true;

	return false;
}

/*
 * mab_no_null_split() - ensure the split doesn't fall on a NULL
 *
 * @b_node: the maple_big_node with the data
 * @split: the suggested split location
 * @slot_count: the number of slots in the node being considered.
 * Returns the split location.
 */
static inline int mab_no_null_split(struct maple_big_node *b_node,
				    unsigned char split, unsigned char slot_count)
{
	if (!b_node->slot[split]) {
		/* If the split is less than the max slot && the right side will
		 * still be sufficient, then increment the split on NULL.
		 */
		if ((split < slot_count - 1) &&
		    (b_node->b_end - split) > (mt_min_slots[b_node->type]))
			split++;
		else
			split--;
	}
	return split;
}

/*
 * mab_calc_split() - Calculate the split location and if there needs to be two
 * splits.
 *
 * @b_node: The maple_big_node with the data
 * @mid_split: The second split, if required.  0 otherwise.
 * Returns: The first split location.
 */
static inline int mab_calc_split(struct ma_state *mas,
				 struct maple_big_node *b_node,
				 unsigned char *mid_split)
{
	int split = b_node->b_end / 2; // Assume equal split.
	unsigned char slot_count = mt_slots[b_node->type];

	if (mab_middle_node(b_node, split, slot_count)) {
		split = b_node->b_end / 3;
		*mid_split = split * 2;
	} else {
		unsigned char min = mt_min_slots[b_node->type] - 1;

		*mid_split = 0;
		if ((mas->mas_flags & MA_STATE_BULK) &&
		    ma_is_leaf(b_node->type)) {
			min = 2;
			split = mt_slots[b_node->type] - min;
			mas->mas_flags |= MA_STATE_REBALANCE;
		}
		/* Avoid having a range less than the slot count unless it
		 * causes one node to be deficient.
		 * NOTE: mt_min_slots is 1 based, b_end and split are zero.
		 */
		while (((b_node->pivot[split] - b_node->min) < slot_count - 1) &&
		       (split < slot_count - 1) &&
		       (b_node->b_end - split > min))
			split++;
	}

	/* Avoid ending a node on a NULL entry */
	split = mab_no_null_split(b_node, split, slot_count);
	if (!(*mid_split))
		return split;

	*mid_split = mab_no_null_split(b_node, *mid_split, slot_count);

	return split;
}

/*
 * mas_mab_cp() - Copy data from a maple state inclusively to a maple_big_node
 * and set @b_node->b_end to the next free slot.
 *
 * @mas: The maple state
 * @mas_start: The starting slot to copy
 * @mas_end: The end slot to copy (inclusively)
 * @b_node: The maple_big_node to place the data
 * @mab_start: The starting location in maple_big_node to store the data.
 */
static inline void mas_mab_cp(struct ma_state *mas, unsigned char mas_start,
			unsigned char mas_end, struct maple_big_node *b_node,
			unsigned char mab_start)
{
	enum maple_type mt = mte_node_type(mas->node);
	struct maple_node *node = mte_to_node(mas->node);
	void **slots = ma_slots(node, mt);
	unsigned long *pivots = ma_pivots(node, mt);
	unsigned long *gaps = NULL;
	int i = mas_start, j = mab_start;

	for (i = mas_start, j = mab_start; i <= mas_end; i++, j++) {
		b_node->pivot[j] = _mas_safe_pivot(mas, pivots, i, mt);

		if ((mas->max == b_node->pivot[j]) ||
		    (j && !b_node->pivot[j])) {       // end of node.
			j++;
			break;
		}
	}

	memcpy(b_node->slot + mab_start,
	       slots + mas_start,
	       sizeof(void*) * (j - mab_start));

	if (!mte_is_leaf(mas->node) && mt_is_alloc(mas->tree)) {
		gaps = ma_gaps(node, mt);
		memcpy(b_node->gap + mab_start,
		       gaps + mas_start,
		       sizeof(unsigned long) * (j - mab_start));
	}
	b_node->b_end = j;
}

/*
 * mab_mas_cp() - Copy data from maple_big_node to a maple encoded node.
 * @b_node: the maple_big_node that has the data
 * @mab_start: the start location in @b_node.
 * @mab_end: The end location in @b_node (inclusively)
 * @mas: The maple state with the maple encoded node.
 */
static inline void mab_mas_cp(struct maple_big_node *b_node,
			      unsigned char mab_start, unsigned char mab_end,
			      struct ma_state *mas)
{
	int i, j = 0;
	enum maple_type mt = mte_node_type(mas->node);
	struct maple_node *node = mte_to_node(mas->node);
	void **slots = ma_slots(node, mt);
	unsigned long *pivots = ma_pivots(node, mt);
	unsigned long *gaps = NULL;

	if (mab_end - mab_start > mt_pivots[mt])
		mab_end--;

	for (i = mab_start; i <= mab_end; i++, j++) {
		if (j && !b_node->pivot[i])
			break;

		pivots[j] = b_node->pivot[i];
	}

	memcpy(slots, b_node->slot + mab_start,
	       sizeof(void*) * (i - mab_start));

	if (!ma_is_leaf(mt) && mt_is_alloc(mas->tree)) {
		unsigned long max_gap = 0;
		unsigned char offset = 15, tmp;
		unsigned char end = i - mab_start;
		gaps = ma_gaps(mas_mn(mas), mt);
		for (tmp = 0; tmp < end; tmp++) {
			gaps[tmp] = b_node->gap[mab_start + tmp];
			if (gaps[tmp] > max_gap) {
				offset = tmp;
				max_gap = gaps[tmp];
			}
		}
//		memcpy(gaps, b_node->gap + mab_start,
//		       sizeof(unsigned long) * end);
		ma_set_meta(node, mt, offset, end - 1);
	}
	mas->max = b_node->pivot[--i];
}

/*
 * mas_descend_adopt() - Descend through a sub-tree and adopt children who do
 * not have the correct parents set.  Follow the parents which have the correct
 * parents as they are the new entries which need to be followed to find other
 * incorrectly set parents.
 *
 * @mas: the maple state with the maple encoded node of the sub-tree.
 */
static inline void mas_descend_adopt(struct ma_state *mas)
{
	struct ma_state list[3], next[3];
	int i, n;

	for (i = 0; i < 3; i++) {
		mas_dup_state(&list[i], mas);
		list[i].offset = 0;
		next[i].offset = 0;
	}
	mas_dup_state(&next[0], mas);


	while (!mte_is_leaf(list[0].node))
	{
		n = 0;
		for (i = 0; i < 3; i++) {
			if (mas_is_none(&list[i]))
				continue;

			if (i && list[i-1].node == list[i].node)
				continue;

			while ((n < 3) && (mas_new_child(&list[i], &next[n])))
				n++;

			mas_adopt_children(&list[i], list[i].node);
		}

		while (n < 3)
			next[n++].node = MAS_NONE;

		for (i = 0; i < 3; i++) { // descend.
			next[i].offset = 0;
			mas_dup_state(&list[i], &next[i]);
		}
	}
}

static inline void mas_bulk_rebalance(struct ma_state *mas, unsigned char end,
				      enum maple_type mt)
{
	if (!(mas->mas_flags & MA_STATE_BULK))
		return;

	if (mte_is_root(mas->node))
		return;

	if (end > mt_min_slots[mt]) {
		mas->mas_flags &= ~MA_STATE_REBALANCE;
		return;
	}
}
/*
 * mas_store_b_node() - Store an @entry into the b_node while also copying the
 * data from a maple encoded node.
 *
 * @mas: the maple state
 * @b_node: the maple_big_node to fill with data
 * @entry: the data to store.
 * Returns: The actual end of the data stored in @b_node
 */
static inline unsigned char mas_store_b_node(struct ma_state *mas,
				    struct maple_big_node *b_node,
				    void *entry, unsigned char end)
{
	unsigned char slot = mas->offset;
	void *contents = mas_get_slot(mas, slot);
	unsigned char b_end = 0;
	// Possible underflow of piv will wrap back to 0 before use.
	unsigned long piv = mas->min - 1;
	unsigned long *pivots = ma_pivots(mas_mn(mas), b_node->type);

	// Copy start data up to insert.
	if (slot) {
		mas_mab_cp(mas, 0, slot - 1, b_node, 0);
		b_end = b_node->b_end;
		piv = b_node->pivot[b_end - 1];
	}

	// Handle range starting after old range
	if (piv + 1 < mas->index) {
		b_node->slot[b_end] = contents;
		if (!contents)
			b_node->gap[b_end] = mas->index - 1 - piv;
		b_node->pivot[b_end++] = mas->index - 1;
	}

	// Store the new entry.
	mas->offset = b_end;
	b_node->slot[b_end] = entry;
	b_node->pivot[b_end] = mas->last;

	// Handle new range ending before old range ends
	piv = _mas_safe_pivot(mas, pivots, slot, b_node->type);
	if (piv > mas->last) {
		if (piv == ULONG_MAX)
			mas_bulk_rebalance(mas, b_node->b_end, b_node->type);

		b_node->slot[++b_end] = contents;
		if (!contents)
			b_node->gap[b_end] = piv - mas->last + 1;
		b_node->pivot[b_end] = piv;
	} else
		piv = mas->last;

	// Appended.
	if (piv >= mas->max)
		return b_end;

	// Handle range overwrites
	do {
		piv = _mas_safe_pivot(mas, pivots, ++slot, b_node->type);
	} while ((piv <= mas->last) && (slot <= end));

	// Copy end data to the end of the node.
	if (piv > mas->last) {
		if (slot > end) {
			b_node->slot[++b_end] = NULL;
			b_node->pivot[b_end] = piv;
		} else {
			mas_mab_cp(mas, slot, end + 1, b_node, ++b_end);
			b_end = b_node->b_end - 1;
		}
	}

	return b_end;
}

static inline bool mas_node_walk(struct ma_state *mas, enum maple_type type,
		unsigned long *range_min, unsigned long *range_max);

/*
 * mas_prev_sibling() - Find the previous node with the same parent.
 *
 * @mas: the maple state
 * Returns: True if there is a previous sibling, false otherwise.
 */
static inline bool mas_prev_sibling(struct ma_state *mas)
{
	unsigned int p_slot = mte_parent_slot(mas->node);

	if (mte_is_root(mas->node))
		return false;

	if (!p_slot)
		return false;

	mas_ascend(mas);
	mas->offset = p_slot - 1;
	mas_descend(mas);
	return true;
}

/*
 * mas_next_sibling() - Find the next node with the same parent.
 *
 * @mas: the maple state
 * Returns true if there is a next sibling, false otherwise.
 */
static inline bool mas_next_sibling(struct ma_state *mas)
{
	MA_STATE(parent, mas->tree, mas->index, mas->last);

	if (mte_is_root(mas->node))
		return false;

	mas_dup_state(&parent, mas);
	mas_ascend(&parent);
	parent.offset = mte_parent_slot(mas->node) + 1;

	if (parent.offset == mt_slot_count(parent.node))
		return false;

	if (!mas_get_slot(&parent, parent.offset))
		return false;

	mas_dup_state(mas, &parent);
	mas_descend(mas);
	return true;
}

static inline struct maple_enode *mte_node_or_none(struct maple_enode *enode)
{
	if (enode)
		return enode;

	return ma_enode_ptr(MAS_NONE);
}

/*
 * mast_topiary() - Add the portions of the tree to the removal list; either to
 * be freed or discarded (destroy walk).
 *
 * @mast: The maple_subtree_state.
 */
static inline void mast_topiary(struct maple_subtree_state *mast)
{
	unsigned char l_off, r_off, offset;
	unsigned long l_index,  range_min, range_max;
	struct maple_enode *child;
	void **slots;

	// The left node is consumed, so add to the free list.
	l_index = mast->orig_l->index;
	mast->orig_l->index = mast->orig_l->last;
	mas_node_walk(mast->orig_l, mte_node_type(mast->orig_l->node),
		      &range_min, &range_max);
	mast->orig_l->index = l_index;
	l_off = mast->orig_l->offset;
	r_off = mast->orig_r->offset;
	if (mast->orig_l->node == mast->orig_r->node) {
		slots = ma_slots(mte_to_node(mast->orig_l->node),
				     mte_node_type(mast->orig_l->node));
		for (offset = l_off + 1; offset < r_off; offset++)
			mat_add(mast->destroy, slots[offset]);
		return;
	}
	/* mast->orig_r is different and consumed. */
	if (mte_is_leaf(mast->orig_r->node))
		return;

	/* Now destroy l_off + 1 -> end and 0 -> r_off - 1 */
	offset = l_off + 1;
	slots = ma_slots(mte_to_node(mast->orig_l->node),
			     mte_node_type(mast->orig_l->node));
	while (offset < mt_slot_count(mast->orig_l->node)) {
		child = slots[offset++];
		if (!child)
			break;
		mat_add(mast->destroy, child);
	}

	slots = ma_slots(mte_to_node(mast->orig_r->node),
			     mte_node_type(mast->orig_r->node));
	for (offset = 0; offset < r_off; offset++)
		mat_add(mast->destroy, slots[offset]);
}

static inline void mast_rebalance_next(struct maple_subtree_state *mast,
				       struct maple_enode *old_r)
{
	unsigned char b_end = mast->bn->b_end;

	mas_mab_cp(mast->orig_r, 0, mt_slot_count(mast->orig_r->node),
		   mast->bn, b_end);
	mat_add(mast->free, old_r);
	mast->orig_r->last = mast->orig_r->max;
	if (old_r == mast->orig_l->node)
		mast->orig_l->node = mast->orig_r->node;
}

static inline void mast_rebalance_prev(struct maple_subtree_state *mast,
				       struct maple_enode *old_l)
{
	unsigned char end = mas_data_end(mast->orig_l);
	unsigned char b_end = mast->bn->b_end;

	mab_shift_right(mast->bn, end + 1);
	mas_mab_cp(mast->orig_l, 0, end, mast->bn, 0);
	mat_add(mast->free, old_l);
	if (mast->orig_r->node == old_l)
		mast->orig_r->node = mast->orig_l->node;
	mast->l->min = mast->orig_l->min;
	mast->orig_l->index = mast->orig_l->min;
	mast->bn->b_end = end + 1 + b_end;
	mast->l->offset += end + 1;
}

static inline bool mast_sibling_rebalance_left(struct maple_subtree_state *mast)
{
	struct maple_enode *old_r = mast->orig_r->node;
	struct maple_enode *old_l = mast->orig_l->node;

	if (mas_prev_sibling(mast->orig_l)) {
		mast_rebalance_prev(mast, old_l);
		return true;
	}
	if (mas_next_sibling(mast->orig_r)) {
		mast_rebalance_next(mast, old_r);
		return true;
	}
	return false;
}

/*
 * mast_sibling_rebalance_right() - Rebalance from nodes with the same parents.
 * Check the right side, then the left.  Data is copied into the @mast->bn.
 *
 * @mast: The maple_subtree_state.
 */
static inline bool mast_sibling_rebalance_right(struct maple_subtree_state *mast)
{
	struct maple_enode *old_r = mast->orig_r->node;
	struct maple_enode *old_l = mast->orig_l->node;

	if (mas_next_sibling(mast->orig_r)) {
		mast_rebalance_next(mast, old_r);
		return true;
	}
	if (mas_prev_sibling(mast->orig_l)) {
		mast_rebalance_prev(mast, old_l);
		return true;
	}
	return false;
}

static inline void mas_prev_node(struct ma_state *mas, unsigned long limit);
static inline unsigned long mas_next_node(struct ma_state *mas,
		unsigned long max);
/*
 * mast_cousin_rebalance_right() - Rebalance from nodes with different parents.
 * Check the right side, then the left.  Data is copied into the @mast->bn.
 *
 * @mast: The maple_subtree_state.
 */
static inline bool mast_cousin_rebalance_right(struct maple_subtree_state *mast)
{
	struct maple_enode *old_l = mast->orig_l->node;
	struct maple_enode *old_r = mast->orig_r->node;
	MA_STATE(tmp, mast->orig_r->tree, mast->orig_r->index, mast->orig_r->last);

	mas_dup_state(&tmp, mast->orig_r);
	mas_next_node(mast->orig_r, ULONG_MAX);
	if (!mas_is_none(mast->orig_r)) {
		mast_rebalance_next(mast, old_r);
		return true;
	}

	mas_dup_state(mast->orig_r, mast->orig_l);
	mas_dup_state(mast->r, mast->l);
	mas_prev_node(mast->orig_l, 0);
	if (mas_is_none(mast->orig_l)) {
		// This is going to be a new root with the contents of mast->bn
		mas_dup_state(mast->orig_l, mast->orig_r);
		mas_dup_state(mast->orig_r, &tmp);
		return false;
	}

	mast->orig_l->offset = 0;
	mast_rebalance_prev(mast, old_l);
	return true;
}

/*
 * mast_ascend_free() - Add current original maple state nodes to the free list
 * and ascend.
 * @mast: the maple subtree state.
 *
 * Ascend the original left and right sides and add the previous nodes to the
 * free list.  Set the slots to point to the correct location in the new nodes.
 */
static inline void
mast_ascend_free(struct maple_subtree_state *mast)
{
	struct maple_enode *left = mast->orig_l->node;
	struct maple_enode *right = mast->orig_r->node;
	unsigned long range_min, range_max;

	mas_ascend(mast->orig_l);
	mas_ascend(mast->orig_r);
	mat_add(mast->free, left);
	if (left != right)
		mat_add(mast->free, right);

	mast->orig_r->offset = 0;
	mast->orig_r->index = mast->r->max;
	/* last should be larger than or equal to index */
	if (mast->orig_r->last < mast->orig_r->index)
		mast->orig_r->last = mast->orig_r->index;
	/* The node may not contain the value so set slot to ensure all
	 * of the nodes contents are freed or destroyed.
	 */
	if (!mas_node_walk(mast->orig_r,
			   mte_node_type(mast->orig_r->node),
			   &range_min, &range_max)) {
		mast->orig_r->offset = mas_data_end(mast->orig_r) + 1;
	}
	/* Set up the left side of things */
	mast->orig_l->offset = 0;
	mast->orig_l->index = mast->l->min;
	mas_node_walk(mast->orig_l, mte_node_type(mast->orig_l->node),
		      &range_min, &range_max);
}

/*
 * mas_new_ma_node() - Create and return a new maple node.  Helper function.
 * @mas: the maple state with the allocations.
 * @b_node: the maple_big_node with the type encoding.
 *
 * Use the node type from the maple_big_node to allocate a new node from the
 * maple_state.  This function exists mainly for code readability.
 *
 * Returns: A new maple encoded node
 */
static inline struct maple_enode
*mas_new_ma_node(struct ma_state *mas, struct maple_big_node *b_node)
{
	return mt_mk_node(ma_mnode_ptr(mas_pop_node(mas)), b_node->type);
}

/*
 * mas_mab_to_node() - Set up right and middle nodes
 *
 * @mas: the maple state that contains the allocations.
 * @b_node: the node which contains the data.
 * @left: The pointer which will have the left node
 * @right: The pointer which may have the right node
 * @middle: the pointer which may have the middle node (rare)
 * @mid_split: the split location for the middle node
 *
 * Returns: the split of left.
 */
static inline unsigned char mas_mab_to_node(struct ma_state *mas,
					    struct maple_big_node *b_node,
					    struct maple_enode **left,
					    struct maple_enode **right,
					    struct maple_enode **middle,
					    unsigned char *mid_split)
{
	unsigned char split = 0;
	unsigned char slot_count = mt_slots[b_node->type];

	*left = mas_new_ma_node(mas, b_node);
	*right = NULL;
	*middle = NULL;
	*mid_split = 0;

	if (b_node->b_end < slot_count) {
		split = b_node->b_end;
	} else {
		split = mab_calc_split(mas, b_node, mid_split);
		*right = mas_new_ma_node(mas, b_node);
	}

	if (*mid_split)
		*middle = mas_new_ma_node(mas, b_node);

	return split;

}

/*
 * mab_set_b_end() - Add entry to b_node at b_node->b_end and increment the end
 * pointer.
 * @b_node - the big node to add the entry
 * @mas - the maple state to get the pivot (mas->max)
 * @entry - the entry to add, if NULL nothing happens.
 */
static inline void mab_set_b_end(struct maple_big_node *b_node,
				 struct ma_state *mas,
				 void *entry)
{
	if (!entry)
		return;

	b_node->slot[b_node->b_end] = entry;
	if (mt_is_alloc(mas->tree))
		b_node->gap[b_node->b_end] = mas_max_gap(mas);
	b_node->pivot[b_node->b_end++] = mas->max;
}

/*
 * mas_set_split_parent() - combine_then_separate helper function.  Sets the parent
 * of @mas->node to either @left or @right, depending on @slot and @split
 *
 * @mas - the maple state with the node that needs a parent
 * @left - possible parent 1
 * @right - possible parent 2
 * @slot - the slot the mas->node was placed
 * @split - the split location between @left and @right
 */
static inline void mas_set_split_parent(struct ma_state *mas,
					struct maple_enode *left,
					struct maple_enode *right,
					unsigned char *slot, unsigned char split)
{
	if (mas_is_none(mas))
		return;

	if ((*slot) <= split)
		mte_set_parent(mas->node, left, *slot);
	else if (right)
		mte_set_parent(mas->node, right, (*slot) - split - 1);

	(*slot)++;
}

/*
 * mte_mid_split_check() - Check if the next node passes the mid-split
 */
static inline void mte_mid_split_check(struct maple_enode **l,
				       struct maple_enode **r,
				       struct maple_enode *right,
				       unsigned char slot,
				       unsigned char *split,
				       unsigned char mid_split)
{
	if (*r == right)
		return;

	if (slot < mid_split)
		return;

	*l = *r;
	*r = right;
	*split = mid_split;
}

/*
 * mast_set_split_parents() - Helper function to set three nodes parents.  Slot
 * is taken from @mast->l.
 *
 * @mast - the maple subtree state
 * @left - the left node
 * @right - the right node
 * @split - the split location.
 */
static inline void mast_set_split_parents(struct maple_subtree_state *mast,
					  struct maple_enode *left,
					  struct maple_enode *middle,
					  struct maple_enode *right,
					  unsigned char split,
					  unsigned char mid_split)
{
	unsigned char slot;
	struct maple_enode *l = left;
	struct maple_enode *r = right;

	if (mas_is_none(mast->l))
		return;

	if (middle)
		r = middle;

	slot = mast->l->offset;

	mte_mid_split_check(&l, &r, right, slot, &split, mid_split);
	// Set left parent.
	mas_set_split_parent(mast->l, l, r, &slot, split);

	mte_mid_split_check(&l, &r, right, slot, &split, mid_split);
	// Set middle parent.
	mas_set_split_parent(mast->m, l, r, &slot, split);

	mte_mid_split_check(&l, &r, right, slot, &split, mid_split);
	// Set right parent.
	mas_set_split_parent(mast->r, l, r, &slot, split);
}

static inline void mas_wmb_replace(struct ma_state *mas,
				   struct ma_topiary *free,
				   struct ma_topiary *destroy)
{
	 /* All nodes must see old data as dead prior to replacing that data.  */
	smp_wmb();

	// Insert the new data in the tree
	mas_replace(mas, true);

	if (!mte_is_leaf(mas->node))
		mas_descend_adopt(mas);

	mas_mat_free(mas, free, false);

	if (destroy)
		mas_mat_free(mas, destroy, true);

	if (mte_is_leaf(mas->node))
		return;

	mas_update_gap(mas);
}

static inline void mast_new_root(struct maple_subtree_state *mast,
				 struct ma_state *mas)
{
	mas_mn(mast->l)->parent =
		ma_parent_ptr(((unsigned long)mas->tree | MA_ROOT_PARENT));
	if (!mte_dead_node(mast->orig_l->node) &&
	    !mte_is_root(mast->orig_l->node)) {
		do {
			mast_ascend_free(mast);
			mast_topiary(mast);
		} while (!mte_is_root(mast->orig_l->node));
	}
	if ((mast->orig_l->node != mas->node) &&
		   (mast->l->depth > mas_mt_height(mas))) {
		mat_add(mast->free, mas->node);
	}
}

static inline void mast_cp_to_nodes(struct maple_subtree_state *mast,
				    struct maple_enode *left,
				    struct maple_enode *middle,
				    struct maple_enode *right,
				    unsigned char split,
				    unsigned char mid_split)
{
	mast->l->node = mte_node_or_none(left);
	mast->m->node = mte_node_or_none(middle);
	mast->r->node = mte_node_or_none(right);

	mast->l->min = mast->orig_l->min;
	mast->l->max = mast->bn->pivot[split];
	mab_mas_cp(mast->bn, 0, split, mast->l);
	mast->r->max = mast->l->max;

	if (middle) {
		mab_mas_cp(mast->bn, 1 + split, mid_split, mast->m);
		mast->m->min = mast->bn->pivot[split] + 1;
		mast->m->max = mast->bn->pivot[mid_split];
		split = mid_split;
	}

	if (right) {
		mab_mas_cp(mast->bn, 1 + split, mast->bn->b_end, mast->r);
		mast->r->min = mast->bn->pivot[split] + 1;
		mast->r->max = mast->bn->pivot[mast->bn->b_end];
	}
}

/*
 * Copy in the original left side of the tree into the combined data set in the
 * maple subtree state big node.
 */
static inline void mast_combine_cp_left(struct maple_subtree_state *mast)
{
	unsigned char l_slot = mast->orig_l->offset;

	if (!l_slot)
		return;

	mas_mab_cp(mast->orig_l, 0, l_slot - 1, mast->bn, 0);
}

/*
 * Copy in the original right side of the tree into the combined data set in
 * the maple subtree state big node.
 */
static inline void mast_combine_cp_right(struct maple_subtree_state *mast)
{
	if (mast->bn->pivot[mast->bn->b_end - 1] >= mast->orig_r->max)
		return;

	mas_mab_cp(mast->orig_r, mast->orig_r->offset + 1,
		   mt_slot_count(mast->orig_r->node), mast->bn,
		   mast->bn->b_end);
	mast->orig_r->last = mast->orig_r->max;
}

/* Check if the maple subtree state has enough data in the big node to create at
 * least one sufficient node
 */
static inline bool mast_sufficient(struct maple_subtree_state *mast)
{
	if (mast->bn->b_end > mt_min_slot_count(mast->orig_l->node))
		return true;

	return false;
}

static inline bool mast_overflow(struct maple_subtree_state *mast)
{
	if (mast->bn->b_end >= mt_slot_count(mast->orig_l->node))
		return true;

	return false;
}

static inline void mast_setup_bnode_for_split(struct maple_subtree_state *mast)
{
	mast->bn->b_end--;
	mast->bn->min = mast->orig_l->min;
	mast->bn->type = mte_node_type(mast->orig_l->node);
}

/*
 *
 * mas_spanning_rebalance() - Rebalance across two nodes which may not be peers.
 * @mas: The starting maple state
 * @mast: The maple_subtree_state, keeps track of 4 maple states.
 * @count: The estimated count of iterations needed.
 *
 * Follow the tree upwards from @l_mas and @r_mas for @count, or until the root
 * is hit.  First @b_node is split into two entries which are inserted into the
 * next iteration of the loop.  @b_node is returned populated with the final
 * iteration. @mas is used to obtain allocations.  orig_l_mas keeps track of the
 * nodes that will remain active by using orig_l_mas->index and orig_l_mas->last
 * to account of what has been copied into the new sub-tree.  The update of
 * orig_l_mas->last is used in mas_consume to find the slots that will need to
 * be either freed or destroyed.  orig_l_mas->depth keeps track of the height of
 * the new sub-tree in case the sub-tree becomes the full tree.
 *
 * Returns the number of elements in b_node during the last loop.
 */
static inline int mas_spanning_rebalance(struct ma_state *mas,
					 struct maple_subtree_state *mast,
					 unsigned char count)
{
	unsigned char split, mid_split;
	unsigned char slot = 0;
	struct maple_enode *left = NULL, *middle = NULL, *right = NULL;

	MA_STATE(l_mas, mas->tree, mas->index, mas->index);
	MA_STATE(r_mas, mas->tree, mas->index, mas->index);
	MA_STATE(m_mas, mas->tree, mas->index, mas->index);
	MA_TOPIARY(free, mas->tree);
	MA_TOPIARY(destroy, mas->tree);

	mast->l = &l_mas;
	mast->m = &m_mas;
	mast->r = &r_mas;
	mast->free = &free;
	mast->destroy = &destroy;
	l_mas.node = r_mas.node = m_mas.node = MAS_NONE;

	MT_BUG_ON(mas->tree, mast->orig_l->depth != mast->orig_r->depth);
	mast->orig_l->depth = 0;
	mast_topiary(mast);
	while (count--) {
		mast_setup_bnode_for_split(mast);
		split = mas_mab_to_node(mas, mast->bn, &left, &right, &middle,
					&mid_split);
		mast_set_split_parents(mast, left, middle, right, split,
				       mid_split);
		mast_cp_to_nodes(mast, left, middle, right, split, mid_split);

		/* Copy data from next level in the tree to mast->bn from next iteration */
		memset(mast->bn, 0, sizeof(struct maple_big_node));
		mast->bn->type = mte_node_type(left);
		mast->orig_l->depth++;

		// Root already stored in l->node.
		if (mas_is_root_limits(mast->l))
			goto new_root;

		mast_ascend_free(mast);
		mast_combine_cp_left(mast);
		l_mas.offset = mast->bn->b_end;
		mab_set_b_end(mast->bn, &l_mas, left);
		mab_set_b_end(mast->bn, &m_mas, middle);
		mab_set_b_end(mast->bn, &r_mas, right);

		// Copy anything necessary out of the right node.
		mast_combine_cp_right(mast);
		mast_topiary(mast);
		mast->orig_l->last = mast->orig_l->max;

		if (mast_sufficient(mast))
			continue;

		if (mast_overflow(mast))
			continue;

		// May be a new root stored in mast->bn
		if (mas_is_root_limits(mast->orig_l))
			break;


		// Try to get enough data for the next iteration.
		if (!mast_sibling_rebalance_right(mast))
			if (!mast_cousin_rebalance_right(mast))
				break;

		// rebalancing from other nodes may require another loop.
		if (!count)
			count++;
	}
	l_mas.node = mt_mk_node(ma_mnode_ptr(mas_pop_node(mas)),
				mte_node_type(mast->orig_l->node));
	mast->orig_l->depth++;
	mab_mas_cp(mast->bn, 0, mt_slots[mast->bn->type] - 1, &l_mas);
	mte_set_parent(left, l_mas.node, slot);
	if (middle)
		mte_set_parent(middle, l_mas.node, ++slot);

	if (right)
		mte_set_parent(right, l_mas.node, ++slot);

new_root:
	if (mas_is_root_limits(mast->l))
		mast_new_root(mast, mas);
	else
		mas_mn(&l_mas)->parent = mas_mn(mast->orig_l)->parent;

	if (!mte_dead_node(mast->orig_l->node))
		mat_add(&free, mast->orig_l->node);

	mas_dup_state(mast->orig_l, &l_mas);
	mas->depth = mast->orig_l->depth;
	mte_set_node_dead(mas->node);
	// Set up mas for insertion.
	mas_dup_state(mas, mast->orig_l);
	mas_wmb_replace(mas, &free, &destroy);
	return mast->bn->b_end;
}

/*
 * mas_rebalance() - Rebalance a given node.
 *
 * @mas: The maple state
 * @b_node: The big maple node.
 *
 * Rebalance two nodes into a single node or two new nodes that are sufficient.
 * Continue upwards until tree is sufficient.
 *
 * Returns the number of elements in b_node during the last loop.
 */
static inline int mas_rebalance(struct ma_state *mas,
				   struct maple_big_node *b_node)
{
	char empty_count = mas_mt_height(mas);
	struct maple_subtree_state mast;
	unsigned char shift, b_end = ++b_node->b_end;

	MA_STATE(l_mas, mas->tree, mas->index, mas->last);
	MA_STATE(r_mas, mas->tree, mas->index, mas->last);

	trace_mas_rebalance(mas);

	mas_node_count(mas, 1 + empty_count * 3);
	if (mas_is_err(mas))
		return 0;


	mast.orig_l = &l_mas;
	mast.orig_r = &r_mas;
	mast.bn = b_node;

	mas_dup_state(&l_mas, mas);
	mas_dup_state(&r_mas, mas);

	if (mas_next_sibling(&r_mas)) {
		MT_BUG_ON(r_mas.tree, mas_is_none(&r_mas));
		mas_mab_cp(&r_mas, 0, mt_slot_count(r_mas.node), b_node, b_end);
		r_mas.last = r_mas.index = r_mas.max;

	} else {
		mas_prev_sibling(&l_mas);
		shift = mas_data_end(&l_mas) + 1;
		mab_shift_right(b_node, shift);
		mas_mab_cp(&l_mas, 0, shift - 1, b_node, 0);
		b_node->b_end = shift + b_end;
		l_mas.index = l_mas.last = l_mas.min;
	}

	return mas_spanning_rebalance(mas, &mast, empty_count);
}

static inline void mas_destroy_rebalance(struct ma_state *mas,
					 unsigned char mas_end)
{
	enum maple_type mt = mte_node_type(mas->node);
	struct maple_node reuse, *newnode, *parent, *new_left;
	struct maple_enode *eparent;
	unsigned char offset, tmp, split = mt_slots[mt] / 2;
	void **l_slots, **slots;
	unsigned long *l_pivs, *pivs, gap;

	MA_STATE(l_mas, mas->tree, mas->index, mas->last);

	mas_dup_state(&l_mas, mas);
	mas_prev_sibling(&l_mas);

	// set up node.
	if (mt_in_rcu(mas->tree)) {
		mas_node_count(mas, 3);  // both left and right as well as parent.
		if (mas_is_err(mas)) // FIXME
			return;

		newnode = mas_pop_node(mas);
	} else {
		memset(&reuse, 0, sizeof(struct maple_node));
		newnode = &reuse;
	}

	newnode->parent = mas_mn(mas)->parent;
	pivs = ma_pivots(newnode, mt);



	slots = ma_slots(newnode, mt);
	pivs = ma_pivots(newnode, mt);
	l_slots = ma_slots(mas_mn(&l_mas), mt);
	l_pivs = ma_pivots(mas_mn(&l_mas), mt);
	if (!l_slots[split])
		split++;
	tmp = mas_data_end(&l_mas) - split;

	memcpy(slots, l_slots + split + 1, sizeof(void *) * tmp);
	memcpy(pivs, l_pivs + split + 1, sizeof(unsigned long) * tmp);
	pivs[tmp] = l_mas.max;
	memcpy(slots + tmp, ma_slots(mas_mn(mas), mt), sizeof(void *) * mas_end);
	memcpy(pivs + tmp, ma_pivots(mas_mn(mas), mt), sizeof(unsigned long) * mas_end);

	l_mas.max = l_pivs[split];
	mas->min = l_mas.max + 1;
	eparent = mt_mk_node(mte_parent(l_mas.node),
			     mas_parent_enum(&l_mas, l_mas.node));
	if (!mt_in_rcu(mas->tree)) {

		memcpy(mas_mn(mas), newnode, sizeof(struct maple_node));
		mte_set_pivot(eparent, mte_parent_slot(l_mas.node),
			      l_pivs[split]);
		// Remove data from l_pivs.
		tmp = split + 1;
		memset(l_pivs + tmp, 0,
		       sizeof(unsigned long) * (mt_pivots[mt] - tmp));
		memset(l_slots + tmp, 0,
		       sizeof(void *) * (mt_slots[mt] - tmp));

		goto done;
	}

	// RCU requires replacing both l_mas, mas, and parent.
	// replace mas
	mas->node = mt_mk_node(newnode, mt);

	// replace l_mas
	new_left = mas_pop_node(mas);
	new_left->parent = mas_mn(&l_mas)->parent;
	mt = mte_node_type(l_mas.node);
	slots = ma_slots(new_left, mt);
	pivs = ma_pivots(new_left, mt);
	memcpy(slots, l_slots, sizeof(void *) * split);
	memcpy(pivs, l_pivs, sizeof(unsigned long) * split);
	l_mas.node = mt_mk_node(new_left, mt);


	// replace parent.
	offset = mte_parent_slot(mas->node);
	mt = mas_parent_enum(&l_mas, l_mas.node);
	parent = mas_pop_node(mas);
	slots = ma_slots(parent, mt);
	pivs = ma_pivots(parent, mt);
	memcpy(parent, mte_to_node(eparent), sizeof(struct maple_node));
	slots[offset] = mas->node;
	slots[offset - 1] = l_mas.node;
	pivs[offset - 1] = l_mas.max;
	eparent = mt_mk_node(parent, mt);
done:
	gap = mas_leaf_max_gap(mas);
	mte_set_gap(eparent, mte_parent_slot(mas->node), gap);
	gap = mas_leaf_max_gap(&l_mas);
	mte_set_gap(eparent, mte_parent_slot(l_mas.node), gap);
	mas_ascend(mas);

	if (mt_in_rcu(mas->tree))
		mas_replace(mas, false);

	mas_update_gap(mas);
}

static inline bool _mas_split_final_node(struct maple_subtree_state *mast,
					struct ma_state *mas, int height)
{
	struct maple_enode *ancestor;

	if (mte_is_root(mas->node)) {
		if (mt_is_alloc(mas->tree))
			mast->bn->type = maple_arange_64;
		else
			mast->bn->type = maple_range_64;
		mas->depth = height;
	}
	/* Only a single node is used here, could be root.
	 * Big_node should just fit in a single node.
	 */
	ancestor = mas_new_ma_node(mas, mast->bn);
	mte_set_parent(mast->l->node, ancestor, mast->l->offset);
	mte_set_parent(mast->r->node, ancestor, mast->r->offset);
	mte_to_node(ancestor)->parent = mas_mn(mas)->parent;

	mast->l->node = ancestor;
	mab_mas_cp(mast->bn, 0, mt_slots[mast->bn->type] - 1, mast->l);
	mas->offset = mast->bn->b_end - 1;
	return true;
}

static inline bool mas_split_final_node(struct maple_subtree_state *mast,
					struct ma_state *mas, int height)
{
	if (mt_slots[mast->bn->type] <= mast->bn->b_end)
		return false;

	return _mas_split_final_node(mast, mas, height);
}

static inline void mast_fill_bnode(struct maple_subtree_state *mast,
					 struct ma_state *mas,
					 unsigned char skip)
{
	bool cp = true;
	struct maple_enode *old = mas->node;
	unsigned char split;

	memset(mast->bn, 0, sizeof(struct maple_big_node));
	if (mte_is_root(mas->node)) {
		cp = false;
	} else {
		mas_ascend(mas);
		mat_add(mast->free, old);
		mas->offset = mte_parent_slot(mas->node);
	}

	mast->bn->min = mas->min;
	if (cp && mast->l->offset)
		mas_mab_cp(mas, 0, mast->l->offset - 1, mast->bn, 0);

	split = mast->bn->b_end;
	mab_set_b_end(mast->bn, mast->l, mast->l->node);
	mast->r->offset = mast->bn->b_end;
	mab_set_b_end(mast->bn, mast->r, mast->r->node);
	if (mast->bn->pivot[mast->bn->b_end - 1] == mas->max)
		cp = false;

	if (cp)
		mas_mab_cp(mas, split + skip, mt_slot_count(mas->node) - 1,
			   mast->bn, mast->bn->b_end);
	mast->bn->b_end--;
	mast->bn->type = mte_node_type(mas->node);
}


static inline void mast_split_data(struct maple_subtree_state *mast,
				   struct ma_state *mas,
				   unsigned char split)
{
	unsigned char p_slot;

	mab_mas_cp(mast->bn, 0, split, mast->l);
	mte_set_pivot(mast->r->node, 0, mast->r->max);
	mab_mas_cp(mast->bn, split + 1, mast->bn->b_end, mast->r);
	mast->l->offset = mte_parent_slot(mas->node);
	mast->l->max = mast->bn->pivot[split];
	mast->r->min = mast->l->max + 1;
	if (!mte_is_leaf(mas->node)) {
		p_slot = mast->orig_l->offset;
		mas_set_split_parent(mast->orig_l, mast->l->node,
				     mast->r->node, &p_slot, split);
		mas_set_split_parent(mast->orig_r, mast->l->node,
				     mast->r->node, &p_slot, split);
	}
}

static inline bool mas_push_data(struct ma_state *mas, int height,
				 struct maple_subtree_state *mast, bool left)
{
	unsigned char slot_total = mast->bn->b_end;
	unsigned char end, space, split;

	MA_STATE(tmp_mas, mas->tree, mas->index, mas->last);
	mas_dup_state(&tmp_mas, mast->l); // for depth.
	tmp_mas.node = mas->node;

	if (left && !mas_prev_sibling(&tmp_mas))
		return false;
	else if (!left && !mas_next_sibling(&tmp_mas))
		return false;

	end = mas_data_end(&tmp_mas);
	slot_total += end;
	space = 2 * mt_slot_count(mas->node) - 2;
	/* -2 instead of -1 to ensure there isn't a triple split */
	if (ma_is_leaf(mast->bn->type))
		space--;

	if (mas->max == ULONG_MAX)
		space--;

	if (slot_total >= space)
		return false;

	/* Get the data; Fill mast->bn */
	mast->bn->b_end++;
	if (left) {
		mab_shift_right(mast->bn, end + 1);
		mas_mab_cp(&tmp_mas, 0, end, mast->bn, 0);
		mast->bn->b_end = slot_total + 1;
	} else {
		mas_mab_cp(&tmp_mas, 0, end, mast->bn, mast->bn->b_end);
	}

	/* Configure mast for splitting of mast->bn */
	split = mt_slots[mast->bn->type] - 2;
	if (left) {
		/*  Switch mas to prev node  */
		mat_add(mast->free, mas->node);
		mas_dup_state(mas, &tmp_mas);
		/* Start using mast->l for the left side. */
		tmp_mas.node = mast->l->node;
		mas_dup_state(mast->l, &tmp_mas);
	} else {
		mat_add(mast->free, tmp_mas.node);
		tmp_mas.node = mast->r->node;
		mas_dup_state(mast->r, &tmp_mas);
		split = slot_total - split;
	}
	split = mab_no_null_split(mast->bn, split, mt_slots[mast->bn->type]);
	// Update parent slot for split calculation.
	if (left)
		mast->orig_l->offset += end + 1;

	mast_split_data(mast, mas, split);
	mast_fill_bnode(mast, mas, 2);
	_mas_split_final_node(mast, mas, height + 1);
	return true;
}

static inline bool mas_push_right(struct ma_state *mas, int height,
				 struct maple_subtree_state *mast)
{
	return mas_push_data(mas, height, mast, false);
}

static inline bool mas_push_left(struct ma_state *mas, int height,
				 struct maple_subtree_state *mast)
{
	return mas_push_data(mas, height, mast, true);
}

static inline int mas_split(struct ma_state *mas,
			    struct maple_big_node *b_node)
{

	struct maple_subtree_state mast;
	int height = 0;
	unsigned char mid_split, split = 0;

	MA_STATE(l_mas, mas->tree, mas->index, mas->last);
	MA_STATE(r_mas, mas->tree, mas->index, mas->last);
	MA_STATE(prev_l_mas, mas->tree, mas->index, mas->last);
	MA_STATE(prev_r_mas, mas->tree, mas->index, mas->last);
	MA_TOPIARY(mat, mas->tree);

	trace_mas_split(mas);
	mas->depth = mas_mt_height(mas);
	// Allocation failures will happen early.
	mas_node_count(mas, 1 + mas->depth * 2);
	if (mas_is_err(mas))
		return 0;

	mast.l = &l_mas;
	mast.r = &r_mas;
	mast.orig_l = &prev_l_mas;
	mast.orig_r = &prev_r_mas;
	mast.free = &mat;
	mast.bn = b_node;

	while (height++ <= mas->depth) {
		if (mas_split_final_node(&mast, mas, height))
			break;

		mas_dup_state(&l_mas, mas);
		mas_dup_state(&r_mas, mas);
		mast.l->node = mas_new_ma_node(mas, b_node);
		mast.r->node = mas_new_ma_node(mas, b_node);
		if (mas_push_left(mas, height, &mast))
			break;

		if (mas_push_right(mas, height, &mast))
			break;

		split = mab_calc_split(mas, mast.bn, &mid_split);
		mast_split_data(&mast, mas, split);
		// Usually correct, mab_mas_cp in the above call overwrites r->max.
		mast.r->max = mas->max;
		mast_fill_bnode(&mast, mas, 1);
		mas_dup_state(&prev_l_mas, mast.l);
		mas_dup_state(&prev_r_mas, mast.r);
	}

	// Set the original node as dead
	mat_add(mast.free, mas->node);
	mas->node = l_mas.node;
	mas_wmb_replace(mas, mast.free, NULL);
	return 1;
}

static inline bool mas_reuse_node(struct ma_state *mas,
				  struct maple_big_node *bn,
				  unsigned char end)
{
	int i;
	unsigned long max = mas->max;

	if (mt_in_rcu(mas->tree))
		return false; // Need to be rcu safe.

	mab_mas_cp(bn, 0, bn->b_end, mas);
	mas->max = max;

	// Zero end of node.
	if (end > bn->b_end) {
		for (i = bn->b_end + 1; i < mt_slot_count(mas->node); i++) {
			mte_set_slot(mas->node, i, NULL);
			if (i < mt_pivot_count(mas->node))
				mte_set_pivot(mas->node, i, 0);

		//	if (!mte_is_leaf(mas->node) && mt_is_alloc(mas->tree))
		//		mte_set_gap(mas->node, i, 0);
		}

	}
	return true;

}

static inline int mas_commit_b_node(struct ma_state *mas,
				    struct maple_big_node *b_node,
				    unsigned char end)
{
	struct maple_enode *new_node;

	if ((b_node->b_end < mt_min_slots[b_node->type]) &&
	    (!mte_is_root(mas->node)) && (mas_mt_height(mas) > 1))
		return mas_rebalance(mas, b_node);


	if (b_node->b_end >= mt_slots[b_node->type])
		return mas_split(mas, b_node);

	if (mas_reuse_node(mas, b_node, end))
		goto reused_node;

	mas_node_count(mas, 1);
	if (mas_is_err(mas))
		return 0;

	new_node = mt_mk_node(mas_pop_node(mas), mte_node_type(mas->node));
	mte_to_node(new_node)->parent = mas_mn(mas)->parent;
	mas->node = new_node;

	mab_mas_cp(b_node, 0, b_node->b_end, mas);
	mas_replace(mas, false);
reused_node:
	mas_update_gap(mas);
	return 2;
}

static inline int mas_root_expand(struct ma_state *mas, void *entry)
{
	void *contents = mas_root_locked(mas);
	enum maple_type type = maple_leaf_64;
	struct maple_node *node;
	void **slots;
	unsigned long *pivots;
	int slot = 0;


	mas_node_count(mas, 1);
	if (mas_is_err(mas))
		return 0;

	node = mas_pop_node(mas);
	pivots = ma_pivots(node, type);
	slots = ma_slots(node, type);
	mas->node = mt_mk_node(node, type);
	mas_mn(mas)->parent = ma_parent_ptr(
		      ((unsigned long)mas->tree | MA_ROOT_PARENT));

	if (contents)
		slots[slot++] = contents;

	if (!mas->index && slot)
		slot--;
	else if (mas->index > 1)
		pivots[slot++] = mas->index - 1;

	slots[slot] = entry;
	pivots[slot++] = mas->last;
	/* swap the new root into the tree */
	rcu_assign_pointer(mas->tree->ma_root, mte_mk_root(mas->node));
	mas->depth = 1;
	mas_set_height(mas);
	return slot;
}

static inline int ma_root_ptr(struct ma_state *mas, void *entry,
		void *contents, bool overwrite)
{
	int ret = 1;

	if (xa_is_node(mas_root(mas)))
		return 0;

	if (mas_root(mas) && mas->last == 0) {
		contents = mas_root_locked(mas);
		if (!overwrite)
			goto exists;
	} else {
		contents = NULL;
	}

	if (mas->last != 0)
		ret = mas_root_expand(mas, entry);
	else if (((unsigned long) (entry) & 3) == 2)
		ret = mas_root_expand(mas, entry);
	else
		rcu_assign_pointer(mas->tree->ma_root, entry);
	return ret;

exists:
	mas_set_err(mas, -EEXIST);
	return 0;
}

/*
 *
 * mas_is_span_() - Check if the write spans the node.
 * entry being written spans this nodes slot or touches the end of this slot and
 * is NULL.
 * @piv - the pivot of the slot in this node
 * @entry - the entry that is going to be written.
 *
 */
bool mas_is_span_wr(struct ma_state *mas, unsigned long piv,
				  enum maple_type type, void *entry)
{
	if (piv > mas->last) // Contained in this pivot
		return false;

	if (ma_is_leaf(type)) {
		if (mas->last < mas->max) // Fits in the node, but may span slots.
			return false;

		if ((mas->last == mas->max) && entry) // Writes to the end of the node but not null.
			return false;
	} else if ((piv == mas->last) && entry) {
		return false;
	}

	/* Writing ULONG_MAX is not a spanning write regardless of the value
	 * being written as long as the range fits in the node.
	 */
	if ((mas->last == ULONG_MAX) && (mas->last == mas->max))
		return false;

	trace_mas_is_span_wr(mas, piv, entry);

	return true;
}

static inline bool mas_node_walk(struct ma_state *mas, enum maple_type type,
		unsigned long *range_min, unsigned long *range_max)
{
	unsigned long *pivots = ma_pivots(mas_mn(mas), type);
	unsigned long min, pivot = 0;

	min = mas_safe_min(mas, pivots, mas->offset);
	if (ma_is_dense(type)) {
		// Linear node.
		// What if mas->index != mas->last?
		pivot = min = mas->index;
		mas->offset = mas->index = mas->min;
		goto dense;
	}

	while(mas->offset < mt_slots[type]) {
		pivot = _mas_safe_pivot(mas, pivots, mas->offset, type);

		if (!pivot && mas->offset) {
			pivot = mas->max;
			break;
		}

		if (mas->index <= pivot)
			break;

		min = pivot + 1;
		mas->offset++;
	}

dense:
	*range_min = min;
	*range_max = pivot;
	return true;
}

/*
 * mas_wr_walk(): Walk the tree for a write.
 * @range_min - pointer that will be set to the minimum of the slot range
 * @range_max - pointer that will be set to the maximum of the slot range
 * @entry - the value that will be written.
 * Returns: True if found, false otherwise.
 *
 * Tracks extra information which is used in special cases of a write.
 */
bool mas_wr_walk(struct ma_state *mas, unsigned long *range_min,
		unsigned long *range_max, void *entry)
{
	enum maple_type type;

	while (true) {
		type = mte_node_type(mas->node);
		mas->depth++;

		mas_node_walk(mas, type, range_min, range_max);
		if (mas_is_span_wr(mas, *range_max, type, entry))
			return false;

		if (ma_is_leaf(type))
			return true;

		// Traverse.
		mas->max = *range_max;
		mas->min = *range_min;
		mas->node = mas_get_slot(mas, mas->offset);
		mas->offset = 0;
	}
	return true;
}

static inline void mas_extend_null(struct ma_state *l_mas, struct ma_state *r_mas)
{
	unsigned char l_slot = l_mas->offset;
	unsigned char r_slot = r_mas->offset;
	unsigned char cp_r_slot = r_slot;
	unsigned long range_max = mas_safe_pivot(r_mas, r_slot);
	unsigned long range_min = l_mas->min;
	void **slots = ma_slots(mte_to_node(l_mas->node),
				    mte_node_type(l_mas->node));
	void *content = slots[l_slot];

	if (l_slot)
		range_min = mas_safe_pivot(l_mas, l_slot - 1) + 1;

	// Expand NULL to start of the range.
	if (!content)
		l_mas->index = range_min;

	if ((l_mas->index == range_min) &&
	    l_slot && !slots[l_slot - 1]) {
		if (l_slot > 1)
			l_mas->index = mas_safe_pivot(l_mas, l_slot - 2) + 1;
		else
			l_mas->index = l_mas->min;
		l_mas->offset = l_slot - 1;
	}

	slots = ma_slots(mte_to_node(r_mas->node),
			     mte_node_type(r_mas->node));
	if (!mas_slot(r_mas, slots, r_slot)) {
		if (r_mas->last < range_max)
			r_mas->last = range_max;
		cp_r_slot++;
	}

	if (r_mas->last == range_max &&
	    r_mas->last < r_mas->max &&
	    !mas_slot(r_mas, slots, r_slot + 1)) {
		r_mas->last = mas_safe_pivot(r_mas, r_slot + 1);
		cp_r_slot++;
	}

	if (r_slot && !r_mas->last)
		r_mas->last = r_mas->max;

	if (l_mas != r_mas)
		r_mas->offset = cp_r_slot;
}

/*
 *
 * __mas_walk(): Locates a value and sets the mas->node and slot accordingly.
 * range_min and range_max are set to the range which the entry is valid.
 * Returns true if mas->node is a leaf.
 *
 * Will not point to a skip entry.
 * May point to a deleted or retry entry.
 *
 */
static inline bool __mas_walk(struct ma_state *mas, unsigned long *range_min,
		unsigned long *range_max)
{
	struct maple_enode *next;
	enum maple_type type;
	bool ret = false;

	while (true) {
		mas->depth++;
		type = mte_node_type(mas->node);

		if (unlikely(!mas_node_walk(mas, type, range_min, range_max)))
			return false;

		if (ma_is_leaf(type)) // Leaf.
			return true;

		next = mas_get_slot(mas, mas->offset);

		if (!next)
			return false;

		// Traverse.
		mas->max = *range_max;
		mas->min = *range_min;
		mas->node = next;
		mas->offset = 0;
	}
	return ret;
}

/*
 *
 * mas_spanning_store() - Create a subtree with the store operation completed
 * and new nodes where necessary, then place the sub-tree in the actual tree.
 * Note that mas is expected to point to the node which caused the store to
 * span.
 *
 */
static inline int mas_spanning_store(struct ma_state *mas, void *entry)
{
	unsigned long range_min, range_max;
	struct maple_big_node b_node;
	struct maple_subtree_state mast;
	unsigned char height = mas_mt_height(mas);
	int node_count = 1 + height * 3;

	// Holds new left and right sub-tree
	MA_STATE(l_mas, mas->tree, mas->index, mas->index);
	MA_STATE(r_mas, mas->tree, mas->index, mas->index);

	trace_mas_spanning_store(mas);
	/* Node rebalancing may occur due to this store, so there may be two new
	 * entries per level plus a new root.
	 */
	mas_node_count(mas, node_count);
	if (mas_is_err(mas))
		return 0;

	mast.bn = &b_node;
	b_node.type = mte_node_type(mas->node);
	mast.orig_l = &l_mas;
	mast.orig_r = &r_mas;

	// Set up right side.
	mas_dup_state(&r_mas, mas);
	r_mas.depth = mas->depth;
	if (r_mas.last + 1) // Avoid overflow.
		r_mas.last++;

	r_mas.index = r_mas.last;
	r_mas.offset = 0;
	__mas_walk(&r_mas, &range_min, &range_max);
	r_mas.last = r_mas.index = mas->last;

	// Set up left side.
	mas_dup_state(&l_mas, mas);
	l_mas.depth = mas->depth;
	l_mas.offset = 0;
	__mas_walk(&l_mas, &range_min, &range_max);

	MT_BUG_ON(mas->tree, l_mas.depth != r_mas.depth);

	if (!entry) {
		mas_extend_null(&l_mas, &r_mas);
		mas->index = l_mas.index;
		mas->last = l_mas.last = r_mas.index = r_mas.last;
		mas->offset = l_mas.offset;
	}


	// Copy l_mas and store the value in b_node.
	b_node.b_end = mas_store_b_node(&l_mas, &b_node, entry,
					mas_data_end(&l_mas));
	// Copy r_mas into b_node.
	mas_mab_cp(&r_mas, r_mas.offset, mt_slot_count(r_mas.node),
		   &b_node, b_node.b_end + 1);
	// Stop spanning searches by searching for just index.
	l_mas.index = l_mas.last = mas->index;

	// Combine l_mas and r_mas and split them up evenly again.
	return mas_spanning_rebalance(mas, &mast, height + 1);
}

static inline bool mas_node_store(struct ma_state *mas, void *entry,
				  unsigned long min, unsigned long max,
				  unsigned char end, void *content)
{
	enum maple_type mt = mte_node_type(mas->node);
	struct maple_node *node = mas_mn(mas);
	void **dst_slots, **slots = ma_slots(node, mt);
	unsigned long *dst_pivots, *pivots = ma_pivots(node, mt);
	unsigned char dst_offset, new_end = end;
	unsigned char offset, offset_end;
	struct maple_node reuse, *newnode;
	unsigned char copy_size;

	offset = offset_end = mas->offset;
	if (mas->last == max) { // don't copy this offset
		offset_end++;
	} else if (mas->last < max) { // new range ends in this range.
		if (max == ULONG_MAX)
			mas_bulk_rebalance(mas, end, mt);

		new_end++;
		offset_end = offset;
	} else if (mas->last == mas->max) { // runs right to the end of the node.
			new_end = offset;
			offset_end = end + 1; // no data beyond this range.
	} else {
		unsigned long piv = 0;
		new_end++;
		do {
			offset_end++;
			new_end--;
			piv = mas_logical_pivot(mas, pivots, offset_end, mt);
		} while(piv <= mas->last);
	}

	if (min < mas->index) // new range starts within a range.
		new_end++;

	if (new_end >= mt_slots[mt]) // Not enough room
		return false;

	if (!mte_is_root(mas->node) && (new_end <= mt_min_slots[mt]) &&
	    !(mas->mas_flags & MA_STATE_BULK)) // not enough data.
		return false;

	// set up node.
	if (mt_in_rcu(mas->tree)) {
		mas_node_count(mas, 1);
		if (mas_is_err(mas))
			return false;

		newnode = mas_pop_node(mas);
	} else {
		memset(&reuse, 0, sizeof(struct maple_node));
		newnode = &reuse;
	}

	newnode->parent = mas_mn(mas)->parent;
	dst_pivots = ma_pivots(newnode, mt);
	dst_slots = ma_slots(newnode, mt);
	// Copy from start to insert point
	memcpy(dst_pivots, pivots, sizeof(unsigned long) * (offset + 1));
	memcpy(dst_slots, slots, sizeof(void*) * (offset + 1));
	dst_offset = offset;

	// Handle insert of new range starting after old range
	if (min < mas->index) {
		dst_slots[dst_offset] = content;
		dst_pivots[dst_offset++] = mas->index - 1;
	}

	// Store the new entry and range end.
	if (dst_offset < mt_pivots[mt])
		dst_pivots[dst_offset] = mas->last;
	dst_slots[dst_offset++] = entry;

	if (offset_end > end) // this range wrote to the end of the node.
		goto done;

	// Copy to the end of node if necessary.
	copy_size = end - offset_end + 1;
	memcpy(dst_slots + dst_offset, slots + offset_end,
	       sizeof(void *) * copy_size);
	if (dst_offset < mt_pivots[mt]) {
		if (copy_size > mt_pivots[mt] - dst_offset)
			copy_size = mt_pivots[mt] - dst_offset;
		memcpy(dst_pivots + dst_offset, pivots + offset_end,
		       sizeof(unsigned long) * copy_size);
	}
done:
	if ((end == mt_slots[mt] - 1) && (new_end < mt_slots[mt] - 1))
		dst_pivots[new_end] = mas->max;

	if (!mt_in_rcu(mas->tree)) {
		memcpy(mas_mn(mas), newnode, sizeof(struct maple_node));
	} else {
		mas->node = mt_mk_node(newnode, mt);
		mas_replace(mas, false);
	}

	mas_update_gap(mas);
	return true;
}

static inline bool mas_slot_store(struct ma_state *mas, void *entry,
				  unsigned long min, unsigned long max,
				  unsigned char end, void *content)
{
	enum maple_type mt = mte_node_type(mas->node);
	struct maple_node *node = mas_mn(mas);
	void **slots = ma_slots(node, mt);
	unsigned long *pivots = ma_pivots(node, mt);
	unsigned long lmax; // Logical max.
	unsigned char offset = mas->offset;

	if (min == mas->index && max == mas->last) { // exact fit.
		slots[offset] = entry;
		goto done;
	}

	if (offset + 1 >= mt_slots[mt]) // out of room.
		return false;

	if (max > mas->last) // going to split a single entry.
		goto try_node_store;

	lmax = mas_logical_pivot(mas, pivots, offset + 1, mt);
	if (lmax < mas->last) // going to overwrite too many slots.
		goto try_node_store;

	if (min == mas->index) {
		if (lmax <= mas->last) // overwriting two or more ranges with one.
			goto try_node_store;

		// Overwriting a portion of offset + 1.
		slots[offset] = entry;
		pivots[offset] = mas->last;
		goto done;
	} else if (min < mas->index) { // split start
		if (lmax != mas->last) // Doesn't end on the next range end.
			goto try_node_store;

		if (offset + 1 < mt_pivots[mt])
			pivots[offset + 1] = mas->last;
		slots[offset + 1] = entry;
		pivots[offset] = mas->index - 1;
		mas->offset++; // Keep mas accurate.
		goto done;
	}

	return false;


done:
	mas_update_gap(mas);
	return true;

try_node_store:
	return mas_node_store(mas, entry, min, max, end, content);
}

static inline void *_mas_store(struct ma_state *mas, void *entry, bool overwrite)
{
	unsigned long r_max, r_min;
	unsigned char end;
	void *content = NULL;
	struct maple_big_node b_node;

	int ret = 0;

	if (mas_is_err(mas))
		return NULL;

	if (mas_start(mas) || mas_is_none(mas) || mas->node == MAS_ROOT) {
		ret = ma_root_ptr(mas, entry, content, overwrite);
		if (mas_is_err(mas))
			return NULL;
		if (ret)
			goto complete_at_root;
	}

	if (!mas_wr_walk(mas, &r_min, &r_max, entry)) {
		if (!overwrite) {
			mas_set_err(mas, -EEXIST);
			return NULL; // spanning writes always overwrite something.
		}

		ret = mas_spanning_store(mas, entry);
		goto spanning_store;
	}

	/* At this point, we are at the leaf node that needs to be altered. */
	/* Calculate needed space */
	content = mas_get_slot(mas, mas->offset);
	if (!overwrite && ((mas->last > r_max) || content)) {
		mas_set_err(mas, -EEXIST);
		return content;
	}

	if (!entry) {
		enum maple_type mt = mte_node_type(mas->node);
		unsigned long *pivots = ma_pivots(mas_mn(mas),mt);
		void **slots = ma_slots(mas_mn(mas), mt);
		unsigned char offset_end = mas->offset;

		if (!content) {
			if (mas->index > r_min)
				mas->index = r_min;
			if (mas->last < r_max)
				mas->last = r_max;
			// if this one is null the next and prev are not.
		} else {
			// Check next slot if we are overwriting the end.
			if ((mas->last == r_max) && !slots[mas->offset + 1]) {
				if (mas->offset < mt_pivots[mt] - 1 &&
				    pivots[mas->offset + 1])
					mas->last = pivots[mas->offset + 1];
				else
					mas->last = mas->max;
			} else if (mas->last > r_max) { // expand over this slot if necessary.
				unsigned long piv;

				do {
					piv = _mas_safe_pivot(mas, pivots,
							      ++offset_end, mt);
				} while (mas->last >= piv);

				if (!slots[offset_end])
					mas->last = piv;
			}

			// Check prev slot if we are overwriting the start.
			if (mas->index == r_min && mas->offset &&
			    !slots[mas->offset - 1]) {
				mas->offset--;
				r_min = mas->index = mas_safe_min(mas, pivots,
								  mas->offset);
				r_max = pivots[mas->offset];
			}
		}
	}

	end = mas_data_end(mas);
	if (mas_slot_store(mas, entry, r_min, r_max, end, content))
		return content;

	if (mas_is_err(mas))
		return content;

	/* Slow path. */
	memset(&b_node, 0, sizeof(struct maple_big_node));
	b_node.type = mte_node_type(mas->node);
	b_node.b_end = mas_store_b_node(mas, &b_node, entry, end);
	b_node.min = mas->min;


	if (!mas_commit_b_node(mas, &b_node, end))
		return NULL;

complete_at_root:
	if (ret > 2)
		return NULL;
spanning_store:

	return content;
}

static inline int mas_dead_node(struct ma_state *mas, unsigned long index);
/*
 * mas_prev_node() - Find the prev non-null entry at the same level in the
 * tree.  The prev value will be mas->node[mas->offset] or MAS_NONE.
 */
static inline void mas_prev_node(struct ma_state *mas, unsigned long limit)
{
	unsigned long start_piv;
	enum maple_type mt;
	int offset, level;
	void **slots;

	if (mas_is_none(mas))
		return;

	if (mte_is_root(mas->node))
		goto no_entry;

	offset = mte_parent_slot(mas->node);
	start_piv = mas_safe_pivot(mas, offset);
restart_prev_node:
	level = 0;
	do {
		if (mte_is_root(mas->node))
			goto no_entry;

		// Walk up.
		offset = mte_parent_slot(mas->node);
		mas_ascend(mas);
		level++;
		if (mas_dead_node(mas, start_piv))
			goto restart_prev_node;
	} while (!offset);

	offset--;
	mt = mte_node_type(mas->node);
	slots = ma_slots(mas_mn(mas), mt);
	mas->max = mas_safe_pivot(mas, offset);
	while (level > 1) {
		level--;
		mas->node = mas_slot(mas, slots, offset);
		if (mas_dead_node(mas, start_piv))
			goto restart_prev_node;
		mt = mte_node_type(mas->node);
		slots = ma_slots(mas_mn(mas), mt);
		offset = mt_slots[mt];
		do {} while(!mas_get_slot(mas, --offset));
		mas->max = mas_safe_pivot(mas, offset);
	}

	mas->offset = offset;
	mas->min = mas_safe_min(mas, ma_pivots(mas_mn(mas),
					       mte_node_type(mas->node)),
				offset);
	mas->node = mas_slot(mas, slots, offset);
	if (mas_dead_node(mas, start_piv))
		goto restart_prev_node;
	return;

no_entry:
	mas->node = MAS_NONE;
}

/*
 * mas_next_node() - Get the next node at the same level in the tree.
 * @mas: The maple state
 * @max: The maximum pivot value to check.
 *
 * Returns: The next value will be mas->node[mas->offset] or MAS_NONE.
 *
 * Finds the next non-null entry at the same level in the tree.  Slot is passed
 * in the maple state offset, eg: mas->offset
 */

static inline unsigned long mas_next_node(struct ma_state *mas,
		unsigned long max)
{
	unsigned long start_piv, prev_piv, pivot;
	int offset, level = 0;
	enum maple_type mt;
	void **slots;

	if (mas_is_none(mas))
		return mas->max;

	if (mte_is_root(mas->node))
		goto no_entry;

	offset = mte_parent_slot(mas->node);
	start_piv = mas_safe_pivot(mas, offset);
restart_next_node:
	level = 0;

ascend_again:
	do {
		if (mte_is_root(mas->node))
			goto no_entry;

		offset = mte_parent_slot(mas->node);
		mas_ascend(mas);
		level++;
		if (mas_dead_node(mas, start_piv))
			goto restart_next_node;

		mt = mte_node_type(mas->node);
		slots = ma_slots(mas_mn(mas), mt);
		prev_piv = mas_safe_pivot(mas, offset);
		if (prev_piv > max)
			goto no_entry;
	} while (prev_piv == mas->max);

	if (++offset >= mt_slots[mt])
		goto ascend_again;

	if (!mas_slot(mas, slots, offset)) // beyond the end of data
		goto ascend_again;

	pivot = mas_safe_pivot(mas, offset);
	// Descend, if necessary.
	while (level > 1) {
		level--;
		mas->node = mas_slot(mas, slots, offset);
		mt = mte_node_type(mas->node);
		slots = ma_slots(mas_mn(mas), mt);
		offset = 0;
		pivot = mas_safe_pivot(mas, offset);
	}

	mas->node = mas_slot(mas, slots,offset);
	mas->min = prev_piv + 1;
	mas->max = pivot;
	return mas->max;

no_entry:
	mas->node = MAS_NONE;
	return mas->max;
}

/*
 * prev node entry
 */
static inline bool mas_prev_nentry(struct ma_state *mas, unsigned long limit,
		unsigned long *max)
{
	unsigned long pivot = mas->max;
	unsigned char slot = mas->offset;
	void *entry;

	if (!slot)
		return false;

	slot--;
	do {
		pivot = mas_safe_pivot(mas, slot);
		if (pivot < limit)
			return false;

		entry = mas_get_slot(mas, slot);
		if (entry)
			break;
	} while (slot--);

	if (!entry)
		return false;

	*max = pivot;
	mas->offset = slot;
	return true;
}

/*
 * mas_next_nentry() - Next node entry.  Set the @mas slot to the next valid
 * entry and range_start to the start value for that entry.  If there is no
 * entry, returns false.
 */
static inline bool mas_next_nentry(struct ma_state *mas, unsigned long max,
		unsigned long *range_start)
{
	enum maple_type type = mte_node_type(mas->node);
	unsigned long pivot = mas->min;
	unsigned long r_start = *range_start;
	unsigned char offset = mas->offset;
	unsigned long *pivots = ma_pivots(mas_mn(mas), type);
	void **slots = ma_slots(mas_mn(mas), type);

	while (offset < mt_slots[type]) {
		pivot = _mas_safe_pivot(mas, pivots, offset, type);
		if (!pivot && offset)
			goto no_entry;

		if (r_start > max)
			goto no_entry;

		if (r_start > mas->max)
			goto no_entry;

		if (mas_slot(mas, slots, offset))
			goto found;

		/* Ran over the limit, this is was the last slot to try */
		if (pivot >= max)
			goto no_entry;

		r_start = pivot + 1;
		offset++;
	}

no_entry:
	*range_start = r_start;
	return false;

found:
	mas->last = pivot;
	*range_start = r_start;
	mas->offset = offset;
	return true;
}

/*
 *
 * Returns the pivot which points to the entry with the highest index.
 * @mas slot is set to the entry location.
 * @limit is the minimum index to check.
 *
 */
static inline void *mas_last_entry(struct ma_state *mas,
		unsigned long limit)
{
	unsigned long prev_min, prev_max, range_start = 0;
	unsigned char slot = 1;
	void *entry;

	if (mas_start(mas) || mas_is_none(mas))
		return NULL;

	prev_min = mas->min;
	prev_max = mas->max;
	while (range_start < limit) {
		mas->offset = slot;
		if (!mas_next_nentry(mas, limit, &range_start)) {
			entry = mas_get_slot(mas, slot - 1);
			if (mte_is_leaf(mas->node)) {
				mas->last = mte_pivot(mas->node, slot - 1);
				mas->index = mte_pivot(mas->node, slot - 2) + 1;
				return entry;
			}

			mas->max = prev_max;
			mas->min = prev_min;
			mas->node = entry;
			slot = 0;
		} else {
			slot = mas->offset + 1;
			prev_min = prev_max + 1;
			if (range_start > prev_min)
				prev_min = range_start;
			range_start = prev_min;
			prev_max = mas->last;
		}
	}
	return NULL;
}

/*
 *
 * __mas_next() Set the @mas->node to the next entry and the range_start to
 * the beginning value for the entry.  Does not check beyond @limit.
 *
 * May return NULL.
 *
 */
static inline void *__mas_next(struct ma_state *mas, unsigned long limit,
		unsigned long *range_start)
{
	void *entry = NULL;
	struct maple_enode *prev_node;
	unsigned long index = mas->index;

	mas->offset++;
retry:
	*range_start = mas->last + 1;

	while (!mas_is_none(mas)) {

		if (mas->offset >= mt_slot_count(mas->node))
			goto next_node;

		if (!mte_is_leaf(mas->node) || !mas->offset) {
			prev_node = mas->node;
			*range_start = mas_first_entry(mas, limit);
			if (mas_is_none(mas)) {
				mas->node = prev_node;
				goto next_node;
			}
		}

		if (mas_next_nentry(mas, limit, range_start))
			break;

		if (*range_start > limit)
			return NULL;

next_node:
		mas_next_node(mas, limit);
		mas->offset = 0;
	}

	if (mas_is_none(mas))
		return NULL;

	entry = mas_get_slot(mas, mas->offset);
	if (mas_dead_node(mas, index))
		goto retry;

	return entry;
}

/*
 *
 * _mas_prev() - Find the previous entry from the current ma state.
 * @mas the current maple state (must have a valid slot)
 */
static inline void *_mas_prev(struct ma_state *mas, unsigned long limit)
{
	unsigned long max = mas->max;
	unsigned long *pivots;

	while (!mas_is_none(mas)) {
		if (mas_prev_nentry(mas, limit, &max))
			break;

		mas_prev_node(mas, limit);
		mas->offset = mt_slot_count(mas->node);
	}

	if (mas_is_none(mas)) {
		mas->index = 0;
		return NULL;
	}

	pivots = ma_pivots(mas_mn(mas), mte_node_type(mas->node));
	mas->last = max;
	mas->index = mas_safe_min(mas, pivots, mas->offset);
	return mas_get_slot(mas, mas->offset);
}

/*
 * mas_prev() - Get the previous entry.  Can return the zero entry.
 *
 *
 */
void *mas_prev(struct ma_state *mas, unsigned long min)
{
	void *entry;

	if (!mas->index) // Nothing comes before 0.
		return NULL;

	if (mas_is_none(mas))
		mas->node = MAS_START;

	if (!mas_searchable(mas))
		return NULL;


	if (mas_is_start(mas)) {
		mas_start(mas);
		mas_walk(mas);
	}

	do {
		entry = _mas_prev(mas, min);
		if (!mas_searchable(mas))
			break;
	} while (!entry);

	return entry;
}
EXPORT_SYMBOL_GPL(mas_prev);

bool _mas_rev_awalk(struct ma_state *mas, unsigned long size)
{
	struct maple_node *node = mas_mn(mas);
	enum maple_type type = mte_node_type(mas->node);
	unsigned long *pivots, *gaps;
	void **slots;
	unsigned char offset = mas->offset;
	unsigned long max;
	unsigned long gap, min;

	if (ma_is_dense(type)) { // dense nodes.
		mas->offset = (unsigned char)(mas->index - mas->min);
		return true;
	}

	pivots = ma_pivots(node, type);
	slots = ma_slots(node, type);
	if (!ma_is_leaf(type))
		gaps = ma_gaps(node, type);

	min = _mas_safe_pivot(mas, pivots, offset, type) + 1;
	do {
		max = min - 1;
		min = mas_safe_min(mas, pivots, offset);
		if (mas->last < min)
			continue;

		if (mas->index > max) {
			mas_set_err(mas, -EBUSY);
			return false;
		}

		if (!ma_is_leaf(type))
			gap = gaps[offset];
		else if (mas_slot(mas, slots, offset))
			continue; // no gap in leaf.
		else
			gap = max - min + 1;

		if (size > gap) // gap too small
			continue;

		if (size > mas->last - min + 1)
			continue;

		if (ma_is_leaf(type)) {
			mas->min = min;
			mas->max = min + gap - 1;
			mas->offset = offset;
			return true;
		}
		break;
	} while (offset--);

	if (offset >= mt_slots[type]) {  // Overflow, node exhausted.
		offset = 0;
		goto ascend;
	}

	//descend
	mas->node = mas_slot(mas, slots, offset);
	mas->min = min;
	mas->max = max;
	mas->offset = mas_data_end(mas);
	return false;

ascend:
	if (mte_is_root(mas->node))
		mas_set_err(mas, -EBUSY);

	mas->offset = offset;
	return false;
}

static inline bool _mas_awalk(struct ma_state *mas, unsigned long size)
{
	enum maple_type type = mte_node_type(mas->node);
	unsigned long pivot, min, gap = 0;
	unsigned char offset = 0;
	unsigned long *gaps = NULL, *pivots = ma_pivots(mas_mn(mas), type);
	void **slots = ma_slots(mas_mn(mas), type);
	bool found = false;

	if (ma_is_dense(type)) {
		mas->offset = (unsigned char)(mas->index - mas->min);
		return true;
	}

	if (!ma_is_leaf(type)) {
		offset = mas->offset;
		gaps = ma_gaps(mte_to_node(mas->node), type);
	}

	min = mas_safe_min(mas, pivots, offset);
	for (; offset < mt_slots[type]; offset++) {
		pivot = _mas_safe_pivot(mas, pivots, offset, type);
		if (offset && !pivot)
			break;

		/* Not within lower bounds */
		if (mas->index > pivot)
			goto next_slot;

		if (gaps)
			gap = gaps[offset];
		else if (!mas_slot(mas, slots, offset))
			gap = min(pivot, mas->last) - max(mas->index, min) + 1;
		else
			goto next_slot;

		if (gap >= size) {
			if (ma_is_leaf(type)) {
				found = true;
				goto done;
			}
			if (mas->index <= pivot) {
				mas->node = mas_slot(mas, slots, offset);
				mas->min = min;
				mas->max = pivot;
				offset = 0;
				break;
			}
		}
next_slot:
		min = pivot + 1;
		if (mas->last < min) {
			mas_set_err(mas, -EBUSY);
			return true;
		}
	}

	if (mte_is_root(mas->node))
		found = true;
done:
	mas->offset = offset;
	return found;
}

/*
 *  _mas_walk(): A walk that supports returning the range in which an
 *  index is located.
 *
 */
static inline bool _mas_walk(struct ma_state *mas, unsigned long *range_min,
			     unsigned long *range_max)
{

	void *entry = mas_start(mas);

	if (entry)
		return true;

	if (mas_is_none(mas))
		goto not_found;

	if (mas_is_ptr(mas)) {
		*range_min = 0;
		*range_max = 0;
		if (!mas->index)
			return true;

		goto not_found;
	}

	return __mas_walk(mas, range_min, range_max);

not_found:
	mas->offset = MAPLE_NODE_SLOTS;
	return false;
}


static inline int mas_dead_node(struct ma_state *mas, unsigned long index)
{
	unsigned long range_max, range_min;

	if (!mas_searchable(mas))
		return 0;

	if (!mte_dead_node(mas->node))
		return 0;

	mas->index = index;
	mas->node = MAS_START;
	_mas_walk(mas, &range_min, &range_max);
	return 1;
}

void *mas_walk(struct ma_state *mas)
{
	unsigned long range_min, range_max;
	unsigned long index = mas->index;

	if (mas_is_none(mas))
		mas->node = MAS_START;

	_mas_walk(mas, &range_min, &range_max);
retry:
	if (mas_dead_node(mas, index))
		goto retry;

	if (mas->offset == MAPLE_NODE_SLOTS)
		return NULL; // Not found.

	return mas_get_slot(mas, mas->offset);
}

static inline bool mas_search_cont(struct ma_state *mas, unsigned long index,
		unsigned long max, void *entry)
{
	if (mas_is_start(mas))
		return true;

	if (index >= max)
		return false;

	if (!mas_searchable(mas))
		return false;

	if (mas_is_err(mas))
		return false;

	if (entry)
		return false;

	return true;
}

/*
 * mas_pause() - Pause a mas_find/mas_for_each to drop the lock.
 *
 * Some users need to pause a walk and drop the lock they're holding in
 * order to yield to a higher priority thread or carry out an operation
 * on an entry.  Those users should call this function before they drop
 * the lock.  It resets the @mas to be suitable for the next iteration
 * of the loop after the user has reacquired the lock.  If most entries
 * found during a walk require you to call mas_pause(), the mt_for_each()
 * iterator may be more appropriate.
 *
 */
void mas_pause(struct ma_state *mas)
{
	// Overflow protection.
	if (mas->last == ULONG_MAX) {
		mas->node = MAS_NONE;
		return;
	}

	mas_reset(mas);
	mas->last++;
	mas->index = mas->last;
}
EXPORT_SYMBOL_GPL(mas_pause);


static inline bool mas_rewind_node(struct ma_state *mas)
{
	unsigned char slot;

	do {
		if (mte_is_root(mas->node)) {
			slot = mas->offset;
			if (!slot) {
				mas_set_err(mas, -EBUSY);
				return false;
			}
		} else {
			slot = mte_parent_slot(mas->node);
			mas_ascend(mas);
		}
	} while (!slot);

	mas->offset = --slot;
	return true;
}

void mas_rev_awalk(struct ma_state *mas, unsigned long size)
{
	struct maple_enode *last = NULL;

	mas->offset = mas_data_end(mas);

	/* There are 4 options:
	 * go to child (descend)
	 * go back to parent (ascend)
	 * no gap found. (return, slot == MAPLE_NODE_SLOTS)
	 * found the gap. (return, slot != MAPLE_NODE_SLOTS)
	 */
	while (!mas_is_err(mas) && !_mas_rev_awalk(mas, size)) {
		if (last == mas->node)
			mas_rewind_node(mas);
		else
			last = mas->node;
	}
}

/* Skip this slot in the parent. */
static inline bool mas_skip_node(struct ma_state *mas)
{
	unsigned char slot;

	do {
		if (mte_is_root(mas->node)) {
			slot = mas->offset;
			if (slot > mt_slot_count(mas->node) - 1) {
				mas_set_err(mas, -EBUSY);
				return false;
			}
		} else {
			slot = mte_parent_slot(mas->node);
			mas_ascend(mas);
		}
	} while (slot > mt_slot_count(mas->node) - 1);

	mas->offset = ++slot;
	if (slot > 0)
		mas->min = mte_pivot(mas->node, slot - 1) + 1;

	if (slot < mt_pivot_count(mas->node))
		mas->max = mte_pivot(mas->node, slot);
	return true;
}

static inline void mas_awalk(struct ma_state *mas, unsigned long size)
{
	struct maple_enode *last = NULL;

	mas_start(mas);
	if (mas_is_none(mas))
		return;

	if (mas_is_ptr(mas))
		return;

	/* There are 4 options:
	 * go to child (descend)
	 * go back to parent (ascend)
	 * no gap found. (return, slot == MAPLE_NODE_SLOTS)
	 * found the gap. (return, slot != MAPLE_NODE_SLOTS)
	 */
	while (!mas_is_err(mas) && !_mas_awalk(mas, size)) {
		if (last == mas->node)
			mas_skip_node(mas);
		else
			last = mas->node;
	}
}

static int mas_fill_gap(struct ma_state *mas, void *entry, unsigned char slot,
		unsigned long size, unsigned long *index)
{
	unsigned char pslot = mte_parent_slot(mas->node);
	struct maple_enode *mn = mas->node;
	unsigned long *pivots;
	enum maple_type ptype;
	/* mas->index is the start address for the search
	 *  which may no longer be needed.
	 * mas->last is the end address for the search
	 */

	*index = mas->index;
	mas->last = mas->index + size - 1;

	/* It is possible that using mas->max and mas->min to correctly
	 * calculate the index and last will cause an issue in the gap
	 * calculation, so fix the ma_state here
	 */
	mas_ascend(mas);
	ptype = mte_node_type(mas->node);
	pivots = ma_pivots(mas_mn(mas), ptype);
	mas->max = _mas_safe_pivot(mas, pivots, pslot, ptype);
	mas->min = mas_safe_min(mas, pivots, pslot);
	mas->node = mn;
	mas->offset = slot;
	_mas_store(mas, entry, false);
	return 0;
}

void mas_set_fwd_index(struct ma_state *mas, unsigned long size)
{
	unsigned long min = mas->min;
	unsigned char slot = mas->offset;
	// At this point, mas->node points to the right node and we have a
	// slot that has a sufficient gap.
	if (slot)
		min = mte_pivot(mas->node, slot - 1) + 1;

	mas->min = min;
	mas->max = mas_safe_pivot(mas, slot);

	if (mas->index < min)
		mas->index = min;
	mas->last = mas->index + size - 1;
}

void mas_set_rev_index(struct ma_state *mas, unsigned long size)
{
	unsigned long gap_max = mas->max; // in-tree gap.
	unsigned long range_max = mas->last; // range window we are searching in.

	// rev_awalk has set mas->min and mas->max to the gap values.
	// If the maximum is outside the window we are searching, then use the
	// last location in the search.
	// mas->max and mas->min is the range of the gap.
	// mas->index and mas->last are currently set to the search range.

	// Trim the upper limit to the max.
	if (gap_max > range_max)
		gap_max = range_max;

	mas->last = gap_max;
	mas->index = mas->last - size + 1;
}

static void _mas_sparse_area(struct ma_state *mas,
			     unsigned long min, unsigned long max,
			     unsigned long size, bool fwd)
{
	unsigned long start = 0;

	if (!mas_is_none(mas))
		start++; // mas_is_ptr

	if (start < min)
		start = min;

	if (fwd) {
		mas->index = start;
		mas->last = start + size - 1;
		return;
	}

	mas->index = max;
}

static inline int _mas_get_empty_area(struct ma_state *mas,
			unsigned long min, unsigned long max,
			unsigned long size, bool forward)
{
	mas_start(mas);
	max--; // Convert to inclusive.

	// Empty set.
	if (mas_is_none(mas) || mas_is_ptr(mas)) {
		_mas_sparse_area(mas, min, max, size, forward);
		return 0;
	}

	// The start of the window can only be within these values.
	mas->index = min;
	mas->last = max;

	if (forward)
		mas_awalk(mas, size);
	else
		mas_rev_awalk(mas, size);


	if (mas_is_err(mas))
		return xa_err(mas->node);

	if (mas->offset == MAPLE_NODE_SLOTS)
		return -EBUSY;

	if (forward)
		mas_set_fwd_index(mas, size);
	else
		mas_set_rev_index(mas, size);

	return 0;
}

int mas_get_empty_area(struct ma_state *mas, unsigned long min,
		unsigned long max, unsigned long size)
{
	return _mas_get_empty_area(mas, min, max, size, true);
}

int mas_get_empty_area_rev(struct ma_state *mas, unsigned long min,
		unsigned long max, unsigned long size)
{
	return _mas_get_empty_area(mas, min, max, size, false);
}

/*
 * mas_alloc() - Allocate a range.
 *
 * Give a size, a minimum starting point (mas->index), a maximum (mas->last),
 * and a size (size), find the lowest location in the min-max window in the
 * tree which this allocation fits and set index to that value.
 *
 * Returns: 0 on success, -ENOMEM if allocation fails, -EBUSY otherwise.
 */
static inline int mas_alloc(struct ma_state *mas, void *entry,
		unsigned long size, unsigned long *index)
{
	unsigned long min;

	mas_start(mas);
	if (mas_is_none(mas) || mas_is_ptr(mas)) {
		mas_root_expand(mas, entry);
		if (mas_is_err(mas))
			return xa_err(mas->node);

		if (!mas->index)
			return mte_pivot(mas->node, 0);
		return mte_pivot(mas->node, 1);
	}

	mas_awalk(mas, size); // Must be walking a tree.
	if (mas_is_err(mas))
		return xa_err(mas->node);

	if (mas->offset == MAPLE_NODE_SLOTS)
		goto no_gap;

	// At this point, mas->node points to the right node and we have an
	// offset that has a sufficient gap.
	min = mas->min;
	if (mas->offset)
		min = mte_pivot(mas->node, mas->offset - 1) + 1;

	if (mas->index < min)
		mas->index = min;

	return mas_fill_gap(mas, entry, mas->offset, size, index);

no_gap:
	return -EBUSY;
}

/*
 * mas_rev_alloc() - Reverse allocate a range.
 *
 * Give a size, a minimum value (mas->index), a maximum starting point
 * (mas->last), and a size (size), find the largest location in the min-max
 * window in tree which this allocation fits and set index to that value.
 *
 * Returns: 0 on success, -EBUSY otherwise.
 */
static inline int mas_rev_alloc(struct ma_state *mas, unsigned long min,
				unsigned long max, void *entry,
				unsigned long size, unsigned long *index)
{
	int ret = 0;

	ret = _mas_get_empty_area(mas, min, max, size, false);
	if (ret)
		return ret;

	if (mas_is_err(mas))
		return xa_err(mas->node);

	if (mas->offset == MAPLE_NODE_SLOTS)
		goto no_gap;

	return mas_fill_gap(mas, entry, mas->offset, size, index);

no_gap:
	return -EBUSY;
}

/*
 *
 * Must hold rcu_read_lock or the write lock.
 *
 * Find where ms->index is located and return the entry.
 * mas->node will point to the node containing the entry.
 *
 * range_min and range_max will be set accordingly.
 *
 */
static inline void *mas_range_load(struct ma_state *mas,
	   unsigned long *range_min, unsigned long *range_max)
{
	void *entry = NULL;

retry:
	if (_mas_walk(mas, range_min, range_max)) {
		if (mas_is_ptr(mas) && mas->last == 0)
			return mte_safe_root(mas->tree->ma_root);

		if (mas->offset >= MAPLE_NODE_SLOTS)
			return NULL;

		entry = mas_get_slot(mas, mas->offset);
		if (mte_dead_node(mas->node))
			goto retry;
	}

	return entry;
}

void *mas_load(struct ma_state *mas)
{
	unsigned long range_max, range_min;

	return mas_range_load(mas, &range_min, &range_max);
}

/*
 *
 * _mas_next() - Finds the next entry, sets index to the start of the range.
 *
 */
static inline void *_mas_next(struct ma_state *mas, unsigned long limit,
		unsigned long *range_start)
{
	void *entry = NULL;


	if (mas_is_start(mas)) {// First run.
		unsigned long range_max;

		mas_start(mas);
		*range_start = 0;
		entry = mas_range_load(mas, range_start, &range_max);
		mas->last = range_max;
		if (entry)
			return entry;
	} else if (!mas_searchable(mas))
		return NULL;

	return __mas_next(mas, limit, range_start);
}

/*
 * mas_find: If mas->node == MAS_START, find the first
 * non-NULL entry >= mas->index.
 * Otherwise, find the first non-NULL entry > mas->index
 *
 * If an entry exists, last and index are updated accordingly.
 *
 * returns entry or null and set mas->node to MAS_NONE.
 */
void *mas_find(struct ma_state *mas, unsigned long max)
{
	unsigned long index = mas->min;
	void *entry = NULL;

	while (mas_search_cont(mas, index, max, entry))
		entry = _mas_next(mas, max, &index);

	if (entry)
		mas->index = index;

	return entry;
}
EXPORT_SYMBOL_GPL(mas_find);

/* mt_find() - Search from start up until an entry is found.
 *
 * Note: Does not return the zero entry.
 * returns an entry.
 */
void *_mt_find(struct maple_tree *mt, unsigned long *index, unsigned long max,
		bool start)
{
	unsigned long range_start = 0, range_end = 0;
	void *entry = NULL;
	bool leaf;

	MA_STATE(mas, mt, *index, *index);

	if (!start && !(*index))
		return NULL;

	rcu_read_lock();
	leaf = _mas_walk(&mas, &range_start, &range_end);
	if (leaf == true && mas.offset != MAPLE_NODE_SLOTS)
		entry = mas_get_slot(&mas, mas.offset);

	mas.last = range_end;
	if (!entry || xa_is_zero(entry))
		entry = NULL;

	while (mas_search_cont(&mas, range_start, max, entry)) {
		entry = _mas_next(&mas, max, &range_start);
		if (!entry || xa_is_zero(entry))
			entry = NULL;
	}

	rcu_read_unlock();
	if (entry)
		*index = mas.last + 1;

	return entry;
}

void *mt_find(struct maple_tree *mt, unsigned long *index, unsigned long max)
{
	return _mt_find(mt, index, max, true);
}
EXPORT_SYMBOL(mt_find);

/*
 * mas_next() - Get the next entry.  Can return the zero entry.  mas->node
 * must be a valid node and not a special value.  Unsafe for single entry
 * trees.
 */
void *mas_next(struct ma_state *mas, unsigned long max)
{
	unsigned long index = 0;

	if (mas_is_none(mas))
		mas->node = MAS_START;

	return _mas_next(mas, max, &index);
}
EXPORT_SYMBOL_GPL(mas_next);
/*
 * mas_erase() - Find the range in which index resides and erase the entire
 * range.
 *
 * Any previous pivots with no value will be set to the same pivot value.
 * Return: the entry that was erased
 */
static inline void *mas_erase(struct ma_state *mas)
{
	unsigned long r_max, r_min;
	void *entry = NULL;

	entry = mas_range_load(mas, &r_min, &r_max);
retry:
	mas->node = MAS_START;
	mas->index = r_min;
	mas->last = r_max;
	_mas_store(mas, NULL, true);
	if (mas_nomem(mas, GFP_KERNEL))
		goto retry;

	return entry;
}

static inline void mas_bfs_preorder(struct ma_state *mas)
{

	if (mas_is_start(mas)) {
		mas_start(mas);
		return;
	}

	if (mte_is_leaf(mas->node) && mte_is_root(mas->node)) {
		mas->node = MAS_NONE;
		return;
	}

}

/* mas limits not adjusted */
static inline void mas_dfs_preorder(struct ma_state *mas)
{

	struct maple_enode *prev;
	unsigned char slot = 0;

	if (mas_is_start(mas)) {
		mas_start(mas);
		return;
	}

	if (mte_is_leaf(mas->node) && mte_is_root(mas->node))
		goto done;

walk_up:
	if (mte_is_leaf(mas->node) ||
	    (slot >= mt_slot_count(mas->node))) {
		if (mte_is_root(mas->node))
			goto done;

		slot = mte_parent_slot(mas->node) + 1;
		mas->node = mt_mk_node(mte_parent(mas->node),
				       mas_parent_enum(mas, mas->node));
		goto walk_up;
	}

	prev = mas->node;
	mas->node = mas_get_slot(mas, slot);
	if (!mas->node) {
		if (mte_is_root(prev))
			goto done;

		mas->node = prev;
		slot = mte_parent_slot(mas->node) + 1;
		mas->node = mt_mk_node(mte_parent(mas->node),
				       mas_parent_enum(mas, mas->node));
		goto walk_up;
	}

	return;
done:
	mas->node = MAS_NONE;
}

static inline unsigned char mas_dead_leaves(struct ma_state *mas, void **slots)
{
	struct maple_node *node;
	int offset;

	for (offset = 0; offset < mt_slot_count(mas->node); offset++) {
		if (!slots[offset])
			break;

		node = mte_to_node(slots[offset]);
		node->parent = ma_parent_ptr(node);
		slots[offset] = (void *)node;
	}

	return offset;
}

static inline void **mas_destroy_descend(struct ma_state *mas)
{
	void **slots = ma_slots(mte_to_node(mas->node),
				    mte_node_type(mas->node));
	while (!mte_is_leaf(slots[0])) {
		mas->node = slots[0];
		slots = ma_slots(mte_to_node(mas->node),
				     mte_node_type(mas->node));
	}

	return slots;
}

/*
 * mt_destroy_walk() - Free this the node and all nodes in this sub-tree.
 *
 * Walk all nodes from the start node and bulk free/ free the all nodes.
 *
 * @head: The rcu_head of the starting node.
 */
static void mt_destroy_walk(struct rcu_head *head)
{
	unsigned char end, offset = 0;
	void **slots;
	struct maple_node *node = container_of(head, struct maple_node, rcu);
	struct maple_enode *start;
	struct maple_tree mt = MTREE_INIT(mt, node->ma_flags);
	MA_STATE(mas, &mt, 0, 0);

	if (ma_is_leaf(node->type))
		goto free_leaf;

	start = mt_mk_node(node, node->type);
	mas.node = start;
	slots = mas_destroy_descend(&mas);

	while (!mas_is_none(&mas)) {
		enum maple_type type;

		end = mas_dead_leaves(&mas, slots);
		mt_free_bulk(end, slots);
		if (mas.node == start)
			break;

		type = mas_parent_enum(&mas, mas.node);
		offset = mte_parent_slot(mas.node);
		mas.node = mt_mk_node(mte_parent(mas.node), type);
		slots = ma_slots(mte_to_node(mas.node), type);

		if ((offset == mt_slots[type] - 1) || !slots[offset + 1])
			continue;

		mas.node = slots[++offset];
		slots = mas_destroy_descend(&mas);
	}

free_leaf:
	ma_free_rcu(node);
}

/*
 *  mte_destroy_walk() - Free the sub-tree from @mn and below.
 *
 * @enode - the encoded maple node (maple_enode) to start
 * @mn - the tree to free - needed for node types.
 */
static inline void mte_destroy_walk(struct maple_enode *enode,
				    struct maple_tree *mt)
{
	struct maple_node *node = mte_to_node(enode);

	node->type = mte_node_type(enode);
	node->ma_flags = mt->ma_flags;
	mte_set_node_dead(enode);
	if (mt_in_rcu(mt))
		call_rcu(&node->rcu, mt_destroy_walk);
	else
		mt_destroy_walk(&node->rcu);
}

/* Interface */

void __init maple_tree_init(void)
{
	maple_node_cache = kmem_cache_create("maple_node",
			sizeof(struct maple_node), sizeof(struct maple_node),
			SLAB_PANIC, NULL);
}

void mtree_init(struct maple_tree *mt, unsigned int ma_flags)
{
	spin_lock_init(&mt->ma_lock);
	mt->ma_flags = ma_flags;
	rcu_assign_pointer(mt->ma_root, NULL);
}
EXPORT_SYMBOL(mtree_init);

void *mtree_load(struct maple_tree *mt, unsigned long index)
{
	void *entry;

	MA_STATE(mas, mt, index, index);
	trace_mtree_load(&mas);
	rcu_read_lock();
	entry = mas_load(&mas);
	rcu_read_unlock();
	if (xa_is_zero(entry))
		return NULL;

	return entry;
}
EXPORT_SYMBOL(mtree_load);

int mtree_store_range(struct maple_tree *mt, unsigned long index,
		unsigned long last, void *entry, gfp_t gfp)
{
	MA_STATE(mas, mt, index, last);

	trace_mtree_store_range(&mas, entry);
	if (WARN_ON_ONCE(xa_is_advanced(entry)))
		return -EINVAL;

	if (index > last)
		return -EINVAL;

	mas_lock(&mas);
retry:
	_mas_store(&mas, entry, true);
	if (mas_nomem(&mas, gfp))
		goto retry;

	mas_unlock(&mas);
	if (mas_is_err(&mas))
		return xa_err(mas.node);

	return 0;
}
EXPORT_SYMBOL(mtree_store_range);

int mtree_store(struct maple_tree *mt, unsigned long index, void *entry,
		 gfp_t gfp)
{
	return mtree_store_range(mt, index, index, entry, gfp);
}
EXPORT_SYMBOL(mtree_store);

int mtree_insert_range(struct maple_tree *mt, unsigned long first,
		unsigned long last, void *entry, gfp_t gfp)
{
	MA_STATE(ms, mt, first, last);

	if (WARN_ON_ONCE(xa_is_advanced(entry)))
		return -EINVAL;

	if (first > last)
		return -EINVAL;

	mtree_lock(ms.tree);
retry:
	_mas_store(&ms, entry, false);
	if (mas_nomem(&ms, gfp))
		goto retry;

	mtree_unlock(ms.tree);
	if (mas_is_err(&ms))
		return xa_err(ms.node);

	return 0;
}
EXPORT_SYMBOL(mtree_insert_range);
int mtree_insert(struct maple_tree *mt, unsigned long index, void *entry,
		 gfp_t gfp)
{
	return mtree_insert_range(mt, index, index, entry, gfp);
}
EXPORT_SYMBOL(mtree_insert);

int mtree_alloc_range(struct maple_tree *mt, unsigned long *startp,
		void *entry, unsigned long size, unsigned long min,
		unsigned long max, gfp_t gfp)
{
	int ret = 0;

	MA_STATE(mas, mt, min, max - size);
	if (!mt_is_alloc(mt))
		return -EINVAL;

	if (WARN_ON_ONCE(mt_is_reserved(entry)))
		return -EINVAL;

	if (min > max)
		return -EINVAL;

	if (max < size)
		return -EINVAL;

	if (!size)
		return -EINVAL;

	mtree_lock(mas.tree);
retry:
	mas.offset = 0;
	mas.index = min;
	mas.last = max - size;
	ret = mas_alloc(&mas, entry, size, startp);
	if (mas_nomem(&mas, gfp))
		goto retry;

	mtree_unlock(mas.tree);
	return ret;
}

int mtree_alloc_rrange(struct maple_tree *mt, unsigned long *startp,
		void *entry, unsigned long size, unsigned long min,
		unsigned long max, gfp_t gfp)
{
	int ret = 0;

	MA_STATE(mas, mt, min, max - size);
	if (!mt_is_alloc(mt))
		return -EINVAL;

	if (WARN_ON_ONCE(mt_is_reserved(entry)))
		return -EINVAL;

	if (min >= max)
		return -EINVAL;

	if (max < size - 1)
		return -EINVAL;

	if (!size)
		return -EINVAL;

	mtree_lock(mas.tree);
retry:
	ret = mas_rev_alloc(&mas, min, max, entry, size, startp);
	if (mas_nomem(&mas, gfp))
		goto retry;

	mtree_unlock(mas.tree);
	return ret;
}

void *mtree_erase(struct maple_tree *mt, unsigned long index)
{
	void *entry = NULL;

	MA_STATE(mas, mt, index, index);
	trace_mtree_erase(&mas);

	mtree_lock(mt);
	entry = mas_erase(&mas);
	mtree_unlock(mt);

	return entry;
}
EXPORT_SYMBOL(mtree_erase);

void mtree_destroy(struct maple_tree *mt)
{
	mtree_lock(mt);
	if (xa_is_node(mt->ma_root))
		mte_destroy_walk(mt->ma_root, mt);

	mt->ma_flags = 0;
	rcu_assign_pointer(mt->ma_root, NULL);
	mtree_unlock(mt);
}
EXPORT_SYMBOL(mtree_destroy);

/*
 * mas_store() - Store an @entry.
 * @mas: The maple state.
 * @entry: The entry to store.
 *
 * The @mas->index and @mas->last is used to set the range for the @entry.
 * Note: The @mas should have pre-allocated entries to ensure there is memory to
 * store the entry.  Please see mas_entry_count()/mas_destroy() for more details.
 */
void *mas_store(struct ma_state *mas, void *entry)
{
	void *existing = NULL;

	if (mas->index > mas->last)
		goto invalid_range;

	existing = _mas_store(mas, entry, true);
	if (mas_is_err(mas))
		return existing;

	if (!mte_is_leaf(mas->node)) // spanning store occurred
		mas->node = MAS_START;

	return existing;

invalid_range:
	mas_set_err(mas, -EINVAL);
	return NULL;

}

int mas_store_gfp(struct ma_state *mas, void *entry, gfp_t gfp)
{

	// Detect spanning store.
	if ((mas->last == mas->max && !entry) ||
	    (mas->last > mas->max))
		mas->node = MAS_START;

retry:
	_mas_store(mas, entry, true);
	if (mas_nomem(mas, gfp))
		goto retry;

	if (mas_is_err(mas))
		return xa_err(mas->node);

	if (!mte_is_leaf(mas->node)) // spanning store occurred
		mas->node = MAS_START;

	return 0;

}

/*
 * mas_entry_count() - Set the expected number of entries that will be inserted.
 *
 * @mas: The maple state
 * @nr_entries: The number of expected entries.
 *
 * This will attempt to pre-allocate enough nodes to store the expected number
 * of entries.  The allocations will occur using the bulk allocator interface
 * for speed.  Please call mas_destroy() on the @mas after inserting the entries
 * to ensure any unused nodes are freed.
 */
int mas_entry_count(struct ma_state *mas, unsigned long nr_entries)
{
	int nonleaf_cap = MAPLE_ARANGE64_SLOTS - 2;
	struct maple_enode *enode = mas->node;
	int nr_nodes;
	int ret;

	// Optimize splitting for bulk insert in-order.
	mas->mas_flags |= MA_STATE_BULK;

	// Avoid overflow, assume a gap between each entry and a trailing null
	// If this is wrong, it just means allocation can happen during
	// insertion of entries.
	nr_nodes = max(nr_entries, nr_entries * 2 + 1);

	if (!mt_is_alloc(mas->tree))
	    nonleaf_cap = MAPLE_RANGE64_SLOTS - 2;

	// Leaves
	nr_nodes = DIV_ROUND_UP(nr_nodes , MAPLE_RANGE64_SLOTS - 1);
	// Internal nodes.
	nr_nodes += DIV_ROUND_UP(nr_nodes, nonleaf_cap);
	mas_node_count(mas, nr_nodes);

	if (!mas_is_err(mas))
		return 0;

	ret = xa_err(mas->node);
	mas->node = enode;
	return ret;

}

/*
 * mas_destroy() - destroy a maple state.
 * @mas: The maple state
 *
 * Frees any allocated nodes associated with this maple state.
 *
 */
void mas_destroy(struct ma_state *mas)
{
	struct maple_alloc *node;

	// When using mas_for_each() to insert an expected number of elements,
	// it is possible that the number inserted is less than the expected
	// number.  To fix an invalid final node, a check is performed here to
	// rebalance the previous node with the final node.
	if (mas->mas_flags & MA_STATE_REBALANCE) {
		unsigned char end;
		unsigned long range_min, range_max;

		if (mas_is_start(mas))
			mas_start(mas);

		__mas_walk(mas, &range_min, &range_max);
		end = mas_data_end(mas) + 1;
		if (end < mt_min_slot_count(mas->node) - 1) {
			mas_destroy_rebalance(mas, end);
		}
		mas->mas_flags &= ~MA_STATE_REBALANCE;
	}
	mas->mas_flags &= ~MA_STATE_BULK;

	while (mas->alloc && !(((unsigned long)mas->alloc & 0x1))) {
		node = mas->alloc;
		mas->alloc = mas->alloc->slot[0];
		if (node->node_count > 0)
			mt_free_bulk(node->node_count, (void**)&node->slot[1]);
		kmem_cache_free(maple_node_cache, node);
	}
	mas->alloc = NULL;
}

/*
 * Check if there was an error allocating and do the allocation if necessary
 * If there are allocations, then free them.
 */
bool mas_nomem(struct ma_state *mas, gfp_t gfp)
	__must_hold(mas->tree->lock)
{
	if (mas->node != MA_ERROR(-ENOMEM)) {
		mas_destroy(mas);
		return false;
	}

	if (gfpflags_allow_blocking(gfp)) {
		mtree_unlock(mas->tree);
		mas_alloc_nodes(mas, gfp);
		mtree_lock(mas->tree);
	} else {
		mas_alloc_nodes(mas, gfp);
	}

	if (!mas_allocated(mas))
		return false;

	mas->node = MAS_START;
	return true;
}

#ifdef CONFIG_DEBUG_MAPLE_TREE
unsigned int maple_tree_tests_run;
EXPORT_SYMBOL_GPL(maple_tree_tests_run);
unsigned int maple_tree_tests_passed;
EXPORT_SYMBOL_GPL(maple_tree_tests_passed);

#ifndef __KERNEL__
extern void kmem_cache_set_non_kernel(struct kmem_cache *, unsigned int);
void mt_set_non_kernel(unsigned int val)
{
	kmem_cache_set_non_kernel(maple_node_cache, val);
}

extern unsigned long kmem_cache_get_alloc(struct kmem_cache *);
unsigned long mt_get_alloc_size(void)
{
	return kmem_cache_get_alloc(maple_node_cache);
}
#define MA_PTR "%p"
#else // __KERNEL__ is defined.
#define MA_PTR "%px"
#endif
// Tree validations
void mt_dump_node(void *entry, unsigned long min, unsigned long max,
		unsigned int depth);
void mt_dump_range(unsigned long min, unsigned long max, unsigned int depth)
{
	static const char spaces[] = "                                ";

	if (min == max)
		pr_info("%.*s%lu: ", depth * 2, spaces, min);
	else
		pr_info("%.*s%lu-%lu: ", depth * 2, spaces, min, max);
}

void mt_dump_entry(void *entry, unsigned long min, unsigned long max,
		unsigned int depth)
{
	mt_dump_range(min, max, depth);

	if (xa_is_value(entry))
		pr_cont("value %ld (0x%lx) ["MA_PTR"]\n", xa_to_value(entry),
				xa_to_value(entry), entry);
	else if (xa_is_zero(entry))
		pr_cont("zero (%ld)\n", xa_to_internal(entry));
	else if (mt_is_reserved(entry))
		pr_cont("UNKNOWN ENTRY ("MA_PTR")\n", entry);
	else
		pr_cont(""MA_PTR"\n", entry);
}

void mt_dump_range64(void *entry, unsigned long min, unsigned long max,
		unsigned int depth)
{
	struct maple_range_64 *node = &mte_to_node(entry)->mr64;
	bool leaf = mte_is_leaf(entry);
	unsigned long first = min;
	int i;

	pr_cont(" contents: ");
	for (i = 0; i < MAPLE_RANGE64_SLOTS - 1; i++)
		pr_cont(""MA_PTR" %lu ", node->slot[i], node->pivot[i]);
	pr_cont(""MA_PTR"\n", node->slot[i]);
	for (i = 0; i < MAPLE_RANGE64_SLOTS; i++) {
		unsigned long last = max;

		if (i < (MAPLE_RANGE64_SLOTS - 1))
			last = node->pivot[i];
		else if (!node->slot[i] && max != mt_max[mte_node_type(entry)])
			break;
		if (last == 0 && i > 0)
			break;
		if (leaf)
			mt_dump_entry(node->slot[i], first, last, depth + 1);
		else if (node->slot[i])
			mt_dump_node(node->slot[i], first, last, depth + 1);

		if (last == max)
			break;
		if (last > max) {
			pr_err("node "MA_PTR" last (%lu) > max (%lu) at pivot %d!\n",
					node, last, max, i);
			break;
		}
		first = last + 1;
	}
}

void mt_dump_arange64(void *entry, unsigned long min, unsigned long max,
		unsigned int depth)
{
	struct maple_arange_64 *node = &mte_to_node(entry)->ma64;
	bool leaf = mte_is_leaf(entry);
	unsigned long first = min;
	int i;

	pr_cont(" contents: ");
	for (i = 0; i < MAPLE_ARANGE64_SLOTS; i++)
		pr_cont("%lu ", node->gap[i]);
	pr_cont("| %02X | ", node->meta);
	for (i = 0; i < MAPLE_ARANGE64_SLOTS - 1; i++)
		pr_cont(MA_PTR" %lu ", node->slot[i], node->pivot[i]);
	pr_cont(MA_PTR"\n", node->slot[i]);
	for (i = 0; i < MAPLE_ARANGE64_SLOTS; i++) {
		unsigned long last = max;

		if (i < (MAPLE_ARANGE64_SLOTS - 1))
			last = node->pivot[i];
		else if (!node->slot[i])
			break;
		if (last == 0 && i > 0)
			break;
		if (leaf)
			mt_dump_entry(node->slot[i], first, last, depth + 1);
		else if (node->slot[i])
			mt_dump_node(node->slot[i], first, last, depth + 1);

		if (last == max)
			break;
		if (last > max) {
			pr_err("node "MA_PTR" last (%lu) > max (%lu) at pivot %d!\n",
					node, last, max, i);
			break;
		}
		first = last + 1;
	}
}

void mt_dump_node(void *entry, unsigned long min, unsigned long max,
		unsigned int depth)
{
	struct maple_node *node = mte_to_node(entry);
	unsigned int type = mte_node_type(entry);
	unsigned int i;

	mt_dump_range(min, max, depth);

	pr_cont("node "MA_PTR" depth %d type %d parent "MA_PTR, node, depth, type,
			node ? node->parent : NULL);
	switch (type) {
	case maple_dense:
		pr_cont("\n");
		for (i = 0; i < MAPLE_NODE_SLOTS; i++) {
			if (min + i > max)
				pr_cont("OUT OF RANGE: ");
			mt_dump_entry(node->slot[i], min + i, min + i, depth);
		}
		break;
	case maple_leaf_64:
	case maple_range_64:
		mt_dump_range64(entry, min, max, depth);
		break;
	case maple_arange_64:
		mt_dump_arange64(entry, min, max, depth);
		break;

	default:
		pr_cont(" UNKNOWN TYPE\n");
	}
}

void mt_dump(const struct maple_tree *mt)
{
	void *entry = mt->ma_root;

	pr_info("maple_tree("MA_PTR") flags %X, height %u root "MA_PTR"\n",
		 mt, mt->ma_flags, mt_height(mt), entry);
	if (!xa_is_node(entry))
		mt_dump_entry(entry, 0, 0, 0);
	else if (entry)
		mt_dump_node(entry, 0, mt_max[mte_node_type(entry)], 0);
}

/*
 * Calculate the maximum gap in a node and check if that's what is reported in
 * the parent (unless root).
 */
void mas_validate_gaps(struct ma_state *mas)
{
	struct maple_enode *mte = mas->node;
	struct maple_node *p_mn;
	unsigned long gap = 0, max_gap = 0;
	unsigned long p_end, p_start = mas->min;
	unsigned char p_slot;
	unsigned long *gaps = NULL;
	unsigned long *pivots = ma_pivots(mte_to_node(mte), mte_node_type(mte));
	int i;

	if (ma_is_dense(mte_node_type(mte))) {
		for (i = 0; i < mt_slot_count(mte); i++) {
			if (mas_get_slot(mas, i)) {
				if (gap > max_gap)
					max_gap = gap;
				gap = 0;
				continue;
			}
			gap++;
		}
		goto counted;
	}

	if (!mte_is_leaf(mte))
		gaps = ma_gaps(mte_to_node(mte), mte_node_type(mte));


	for (i = 0; i < mt_slot_count(mte); i++) {
		p_end = mas_logical_pivot(mas, pivots, i, mte_node_type(mte));

		if (!gaps) {
			if (mas_get_slot(mas, i)) {
				gap = 0;
				goto not_empty;
			}

			gap += p_end - p_start + 1;
		} else {
			void *entry = mas_get_slot(mas, i);

			gap = gaps[i];
			if (!entry) {
				if (gap != p_end - p_start + 1) {
					pr_err(MA_PTR"[%u] -> "MA_PTR" %lu != %lu - %lu + 1\n",
						mas_mn(mas), i,
						mas_get_slot(mas, i), gap,
						p_end, p_start);
					mt_dump(mas->tree);

					MT_BUG_ON(mas->tree,
						gap != p_end - p_start + 1);
				}
			} else {
				if (gap > p_end - p_start + 1) {
					pr_err(MA_PTR"[%u] %lu >= %lu - %lu + 1 (%lu)\n",
					mas_mn(mas), i, gap, p_end, p_start,
					p_end - p_start + 1);
					mt_dump(mas->tree);
					MT_BUG_ON(mas->tree,
						gap > p_end - p_start + 1);
				}
			}
		}

		if (gap > max_gap)
			max_gap = gap;
not_empty:
		p_start = p_end + 1;
		if (p_end >= mas->max)
			break;
	}

counted:
	if (mte_is_root(mte))
		return;

	p_slot = mte_parent_slot(mas->node);
	p_mn = mte_parent(mte);
	MT_BUG_ON(mas->tree, max_gap > mas->max);
	if (ma_gaps(p_mn, mas_parent_enum(mas, mte))[p_slot] != max_gap) {
		pr_err("gap "MA_PTR"[%u] != %lu\n", p_mn, p_slot, max_gap);
		mt_dump(mas->tree);
	}

	MT_BUG_ON(mas->tree,
		  ma_gaps(p_mn, mas_parent_enum(mas, mte))[p_slot] != max_gap);
}

void mas_validate_parent_slot(struct ma_state *mas)
{
	struct maple_node *parent;
	struct maple_enode *node;
	enum maple_type p_type = mas_parent_enum(mas, mas->node);
	unsigned char p_slot = mte_parent_slot(mas->node);
	void **slots;
	int i;

	if (mte_is_root(mas->node))
		return;

	parent = mte_parent(mas->node);
	slots = ma_slots(parent, p_type);
	MT_BUG_ON(mas->tree, mas_mn(mas) == parent);

	// Check prev/next parent slot for duplicate node entry

	for (i = 0; i < mt_slots[p_type]; i++) {
		node = slots[i];
		if (i == p_slot) {
			if (node != mas->node)
				pr_err("parent %p[%u] does not have %p\n",
					parent, i, mas_mn(mas));
			MT_BUG_ON(mas->tree, node != mas->node);
		} else if (node == mas->node) {
			pr_err("parent contains invalid child at "MA_PTR"[%u] "
				MA_PTR" p_slot %u\n", parent, i, mas_mn(mas), p_slot);
			MT_BUG_ON(mas->tree, node == mas->node);
		}
	}
}

void mas_validate_child_slot(struct ma_state *mas)
{
	enum maple_type type = mte_node_type(mas->node);
	void **slots = ma_slots(mte_to_node(mas->node), type);
	struct maple_enode *child;
	unsigned char i;

	if (mte_is_leaf(mas->node))
		return;

	for (i = 0; i < mt_slots[type]; i++) {
		child = slots[i];
		if (!child)
			break;

		if (mte_parent_slot(child) != i) {
			pr_err("child has incorrect slot at "MA_PTR"[%u] "
				MA_PTR" is set to %u\n", mas_mn(mas),
				i, mte_to_node(child), mte_parent_slot(child));
			MT_BUG_ON(mas->tree, 1);
		}

		if (mte_parent(child) != mte_to_node(mas->node)) {
			pr_err("child "MA_PTR" has parent "MA_PTR" not "MA_PTR"\n",
			mte_to_node(child), mte_parent(child),
			mte_to_node(mas->node));
			MT_BUG_ON(mas->tree, 1);
		}
	}
}

/*
 * Validate all pivots are within mas->min and mas->max.
 */
void mas_validate_limits(struct ma_state *mas)
{
	int i;
	unsigned long prev_piv = 0;
	void **slots = ma_slots(mte_to_node(mas->node),
				mte_node_type(mas->node));

	if (mte_is_root(mas->node))
		return; // all limits are fine here.

	for (i = 0; i < mt_slot_count(mas->node); i++) {
		unsigned long piv = mas_safe_pivot(mas, i);

		if (!piv)
			break;

		if (!mte_is_leaf(mas->node)) {
			if (!slots[i])
				pr_err(MA_PTR"[%u] cannot be null\n",
				       mas_mn(mas), i);

			MT_BUG_ON(mas->tree, !slots[i]);
		}

		if (prev_piv > piv) {
			pr_err(MA_PTR"[%u] piv %lu < prev_piv %lu\n",
				mas_mn(mas), i, piv, prev_piv);
			mt_dump(mas->tree);
			MT_BUG_ON(mas->tree, piv < prev_piv);
		}

		if (piv < mas->min) {
			if (piv < mas->min)
				mt_dump(mas->tree);
			pr_err(MA_PTR"[%u] %lu < %lu\n", mas_mn(mas), i,
				piv, mas->min);
			mt_dump(mas->tree);
			MT_BUG_ON(mas->tree, piv < mas->min);
		}
		if (piv > mas->max) {
			pr_err(MA_PTR"[%u] %lu > %lu\n", mas_mn(mas), i,
				piv, mas->max);
			mt_dump(mas->tree);
			MT_BUG_ON(mas->tree, piv > mas->max);
		}
		prev_piv = piv;
		if (piv == mas->max)
			break;
	}
}

/* Depth first search, post-order */
static inline void mas_dfs_postorder(struct ma_state *mas, unsigned long max)
{

	struct maple_enode *p = MAS_NONE, *mn = mas->node;
	unsigned long p_min, p_max;

	mas_next_node(mas, max);
	if (!mas_is_none(mas))
		return;

	if (mte_is_root(mn))
		return;

	mas->node = mn;
	mas_ascend(mas);
	while (mas->node != MAS_NONE) {
		p = mas->node;
		p_min = mas->min;
		p_max = mas->max;
		mas_prev_node(mas, 0);
	}

	if (p == MAS_NONE)
		return;

	mas->node = p;
	mas->max = p_max;
	mas->min = p_min;
}

void mt_validate_nulls(struct maple_tree *mt)
{
	void *entry, *last = (void*)1;
	unsigned char end, offset = 0;
	void **slots;
	MA_STATE(mas, mt, 0, 0);

	mas_start(&mas);
	if (mas_is_none(&mas) || (mas.node == MAS_ROOT))
		return;

	while (!mte_is_leaf(mas.node)) {
		mas_descend(&mas);
	}

	slots = ma_slots(mte_to_node(mas.node), mte_node_type(mas.node));
	end = mas_data_end(&mas);
	do {
		entry = slots[offset];
		if (!last && !entry) {
			pr_err("Sequential nulls end at %p[%u]\n",
				mas_mn(&mas), offset);
		}
		MT_BUG_ON(mt, !last && !entry);
		last = entry;
		if (offset == end) {
			mas_next_node(&mas, ULONG_MAX);
			if (mas_is_none(&mas))
				return;
			offset = 0;
			end = mas_data_end(&mas);
			slots = ma_slots(mte_to_node(mas.node),
					 mte_node_type(mas.node));
		} else
			offset++;

	} while(!mas_is_none(&mas));
}
/*
 * validate a maple tree by checking:
 * 1. The limits (pivots are within mas->min to mas->max)
 * 2. The gap is correctly set in the parents
 */
void mt_validate(struct maple_tree *mt)
{
	unsigned char end;

	MA_STATE(mas, mt, 0, 0);
	rcu_read_lock();
	mas_start(&mas);
	if (!mas_searchable(&mas))
		goto done;

	mas_first_entry(&mas, ULONG_MAX);
	while (!mas_is_none(&mas)) {
		if (!mte_is_root(mas.node)) {
			end = mas_data_end(&mas);
			if ((end < mt_min_slot_count(mas.node)) &&
			    (mas.max != ULONG_MAX)) {
				pr_err("Invalid size %u of "MA_PTR"\n", end,
				mas_mn(&mas));
				MT_BUG_ON(mas.tree, 1);
			}

		}
		mas_validate_parent_slot(&mas);
		mas_validate_child_slot(&mas);
		mas_validate_limits(&mas);
		if (mt_is_alloc(mt))
			mas_validate_gaps(&mas);
		mas_dfs_postorder(&mas, ULONG_MAX);
	}
	mt_validate_nulls(mt);
done:
	rcu_read_unlock();

}
#endif /* CONFIG_DEBUG_MAPLE_TREE */
