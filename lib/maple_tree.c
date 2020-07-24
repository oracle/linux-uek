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

#define MAPLE_BIG_NODE_SLOTS	(MAPLE_RANGE64_SLOTS * 2 + 2)

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
	struct ma_state *orig_r;	/* Original right side of subtree */
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

static inline void mt_free_bulk(size_t size, void __rcu **nodes)
{
	kmem_cache_free_bulk(maple_node_cache, size, (void **)nodes);
}

static void mt_free_rcu(struct rcu_head *head)
{
	struct maple_node *node = container_of(head, struct maple_node, rcu);

	kmem_cache_free(maple_node_cache, node);
}

/* ma_free_rcu() - Use rcu callback to free a maple node
 * @node: The node to free
 *
 * The maple tree uses the parent pointer to indicate this node is no longer in
 * use and will be freed.
 */
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

/*
 * mte_to_mat() - Convert a maple encoded node to a maple topiary node.
 * @entry: The maple encoded node
 *
 * Return: a maple topiary pointer
 */
static inline struct maple_topiary *mte_to_mat(const struct maple_enode *entry)
{
	return (struct maple_topiary *)((unsigned long)entry & ~127);
}

/*
 * mas_mn() - Get the maple state node.
 * @mas: The maple state
 *
 * Return: the maple node (not encoded - bare pointer).
 */
static inline struct maple_node *mas_mn(const struct ma_state *mas)
{
	return mte_to_node(mas->node);
}

/*
 * mte_set_node_dead() - Set a maple encoded node as dead.
 * @mn: The maple encoded node.
 */
static inline void mte_set_node_dead(struct maple_enode *mn)
{
	mte_to_node(mn)->parent = ma_parent_ptr(mte_to_node(mn));
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

#define MAPLE_PARENT_SHIFT 3

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

	if (likely(!mte_is_root(mas->node))) {
		parent = (unsigned long) mte_to_node(node)->parent;
		parent &= (1 << MAPLE_PARENT_SHIFT) - 1;
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
 * bit 2: 0 = range 32, 1 = [a]range 64
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
	unsigned long val = (unsigned long) parent;
	unsigned long type = 0;

	switch (mte_node_type(parent)) {
	case maple_range_64:
	case maple_arange_64:
		type = 6;
		break;
	default:
		break;
	}

	val &= ~bitmask; // Remove any old slot number.
	val |= (slot << MAPLE_PARENT_SHIFT); // Set the slot.
	val |= type;
	mte_to_node(enode)->parent = ma_parent_ptr(val);
}

/*
 * mte_parent_slot() - get the parent slot of @enode.
 * @enode: The encoded maple node.
 *
 * Return: The slot in the parent node where @enode resides.
 */
static inline unsigned int mte_parent_slot(const struct maple_enode *enode)
{
	unsigned long bitmask = 0x7C;
	unsigned long val = (unsigned long) mte_to_node(enode)->parent;

	if (val & 1)
		return 0; // Root.

	return (val & bitmask) >> MAPLE_PARENT_SHIFT;
}

/*
 * mte_parent() - Get the parent of @node.
 * @node: The encoded maple node.
 *
 * Return: The parent maple node.
 */
static inline struct maple_node *mte_parent(const struct maple_enode *enode)
{
	return (void *)((unsigned long)
			(mte_to_node(enode)->parent) & ~MAPLE_NODE_MASK);
}

/*
 * mte_dead_node() - check if the @enode is dead.
 * @enode: The encoded maple node
 *
 * Return: true if dead, false otherwise.
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
 * If @mas->alloc has bit 1 set (0x1), then there is a request for
 * (@mas->alloc >> 1) nodes. See mas_alloc_req().  Otherwise, there is a total
 * of @mas->alloc->total nodes allocated.
 *
 * Return: The total number of nodes allocated
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
 *
 * If @mas->alloc has bit 1 set (0x1) or @mas->alloc is %NULL, then there are no
 * nodes allocated and @mas->alloc should be set to count << 1 | 1.  If there is
 * already nodes allocated, then @mas->alloc->request_count stores the request.
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
 * @mas: The maple state
 *
 * The alloc count is either stored directly in @mas, or in
 * @mas->alloc->request_count if there is at least one node allocated.
 *
 * Return: The allocation request count.
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
 * ma_pivots() - Get a pointer to the maple node pivots.
 * @node - the maple node
 * @type - the node type
 *
 * Return: A pointer to the maple node pivots
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

/*
 * ma_gaps() - Get a pointer to the maple node gaps.
 * @node - the maple node
 * @type - the node type
 *
 * Return: A pointer to the maple node gaps
 */
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

/*
 * mte_pivot() - Get the pivot at @piv of the maple encoded node.
 * @mn: The maple encoded node.
 * @piv: The pivot.
 *
 * Return: the pivot at @piv of @mn.
 */
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

/*
 * _mas_safe_pivot() - get the pivot at @piv or mas->max.
 * @mas: The maple state
 * @pivots: The pointer to the maple node pivots
 * @piv: The pivot to fetch
 * @type: The maple node type
 *
 * Return: The pivot at @piv within the limit of the @pivots array, @mas->max
 * otherwise.
 */
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
 * @mas: The maple state
 * @piv:  the pivot location
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
 * @mas: The maple state
 * @pivots: The pointer to the maple node pivots
 * @offset: The offset into the pivot array
 *
 * Returns: The minimum range value that is contained in @offset.
 */
static inline unsigned long
mas_safe_min(struct ma_state *mas, unsigned long *pivots, unsigned char offset)
{
	if (unlikely(!offset))
		return mas->min;

	return pivots[offset - 1] + 1;
}

/*
 * mas_logical_pivot() - Get the logical pivot of a given offset.
 * @mas: The maple state
 * @pivots: The pointer to the maple node pivots
 * @offset: The offset into the pivot array
 * @type: The maple node type
 *
 * When there is no value at a pivot (beyond the end of the data), then the
 * pivot is actually @mas->max.
 *
 * Return: the logical pivot of a given @offset.
 */
static inline unsigned long
mas_logical_pivot(struct ma_state *mas, unsigned long *pivots,
		  unsigned char offset, enum maple_type type)
{
	unsigned long lpiv = _mas_safe_pivot(mas, pivots, offset, type);

	if (!lpiv && offset)
		return mas->max;
	return lpiv;
}

/*
 * ma_set_pivot() - Set a pivot to a value.
 * @mn: The maple node
 * @piv: The pivot offset
 * @type: The maple node type
 * @val: The value of the pivot
 */
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

/*
 * mte_set_pivot() - Set a pivot to a value in an encoded maple node.
 * @mn: The encoded maple node
 * @piv: The pivot offset
 * @val: The value of the pivot
 */
static inline void mte_set_pivot(struct maple_enode *mn, unsigned char piv,
				unsigned long val)
{
	return ma_set_pivot(mte_to_node(mn), piv, mte_node_type(mn), val);
}

/*
 * ma_slots() - Get a pointer to the maple node slots.
 * @mn: The maple node
 * @mt: The maple node type
 *
 * Return: A pointer to the maple node slots
 */
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

static inline void *mt_slot(const struct maple_tree *mt,
		void __rcu **slots, unsigned char offset)
{
	return rcu_dereference_check(slots[offset],
			lockdep_is_held(&mt->ma_lock));
}

static inline void *mt_slot_locked(const struct maple_tree *mt,
		void __rcu **slots, unsigned char offset)
{
	return rcu_dereference_protected(slots[offset],
			lockdep_is_held(&mt->ma_lock));
}

/*
 * mas_slot_locked() - Get the slot value when holding the maple tree lock.
 * @mas: The maple state
 * @slots: The pointer to the slots
 * @offset: The offset into the slots array to fetch
 *
 * Return: The entry stored in @slots at the @offset.
 */
static inline void *mas_slot_locked(struct ma_state *mas, void __rcu **slots,
				       unsigned char offset)
{
	return mt_slot_locked(mas->tree, slots, offset);
}

/*
 * mas_slot() - Get the slot value when not holding the maple tree lock.
 * @mas: The maple state
 * @slots: The pointer to the slots
 * @offset: The offset into the slots array to fetch
 *
 * Return: The entry stored in @slots at the @offset
 */
static inline void *mas_slot(struct ma_state *mas, void __rcu **slots,
			     unsigned char offset)
{
	return mt_slot(mas->tree, slots, offset);
}

/*
 * mas_get_slot() - Get the entry in the maple state node stored at @offset.
 * @mas: The maple state
 * @offset: The offset into the slot array to fetch.
 *
 * Return: The entry stored at @offset.
 */
static inline struct maple_enode *mas_get_slot(struct ma_state *mas,
		unsigned char offset)
{
	return mas_slot(mas, ma_slots(mas_mn(mas), mte_node_type(mas->node)),
		       offset);
}

/*
 * mas_root() - Get the maple tree root.
 * @mas: The maple state.
 *
 * Return: The pointer to the root of the tree
 */
static inline void *mas_root(struct ma_state *mas)
{
	return rcu_dereference_check(mas->tree->ma_root,
			lockdep_is_held(&mas->tree->ma_lock));
}

static inline void *mt_root_locked(const struct maple_tree *mt)
{
	return rcu_dereference_protected(mt->ma_root,
			lockdep_is_held(&mt->ma_lock));
}

/*
 * mas_root_locked() - Get the maple tree root when holding the maple tree lock.
 * @mas: The maple state.
 *
 * Return: The pointer to the root of the tree
 */
static inline void *mas_root_locked(struct ma_state *mas)
{
	return mt_root_locked(mas->tree);
}

#define MA_META_END_MASK	0b1111
#define MA_META_GAP_SHIFT	4
/*
 * ma_set_meta() - Set the metadata information of a node.
 * @mn: The maple node
 * @mt: The maple node type
 * @offset: The offset of the highest sub-gap in this node.
 * @end: The end of the data in this node.
 */
static inline void ma_set_meta(struct maple_node *mn, enum maple_type mt,
			       unsigned char offset, unsigned char end)
{

	mn->ma64.meta = (offset << MA_META_GAP_SHIFT) | end;
}

/*
 * ma_meta_end() - Get the data end of a node from the metadata
 * @mn: The maple node
 * @mt: The maple node type
 */
static inline unsigned char ma_meta_end(struct maple_node *mn,
					enum maple_type mt)
{

	return mn->ma64.meta & MA_META_END_MASK;
}

/*
 * ma_meta_gap() - Get the largest gap location of a node from the metadat
 * @mn: The maple node
 * @mt: The maple node type
 */
static inline unsigned char ma_meta_gap(struct maple_node *mn,
					enum maple_type mt)
{

	return mn->ma64.meta >> MA_META_GAP_SHIFT;
}

/*
 * ma_set_meta_gap() - Set the largest gap location in a nodes metadata
 * @mn: The maple node
 * @mn: The maple node type
 * @offset: The location of the largest gap.
 */
static inline void ma_set_meta_gap(struct maple_node *mn, enum maple_type mt,
				   unsigned char offset)
{

	mn->ma64.meta = (offset << MA_META_GAP_SHIFT) |
		(mn->ma64.meta & MA_META_END_MASK);
}

/*
 * mat_add() - Add a @dead_enode to the ma_topiary of a list of dead nodes.
 * @mat - the ma_topiary, a linked list of dead nodes.
 * @dead_enode - the node to be marked as dead and added to the tail of the list
 *
 * Add the @dead_enode to the linked list in @mat.
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
static inline void mas_free(struct ma_state *mas, struct maple_enode *used);

/*
 * mat_free() - Free all nodes in a dead list.
 * @mat - the ma_topiary linked list of dead nodes to free.
 * @recursive - specifies if this sub-tree is to be freed or just the single
 * node.
 *
 * Free or destroy walk a dead list.
 */
static void mas_mat_free(struct ma_state *mas, struct ma_topiary *mat,
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
 * @mas - the maple state.
 */
static inline void mas_descend(struct ma_state *mas)
{
	enum maple_type type;
	unsigned long *pivots;
	struct maple_node *node;
	void __rcu **slots;

	node = mas_mn(mas);
	type = mte_node_type(mas->node);
	pivots = ma_pivots(node, type);
	slots = ma_slots(node, type);

	if (mas->offset)
		mas->min = pivots[mas->offset - 1] + 1;
	mas->max = _mas_safe_pivot(mas, pivots, mas->offset, type);
	mas->node = mas_slot(mas, slots, mas->offset);
}

/*
 * mte_set_gap() - Set a maple node gap.
 * @mn: The encoded maple node
 * @gap: The offset of the gap to set
 * @val: The gap value
 */
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

/*
 * mas_ascend() - Walk up a level of the tree.
 * @mas: The maple state
 *
 * Sets the @mas->max and @mas->min to the correct values when walking up.  This
 * may cause several levels of walking up to find the correct min and max.
 * May find a dead node which will cause a premature return.
 */
static void mas_ascend(struct ma_state *mas)
{
	struct maple_enode *p_enode; // parent enode.
	struct maple_enode *a_enode; // ancestor enode.
	struct maple_node *a_node = mas_mn(mas); // ancestor node.
	unsigned char a_slot;
	enum maple_type a_type;
	unsigned long min, max;
	unsigned long *pivots;
	bool set_max = false, set_min = false;

	if (ma_is_root(a_node))
		return;

	a_type = mas_parent_enum(mas, mas->node);
	a_enode = mt_mk_node(mte_parent(mas->node), a_type);
	mas->node = a_enode;
	if (mte_is_root(a_enode)) {
		mas->max = ULONG_MAX;
		mas->min = 0;
		return;
	}

	min = 0;
	max = ULONG_MAX;
	p_enode = a_enode;
	do {
		a_type = mas_parent_enum(mas, p_enode);
		a_node = mte_parent(p_enode);
		a_slot = mte_parent_slot(p_enode);
		pivots = ma_pivots(a_node, a_type);
		a_enode = mt_mk_node(a_node, a_type);

		if (unlikely(p_enode == a_enode))
			return; // Dead node must be handled at a higher level.

		if (!set_min && a_slot) {
			set_min = true;
			min = pivots[a_slot - 1] + 1;
		}

		if (!set_max && a_slot < mt_pivots[a_type]) {
			set_max = true;
			max = pivots[a_slot];
		}

		if (unlikely(ma_is_root(a_node))) {
			break;
		}

		p_enode = a_enode;
	} while (!set_min || !set_max);

	mas->max = max;
	mas->min = min;
	return;
}

/*
 * mas_pop_node() - Get a previously allocated maple node from the maple state.
 * @mas: The maple state
 *
 * Return: A pointer to a maple node.
 */
static inline struct maple_node *mas_pop_node(struct ma_state *mas)
{
	struct maple_alloc *ret, *node = mas->alloc;
	unsigned long total = mas_allocated(mas);

	if (unlikely(!total)) // nothing or a request pending.
		return NULL;

	if (total == 1) { // single allocation in this ma_state
		mas->alloc = NULL;
		ret = node;
		goto single_node;
	}

	if (!node->node_count) { // Single allocation in this node.
		mas->alloc = node->slot[0];
		node->slot[0] = NULL;
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
	if (ret->request_count) {
		mas_set_alloc_req(mas, ret->request_count + 1);
		ret->request_count = 0;
	}
	return (struct maple_node *)ret;
}

/*
 * mas_push_node() - Push a node back on the maple state allocation.
 * @mas: The maple state
 * @used: The used encoded maple node
 *
 * Stores the maple node back into @mas->alloc for reuse.  Updates allocated and
 * requested node count as necessary.
 */
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
	if ((head) && !((unsigned long)head & 0x1)) {
		head->request_count = 0;
		reuse->slot[0] = head;
		reuse->total += head->total;
	}

	mas->alloc = reuse;
done:
	if (requested > 1)
		mas_set_alloc_req(mas, requested - 1);
}

/*
 * mas_alloc_nodes() - Allocate nodes into a maple state
 * @mas: The maple state
 * @gfp: The GFP Flags
 */
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
		void **slots = (void **)&node->slot;
		unsigned int max_req = MAPLE_NODE_SLOTS - 1;

		if (node->slot[0]) {
			unsigned int offset = node->node_count + 1;

			slots = (void **)&node->slot[offset];
			max_req -= offset;
		}

		count = mt_alloc_bulk(gfp, min(requested, max_req),
				      slots);
		if (!count)
			goto nomem;

		node->node_count += count;
		if (slots == (void **)&node->slot)
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

/*
 * mas_free() - Free an encoded maple node
 * @mas: The maple state
 * @used: The encoded maple node to free.
 *
 * Uses rcu free if necessary, pushes @used back on the maple state allocations
 * otherwise.
 */
static inline void mas_free(struct ma_state *mas, struct maple_enode *used)
{
	if (mt_in_rcu(mas->tree))
		ma_free_rcu(mte_to_node(used));
	else
		mas_push_node(mas, used);
}

/*
 * mas_node_count() - Check if enough nodes are allocated and request more if
 * there is not enough nodes.
 * @mas: The maple state
 * @count: The number of nodes needed
 */
static void mas_node_count(struct ma_state *mas, int count)
{
	unsigned long allocated = mas_allocated(mas);

	if (allocated < count) {
		mas_set_alloc_req(mas, count - allocated);
		mas_alloc_nodes(mas, GFP_NOWAIT | __GFP_NOWARN);
	}
}

/*
 * mas_start() - Sets up maple state for operations.
 * @mas: The maple state.
 *
 * If mas->node == MAS_START, then set the min, max, depth, and offset to
 * defaults.
 *
 * Return:
 * - If mas->node is an error or MAS_START, return NULL.
 * - If it's an empty tree:     NULL & mas->node == MAS_NONE
 * - If it's a single entry:    The entry & mas->node == MAS_ROOT
 * - If it's a tree:            NULL & mas->node == safe root node.
 */
static inline struct maple_enode *mas_start(struct ma_state *mas)
{
	void *entry = NULL;

	if (likely(mas_is_start(mas))) {
		struct maple_enode *root;

		mas->node = MAS_NONE;
		mas->min = 0;
		mas->max = ULONG_MAX;
		mas->depth = 0;
		mas->offset = 0;
		if (unlikely(!mas_root(mas))) // empty tree.
			goto done;

		root = mte_safe_root(mas_root(mas));

		if (unlikely(xa_is_node(mas_root(mas)))) {
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
 * This method is optimized to check the metadata of a node if the node type
 * supports data end metadata.
 *
 * Return: The zero indexed last slot with data (may be null).
 */
static inline unsigned char mas_data_end(struct ma_state *mas)
{
	enum maple_type type;
	unsigned char offset;
	unsigned long *pivots;

	type = mte_node_type(mas->node);
	if (type == maple_arange_64)
		return ma_meta_end(mte_to_node(mas->node), type);

	offset = mt_min_slots[type];
	pivots = ma_pivots(mas_mn(mas), type);
	if (unlikely(!pivots[offset]))
		goto decrement;

	// Higher than the min.
	offset = mt_pivots[type] - 1;
	// Check exceptions outside of the loop.
	if (unlikely(pivots[offset])) { // almost full.
		if (pivots[offset] != mas->max) // Totally full.
			return offset + 1;
		return offset;
	}

decrement:
	while (--offset) {
		if (likely(pivots[offset]))
			break;
	};
	if (likely(pivots[offset] < mas->max))
		offset++;

	return offset;
}

/*
 * mas_leaf_max_gap() - Returns the largest gap in a leaf node
 * @mas - the maple state
 *
 * Return: The maximum gap in the leaf.
 */
static unsigned long mas_leaf_max_gap(struct ma_state *mas)
{
	enum maple_type mt;
	unsigned long pstart, gap, max_gap;
	struct maple_node *mn;
	unsigned long *pivots;
	void __rcu **slots;
	unsigned char i;
	unsigned char max_piv;

	mt = mte_node_type(mas->node);
	mn = mas_mn(mas);
	slots = ma_slots(mn, mt);
	max_gap = 0;
	if (unlikely(ma_is_dense(mt))) {
		gap = 0;
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
	// Check the first implied pivot.
	pivots = ma_pivots(mn, mt);
	i = 2;
	if (likely(!slots[0])) {
		max_gap = pivots[0] - mas->min + 1;
	} else if (!slots[1]) {
		// Checking the first slot remove the !pstart && mas->min check
		// below.
		i = 3;
		max_gap = pivots[1] - pivots[0];
	}

	// Check end implied pivot which can only be a gap on the right most
	// node.
	max_piv = mt_pivots[mt] - 1;
	if (unlikely(mas->max == ULONG_MAX) && !slots[max_piv + 1] &&
	    pivots[max_piv] && pivots[max_piv] != mas->max) {
		gap = mas->max - pivots[max_piv];
		if (gap > max_gap)
			max_gap = gap;
	}

	for (; i <= max_piv; i++) {
		if (likely(slots[i])) // data == no gap.
			continue;

		pstart = pivots[i - 1];
		if (!pstart || pstart == mas->max)  // end cannot be a gap, so beyond data.
			break;

		gap = pivots[i] - pstart;
		if (gap > max_gap)
			max_gap = gap;

		i++; // There cannot be two gaps in a row.
	}
	return max_gap;
}

/*
 * ma_max_gap() - Get the maximum gap in a maple node (non-leaf)
 * @node: The maple node
 * @gaps: The pointer to the gaps
 * @mt: The maple node type
 * @*off: Pointer to store the offset location of the gap.
 *
 * Uses the metadata data end to scan backwards across set gaps.
 *
 * Return: The maximum gap value
 */
static inline unsigned long
ma_max_gap(struct maple_node *node, unsigned long *gaps, enum maple_type mt,
	    unsigned char *off)
{
	unsigned char offset, i;
	unsigned long max_gap = 0;

	i = offset = ma_meta_end(node, mt);
	do {
		if (gaps[i] > max_gap) {
			max_gap = gaps[i];
			offset = i;
		}
	} while (i--);

	*off = offset;
	return max_gap;
}

/*
 * mas_max_gap() - find the largest gap in a non-leaf node and set the slot.
 * @mas: The maple state.
 *
 * If the metadata gap is set to MAPLE_ARANGE64_META_MAX, there is no gap.
 *
 * Return: The gap value.
 */
static inline unsigned long mas_max_gap(struct ma_state *mas)
{
	unsigned long *gaps;
	unsigned char offset;
	enum maple_type mt;
	struct maple_node *node;

	mt = mte_node_type(mas->node);
	if (ma_is_leaf(mt))
		return mas_leaf_max_gap(mas);

	node = mas_mn(mas);
	offset = ma_meta_gap(node, mt);
	if (offset == MAPLE_ARANGE64_META_MAX)
		return 0;

	gaps = ma_gaps(node, mt);
	return gaps[offset];
}

/*
 * mas_parent_gap() - Set the parent gap and any gaps above, as needed
 * @mas: The maple state
 * @offset: The gap offset in the parent to set
 * @new: The new gap value.
 *
 * Set the parent gap then continue to set the gap upwards, using the metadata
 * of the parent to see if it is necessary to check the node above.
 */
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
	if (meta_offset == MAPLE_ARANGE64_META_MAX)
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
 * @mas - the maple state.
 */
static inline void mas_update_gap(struct ma_state *mas)
{
	unsigned char pslot;
	unsigned long p_gap;
	unsigned long max_gap;

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
 * mas_adopt_children() - Set the parent pointer of all nodes in @parent to
 * @parent with the slot encoded.
 * @mas - the maple state (for the tree)
 * @parent - the maple encoded node containing the children.
 */
static inline void mas_adopt_children(struct ma_state *mas,
		struct maple_enode *parent)
{
	enum maple_type type = mte_node_type(parent);
	void __rcu **slots = ma_slots(mte_to_node(mas->node), type);
	struct maple_enode *child;
	unsigned char offset;

	for (offset = 0; offset < mt_slots[type]; offset++) {
		child = mas_slot_locked(mas, slots, offset);
		if (unlikely(!child))
			break;
		mte_set_parent(child, parent, offset);
	}
}

/*
 * mas_replace() - Replace a maple node in the tree with mas->node.  Uses the
 * parent encoding to locate the maple node in the tree.
 * @mas - the ma_state to use for operations.
 * @advanced - boolean to adopt the child nodes and free the old node (false) or
 * leave the node (true) and handle the adoption and free elsewhere.
 */
static inline void mas_replace(struct ma_state *mas, bool advanced)
	__must_hold(mas->tree->lock)
{
	struct maple_node *mn = mas_mn(mas);
	struct maple_enode *old_enode;
	unsigned char offset = 0;
	void __rcu **slots = NULL;


	if (ma_is_root(mn)) {
		old_enode = mas_root_locked(mas);
	} else {
		offset = mte_parent_slot(mas->node);
		slots = ma_slots(mte_parent(mas->node),
				 mas_parent_enum(mas, mas->node));
		old_enode = mas_slot_locked(mas, slots, offset);
	}

	if (!advanced && !mte_is_leaf(mas->node))
		mas_adopt_children(mas, mas->node);

	if (mte_is_root(mas->node)) {
		mn->parent = ma_parent_ptr(
			      ((unsigned long)mas->tree | MA_ROOT_PARENT));
		rcu_assign_pointer(mas->tree->ma_root, mte_mk_root(mas->node));
		mas_set_height(mas);
	} else {
		rcu_assign_pointer(slots[offset], mas->node);
	}

	if (!advanced)
		mas_free(mas, old_enode);
}

/*
 * mas_new_child() - Find the new child of a node.
 * @mas: the maple state
 * @child: the maple state to store the child.
 */
static inline bool mas_new_child(struct ma_state *mas, struct ma_state *child)
	__must_hold(mas->tree->lock)
{
	enum maple_type mt;
	unsigned char offset, count;
	struct maple_enode *entry;
	struct maple_node *node;
	void __rcu **slots;

	mt = mte_node_type(mas->node);
	node = mas_mn(mas);
	slots = ma_slots(node, mt);
	count = mt_slots[mt];
	for (offset = mas->offset; offset < count; offset++) {
		entry = mas_slot_locked(mas, slots, offset);
		if (unlikely(!entry)) // end of node data.
			break;

		if (mte_parent(entry) == node) {
			mas_dup_state(child, mas);
			mas->offset = offset + 1;
			child->offset = offset;
			mas_descend(child);
			child->offset = 0;
			return true;
		}
	}
	return false;
}

/*
 * mab_shift_right() - Shift the data in mab right. Note, does not clean out the
 * old data or set b_node->b_end.
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
 * @b_node: the maple_big_node that contains the data.
 * @size: the amount of data in the b_node
 * @split: the potential split location
 * @slot_count: the size that can be stored in a single node being considered.
 *
 * Return: true if a middle node is required.
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
 * @b_node: the maple_big_node with the data
 * @split: the suggested split location
 * @slot_count: the number of slots in the node being considered.
 *
 * Return: the split location.
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
 * @bn: The maple_big_node with the data
 * @mid_split: The second split, if required.  0 otherwise.
 *
 * Return: The first split location.  The middle split is set in @mid_split.
 */
static inline int mab_calc_split(struct ma_state *mas,
				 struct maple_big_node *bn,
				 unsigned char *mid_split)
{
	unsigned char b_end = bn->b_end;
	int split = b_end / 2; // Assume equal split.
	unsigned char min, slot_count = mt_slots[bn->type];

	if (unlikely((mas->mas_flags & MA_STATE_BULK))) {
		*mid_split = 0;
		if (ma_is_leaf(bn->type))
			min = 2;
		else
			return b_end - mt_min_slots[bn->type];

		split = b_end - min;
		mas->mas_flags |= MA_STATE_REBALANCE;
		if (!bn->slot[split])
			split--;
		return split;
	}

	if (unlikely(mab_middle_node(bn, split, slot_count))) {
		split = b_end / 3;
		*mid_split = split * 2;
	} else {
		min = mt_min_slots[bn->type];

		*mid_split = 0;
		/* Avoid having a range less than the slot count unless it
		 * causes one node to be deficient.
		 * NOTE: mt_min_slots is 1 based, b_end and split are zero.
		 */
		while (((bn->pivot[split] - bn->min) < slot_count - 1) &&
		       (split < slot_count - 1) && (b_end - split > min))
			split++;
	}

	/* Avoid ending a node on a NULL entry */
	split = mab_no_null_split(bn, split, slot_count);
	if (!(*mid_split))
		return split;

	*mid_split = mab_no_null_split(bn, *mid_split, slot_count);

	return split;
}

/*
 * mas_mab_cp() - Copy data from a maple state inclusively to a maple_big_node
 * and set @b_node->b_end to the next free slot.
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
	enum maple_type mt;
	struct maple_node *node;
	void __rcu **slots;
	unsigned long *pivots, *gaps;
	int i = mas_start, j = mab_start;
	unsigned char piv_end;

	node = mas_mn(mas);
	mt = mte_node_type(mas->node);
	pivots = ma_pivots(node, mt);
	if (!i) {
		b_node->pivot[j] = pivots[i++];
		if (unlikely(i > mas_end))
			goto complete;
		j++;
	}

	piv_end = min(mas_end, mt_pivots[mt]);
	for (; i < piv_end; i++, j++) {
		b_node->pivot[j] = pivots[i];
		if (unlikely(!b_node->pivot[j]))
			break;

		if (unlikely(mas->max == b_node->pivot[j]))
			goto complete;
	}

	if (likely(i <= mas_end))
		b_node->pivot[j] = _mas_safe_pivot(mas, pivots, i, mt);

complete:
	b_node->b_end = ++j;
	j -= mab_start;
	slots = ma_slots(node, mt);
	memcpy(b_node->slot + mab_start, slots + mas_start, sizeof(void *) * j);
	if (!ma_is_leaf(mt) && mt_is_alloc(mas->tree)) {
		gaps = ma_gaps(node, mt);
		memcpy(b_node->gap + mab_start, gaps + mas_start,
		       sizeof(unsigned long) * j);
	}
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
	void __rcu **slots = ma_slots(node, mt);
	unsigned long *pivots = ma_pivots(node, mt);
	unsigned long *gaps = NULL;

	if (mab_end - mab_start > mt_pivots[mt])
		mab_end--;

	i = mab_start;
	pivots[j++] = b_node->pivot[i++];
	do {
		pivots[j++] = b_node->pivot[i++];
	} while (i <= mab_end && likely(b_node->pivot[i]));

	memcpy(slots, b_node->slot + mab_start,
	       sizeof(void *) * (i - mab_start));

	mas->max = b_node->pivot[i - 1];
	if (likely(!ma_is_leaf(mt) && mt_is_alloc(mas->tree))) {
		unsigned long max_gap = 0;
		unsigned char offset = 15;
		unsigned char end = j - 1;

		gaps = ma_gaps(node, mt);
		do {
			gaps[--j] = b_node->gap[--i];
			if (gaps[j] > max_gap) {
				offset = j;
				max_gap = gaps[j];
			}
		} while (j);
		ma_set_meta(node, mt, offset, end);
	}
}

/*
 * mas_descend_adopt() - Descend through a sub-tree and adopt children.
 * @mas: the maple state with the maple encoded node of the sub-tree.
 *
 * Descend through a sub-tree and adopt children who do not have the correct
 * parents set.  Follow the parents which have the correct parents as they are
 * the new entries which need to be followed to find other incorrectly set
 * parents.
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


	while (!mte_is_leaf(list[0].node)) {
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

		for (i = 0; i < 3; i++) // descend by setting the list to the children.
			mas_dup_state(&list[i], &next[i]);
	}
}

/*
 * mas_bulk_rebalance() - Rebalance the end of a tree after a bulk insert.
 * @mas: The maple state
 * @end: The maple node end
 * @mt: The maple node type
 */
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
 * @mas: the maple state
 * @b_node: the maple_big_node to fill with data
 * @entry: the data to store.
 *
 * Return: The actual end of the data stored in @b_node
 */
static inline unsigned char mas_store_b_node(struct ma_state *mas,
				    struct maple_big_node *b_node,
				    void *entry, unsigned char end)
{
	unsigned char slot = mas->offset;
	void *contents;
	unsigned char b_end = 0;
	// Possible underflow of piv will wrap back to 0 before use.
	unsigned long piv = mas->min - 1;
	struct maple_node *node = mas_mn(mas);
	enum maple_type mt = mte_node_type(mas->node);
	unsigned long *pivots = ma_pivots(node, mt);

	// Copy start data up to insert.
	if (slot) {
		mas_mab_cp(mas, 0, slot - 1, b_node, 0);
		b_end = b_node->b_end;
		piv = b_node->pivot[b_end - 1];
	}

	contents = mas_slot(mas, ma_slots(node, mt), slot);
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
	piv = _mas_safe_pivot(mas, pivots, slot, mt);
	if (piv > mas->last) {
		if (piv == ULONG_MAX)
			mas_bulk_rebalance(mas, b_node->b_end, mt);

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
		piv = _mas_safe_pivot(mas, pivots, ++slot, mt);
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

static inline void mas_node_walk(struct ma_state *mas, enum maple_type type,
		unsigned long *range_min, unsigned long *range_max);

/*
 * mas_prev_sibling() - Find the previous node with the same parent.
 * @mas: the maple state
 *
 * Return: True if there is a previous sibling, false otherwise.
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
 * @mas: the maple state
 *
 * Return: true if there is a next sibling, false otherwise.
 */
static inline bool mas_next_sibling(struct ma_state *mas)
{
	unsigned char end;
	MA_STATE(parent, mas->tree, mas->index, mas->last);

	if (mte_is_root(mas->node))
		return false;

	mas_dup_state(&parent, mas);
	mas_ascend(&parent);
	end = mas_data_end(&parent);
	parent.offset = mte_parent_slot(mas->node) + 1;
	if (parent.offset > end)
		return false;

	if (!mas_get_slot(&parent, parent.offset))
		return false;

	mas_dup_state(mas, &parent);
	mas_descend(mas);
	return true;
}

/*
 * mte_node_or_node() - Return the encoded node or MAS_NONE.
 * @enode: The encoded maple node.
 *
 * Shorthand to avoid setting %NULLs in the tree or maple_subtree_state.
 *
 * Return: @enode or MAS_NONE
 */
static inline struct maple_enode *mte_node_or_none(struct maple_enode *enode)
{
	if (enode)
		return enode;

	return ma_enode_ptr(MAS_NONE);
}

/*
 * mast_topiary() - Add the portions of the tree to the removal list; either to
 * be freed or discarded (destroy walk).
 * @mast: The maple_subtree_state.
 */
static inline void mast_topiary(struct maple_subtree_state *mast)
{
	unsigned char l_off, r_off, offset;
	unsigned long l_index,  range_min, range_max;
	struct maple_enode *child;
	void __rcu **slots;
	enum maple_type mt;

	// The left node is consumed, so add to the free list.
	l_index = mast->orig_l->index;
	mast->orig_l->index = mast->orig_l->last;
	mt = mte_node_type(mast->orig_l->node);
	mas_node_walk(mast->orig_l, mt, &range_min, &range_max);
	mast->orig_l->index = l_index;
	l_off = mast->orig_l->offset;
	r_off = mast->orig_r->offset;
	if (mast->orig_l->node == mast->orig_r->node) {
		slots = ma_slots(mte_to_node(mast->orig_l->node), mt);
		for (offset = l_off + 1; offset < r_off; offset++)
			mat_add(mast->destroy, mas_slot_locked(mast->orig_l,
							slots, offset));

		return;
	}
	/* mast->orig_r is different and consumed. */
	if (mte_is_leaf(mast->orig_r->node))
		return;

	/* Now destroy l_off + 1 -> end and 0 -> r_off - 1 */
	offset = l_off + 1;
	slots = ma_slots(mte_to_node(mast->orig_l->node), mt);
	while (offset < mt_slots[mt]) {
		child = mas_slot_locked(mast->orig_l, slots, offset++);
		if (!child)
			break;

		mat_add(mast->destroy, child);
	}

	slots = ma_slots(mte_to_node(mast->orig_r->node),
			     mte_node_type(mast->orig_r->node));
	for (offset = 0; offset < r_off; offset++)
		mat_add(mast->destroy,
				mas_slot_locked(mast->orig_l, slots, offset));
}

/*
 * mast_rebalance_next() - Rebalance against the next node
 * @mast: The maple subtree state
 * @old_r: The encoded maple node to the right (next node).
 */
static inline void mast_rebalance_next(struct maple_subtree_state *mast,
				       struct maple_enode *old_r, bool free)
{
	unsigned char b_end = mast->bn->b_end;

	mas_mab_cp(mast->orig_r, 0, mt_slot_count(mast->orig_r->node),
		   mast->bn, b_end);
	if (free)
		mat_add(mast->free, old_r);

	mast->orig_r->last = mast->orig_r->max;
	if (old_r == mast->orig_l->node)
		mast->orig_l->node = mast->orig_r->node;
}

/*
 * mast_rebalace_prev() - Rebalance against the previous node
 * @mast: The maple subtree state
 * @old_l: The encoded maple node to the left (previous node)
 */
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

/*
 * mast_sibling_rebalance_right() - Rebalance from nodes with the same parents.
 * Check the right side, then the left.  Data is copied into the @mast->bn.
 * @mast: The maple_subtree_state.
 */
static inline
bool mast_sibling_rebalance_right(struct maple_subtree_state *mast, bool free)
{
	struct maple_enode *old_r;
	struct maple_enode *old_l;

	old_r = mast->orig_r->node;
	if (mas_next_sibling(mast->orig_r)) {
		mast_rebalance_next(mast, old_r, free);
		return true;
	}

	old_l = mast->orig_l->node;
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
 * @mast: The maple_subtree_state.
 */
static inline
bool mast_cousin_rebalance_right(struct maple_subtree_state *mast, bool free)
{
	struct maple_enode *old_l = mast->orig_l->node;
	struct maple_enode *old_r = mast->orig_r->node;

	MA_STATE(tmp, mast->orig_r->tree, mast->orig_r->index, mast->orig_r->last);

	mas_dup_state(&tmp, mast->orig_r);
	mas_next_node(mast->orig_r, ULONG_MAX);
	if (!mas_is_none(mast->orig_r)) {
		mast_rebalance_next(mast, old_r, free);
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
	if (mast->orig_r->max < mast->orig_r->last)
		mast->orig_r->offset = mas_data_end(mast->orig_r) + 1;
	else
		mas_node_walk(mast->orig_r, mte_node_type(mast->orig_r->node),
			      &range_min, &range_max);
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
 * ma_state.  This function exists mainly for code readability.
 *
 * Return: A new maple encoded node
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
 * Return: the split of left.
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
 * @**l: Pointer to left encoded maple node.
 * @**m: Pointer to middle encoded maple node.
 * @**r: Pointer to right encoded maple node.
 * @slot: The offset
 * @*split: The split location.
 * @mid_split: The middle split.
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

/*
 * mas_wmb_replace() - Write memory barrier and replace
 * @mas: The maple state
 * @free: the maple topiary list of nodes to free
 * @destroy: The maple topiary list of nodes to destroy (walk and free)
 *
 * Updates gap as necessary.
 */
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

/*
 * mast_new_root() - Set a new tree root during subtree creation
 * @mast: The maple subtree state
 * @mas: The maple state
 * */
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

/*
 * mast_cp_to_nodes() - Copy data out to nodes.
 * @mast: The maple subtree state
 * @left: The left encoded maple node
 * @middle: The middle encoded maple node
 * @right: The right encoded maple node
 * @split: The location to split between left and (middle ? middle : right)
 * @mid_split: The location to split between middle and right.
 */
static inline void mast_cp_to_nodes(struct maple_subtree_state *mast,
	struct maple_enode *left, struct maple_enode *middle,
	struct maple_enode *right, unsigned char split, unsigned char mid_split,
	struct ma_state *save)
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
		if (!save->node &&
		    (save->offset > split) && (save->offset < mid_split)) {
			save->offset -= (split + 1);
			save->node= mast->m->node;
			save->min = mast->m->min;
			save->max = mast->m->max;
		}
		split = mid_split;
	}

	if (right) {
		mab_mas_cp(mast->bn, 1 + split, mast->bn->b_end, mast->r);
		mast->r->min = mast->bn->pivot[split] + 1;
		mast->r->max = mast->bn->pivot[mast->bn->b_end];
		if (!save->node && (save->offset > split)) {
			save->offset -= (split + 1);
			save->node= mast->r->node;
			save->min = mast->r->min;
			save->max = mast->r->max;
		}
	}
	if (!save->node) {
		save->node= mast->l->node;
		save->min = mast->l->min;
		save->max = mast->l->max;
	}
}

/*
 * mast_combine_cp_left - Copy in the original left side of the tree into the
 * combined data set in the maple subtree state big node.
 * @mast: The maple subtree state
 */
static inline void mast_combine_cp_left(struct maple_subtree_state *mast)
{
	unsigned char l_slot = mast->orig_l->offset;

	if (!l_slot)
		return;

	mas_mab_cp(mast->orig_l, 0, l_slot - 1, mast->bn, 0);
}

/*
 * mast_combine_cp_right: Copy in the original right side of the tree into the
 * combined data set in the maple subtree state big node.
 * @mast: The maple subtree state
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

/*
 * mast_sufficient: Check if the maple subtree state has enough data in the big
 * node to create at least one sufficient node
 * @mast: the maple subtree state
 */
static inline bool mast_sufficient(struct maple_subtree_state *mast)
{
	if (mast->bn->b_end > mt_min_slot_count(mast->orig_l->node))
		return true;

	return false;
}

/*
 * mast_overflow: Check if there is too much data in the subtree state for a
 * single node.
 * @mast: The maple subtree state
 */
static inline bool mast_overflow(struct maple_subtree_state *mast)
{
	if (mast->bn->b_end >= mt_slot_count(mast->orig_l->node))
		return true;

	return false;
}

/*
 * mast_setup_bnode_for_split() - Prepare the subtree state big node for
 * splitting
 * @mast: The maple subtree state
 */
static inline void mast_setup_bnode_for_split(struct maple_subtree_state *mast)
{
	mast->bn->b_end--;
	mast->bn->min = mast->orig_l->min;
	mast->bn->type = mte_node_type(mast->orig_l->node);
}

/*
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
 * Return: the number of elements in b_node during the last loop.
 */
static int mas_spanning_rebalance(struct ma_state *mas,
		struct maple_subtree_state *mast, unsigned char count)
{
	struct ma_state restore;
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
	if (!mas_is_root_limits(mas) &&
	    unlikely(mast->bn->b_end <= mt_min_slots[mast->bn->type])) {
		// Do not free the current node as it may be freed in a bulk
		// free.
		if (!mast_sibling_rebalance_right(mast, false))
			mast_cousin_rebalance_right(mast, false);
	}
	restore.node = NULL;
	restore.offset = mas->offset;
	mast->orig_l->depth = 0;

	while (count--) {
		mast_setup_bnode_for_split(mast);
		split = mas_mab_to_node(mas, mast->bn, &left, &right, &middle,
					&mid_split);
		mast_set_split_parents(mast, left, middle, right, split,
				       mid_split);
		mast_cp_to_nodes(mast, left, middle, right, split, mid_split,
				 &restore);

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
		if (!mast_sibling_rebalance_right(mast, true))
			if (!mast_cousin_rebalance_right(mast, true))
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
	mas->offset = restore.offset;
	mas->min = restore.min;
	mas->max = restore.max;
	mas->node = restore.node;
	return mast->bn->b_end;
}

/*
 * mas_rebalance() - Rebalance a given node.
 * @mas: The maple state
 * @b_node: The big maple node.
 *
 * Rebalance two nodes into a single node or two new nodes that are sufficient.
 * Continue upwards until tree is sufficient.
 *
 * Return: the number of elements in b_node during the last loop.
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
		mas_mab_cp(&r_mas, 0, mt_slot_count(r_mas.node), b_node, b_end);
		r_mas.last = r_mas.index = r_mas.max;

	} else {
		mas_prev_sibling(&l_mas);
		shift = mas_data_end(&l_mas) + 1;
		mab_shift_right(b_node, shift);
		mas->offset += shift;
		mas_mab_cp(&l_mas, 0, shift - 1, b_node, 0);
		b_node->b_end = shift + b_end;
		l_mas.index = l_mas.last = l_mas.min;
	}

	return mas_spanning_rebalance(mas, &mast, empty_count);
}

/*
 * mas_destroy_rebalance() - Rebalance left-most node while destroying the maple
 * state.
 * @mas: The maple state
 * @end: The end of the left-most node.
 *
 * During a mass-insert event (such as forking), it may be necessary to
 * rebalance the left-most node when it is not sufficient.
 */
static inline void mas_destroy_rebalance(struct ma_state *mas, unsigned char end)
{
	enum maple_type mt = mte_node_type(mas->node);
	struct maple_node reuse, *newnode, *parent, *new_left, *left, *node;
	struct maple_enode *eparent;
	unsigned char offset, tmp, split = mt_slots[mt] / 2;
	void __rcu **l_slots, **slots;
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
		newnode = &reuse;
	}

	node = mas_mn(mas);
	newnode->parent = node->parent;
	pivs = ma_pivots(newnode, mt);



	slots = ma_slots(newnode, mt);
	pivs = ma_pivots(newnode, mt);
	left = mas_mn(&l_mas);
	l_slots = ma_slots(left, mt);
	l_pivs = ma_pivots(left, mt);
	if (!l_slots[split])
		split++;
	tmp = mas_data_end(&l_mas) - split;

	memcpy(slots, l_slots + split + 1, sizeof(void *) * tmp);
	memcpy(pivs, l_pivs + split + 1, sizeof(unsigned long) * tmp);
	pivs[tmp] = l_mas.max;
	memcpy(slots + tmp, ma_slots(node, mt), sizeof(void *) * end);
	memcpy(pivs + tmp, ma_pivots(node, mt), sizeof(unsigned long) * end);

	l_mas.max = l_pivs[split];
	mas->min = l_mas.max + 1;
	eparent = mt_mk_node(mte_parent(l_mas.node),
			     mas_parent_enum(&l_mas, l_mas.node));
	if (!mt_in_rcu(mas->tree)) {
		unsigned char max_p = mt_pivots[mt];
		unsigned char max_s = mt_slots[mt];

		tmp += end;
		if (tmp < max_p)
			memset(pivs + tmp, 0,
			       sizeof(unsigned long *) * (max_p - tmp));

		if (tmp < mt_slots[mt])
			memset(slots + tmp, 0, sizeof(void *) * (max_s - tmp));

		memcpy(node, newnode, sizeof(struct maple_node));
		mte_set_pivot(eparent, mte_parent_slot(l_mas.node),
			      l_pivs[split]);
		// Remove data from l_pivs.
		tmp = split + 1;
		memset(l_pivs + tmp, 0, sizeof(unsigned long) * (max_p - tmp));
		memset(l_slots + tmp, 0, sizeof(void *) * (max_s - tmp));

		goto done;
	}

	// RCU requires replacing both l_mas, mas, and parent.
	// replace mas
	mas->node = mt_mk_node(newnode, mt);

	// replace l_mas
	new_left = mas_pop_node(mas);
	new_left->parent = left->parent;
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
	rcu_assign_pointer(slots[offset], mas->node);
	rcu_assign_pointer(slots[offset - 1], l_mas.node);
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

/*
 * _mas_split_final_node() - Split the final node in a subtree operation.
 * @mast: the maple subtree state
 * @mas: The maple state
 * @height: The height of the tree in case it's a new root.
 */
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
	 * The Big_node data should just fit in a single node.
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

/*
 * mas_split_final_node() - Check if a subtree state can be contained within a
 * single node and do so if possible.
 * @mast: The maple subtree state
 * @mas: The maple state
 * @height: The height in case of a new root.
 *
 * Return: True if this was the final node and it has been handled, false
 * otherwise.
 */
static inline bool mas_split_final_node(struct maple_subtree_state *mast,
					struct ma_state *mas, int height)
{
	if (mt_slots[mast->bn->type] <= mast->bn->b_end)
		return false;

	return _mas_split_final_node(mast, mas, height);
}

/*
 * mast_fill_bnode() - Copy data into the big node in the subtree state
 * @mast: The maple subtree state
 * @mas: the maple state
 * @skip: The number of entries to skip for new nodes insertion.
 */
static inline void mast_fill_bnode(struct maple_subtree_state *mast,
					 struct ma_state *mas,
					 unsigned char skip)
{
	bool cp = true;
	struct maple_enode *old = mas->node;
	unsigned char split, zero;

	mast->bn->b_end = 0;
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

	zero = MAPLE_BIG_NODE_SLOTS - mast->bn->b_end - 2;
	memset(mast->bn->gap + mast->bn->b_end + 1, 0,
	       sizeof(unsigned long) * zero);
	memset(mast->bn->slot + mast->bn->b_end + 1, 0, sizeof(void*) * zero--);
	memset(mast->bn->pivot + mast->bn->b_end + 1, 0,
	       sizeof(unsigned long) * zero);
}

/*
 * mast_split_data() - Split the data in the subtree state big node into regular
 * nodes.
 * @mast: The maple subtree state
 * @mas: The maple state
 * @split: The location to split the big node
 */
static inline void mast_split_data(struct maple_subtree_state *mast,
	   struct ma_state *mas, unsigned char split, struct ma_state *save)
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
	} else {
		if (save->offset > split) {
			save->node = mast->r->node;
			save->min = mast->r->min;
			save->max = mast->r->max;
			save->offset -= (split + 1);
		} else {
			save->node = mast->l->node;
			save->min = mast->l->min;
			save->max = mast->l->max;
		}
	}
}

/*
 * mas_push_data() - Instead of splitting a node, it is beneficial to push the
 * data to the right or left node if there is room.
 * @mas: The maple state
 * @height: The current height of the maple state
 * @mast: The maple subtree state
 * @left: Push left or not.
 *
 * Keeping the height of the tree low means faster lookups.
 *
 * Return: True if pushed, false otherwise.
 */
static inline bool mas_push_data(struct ma_state *mas, int height,
				 struct maple_subtree_state *mast, bool left,
				 struct ma_state *save)
{
	unsigned char slot_total = mast->bn->b_end;
	unsigned char end, space, split;

	MA_STATE(tmp_mas, mas->tree, mas->index, mas->last);
	tmp_mas.depth = mast->l->depth;
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
		if (!save->node)
			save->offset = mas->offset + end + 1;
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

	mast_split_data(mast, mas, split, save);
	mast_fill_bnode(mast, mas, 2);
	_mas_split_final_node(mast, mas, height + 1);
	return true;
}

/*
 * mas_split() - Split data that is too big for one node into two.
 * @mas: The maple state
 * @b_node: The maple big node
 * Return: 1 on success, 0 on failure.
 */
static int mas_split(struct ma_state *mas, struct maple_big_node *b_node)
{

	struct maple_subtree_state mast;
	int height = 0;
	unsigned char mid_split, split = 0;
	struct ma_state restore;

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
	restore.node = NULL;
	restore.offset = mas->offset;

	while (height++ <= mas->depth) {
		if (mas_split_final_node(&mast, mas, height))
			break;

		mas_dup_state(&l_mas, mas);
		mas_dup_state(&r_mas, mas);
		l_mas.node = mas_new_ma_node(mas, b_node);
		r_mas.node = mas_new_ma_node(mas, b_node);
		// Try to push left.
		if (mas_push_data(mas, height, &mast, true, &restore))
			break;

		// Try to push right.
		if (mas_push_data(mas, height, &mast, false, &restore))
			break;

		split = mab_calc_split(mas, b_node, &mid_split);
		mast_split_data(&mast, mas, split, &restore);
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
	mas->offset = restore.offset;
	mas->min = restore.min;
	mas->max = restore.max;
	mas->node = restore.node;
	return 1;
}

/*
 * mas_reuse_node() - Reuse the node to store the data.
 * @mas: The maple state
 * @bn: The maple big node
 * @end: The end of the data.
 *
 * Will always return false in RCU mode.
 *
 * Return: True if node was reused, false otherwise.
 */
static inline bool mas_reuse_node(struct ma_state *mas,
			  struct maple_big_node *bn, unsigned char end)
{
	unsigned long max;

	if (mt_in_rcu(mas->tree))
		return false; // Need to be rcu safe.

	max = mas->max;
	mab_mas_cp(bn, 0, bn->b_end, mas);
	mas->max = max;

	// Zero end of node.
	if (end > bn->b_end) {
		enum maple_type mt = mte_node_type(mas->node);
		struct maple_node *mn = mas_mn(mas);
		unsigned long *pivots = ma_pivots(mn, mt);
		void __rcu **slots = ma_slots(mn, mt);
		char zero = mt_slots[mt] - bn->b_end - 1;

		memset(slots + bn->b_end + 1, 0, sizeof(void *) * zero--);
		memset(pivots + bn->b_end + 1, 0, sizeof(unsigned long *) * zero);
	}
	return true;

}

/*
 * mas_commit_b_node() - Commit the big node into the tree.
 * @mas: The maple state
 * @b_node: The maple big node
 * @end: The end of the data.
 */
static inline int mas_commit_b_node(struct ma_state *mas,
			    struct maple_big_node *b_node, unsigned char end)
{
	struct maple_enode *new_node;
	unsigned char b_end = b_node->b_end;
	enum maple_type b_type = b_node->type;

	if ((b_end < mt_min_slots[b_type]) &&
	    (!mte_is_root(mas->node)) && (mas_mt_height(mas) > 1))
		return mas_rebalance(mas, b_node);


	if (b_end >= mt_slots[b_type])
		return mas_split(mas, b_node);

	if (mas_reuse_node(mas, b_node, end))
		goto reuse_node;

	mas_node_count(mas, 1);
	if (mas_is_err(mas))
		return 0;

	new_node = mt_mk_node(mas_pop_node(mas), mte_node_type(mas->node));
	mte_to_node(new_node)->parent = mas_mn(mas)->parent;
	mas->node = new_node;
	mab_mas_cp(b_node, 0, b_end, mas);
	mas_replace(mas, false);
reuse_node:
	mas_update_gap(mas);
	return 1;
}

/*
 * mas_root_expand() - Expand a root to a node
 * @mas: The maple state
 * @entry: The entry to store into the tree
 */
static inline int mas_root_expand(struct ma_state *mas, void *entry)
{
	void *contents = mas_root_locked(mas);
	enum maple_type type = maple_leaf_64;
	struct maple_node *node;
	void __rcu **slots;
	unsigned long *pivots;
	int slot = 0;


	mas_node_count(mas, 1);
	if (unlikely(mas_is_err(mas)))
		return 0;

	node = mas_pop_node(mas);
	pivots = ma_pivots(node, type);
	slots = ma_slots(node, type);
	node->parent = ma_parent_ptr(
		      ((unsigned long)mas->tree | MA_ROOT_PARENT));
	mas->node = mt_mk_node(node, type);

	if (contents)
		rcu_assign_pointer(slots[slot++], contents);

	if (!mas->index && slot)
		slot--;
	else if (mas->index > 1)
		pivots[slot++] = mas->index - 1;

	rcu_assign_pointer(slots[slot], entry);
	mas->offset = slot;
	pivots[slot++] = mas->last;
	mas->depth = 1;
	mas_set_height(mas);
	/* swap the new root into the tree */
	rcu_assign_pointer(mas->tree->ma_root, mte_mk_root(mas->node));
	return slot;
}

/*
 * mas_root_ptr() - Store entry into root.
 * @mas: The maple state
 * @entry: The entry to store
 * @overwrite: If it is okay to overwrite data
 *
 * Return: 0 on success, 1 otherwise.
 */
static inline int mas_root_ptr(struct ma_state *mas, void *entry,
			       bool overwrite)
{
	int ret = 1;

	if (xa_is_node(mas_root(mas)))
		return 0;

	if (mas_root(mas) && mas->last == 0) {
		if (!overwrite)
			goto exists;
	}

	if (mas->last != 0)
		ret = mas_root_expand(mas, entry);
	else if (((unsigned long) (entry) & 3) == 2)
		ret = mas_root_expand(mas, entry);
	else {
		rcu_assign_pointer(mas->tree->ma_root, entry);
		mas->node = MAS_START;
	}
	return ret;

exists:
	mas_set_err(mas, -EEXIST);
	return 0;
}

/*
 * mas_is_span_wr() - Check if the write needs to be treated as a write that
 * spans the node.
 * @mas: The maple state
 * @piv: The pivot value being written
 * @type: The maple node type
 * @entry: The data to write
 *
 * Spanning writes are writes that start in one node and end in another OR if
 * the write of a %NULL will cause the node to end with a %NULL.
 *
 * Return: True if this is a spanning write, false otherwise.
 */
static bool mas_is_span_wr(struct ma_state *mas, unsigned long piv,
			   enum maple_type type, void *entry)
{
	unsigned long max;
	unsigned long last = mas->last;

	if (piv > last) // Contained in this pivot
		return false;

	max = mas->max;
	if (unlikely(ma_is_leaf(type))) {
		if (last < max) // Fits in the node, but may span slots.
			return false;

		if ((last == max) && entry) // Writes to the end of the node but not null.
			return false;
	} else if ((piv == last) && entry) {
		return false;
	}

	/* Writing ULONG_MAX is not a spanning write regardless of the value
	 * being written as long as the range fits in the node.
	 */
	if ((last == ULONG_MAX) && (last == max))
		return false;

	trace_mas_is_span_wr(mas, piv, entry);

	return true;
}

/*
 * mas_node_walk() - Walk a maple node to offset of the index.
 * @mas: The maple state
 * @type: The maple node type
 * @*range_min: Pointer to store the minimum range of the offset
 * @*range_max: Pointer to store the maximum range of the offset
 *
 * The offset will be stored in the maple state.
 *
 */
static inline void mas_node_walk(struct ma_state *mas, enum maple_type type,
		unsigned long *range_min, unsigned long *range_max)
{
	unsigned long *pivots = ma_pivots(mas_mn(mas), type);
	unsigned char offset, count;
	unsigned long min, max, index;

	if (unlikely(ma_is_dense(type))) {
		(*range_max) = (*range_min) = mas->index;
		mas->offset = mas->index = mas->min;
		return;
	}

	offset = mas->offset;
	min = mas_safe_min(mas, pivots, offset);
	count = mt_pivots[type];
	if (unlikely(offset == count))
		goto max;

	index = mas->index;
	max = pivots[offset];
	if (unlikely(index <= max))
		goto done;

	if (unlikely(!max && offset))
		goto max;

	offset++;
	min = max + 1;
	while (offset < count) {
		max = pivots[offset];
		if (index <= max)
			goto done;

		if (unlikely(!max))
			break;

		min = max + 1;
		offset++;
	}

max:
	max = mas->max;
done:
	*range_max = max;
	*range_min = min;
	mas->offset = offset;
}

/*
 * mas_wr_walk(): Walk the tree for a write.
 * @range_min - pointer that will be set to the minimum of the slot range
 * @range_max - pointer that will be set to the maximum of the slot range
 * @entry - the value that will be written.
 *
 * Uses mas_slot_locked() and does not need to worry about dead nodes.
 *
 * Return: True if it's contained in a node, false on spanning write.
 */
static bool mas_wr_walk(struct ma_state *mas, unsigned long *range_min,
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
		mas->node = mas_slot_locked(mas, ma_slots(mas_mn(mas), type),
				     mas->offset);
		mas->offset = 0;
	}
	return true;
}

/*
 * mas_extend_null() - Extend a store of a %NULL to include surrounding %NULLs.
 * @l_mas: The left maple state
 * @r_mas: The right maple state
 */
static inline void mas_extend_null(struct ma_state *l_mas, struct ma_state *r_mas)
{
	unsigned char l_slot = l_mas->offset;
	unsigned char r_slot = r_mas->offset;
	unsigned char cp_r_slot = r_slot;
	unsigned long range_max = mas_safe_pivot(r_mas, r_slot);
	unsigned long range_min = l_mas->min;
	void __rcu **slots = ma_slots(mte_to_node(l_mas->node),
				    mte_node_type(l_mas->node));
	void *content = mas_slot_locked(l_mas, slots, l_slot);

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
 * __mas_walk(): Locates a value and sets the mas->node and slot accordingly.
 * range_min and range_max are set to the range which the entry is valid.
 * @mas: The maple state
 * @*range_min: A pointer to store the minimum of the range
 * @*range_max: A pointer to store the maximum of the range
 *
 * Check mas->node is still valid on return of any value.
 *
 * Return: true if pointing to a valid node and offset.  False otherwise.
 */
static inline bool __mas_walk(struct ma_state *mas, unsigned long *range_min,
		unsigned long *range_max)
{
	struct maple_enode *next;
	enum maple_type type;

	while (true) {
		type = mte_node_type(mas->node);
		mas->depth++;

		mas_node_walk(mas, type, range_min, range_max);
		if (unlikely(ma_is_leaf(type)))
			return true;

		next = mas_slot(mas, ma_slots(mas_mn(mas), type), mas->offset);
		if (unlikely(mte_dead_node(mas->node)))
			return false;

		if (unlikely(!next))
			return false;

		// Descend.
		mas->max = *range_max;
		mas->min = *range_min;
		mas->node = next;
		mas->offset = 0;
	}
	return false;
}

/*
 * mas_spanning_store() - Create a subtree with the store operation completed
 * and new nodes where necessary, then place the sub-tree in the actual tree.
 * Note that mas is expected to point to the node which caused the store to
 * span.
 * @mas: The maple state
 * @entry: The entry to store.
 *
 * Return: 0 on error, positive on success.
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

/*
 * mas_append() - Attempt to append data to the end of a node
 * @mas: The maple state
 * @entry: The entry to store
 * @min: The minimum of the range
 * @end: The end of the node
 * @content: The contents of the slot currently
 * @mt: The maple node type
 *
 * Appending never needs to allocate.
 *
 * Return: True if stored, false otherwise
 */
static inline bool mas_append(struct ma_state *mas, void *entry,
			      unsigned long min, unsigned char end,
			      void *content, enum maple_type mt)
{
	void __rcu **slots = ma_slots(mas_mn(mas), mt);
	unsigned long *pivots = ma_pivots(mas_mn(mas), mt);
	unsigned char new_end;
	unsigned char max_slots = mt_slots[mt];

	/* slot store would happen if the last entry wasn't being split, so add
	 * one.
	 */
	new_end = end + 1;
	if (min < mas->index)
		new_end++;

	if (new_end >= max_slots)
		return false;

	if (new_end < max_slots - 1)
		pivots[new_end] = pivots[end];
	rcu_assign_pointer(slots[new_end--], content);

	if (new_end < max_slots - 1)
		pivots[new_end] = mas->last;
	rcu_assign_pointer(slots[new_end--], entry);

	if (min < mas->index) {
		pivots[new_end] = mas->index - 1;
		mas->offset++;
	}

	mas_update_gap(mas);
	return true;
}

/*
 * mas_node_store() - Attempt to store the value in a node
 * @mas: The maple state
 * @entry: The value to store
 * @min: The minimum of the range
 * @max: The maximum of the range
 * @mt: The maple node type
 * @slots: Pointer to the slot array
 * @pivots: Pointer to the pivot array
 *
 * Attempts to reuse the node, but may allocate.
 *
 * Return: True if stored, false otherwise
 */
static inline bool mas_node_store(struct ma_state *mas, void *entry,
				  unsigned long min, unsigned long max,
				  unsigned char end, void *content,
				  enum maple_type mt, void __rcu **slots,
				  unsigned long *pivots)
{
	void __rcu **dst_slots;
	unsigned long *dst_pivots;
	unsigned char dst_offset, new_end = end;
	unsigned char offset, offset_end;
	struct maple_node reuse, *newnode;
	unsigned char copy_size, max_piv = mt_pivots[mt];

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
		} while (piv <= mas->last);
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
	memcpy(dst_slots, slots, sizeof(void *) * (offset + 1));
	dst_offset = offset;

	// Handle insert of new range starting after old range
	if (min < mas->index) {
		rcu_assign_pointer(dst_slots[dst_offset], content);
		dst_pivots[dst_offset++] = mas->index - 1;
	}

	// Store the new entry and range end.
	if (dst_offset < max_piv)
		dst_pivots[dst_offset] = mas->last;
	mas->offset = dst_offset;
	rcu_assign_pointer(dst_slots[dst_offset++], entry);

	if (offset_end > end) // this range wrote to the end of the node.
		goto done;

	// Copy to the end of node if necessary.
	copy_size = end - offset_end + 1;
	memcpy(dst_slots + dst_offset, slots + offset_end,
	       sizeof(void *) * copy_size);
	if (dst_offset < max_piv) {
		if (copy_size > max_piv - dst_offset)
			copy_size = max_piv - dst_offset;
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

/*
 * mas_slot_store: Attempt to store a value in a slot.
 * @mas: the maple state
 * @entry: The entry to store
 * @min: The range minimum
 * @max: The range maximum
 * @end: The end of the maple node
 * @content: The current content
 * @mt: The maple node type
 * @slots: The pointer to the slots array
 *
 * Return: True if stored, false otherwise
 */
static inline bool mas_slot_store(struct ma_state *mas, void *entry,
				  unsigned long min, unsigned long max,
				  unsigned char end, void *content,
				  enum maple_type mt, void __rcu **slots)
{
	struct maple_node *node = mas_mn(mas);
	unsigned long *pivots = ma_pivots(node, mt);
	unsigned long lmax; // Logical max.
	unsigned char offset = mas->offset;

	if (min == mas->index && max == mas->last) { // exact fit.
		rcu_assign_pointer(slots[offset], entry);
		goto done;
	}

	if (offset + 1 >= mt_slots[mt]) // out of room.
		return false;

	if (max > mas->last){ // going to split a single entry.
		if ((offset == end) &&
		    mas_append(mas, entry, min, end, content, mt))
		    return true;

		goto try_node_store;
	}

	lmax = mas_logical_pivot(mas, pivots, offset + 1, mt);
	if (lmax < mas->last) // going to overwrite too many slots.
		goto try_node_store;

	if (min == mas->index) {
		if (lmax <= mas->last) // overwriting two or more ranges with one.
			goto try_node_store;

		// Overwriting a portion of offset + 1.
		rcu_assign_pointer(slots[offset], entry);
		pivots[offset] = mas->last;
		goto done;
	} else if (min < mas->index) { // split start
		if (lmax != mas->last) // Doesn't end on the next range end.
			goto try_node_store;

		if (offset + 1 < mt_pivots[mt])
			pivots[offset + 1] = mas->last;
		rcu_assign_pointer(slots[offset + 1], entry);
		pivots[offset] = mas->index - 1;
		mas->offset++; // Keep mas accurate.
		goto done;
	}

	return false;


done:
	mas_update_gap(mas);
	return true;

try_node_store:
	return mas_node_store(mas, entry, min, max, end, content, mt, slots, pivots);
}

/*
 * _mas_store() - Internal call to store a value
 * @mas: The maple state
 * @entry: The entry to store
 * @overwrite: Allowed to overwrite entries or not
 *
 * Return: The contents that was stored at the index.
 */
static inline void *_mas_store(struct ma_state *mas, void *entry, bool overwrite)
{
	unsigned long r_max, r_min;
	unsigned char end, zero;
	void *content = NULL;
	struct maple_big_node b_node;
	void __rcu **slots;
	enum maple_type mt;
	struct maple_node *node;

	int ret = 0;

	if (mas_start(mas) || mas_is_none(mas) || mas->node == MAS_ROOT) {
		ret = mas_root_ptr(mas, entry, overwrite);
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
	mt = mte_node_type(mas->node);
	node = mas_mn(mas);
	slots = ma_slots(node, mt);
	content = mas_slot_locked(mas, slots, mas->offset);
	if (unlikely(!overwrite) && (content || (mas->last > r_max))) {
		mas_set_err(mas, -EEXIST);
		return content;
	}

	if (!entry) {
		unsigned char offset_end = mas->offset;

		if (!content) {
			mas->index = r_min;
			if (mas->last < r_max)
				mas->last = r_max;
			// if this one is null the next and prev are not.
		} else {
			unsigned long *pivots = ma_pivots(node, mt);

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
	if (mas_slot_store(mas, entry, r_min, r_max, end, content, mt, slots))
		return content;

	if (mas_is_err(mas))
		return content;

	/* Slow path. */
	b_node.type = mte_node_type(mas->node);
	b_node.b_end = mas_store_b_node(mas, &b_node, entry, end);
	b_node.min = mas->min;

	zero = MAPLE_BIG_NODE_SLOTS - b_node.b_end - 1;
	memset(b_node.slot + b_node.b_end + 1, 0, sizeof(void *) * zero--);
	memset(b_node.pivot + b_node.b_end + 1, 0,
	       sizeof(unsigned long) * zero);

	if (!mas_commit_b_node(mas, &b_node, end))
		return NULL;

complete_at_root:
	if (ret > 2)
		return NULL;
spanning_store:
	return content;
}

/*
 * mas_prev_node() - Find the prev non-null entry at the same level in the
 * tree.  The prev value will be mas->node[mas->offset] or MAS_NONE.
 * @mas: The maple state
 * @limit: The lower limit to search
 *
 * Result needs to be checked if the node is dead.
 * The prev node value will be mas->node[mas->offset] or MAS_NONE.
 */
static inline void mas_prev_node(struct ma_state *mas, unsigned long limit)
{
	enum maple_type mt;
	int offset, level;
	void __rcu **slots;
	struct maple_node *node;
	unsigned long *pivots;

	if (mas_is_none(mas))
		return;

	if (mte_is_root(mas->node))
		goto no_entry;

	level = 0;
	do {
		if (mte_is_root(mas->node))
			goto no_entry;

		// Walk up.
		offset = mte_parent_slot(mas->node);
		mas_ascend(mas);
		if (unlikely(mte_dead_node(mas->node)))
			return;

		level++;
	} while (!offset);

	offset--;
	mt = mte_node_type(mas->node);
	node = mas_mn(mas);
	slots = ma_slots(node, mt);
	pivots = ma_pivots(node, mt);
	mas->max = pivots[offset];
	if (mas->max < limit)
		goto no_entry;

	while (level > 1) {
		mas->node = mas_slot(mas, slots, offset);
		if (unlikely(mte_dead_node(mas->node)))
			return;

		level--;
		mt = mte_node_type(mas->node);
		node = mas_mn(mas);
		slots = ma_slots(node, mt);
		pivots = ma_pivots(node, mt);
		offset = mas_data_end(mas);
		if (offset < mt_pivots[mt]) {
			mas->max = pivots[offset];
			if (mas->max < limit)
				goto no_entry;
		}
	}

	mas->node = mas_slot(mas, slots, offset);
	if (unlikely(mte_dead_node(mas->node)))
		return;

	mas->offset = offset;
	if (offset)
		mas->min = pivots[offset - 1] + 1;

	return;

no_entry:
	mas->node = MAS_NONE;
	return;

}

/*
 * mas_next_node() - Get the next node at the same level in the tree.
 * @mas: The maple state
 * @max: The maximum pivot value to check.
 *
 * Return needs to be checked for dead nodes.
 *
 * Return: The next value will be mas->node[mas->offset] or MAS_NONE.
 */
static inline unsigned long mas_next_node(struct ma_state *mas,
		unsigned long max)
{
	unsigned long min, pivot;
	unsigned long *pivots;
	struct maple_node *node;
	int level = 0;
	unsigned char offset, end;
	enum maple_type mt;
	void __rcu **slots;

	if (mte_is_root(mas->node))
		goto no_entry;

	if (mas->max >= max)
		goto no_entry;

	level = 0;
	do {
		if (mte_is_root(mas->node))
			goto no_entry;

		offset = mte_parent_slot(mas->node);
		min = mas->max + 1;
		if (min > max)
			goto no_entry;
		mas_ascend(mas);
		if (unlikely(mte_dead_node(mas->node)))
			return mas->max;

		level++;
		end = mas_data_end(mas);
		node = mas_mn(mas);
		mt = mte_node_type(mas->node);
		slots = ma_slots(node, mt);
		pivots = ma_pivots(node, mt);
	} while (unlikely(offset == end));

	pivot = _mas_safe_pivot(mas, pivots, ++offset, mt);
	// Descend, if necessary.
	while (unlikely(level > 1)) {
		mas->node = mas_slot(mas, slots, offset);
		if (unlikely(mte_dead_node(mas->node)))
			return mas->max;

		level--;
		node = mas_mn(mas);
		mt = mte_node_type(mas->node);
		slots = ma_slots(node, mt);
		pivots = ma_pivots(node, mt);
		offset = 0;
		pivot = pivots[0];
	}

	mas->node = mas_slot(mas, slots, offset);
	if (unlikely(mte_dead_node(mas->node)))
		return mas->max;

	mas->min = min;
	mas->max = pivot;
	return mas->max;

no_entry:
	mas->node = MAS_NONE;
	return mas->max;
}

/*
 * mas_prev_nentry() - Get the previous node entry.
 * @mas: The maple state.
 * @limit: The lower limit to check for a value.
 *
 * Return: the entry, %NULL otherwise.
 */
static inline void *mas_prev_nentry(struct ma_state *mas, unsigned long limit)
{
	unsigned long pivot;
	unsigned char offset;
	struct maple_node *mn;
	enum maple_type mt;
	unsigned long *pivots;
	void __rcu **slots;

	if (!mas->offset)
		return NULL;

	mn = mas_mn(mas);
	mt = mte_node_type(mas->node);
	offset = mas->offset - 1;
	slots = ma_slots(mn, mt);
	pivots = ma_pivots(mn, mt);
	if (offset == mt_pivots[mt])
		pivot = mas->max;
	else
		pivot = pivots[offset];

	while ((offset && !mas_slot(mas, slots, offset) && pivot >= limit) ||
			!pivot)
		pivot = pivots[--offset];

	mas->offset = offset;
	if (!mas_slot(mas, slots, offset))
		return NULL;

	mas->last = pivot;
	mas->index = mas_safe_min(mas, pivots, offset);
	return mas_slot(mas, slots, offset);
}

/*
 * mas_next_nentry() - Get the next node entry
 * @mas: The maple state
 * @max: The maximum value to check
 * @*range_start: Pointer to store the start of the range.
 *
 * Sets @mas->offset to the offset of the next node entry, @mas->last to the
 * pivot of the entry.
 *
 * Return: The next entry, %NULL otherwise
 */
static inline void *mas_next_nentry(struct ma_state *mas, unsigned long max,
		unsigned long *range_start)
{
	enum maple_type type = mte_node_type(mas->node);
	struct maple_node *node = mas_mn(mas);
	unsigned long pivot;
	unsigned long r_start;
	unsigned char count, offset = mas->offset;
	unsigned long *pivots = ma_pivots(node, type);
	void __rcu **slots;
	void *entry = NULL;

	r_start = mas_safe_min(mas, pivots, offset);
	if (r_start > max) {
		mas->index = max;
		goto no_entry;
	}

	count = mt_pivots[type];
	slots = ma_slots(node, type);
	while (offset < count) {
		pivot = pivots[offset];
		if (!pivot)
			goto no_entry;

		entry = mas_slot(mas, slots, offset);
		if (entry)
			goto found;

		r_start = pivot + 1;
		if (r_start > max) {
			mas->index = max;
			goto no_entry;
		}
		offset++;
	}

	pivot = _mas_safe_pivot(mas, pivots, offset, type);
	if (!pivot)
		goto no_entry;

	entry = mas_slot(mas, slots, offset);
	if (entry)
		goto found;


no_entry:
	*range_start = r_start;
	return NULL;

found:
	mas->last = pivot;
	*range_start = r_start;
	mas->offset = offset;
	return entry;
}

/*
 *  _mas_walk() - Walk to @mas->index and set the range values.
 * @mas: The maple state.
 * @*range_min: The minimum range to be set.
 * @*range_max: The maximum range to be set.
 *
 * Ranges are only valid if there is a valid entry at @mas->index.
 *
 * Return: True if a value exists, false otherwise.
 */
static inline bool _mas_walk(struct ma_state *mas, unsigned long *range_min,
			     unsigned long *range_max)
{

	void *entry;
	bool ret;

retry:
	ret = false;
	entry = mas_start(mas);
	if (entry)
		return true;

	if (mas_is_none(mas))
		goto not_found;

	if (mas_is_ptr(mas)) {
		*range_min = *range_max = 0;
		if (!mas->index)
			return true;

		goto not_found;
	}

	ret = __mas_walk(mas, range_min, range_max);

	if (unlikely(mte_dead_node(mas->node))) {
		mas->node = MAS_START;
		goto retry;
	}

	return ret;

not_found:
	mas->offset = MAPLE_NODE_SLOTS;
	return false;
}

/*
 * mas_dead_node() - Check if the maple state is pointing to a dead node.
 * @mas: The maple state
 * @index: The index to restore in @mas.
 *
 * Return: 1 if @mas has been reset to MAS_START, 0 otherwise.
 */
static inline int mas_dead_node(struct ma_state *mas, unsigned long index)
{
	unsigned long range_max, range_min;

	if (unlikely(!mas_searchable(mas) || mas_is_start(mas)))
		return 0;

	if (likely(!mte_dead_node(mas->node)))
		return 0;

	mas->index = index;
	mas->node = MAS_START;
	_mas_walk(mas, &range_min, &range_max);
	return 1;
}

/*
 * mas_first_entry() - Go the first leaf and find the first entry.
 * @mas: the maple state.
 * @limit: the maximum index to check.
 * @*r_start: Pointer to set to the range start.
 *
 * Sets mas->offset to the offset of the entry, r_start to the range minimum.
 *
 * Return: The first entry or MAS_NONE.
 */
static inline void *mas_first_entry(struct ma_state *mas,
		unsigned long limit, unsigned long *r_start)
{
	unsigned long max;
	unsigned long range_start;
	unsigned char offset;
	unsigned long *pivots;
	struct maple_node *mn;
	void __rcu **slots;
	enum maple_type mt;
	void *entry = NULL;

	range_start = mas->min;
	max = mas->max;
restart:
	while (likely(!mte_is_leaf(mas->node))) {
		mn = mas_mn(mas);
		mt = mte_node_type(mas->node);
		slots = ma_slots(mn, mt);
		pivots = ma_pivots(mn, mt);
		max = pivots[0];
		mas->node = mas_slot(mas, slots, 0);
		if (unlikely(mas_dead_node(mas, range_start)))
			goto restart;
	}

	mas->max = max;
	mn = mas_mn(mas);
	mt = mte_node_type(mas->node);
	slots = ma_slots(mn, mt);
	/* 0 or 1 must be set */
	offset = 0;
	if (range_start > limit)
		goto none;

	entry = mas_slot(mas, slots, offset);
	if(likely(entry))
		goto done;

	pivots = ma_pivots(mn, mt);
	range_start = pivots[0] + 1;

	if (range_start > limit)
		goto none;

	entry = mas_slot(mas, slots, offset);
	if(likely(entry))
		goto done;

none:
	mas->node = MAS_NONE;
done:
	mas->offset = offset;
	*r_start = range_start;
	return entry;
}

/*
 * __mas_next() - Internal function to get the next entry.
 * @mas: The maple state
 * @limit: The maximum range start.
 *
 * Set the @mas->node to the next entry and the range_start to
 * the beginning value for the entry.  Does not check beyond @limit.
 * Sets @mas->index and @mas->last to the limit if it is hit.
 * Restarts on dead nodes.
 *
 * Return: the next entry or %NULL.
 */
static inline void *__mas_next(struct ma_state *mas, unsigned long limit)
{
	void *entry = NULL;
	struct maple_enode *prev_node = mas->node;
	unsigned char offset = mas->offset;
	unsigned long last = mas->last;
	enum maple_type mt = mte_node_type(mas->node);
	unsigned long r_start;

retry:
	mas->offset++;
	if (unlikely(mas->offset >= mt_slots[mt]))
		goto next_node;

	while (!mas_is_none(mas)) {

		if (likely(ma_is_leaf(mt)))
			entry = mas_next_nentry(mas, limit, &r_start);
		else
			entry = mas_first_entry(mas, limit, &r_start);

		if (unlikely((r_start > limit)))
			break;

		if (likely(entry)) {
			if (unlikely(mas_dead_node(mas, last)))
				goto retry;

			mas->index = r_start;
			return entry;
		}

next_node:
		prev_node = mas->node;
		offset = mas->offset;
		mas_next_node(mas, limit);
		if (unlikely(mas_dead_node(mas, last)))
			goto retry;

		mas->offset = 0;
		mt = mte_node_type(mas->node);
	}

	mas->index = mas->last = limit;
	mas->offset = offset;
	mas->node = prev_node;
	return NULL;
}

/*
 * _mas_prev() - Internal function. Return the previous entry
 * @mas: The maple state.
 * @limit: The lower limit to check.
 *
 * Return: the previous entry or %NULL.
 */
static inline void *_mas_prev(struct ma_state *mas, unsigned long limit)
{
	void *entry;
	unsigned long index = mas->index;

retry:
	while (likely(!mas_is_none(mas))) {
		entry = mas_prev_nentry(mas, limit);
		if (likely(entry))
			return entry;

		mas_prev_node(mas, limit);
		if (unlikely(mas_dead_node(mas, index)))
			goto retry;

		mas->offset = mt_slot_count(mas->node);
	}

	mas->index = mas->last = limit;
	return NULL;
}

/*
 * _mas_rev_awalk() - Internal function.  Reverse allocation walk.  Find the
 * highest gap address of a given size in a given node and descend.
 * @mas: The maple state
 * @size: The needed size.
 *
 * Return: True if found in a leaf, false otherwise.
 *
 */
static bool _mas_rev_awalk(struct ma_state *mas, unsigned long size)
{
	enum maple_type type = mte_node_type(mas->node);
	struct maple_node *node = mas_mn(mas);
	unsigned long *pivots, *gaps;
	void __rcu **slots;
	unsigned long gap = 0;
	unsigned long max, min, index;
	unsigned char offset;

	if (unlikely(mas_is_err(mas)))
	    return true;

	if (ma_is_dense(type)) { // dense nodes.
		mas->offset = (unsigned char)(mas->index - mas->min);
		return true;
	}

	pivots = ma_pivots(node, type);
	slots = ma_slots(node, type);
	if (ma_is_leaf(type))
		gaps = NULL;
	else
		gaps = ma_gaps(node, type);

	offset = mas->offset;
	min = mas_safe_min(mas, pivots, offset);
	while (mas->last < min) // Skip out of bounds.
		min = mas_safe_min(mas, pivots, --offset);

	max = _mas_safe_pivot(mas, pivots, offset, type);
	index = mas->index;
	while (index <= max) {
		gap = 0;
		if (gaps)
			gap = gaps[offset];
		else if (!mas_slot(mas, slots, offset))
			gap = max - min + 1;

		if (gap) {
			if ((size <= gap) && (size <= mas->last - min + 1))
				break;

			if (!gaps) {
				// Skip the next slot, it cannot be a gap.
				if (offset < 2)
					goto ascend;

				offset -= 2;
				max = pivots[offset];
				min = mas_safe_min(mas, pivots, offset);
				continue;
			}
		}

		if (!offset)
			goto ascend;

		offset--;
		max = min - 1;
		min = mas_safe_min(mas, pivots, offset);
	}

	if (unlikely(index > max)) {
		mas_set_err(mas, -EBUSY);
		return false;
	}

	if (unlikely(ma_is_leaf(type))) {
		mas->offset = offset;
		mas->min = min;
		mas->max = min + gap - 1;
		return true;
	}

	// descend, only happens under lock.
	mas->node = mas_slot(mas, slots, offset);
	mas->min = min;
	mas->max = max;
	mas->offset = mas_data_end(mas);
	return false;

ascend:
	if (mte_is_root(mas->node))
		mas_set_err(mas, -EBUSY);

	return false;
}

static inline bool _mas_awalk(struct ma_state *mas, unsigned long size)
{
	enum maple_type type = mte_node_type(mas->node);
	unsigned long pivot, min, gap = 0;
	unsigned char count, offset;
	unsigned long *gaps = NULL, *pivots = ma_pivots(mas_mn(mas), type);
	void __rcu **slots = ma_slots(mas_mn(mas), type);
	bool found = false;

	if (ma_is_dense(type)) {
		mas->offset = (unsigned char)(mas->index - mas->min);
		return true;
	}

	if (!ma_is_leaf(type))
		gaps = ma_gaps(mte_to_node(mas->node), type);

	offset = mas->offset;
	count = mt_slots[type];
	min = mas_safe_min(mas, pivots, offset);
	for (; offset < count; offset++) {
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

/* mas_walk() - Search for @mas->index in the tree.
 * @mas - the maple state.
 *
 * mas->index and mas->last will be set to the range if there is a value.  If
 * mas->node is MAS_NONE, reset to MAS_START.
 *
 * Return: the entry at the location or %NULL.
 */
void *mas_walk(struct ma_state *mas)
{
	unsigned long range_min, range_max;
	unsigned long index = mas->index;
	void *entry;

	if (mas_is_none(mas))
		mas->node = MAS_START;

	_mas_walk(mas, &range_min, &range_max);
retry:
	entry = NULL;
	if (mas->offset != MAPLE_NODE_SLOTS)
		entry = mas_get_slot(mas, mas->offset);

	if (unlikely(mas_dead_node(mas, index)))
		goto retry;

	mas->index = range_min;
	mas->last = range_max;

	return entry;
}

static inline bool mas_search_cont(struct ma_state *mas, unsigned long index,
		unsigned long max, void *entry)
{
	if (index > max)
		return false;

	if (mas_is_start(mas))
		return true;

	if (index == max)
		return false;

	if (!mas_searchable(mas))
		return false;

	if (mas_is_err(mas))
		return false;

	if (entry)
		return false;

	return true;
}

static inline bool mas_rewind_node(struct ma_state *mas)
{
	unsigned char slot;

	do {
		if (mte_is_root(mas->node)) {
			slot = mas->offset;
			if (!slot)
				return false;
		} else {
			slot = mte_parent_slot(mas->node);
			mas_ascend(mas);
		}
	} while (!slot);

	mas->offset = --slot;
	return true;
}

/*
 * mas_skip_node() - Internal function.  Skip over a node.
 * @mas: The maple state.
 *
 * Return: true if there is another node, false otherwise.
 */
static inline bool mas_skip_node(struct ma_state *mas)
{
	unsigned char slot, slot_count;
	unsigned long *pivots;
	enum maple_type mt;

	mt = mte_node_type(mas->node);
	slot_count = mt_slots[mt] - 1;
	do {
		if (mte_is_root(mas->node)) {
			slot = mas->offset;
			if (slot > slot_count) {
				mas_set_err(mas, -EBUSY);
				return false;
			}
		} else {
			slot = mte_parent_slot(mas->node);
			mas_ascend(mas);
			mt = mte_node_type(mas->node);
			slot_count = mt_slots[mt] - 1;
		}
	} while (slot > slot_count);

	mas->offset = ++slot;
	pivots = ma_pivots(mas_mn(mas), mt);
	if (slot > 0)
		mas->min = pivots[slot - 1] + 1;

	if (slot <= slot_count)
		mas->max = pivots[slot];

	return true;
}

/*
 * mas_awalk() - Allocation walk.  Search from low address to high, for a gap of
 * @size
 * @mas: The maple state
 * @size: The size of the gap required
 *
 * Search between @mas->index and @mas->last for a gap of @size.
 */
static inline void mas_awalk(struct ma_state *mas, unsigned long size)
{
	struct maple_enode *last = NULL;

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

/*
 * mas_fill_gap() - Fill a located gap with @entry.
 * @mas: The maple state
 * @entry: The value to store
 * @slot: The offset into the node to store the @entry
 * @size: The size of the entry
 * @index: The start location
 */
static inline void mas_fill_gap(struct ma_state *mas, void *entry,
		unsigned char slot, unsigned long size, unsigned long *index)
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
}

/*
 * mas_sparse_area() - Internal function.  Return upper or lower limit when
 * searching for a gap in an empty tree.
 * @mas: The maple state
 * @min: the minimum range
 * @max: The maximum range
 * @size: The size of the gap
 * @fwd: Searching forward or back
 */
static inline void mas_sparse_area(struct ma_state *mas, unsigned long min,
				unsigned long max, unsigned long size, bool fwd)
{
	unsigned long start = 0;

	if (!unlikely(mas_is_none(mas)))
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

/*
 * mas_empty_area() - Get the lowest address within the range that is
 * sufficient for the size requested.
 * @mas: The maple state
 * @min: The lowest value of the range
 * @max: The highest value of the range
 * @size: The size needed
 */
int mas_empty_area(struct ma_state *mas, unsigned long min,
		unsigned long max, unsigned long size)
{
	unsigned char offset;
	unsigned long *pivots;
	enum maple_type mt;

	if (mas_is_start(mas)) {
		mas_start(mas);
	} else if (mas->offset >= 2) {
		mas->offset -= 2;
	} else if (!mas_skip_node(mas)) {
		return -EBUSY;
	}

	// Empty set.
	if (mas_is_none(mas) || mas_is_ptr(mas)) {
		mas_sparse_area(mas, min, max, size, true);
		return 0;
	}

	// The start of the window can only be within these values.
	mas->index = min;
	mas->last = max;
	mas_awalk(mas, size);

	if (unlikely(mas_is_err(mas)))
		return xa_err(mas->node);

	offset = mas->offset;
	if (unlikely(offset == MAPLE_NODE_SLOTS))
		return -EBUSY;

	mt = mte_node_type(mas->node);
	pivots = ma_pivots(mas_mn(mas), mt);
	if (offset)
		mas->min = pivots[offset - 1] + 1;

	if (offset < mt_pivots[mt])
		mas->max = pivots[offset];

	if (mas->index < mas->min)
		mas->index = mas->min;

	mas->last = mas->index + size - 1;
	return 0;
}

/*
 * mas_empty_area_rev() - Get the highest address within the range that is
 * sufficient for the size requested.
 * @mas: The maple state
 * @min: The lowest value of the range
 * @max: The highest value of the range
 * @size: The size needed
 */
int mas_empty_area_rev(struct ma_state *mas, unsigned long min,
		unsigned long max, unsigned long size)
{
	struct maple_enode *last = mas->node;

	if (mas_is_start(mas)) {
		mas_start(mas);
		mas->offset = mas_data_end(mas);
	} else if (mas->offset >= 2) {
		mas->offset -= 2;
	} else if (!mas_rewind_node(mas)) {
		return -EBUSY;
	}

	// Empty set.
	if (mas_is_none(mas) || mas_is_ptr(mas)) {
		mas_sparse_area(mas, min, max, size, false);
		return 0;
	}

	// The start of the window can only be within these values.
	mas->index = min;
	mas->last = max;

	while (!_mas_rev_awalk(mas, size)) {
		if (last == mas->node) {
			if (!mas_rewind_node(mas))
				return -EBUSY;
		} else {
			last = mas->node;
		}
	}

	if (unlikely(mas->offset == MAPLE_NODE_SLOTS))
		return -EBUSY;

	/* mas_rev_awalk() has set mas->min and mas->max to the gap values.  If
	 * the maximum is outside the window we are searching, then use the last
	 * location in the search.
	 * mas->max and mas->min is the range of the gap.
	 * mas->index and mas->last are currently set to the search range.
	 */
	// Trim the upper limit to the max.
	if (mas->max <= mas->last)
		mas->last = mas->max;

	mas->index = mas->last - size + 1;
	return 0;
}

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

	mas_fill_gap(mas, entry, mas->offset, size, index);
	return 0;

no_gap:
	return -EBUSY;
}

static inline int mas_rev_alloc(struct ma_state *mas, unsigned long min,
				unsigned long max, void *entry,
				unsigned long size, unsigned long *index)
{
	int ret = 0;

	ret = mas_empty_area_rev(mas, min, max, size);
	if (ret)
		return ret;

	if (mas_is_err(mas))
		return xa_err(mas->node);

	if (mas->offset == MAPLE_NODE_SLOTS)
		goto no_gap;

	mas_fill_gap(mas, entry, mas->offset, size, index);
	return 0;

no_gap:
	return -EBUSY;
}

/*
 * mas_range_load() - Load the entry at an index and get the range.
 * @mas: The maple state
 * @*range_min: Pointer to store the minimum range the entry is valid
 * @*range_max: Pointer to store the maximum range the entry is valid
 *
 * Must hold rcu_read_lock or the write lock.
 * Find where mas->index is located and return the entry.
 * @mas->node will point to the node containing the entry.
 * range_min and range_max will be set accordingly.
 *
 * Return: The entry at mas->index or %NULL
 */
static inline void *mas_range_load(struct ma_state *mas,
	   unsigned long *range_min, unsigned long *range_max)
{
	unsigned long index = mas->index;
	void *entry;

	if (mas_is_none(mas))
		mas->node = MAS_START;

	if (_mas_walk(mas, range_min, range_max))
		if (unlikely(mas->node == MAS_ROOT))
			return mas_root(mas);
retry:
	entry = NULL;
	if (likely(mas->offset != MAPLE_NODE_SLOTS))
		entry = mas_get_slot(mas, mas->offset);

	if (unlikely(mas_dead_node(mas, index)))
		goto retry;

	return entry;
}

/*
 * _mas_next() - Finds the next entry and sets @mas->index and @mas->last to the
 * range.
 * @mas: The maple state
 * @limit: The maximum value to check.
 *.
 *
 * Return: Point to the next entry or %NULL
 *
 */
static void *_mas_next(struct ma_state *mas, unsigned long limit)
{
	void *entry = NULL;


	if (unlikely(mas_is_start(mas))) {// First run.
		unsigned long range_max;
		unsigned long range_start;

		mas_start(mas);
		entry = mas_range_load(mas, &range_start, &range_max);
		mas->last = range_max;
		mas->index = range_start;
		if (entry)
			return entry;
	}

	if (unlikely(!mas_searchable(mas)))
		return NULL;

	entry = __mas_next(mas, limit);
	return entry;
}

/*
 * _mt_find() - Search from start up until an entry is found.
 * @mt: The maple tree
 * @*index: Pointer which contains the start location of the search
 * @max: The maximum value to check
 * @start: If this is the first time being called or not.
 *.  Does not return the zero entry.  Handles locking.
 * Return: the entry or %NULL
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
		entry = _mas_next(&mas, max);
		range_start = mas.index;
		if (!entry || xa_is_zero(entry))
			entry = NULL;
	}

	rcu_read_unlock();
	if (entry)
		*index = mas.last + 1;

	return entry;
}

/*
 * mas_dead_leaves() - Mark all leaves of a node as dead.
 * @mas: The maple state
 * @slots: Pointer to the slot array
 *
 * Must hold the write lock.
 *
 * Return: The number of leaves marked as dead.
 */
static inline
unsigned char mas_dead_leaves(struct ma_state *mas, void __rcu **slots)
{
	struct maple_node *node;
	int offset;

	for (offset = 0; offset < mt_slot_count(mas->node); offset++) {
		void *entry = mas_slot_locked(mas, slots, offset);

		if (!entry)
			break;
		node = mte_to_node(entry);
		node->parent = ma_parent_ptr(node);
		rcu_assign_pointer(slots[offset], node);
	}

	return offset;
}

/*
 * mas_destroy_descend() - Descend until one level before the leaves.
 * @mas: The maple state
 *
 * Internal Function.
 * Must hold the write lock.
 * Used to walk down the left side of the tree during a destroy operation.
 *
 * Return: Pointer to the slot array of the left most node one level above the
 * leave nodes.
 */
static inline void __rcu **mas_destroy_descend(struct ma_state *mas)
{
	void __rcu **slots = ma_slots(mte_to_node(mas->node),
				    mte_node_type(mas->node));
	while (!mte_is_leaf(mas_slot_locked(mas, slots, 0))) {
		mas->node = mas_slot_locked(mas, slots, 0);
		slots = ma_slots(mte_to_node(mas->node),
				     mte_node_type(mas->node));
	}

	return slots;
}

/*
 * mt_destroy_walk() - Free this the node and all nodes in this sub-tree.
 * @head: The rcu_head of the starting node.
 *
 * Must hold the write lock.
 * Walk all nodes from the start node and frees all nodes with use of the bulk
 * free where possible.
 */
static void mt_destroy_walk(struct rcu_head *head)
{
	unsigned char end, offset = 0;
	void __rcu **slots;
	struct maple_node *node = container_of(head, struct maple_node, rcu);
	struct maple_enode *start;
	struct maple_tree mt;
	MA_STATE(mas, NULL, 0, 0);

	if (ma_is_leaf(node->type))
		goto free_leaf;

	mtree_init(&mt, node->ma_flags);
	mas.tree = &mt;
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

		mas.node = mas_slot_locked(&mas, slots, ++offset);
		slots = mas_destroy_descend(&mas);
	}

free_leaf:
	ma_free_rcu(node);
}

/*
 * mte_destroy_walk() - Free a tree or sub-tree.
 * @enode - the encoded maple node (maple_enode) to start
 * @mn - the tree to free - needed for node types.
 *
 * Must hold the write lock.
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

	if (mas->index > mas->last) {
		mas_set_err(mas, -EINVAL);
		return NULL;
	}

	existing = _mas_store(mas, entry, true);
	if (unlikely(mas_is_err(mas)))
		return existing;

	return existing;
}

/*
 * mas_store_gfp() - Store a value into the tree.
 * @mas: The maple state
 * @entry: The entry to store
 * @gfp: The GFP_FLAGS to use for allocations if necessary.
 *
 * Return: 0 on success, -EINVAL on invalid request, -ENOMEM if memory could not
 * be allocated.
 */
int mas_store_gfp(struct ma_state *mas, void *entry, gfp_t gfp)
{

	if (mas_is_span_wr(mas, mas->max, mte_node_type(mas->node), entry) ||
	    mas_is_none(mas))
		mas->node = MAS_START;

retry:
	_mas_store(mas, entry, true);
	if (unlikely(mas_nomem(mas, gfp)))
		goto retry;

	if (unlikely(mas_is_err(mas)))
		return xa_err(mas->node);

	return 0;
}

/*
 * mas_entry_count() - Set the expected number of entries that will be inserted.
 * @mas: The maple state
 * @nr_entries: The number of expected entries.
 *
 * This will attempt to pre-allocate enough nodes to store the expected number
 * of entries.  The allocations will occur using the bulk allocator interface
 * for speed.  Please call mas_destroy() on the @mas after inserting the entries
 * to ensure any unused nodes are freed.
 *
 * Return: 0 on success, -ENOMEM if memory could not be allocated.
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
	nr_nodes = DIV_ROUND_UP(nr_nodes, MAPLE_RANGE64_SLOTS - 1);
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
		if (end < mt_min_slot_count(mas->node) - 1)
			mas_destroy_rebalance(mas, end);

		mas->mas_flags &= ~MA_STATE_REBALANCE;
	}
	mas->mas_flags &= ~MA_STATE_BULK;

	while (mas->alloc && !((unsigned long)mas->alloc & 0x1)) {
		node = mas->alloc;
		mas->alloc = node->slot[0];
		if (node->node_count > 0)
			mt_free_bulk(node->node_count,
					(void __rcu **)&node->slot[1]);
		kmem_cache_free(maple_node_cache, node);
	}
	mas->alloc = NULL;
}

/*
 * mas_next() - Get the next entry.
 * @mas: The maple state
 * @max: The maximum index to check.
 *
 * Must hold rcu_read_lock or the write lock.
 * Can return the zero entry.
 *
 * Return: The next entry or %NULL
 */
void *mas_next(struct ma_state *mas, unsigned long max)
{
	if (mas_is_none(mas))
		mas->node = MAS_START;

	return _mas_next(mas, max);
}
EXPORT_SYMBOL_GPL(mas_next);

/*
 * mas_prev() - Get the previous entry
 * @mas: The maple state
 * @min: The minimum value to check.
 *
 * Must hold rcu_read_lock or the write lock.
 * Will reset mas to MAS_START if the node is MAS_NONE.  Will stop on not
 * searchable nodes.  If mas->node is MAS_START, it will first look up the
 * index, then get the previous entry.
 *
 * Return: the previous value or %NULL.
 */
void *mas_prev(struct ma_state *mas, unsigned long min)
{
	void *entry;

	if (!mas->index) {// Nothing comes before 0.
		mas->last = 0;
		return NULL;
	}

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
	} while (!mas_is_none(mas) && !entry);

	return entry;
}
EXPORT_SYMBOL_GPL(mas_prev);

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


/*
 * mas_find: If mas->node == MAS_START, find the first
 * non-NULL entry >= mas->index.
 * Otherwise, find the first non-NULL entry > mas->index
 * @mas: The maple state
 * @max: The maximum value to check.
 *
 * Must hold rcu_read_lock or the write lock.
 * If an entry exists, last and index are updated accordingly.
 * May set @mas->node to MAS_NONE.
 *
 * Return: The entry or %NULL.
 */
void *mas_find(struct ma_state *mas, unsigned long max)
{
	void *entry = NULL;
	bool first = false;
	unsigned long index = mas->index;

	if (mas_is_start(mas) && (mas->index <= max))
		first = true;

retry:
	while (mas_search_cont(mas, mas->index, max, entry))
		entry = _mas_next(mas, max);

	if (unlikely(mas_dead_node(mas, index))) {
		if (first)
			mas->node = MAS_START;

		goto retry;
	}

	return entry;
}
EXPORT_SYMBOL_GPL(mas_find);

/*
 * mas_erase() - Find the range in which index resides and erase the entire
 * range.
 * @mas: The maple state
 *
 * Must hold the write lock.
 * Searches for @mas->index, sets @mas->index and @mas->last to the range and
 * erases that range.
 *
 * Return: the entry that was erased, @mas->index and @mas->last are updated.
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

/*
 * mas_nomem() - * Check if there was an error allocating and do the allocation
 * if necessary If there are allocations, then free them.
 * @mas: The maple state
 * @gfp: The GFP_FALGS to use for allocations
 */
bool mas_nomem(struct ma_state *mas, gfp_t gfp)
	__must_hold(mas->tree->lock)
{
	if (likely(mas->node != MA_ERROR(-ENOMEM))) {
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

void __init maple_tree_init(void)
{
	maple_node_cache = kmem_cache_create("maple_node",
			sizeof(struct maple_node), sizeof(struct maple_node),
			SLAB_PANIC, NULL);
}

/*
 * mtree_init() - Initialize a maple tree.
 * @mt: The maple tree
 * @ma_flags: The flags to use for the tree.
 */
void mtree_init(struct maple_tree *mt, unsigned int ma_flags)
{
	spin_lock_init(&mt->ma_lock);
	mt->ma_flags = ma_flags;
	rcu_assign_pointer(mt->ma_root, NULL);
}
EXPORT_SYMBOL(mtree_init);

/*
 * mtree_load() - Load a value stored in a maple tree
 * @mt: The maple tree
 * @index: The index to load
 *
 * Return: the entry of %NULL
 */
void *mtree_load(struct maple_tree *mt, unsigned long index)
{
	void *entry;
	unsigned long range_max, range_min;

	MA_STATE(mas, mt, index, index);
	trace_mtree_load(&mas);
	rcu_read_lock();
	entry = mas_range_load(&mas, &range_min, &range_max);
	rcu_read_unlock();
	if (xa_is_zero(entry))
		return NULL;

	return entry;
}
EXPORT_SYMBOL(mtree_load);

/*
 * mtree_store_range() - Store an entry at a given range.
 * @mt: The maple tree
 * @index: The start of the range
 * @last: The end of the range
 * @entry: The entry to store
 * @gfp: The GFP_FLAGS to use for allocations
 *
 * Return: 0 on success, -EINVAL on invalid request, -ENOMEM if memory could not
 * be allocated.
 */
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

/*
 * mtree_store() - Store an entry at a given index.
 * @mt: The maple tree
 * @index: The index to store the value
 * @entry: The entry to store
 * @gfp: The GFP_FLAGS to use for allocations
 *
 * Return: 0 on success, -EINVAL on invalid request, -ENOMEM if memory could not
 * be allocated.
 */
int mtree_store(struct maple_tree *mt, unsigned long index, void *entry,
		 gfp_t gfp)
{
	return mtree_store_range(mt, index, index, entry, gfp);
}
EXPORT_SYMBOL(mtree_store);

/*
 * mtree_insert_range() - Insert an entry at a give range if there is no value.
 * @mt: The maple tree
 * @first: The start of the range
 * @last: The end of the range
 * @entry: The entry to store
 * @gfp: The FGP_FLAGS to use for allocations.
 *
 * Return: 0 on success, -EINVAL on invalid request, -ENOMEM if memory could not
 * be allocated.
 */
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

/*
 * mtree_insert() - Insert an entry at a give index if there is no value.
 * @mt: The maple tree
 * @index : The index to store the value
 * @entry: The entry to store
 * @gfp: The FGP_FLAGS to use for allocations.
 *
 * Return: 0 on success, -EINVAL on invalid request, -ENOMEM if memory could not
 * be allocated.
 */
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

/*
 * mtree_erase() - Find an index and erase the entire range.
 * @mt: The maple tree
 * @index: The index to erase
 *
 * Return: The entry stored at the @index or %NULL
 */
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

/*
 * mtree_destroy() - Destroy a maple tree
 * @mt: The maple tree
 *
 * Frees all resources used by the tree.
 */
void mtree_destroy(struct maple_tree *mt)
{
	void *root;

	mtree_lock(mt);
	root = mt_root_locked(mt);
	if (xa_is_node(root))
		mte_destroy_walk(root, mt);

	mt->ma_flags = 0;
	rcu_assign_pointer(mt->ma_root, NULL);
	mtree_unlock(mt);
}
EXPORT_SYMBOL(mtree_destroy);

/*
 * mt_find() - Search from the start up until an entry is found.
 * @mt: The maple tree
 * @*index: Pointer which contains the start location of the search
 * @max: The maximum value to check
 *
 * Handles locking.
 *
 * Return: The entry at or after the @*index or %NULL
 */
void *mt_find(struct maple_tree *mt, unsigned long *index, unsigned long max)
{
	return _mt_find(mt, index, max, true);
}
EXPORT_SYMBOL(mt_find);

#ifdef CONFIG_DEBUG_MAPLE_TREE
atomic_t maple_tree_tests_run;
EXPORT_SYMBOL_GPL(maple_tree_tests_run);
atomic_t maple_tree_tests_passed;
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

#ifdef CONFIG_MAPLE_SEARCH
/* mas limits not adjusted */
static void mas_dfs_preorder(struct ma_state *mas)
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
#ifdef CONFIG_MAPLE_EXTRAS
static void mas_bfs_preorder(struct ma_state *mas)
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
#endif // CONFIG_MAPLE_EXTRAS

#endif

/* Depth first search, post-order */
static void mas_dfs_postorder(struct ma_state *mas, unsigned long max)
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

// Tree validations
void mt_dump_node(const struct maple_tree *mt, void *entry, unsigned long min,
		unsigned long max, unsigned int depth);
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

void mt_dump_range64(const struct maple_tree *mt, void *entry,
		unsigned long min, unsigned long max, unsigned int depth)
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
			mt_dump_entry(mt_slot(mt, node->slot, i),
					first, last, depth + 1);
		else if (node->slot[i])
			mt_dump_node(mt, mt_slot(mt, node->slot, i),
					first, last, depth + 1);

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

void mt_dump_arange64(const struct maple_tree *mt, void *entry,
		unsigned long min, unsigned long max, unsigned int depth)
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
			mt_dump_entry(mt_slot(mt, node->slot, i),
					first, last, depth + 1);
		else if (node->slot[i])
			mt_dump_node(mt, mt_slot(mt, node->slot, i),
					first, last, depth + 1);

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

void mt_dump_node(const struct maple_tree *mt, void *entry, unsigned long min,
		unsigned long max, unsigned int depth)
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
			mt_dump_entry(mt_slot(mt, node->slot, i),
					min + i, min + i, depth);
		}
		break;
	case maple_leaf_64:
	case maple_range_64:
		mt_dump_range64(mt, entry, min, max, depth);
		break;
	case maple_arange_64:
		mt_dump_arange64(mt, entry, min, max, depth);
		break;

	default:
		pr_cont(" UNKNOWN TYPE\n");
	}
}

void mt_dump(const struct maple_tree *mt)
{
	void *entry = rcu_dereference_check(mt->ma_root,
			lockdep_is_held(&mt->ma_lock));

	pr_info("maple_tree("MA_PTR") flags %X, height %u root "MA_PTR"\n",
		 mt, mt->ma_flags, mt_height(mt), entry);
	if (!xa_is_node(entry))
		mt_dump_entry(entry, 0, 0, 0);
	else if (entry)
		mt_dump_node(mt, entry, 0, mt_max[mte_node_type(entry)], 0);
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
	void __rcu **slots;
	int i;

	if (mte_is_root(mas->node))
		return;

	parent = mte_parent(mas->node);
	slots = ma_slots(parent, p_type);
	MT_BUG_ON(mas->tree, mas_mn(mas) == parent);

	// Check prev/next parent slot for duplicate node entry

	for (i = 0; i < mt_slots[p_type]; i++) {
		node = mas_slot(mas, slots, i);
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
	void __rcu **slots = ma_slots(mte_to_node(mas->node), type);
	struct maple_enode *child;
	unsigned char i;

	if (mte_is_leaf(mas->node))
		return;

	for (i = 0; i < mt_slots[type]; i++) {
		child = mas_slot(mas, slots, i);
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
	void __rcu **slots = ma_slots(mte_to_node(mas->node),
				mte_node_type(mas->node));

	if (mte_is_root(mas->node))
		return; // all limits are fine here.

	for (i = 0; i < mt_slot_count(mas->node); i++) {
		unsigned long piv = mas_safe_pivot(mas, i);

		if (!piv)
			break;

		if (!mte_is_leaf(mas->node)) {
			void *entry = mas_slot(mas, slots, i);
			if (!entry)
				pr_err(MA_PTR"[%u] cannot be null\n",
				       mas_mn(mas), i);

			MT_BUG_ON(mas->tree, !entry);
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

void mt_validate_nulls(struct maple_tree *mt)
{
	void *entry, *last = (void *)1;
	unsigned char end, offset = 0;
	void __rcu **slots;
	MA_STATE(mas, mt, 0, 0);

	mas_start(&mas);
	if (mas_is_none(&mas) || (mas.node == MAS_ROOT))
		return;

	while (!mte_is_leaf(mas.node))
		mas_descend(&mas);

	slots = ma_slots(mte_to_node(mas.node), mte_node_type(mas.node));
	end = mas_data_end(&mas);
	do {
		entry = mas_slot(&mas, slots, offset);
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

	} while (!mas_is_none(&mas));
}
/*
 * validate a maple tree by checking:
 * 1. The limits (pivots are within mas->min to mas->max)
 * 2. The gap is correctly set in the parents
 */
void mt_validate(struct maple_tree *mt)
{
	unsigned char end;
	unsigned long r_start;

	MA_STATE(mas, mt, 0, 0);
	rcu_read_lock();
	mas_start(&mas);
	if (!mas_searchable(&mas))
		goto done;

	mas_first_entry(&mas, ULONG_MAX, &r_start);
	while (!mas_is_none(&mas)) {
		MT_BUG_ON(mas.tree, mte_dead_node(mas.node));
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
