// SPDX-License-Identifier: GPL-2.0+
/*
 * Maple Tree implementation
 * Copyright (c) 2018 Oracle Corporation
 * Authors: Liam R. Howlett <jedix@infradead.org>
 *	    Matthew Wilcox <willy@infradead.org>
 */

#include <linux/maple_tree.h>
#include <linux/xarray.h>
#include <linux/types.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <asm/barrier.h>
//#include <linux/mm.h> // for task_size

#define CONFIG_DEBUG_MAPLE_TREE
#define MA_ROOT_PARENT 1
#define ma_parent_ptr(x) ((struct maple_pnode *)(x))
#define ma_mnode_ptr(x) ((struct maple_node *)(x))
#define ma_enode_ptr(x) ((struct maple_enode *)(x))

static struct kmem_cache *maple_node_cache;

unsigned long mt_max[] = {
	[maple_dense]		= MAPLE_NODE_SLOTS,
	[maple_sparse_6]	= (1UL << 6) - 1,
	[maple_sparse_9]	= (1UL << 9) - 1,
	[maple_sparse_16]	= (1UL << 16) - 1,
	[maple_sparse_21]	= (1UL << 21) - 1,
	[maple_sparse_32]	= UINT_MAX,
	[maple_sparse_64]	= ULONG_MAX,
	[maple_leaf_16]		= (1UL << 16) - 1,
	[maple_leaf_32]		= UINT_MAX,
	[maple_leaf_64]		= ULONG_MAX,
	[maple_range_16]	= (1UL << 16) - 1,
	[maple_range_32]	= UINT_MAX,
	[maple_range_64]	= ULONG_MAX,
	[maple_arange_64]	= ULONG_MAX,
};
#define mt_node_max(x) mt_max[mte_node_type(x)]


unsigned char mt_slots[] = {
	[maple_dense]		= MAPLE_NODE_SLOTS,
	[maple_sparse_6]	= MAPLE_SPARSE6_SLOTS,
	[maple_sparse_9]	= MAPLE_SPARSE9_SLOTS,
	[maple_sparse_16]	= MAPLE_SPARSE16_SLOTS,
	[maple_sparse_21]	= MAPLE_SPARSE21_SLOTS,
	[maple_sparse_32]	= MAPLE_SPARSE32_SLOTS,
	[maple_sparse_64]	= MAPLE_SPARSE64_SLOTS,
	[maple_leaf_16]		= MAPLE_RANGE16_SLOTS,
	[maple_leaf_32]		= MAPLE_RANGE32_SLOTS,
	[maple_leaf_64]		= MAPLE_RANGE64_SLOTS,
	[maple_range_16]	= MAPLE_RANGE16_SLOTS,
	[maple_range_32]	= MAPLE_RANGE32_SLOTS,
	[maple_range_64]	= MAPLE_RANGE64_SLOTS,
	[maple_arange_64]	= MAPLE_ARANGE64_SLOTS,
};
#define mt_slot_count(x) mt_slots[mte_node_type(x)]

unsigned char mt_pivots[] = {
	[maple_dense]		= 0,
	[maple_sparse_6]	= 1,
	[maple_sparse_9]	= MAPLE_SPARSE9_SLOTS - 1,
	[maple_sparse_16]	= MAPLE_SPARSE16_SLOTS - 1,
	[maple_sparse_21]	= MAPLE_SPARSE21_SLOTS - 1,
	[maple_sparse_32]	= MAPLE_SPARSE32_SLOTS - 1,
	[maple_sparse_64]	= MAPLE_SPARSE64_SLOTS - 1,
	[maple_leaf_16]		= MAPLE_RANGE16_SLOTS - 1,
	[maple_leaf_32]		= MAPLE_RANGE32_SLOTS - 1,
	[maple_leaf_64]		= MAPLE_RANGE64_SLOTS - 1,
	[maple_range_16]	= MAPLE_RANGE16_SLOTS - 1,
	[maple_range_32]	= MAPLE_RANGE32_SLOTS - 1,
	[maple_range_64]	= MAPLE_RANGE64_SLOTS - 1,
	[maple_arange_64]	= MAPLE_ARANGE64_SLOTS - 1,
};
#define mt_pivot_count(x) mt_pivots[mte_node_type(x)]

unsigned char mt_min_slots[] = {
	[maple_dense]		= MAPLE_NODE_SLOTS / 2,
	[maple_sparse_6]	= MAPLE_SPARSE6_SLOTS / 2,
	[maple_sparse_9]	= MAPLE_SPARSE9_SLOTS / 2,
	[maple_sparse_16]	= MAPLE_SPARSE16_SLOTS / 2,
	[maple_sparse_21]	= MAPLE_SPARSE21_SLOTS / 2,
	[maple_sparse_32]	= MAPLE_SPARSE32_SLOTS / 2,
	[maple_sparse_64]	= MAPLE_SPARSE64_SLOTS / 2,
	[maple_leaf_16]		= MAPLE_RANGE16_SLOTS / 2,
	[maple_leaf_32]		= MAPLE_RANGE32_SLOTS / 2,
	[maple_leaf_64]		= (MAPLE_RANGE64_SLOTS / 2) - 2,
	[maple_range_16]	= MAPLE_RANGE16_SLOTS / 2,
	[maple_range_32]	= MAPLE_RANGE32_SLOTS / 2,
	[maple_range_64]	= (MAPLE_RANGE64_SLOTS / 2) - 2,
	[maple_arange_64]	= (MAPLE_ARANGE64_SLOTS + 1) / 2,
};
#define mt_min_slot_cnt(x) mt_min_slots[mte_node_type(x)]

// Functions
static struct maple_node *mt_alloc_one(gfp_t gfp)
{
	return kmem_cache_alloc(maple_node_cache, gfp | __GFP_ZERO);
}

static void mt_free_rcu(struct rcu_head *head)
{
	struct maple_node *node = container_of(head, struct maple_node, rcu);

	kmem_cache_free(maple_node_cache, node);
}

static void ma_free(struct maple_node *node)
{
	node->parent = ma_parent_ptr(node);
	call_rcu(&node->rcu, mt_free_rcu);
}

static inline enum maple_type mte_node_type(const struct maple_enode *entry)
{
	return ((unsigned long)entry >> 3) & 15;
}

static inline bool ma_is_dense(const enum maple_type type)
{
	return type < maple_sparse_6;
}

static inline bool mte_is_dense(const struct maple_enode *entry)
{
	return ma_is_dense(mte_node_type(entry));
}
static inline bool ma_is_leaf(const enum maple_type type)
{
	return type < maple_range_16;
}

static inline bool mte_is_leaf(const struct maple_enode *entry)
{
	return ma_is_leaf(mte_node_type(entry));
}

static inline enum maple_type mt_node_hole(const void *entry)
{
	return (unsigned long)entry & 4;

}
/* Private
 * We also reserve values with the bottom two bits set to '10' which are
 * below 4096
 */
static inline bool mt_is_reserved(const void *entry)
{
	return ((unsigned long)entry < 4096) && xa_is_internal(entry);
}

static inline bool mt_is_advanced(const void *entry)
{
	return xa_is_internal(entry) && (entry < XA_ZERO_ENTRY);
}

static inline bool mt_is_empty(const void *entry)
{
	return (!entry) || xa_is_deleted(entry) || xa_is_skip(entry);
}
static inline bool mt_will_coalesce(const void *entry)
{
	return (xa_is_deleted((entry)) || xa_is_skip(entry) ||
			xa_is_retry(entry));
}

static inline void mas_set_err(struct ma_state *mas, long err)
{
	mas->node = MA_ERROR(err);
}
static inline bool mas_is_ptr(struct ma_state *mas)
{
	return mas->node == MAS_ROOT;
}
static inline bool mas_is_none(struct ma_state *mas)
{
	return mas->node == MAS_NONE;
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
	if (!mas->node)
		return false;

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
static inline struct maple_node *mas_mn(const struct ma_state *mas)
{
	return mte_to_node(mas->node);
}

static void mte_free(struct maple_enode *enode)
{
	ma_free(mte_to_node(enode));
}

static inline struct maple_enode *mt_mk_node(const struct maple_node *node,
		enum maple_type type) {
	return (void *)((unsigned long)node | (type << 3) | 4);
}

static inline
void *mte_mk_root(const struct maple_enode *node)
{
	return (void *)((unsigned long)node | 2);
}
static inline
void *mte_safe_root(const struct maple_enode *node)
{
	return (void *)((unsigned long)node & ~2);
}
static inline
void *mte_is_full(const struct maple_enode *node)
{
	return (void *)((unsigned long)node & ~4);
}

static inline
void mte_set_full(const struct maple_enode *node)
{
	node = (void *)((unsigned long)node | 4);
}

static inline unsigned int mte_slot_mask(const struct maple_enode *node)
{
	unsigned int bitmask = 0x78; // Bits 3-6

	if (mte_node_type(node) == MAPLE_RANGE16_SLOTS)
		bitmask |= 0x04; // Set bit 2.
	return bitmask;
}
static inline bool _ma_is_root(struct maple_node *node)
{
	return ((unsigned long)node->parent & MA_ROOT_PARENT);
}

static inline bool mte_is_root(const struct maple_enode *node)
{
	return _ma_is_root(mte_to_node(node));
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
	switch (parent) {
	case 6:
		return maple_range_64;
	case 4:
		return maple_range_32;
	case 0:
		return maple_range_16;
	}
	return maple_dense;
}

static inline enum maple_type mte_parent_alloc_enum(unsigned long parent)
{
	switch (parent) {
	case 6:
		return maple_arange_64;
	}
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

/* Private
 *
 * Type is encoded in the node->parent
 * bit 0: 1 = root, 0 otherwise
 * bit 1: 0 = range 16, 1 otherwise
 * bit 2: 0 = range 32, 1 = [a]range 64 | lowest bit of range_16's slot.
 *
 * Slot number is encoded in the node->parent
 * range_16, slot number is encoded in bits 2-6
 * range_32, slot number is encoded in bits 3-6
 * [a]range_64, slot number is encoded in bits 3-6
 */
static inline void mte_set_parent(struct maple_enode *node,
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
		/* fallthrough */
	case maple_range_32:
		type |= 2;
		break;
	case maple_range_16:
		slot_shift = 2;
		break;
	default:
		break;
	}

	BUG_ON(slot > MAPLE_NODE_SLOTS); // Only 4 bits to use.
	val &= ~bitmask; // Remove any old slot number.
	val |= (slot << slot_shift); // Set the slot.
	val |= type;
	mte_to_node(node)->parent = ma_parent_ptr(val);
}

static inline unsigned int mte_parent_slot(const struct maple_enode *node)
{
	unsigned long bitmask = 0x7C;
	unsigned long val = (unsigned long) mte_to_node(node)->parent;
	unsigned long slot_shift = mte_parent_shift(val);

	if (val & 1)
		return 0; // Root.

	return (val & bitmask) >> slot_shift;
}


static inline struct maple_node *mte_parent(const struct maple_enode *node)
{
	unsigned long bitmask = 0x7F;

	return (void *)((unsigned long)(mte_to_node(node)->parent) & ~bitmask);

}

static inline bool mte_dead_node(const struct maple_enode *enode)
{
	struct maple_node *parent, *node = mte_to_node(enode);

	parent = mte_parent(enode);
	return (parent == node);
}

static inline struct maple_node *mas_get_alloc(const struct ma_state *ms)
{
	return (struct maple_node *)((unsigned long)ms->alloc & ~0x7F);
}

static inline int ma_get_node_alloc_cnt(const struct maple_node *node)
{
	int ret = 1;
	int slot = 0;

	while (slot < MAPLE_NODE_SLOTS) {
		if (!node->slot[slot])
			return ret;

		if (ma_mnode_ptr(node->slot[slot])->slot[0]) {
			ret += ma_get_node_alloc_cnt(
				ma_mnode_ptr(node->slot[slot]));
		} else {
			ret++;
		}
		slot++;
	}
	return ret;
}

static inline int mas_get_alloc_cnt(const struct ma_state *mas)
{
	struct maple_node *node = mas_get_alloc(mas);

	if (!node)
		return 0;

	return ma_get_node_alloc_cnt(node);
}

static inline void mas_set_alloc_req(struct ma_state *mas, int count)
{
	mas->alloc = (struct maple_node *)((unsigned long)mas->alloc & ~0x7F);
	mas->alloc = (struct maple_node *)((unsigned long)mas->alloc | count);
}

static inline int mas_get_alloc_req(const struct ma_state *mas)
{
	return (int)(((unsigned long)mas->alloc & 0x7F));
}

static inline int mas_get_slot(const struct ma_state *mas)
{
	return mas_get_alloc_req(mas);
}

static inline void mas_set_slot(struct ma_state *mas, int slot)
{
	mas_set_alloc_req(mas, slot);
}

static inline unsigned long ma_get_pivot(const struct maple_node *mn,
				 unsigned char slot, enum maple_type type)
{
	switch (type) {
	case maple_arange_64:
		return mn->ma64.pivot[slot];
	case maple_range_64:
	case maple_leaf_64:
		return mn->mr64.pivot[slot];
	case maple_sparse_6:
		return mn->ms6.pivot;
	case maple_sparse_9:
		return mn->ms9.pivot[slot];
	case maple_sparse_16:
		return mn->ms16.pivot[slot];
	case maple_sparse_21:
		return mn->ms21.pivot[slot];
	case maple_sparse_32:
		return mn->ms32.pivot[slot];
	case maple_sparse_64:
		return mn->ms64.pivot[slot];
	case maple_range_16:
	case maple_leaf_16:
		return mn->mr16.pivot[slot];
	case maple_range_32:
	case maple_leaf_32:
		return mn->mr32.pivot[slot];
	case maple_dense:
	default:
		return 0;
	}
}
static inline unsigned long _mte_get_pivot(const struct maple_enode *mn,
				 unsigned char slot, enum maple_type type)
{
	return ma_get_pivot(mte_to_node(mn), slot, type);
}
static inline unsigned long mte_get_pivot(const struct maple_enode *mn,
					 unsigned char slot)
{
	return _mte_get_pivot(mn, slot, mte_node_type(mn));
}
static inline unsigned long _mas_get_safe_pivot(const struct ma_state *mas,
				unsigned char slot, enum maple_type type)
{
	if (slot >= mt_pivots[type])
		return mas->max;

	return _mte_get_pivot(mas->node, slot, type);
}
/** Private
 * mas_get_safe_pivot() - Return the pivot or the mas->max.
 *
 * Return: The pivot (including mas->max for the final slot)
 */
static inline unsigned long mas_get_safe_pivot(const struct ma_state *mas,
					 unsigned char slot)
{
	enum maple_type type = mte_node_type(mas->node);

	return _mas_get_safe_pivot(mas, slot, type);
}

static inline void ma_set_pivot(struct maple_node *mn, unsigned char slot,
		enum maple_type type, unsigned long val)
{
	BUG_ON(slot >= mt_slots[type]);

	switch (type) {
	default:
	case maple_range_64:
	case maple_leaf_64:
		(&mn->mr64)->pivot[slot] = val;
		break;
	case maple_arange_64:
		(&mn->ma64)->pivot[slot] = val;
	case maple_dense:
		break;
	case maple_sparse_6:
		(&mn->ms6)->pivot = val;
		break;
	case maple_sparse_9:
		(&mn->ms9)->pivot[slot] = val;
		break;
	case maple_sparse_16:
		(&mn->ms16)->pivot[slot] = val;
		break;
	case maple_sparse_21:
		(&mn->ms21)->pivot[slot] = val;
		break;
	case maple_sparse_32:
		(&mn->ms32)->pivot[slot] = val;
		break;
	case maple_sparse_64:
		(&mn->ms64)->pivot[slot] = val;
		break;
	case maple_range_16:
	case maple_leaf_16:
		(&mn->mr16)->pivot[slot] = val;
		break;
	case maple_range_32:
	case maple_leaf_32:
		(&mn->mr32)->pivot[slot] = val;
		break;
	}
}
static inline void mte_set_pivot(struct maple_enode *mn, unsigned char slot,
				unsigned long val)
{
	return ma_set_pivot(mte_to_node(mn), slot, mte_node_type(mn), val);
}
static inline struct maple_enode *ma_get_rcu_slot(
		const struct maple_node *mn, unsigned char slot,
		enum maple_type type, struct maple_tree *mtree)
{
	switch (type) {
	case maple_range_64:
	case maple_leaf_64:
		return rcu_dereference_check(mn->mr64.slot[slot],
				lockdep_is_held(&mtree->ma_lock));
	default:
	case maple_dense:
		return rcu_dereference_check(mn->slot[slot],
				lockdep_is_held(&mtree->ma_lock));
	case maple_arange_64:
		return rcu_dereference_check(mn->ma64.slot[slot],
				lockdep_is_held(&mtree->ma_lock));
	case maple_sparse_6:
		return rcu_dereference_check(mn->ms6.slot[slot],
				lockdep_is_held(&mtree->ma_lock));
	case maple_sparse_9:
		return rcu_dereference_check(mn->ms9.slot[slot],
				lockdep_is_held(&mtree->ma_lock));
	case maple_sparse_16:
		return rcu_dereference_check(mn->ms16.slot[slot],
				lockdep_is_held(&mtree->ma_lock));
	case maple_sparse_21:
		return rcu_dereference_check(mn->ms21.slot[slot],
				lockdep_is_held(&mtree->ma_lock));
	case maple_sparse_32:
		return rcu_dereference_check(mn->ms32.slot[slot],
				lockdep_is_held(&mtree->ma_lock));
	case maple_sparse_64:
		return rcu_dereference_check(mn->ms64.slot[slot],
				lockdep_is_held(&mtree->ma_lock));
	case maple_range_16:
	case maple_leaf_16:
		return rcu_dereference_check(mn->mr16.slot[slot],
				lockdep_is_held(&mtree->ma_lock));
	case maple_range_32:
	case maple_leaf_32:
		return rcu_dereference_check(mn->mr32.slot[slot],
				lockdep_is_held(&mtree->ma_lock));
	}
}

static inline struct maple_enode *_mte_get_rcu_slot(
		const struct maple_enode *mn, unsigned char slot,
		enum maple_type type, struct maple_tree *mtree)
{
	return ma_get_rcu_slot(mte_to_node(mn), slot, type, mtree);
}
static inline struct maple_enode *mte_get_rcu_slot(const struct maple_enode *mn,
		 unsigned char slot, struct maple_tree *mtree)
{
	return _mte_get_rcu_slot(mn, slot, mte_node_type(mn), mtree);
}

static inline struct maple_enode *mas_get_rcu_slot(const struct ma_state *mas,
		unsigned char slot)
{
	return mte_get_rcu_slot(mas->node, slot, mas->tree);
}
static inline struct maple_enode *mas_get_rcu_sanitized(
		struct ma_state *mas, unsigned char slot)
{
	void *entry = mte_get_rcu_slot(mas->node, slot, mas->tree);

	if (xa_is_deleted(entry))
		return NULL;

	return entry;
}

static inline void ma_set_rcu_slot(struct maple_node *mn,
		unsigned char slot, enum maple_type type, void *val)
{

	switch (type) {
	default:
	case maple_dense:
		rcu_assign_pointer(mn->slot[slot], val);
		break;
	case maple_sparse_6:
		rcu_assign_pointer(mn->ms6.slot[slot], val);
		break;
	case maple_sparse_9:
		rcu_assign_pointer(mn->ms9.slot[slot], val);
		break;
	case maple_sparse_16:
		rcu_assign_pointer(mn->ms16.slot[slot], val);
		break;
	case maple_sparse_21:
		rcu_assign_pointer(mn->ms21.slot[slot], val);
		break;
	case maple_sparse_32:
		rcu_assign_pointer(mn->ms32.slot[slot], val);
		break;
	case maple_sparse_64:
		rcu_assign_pointer(mn->ms64.slot[slot], val);
		break;
	case maple_range_16:
	case maple_leaf_16:
		rcu_assign_pointer(mn->mr16.slot[slot], val);
		break;
	case maple_range_32:
	case maple_leaf_32:
		rcu_assign_pointer(mn->mr32.slot[slot], val);
		break;
	case maple_range_64:
	case maple_leaf_64:
		BUG_ON(slot >= 8);
		rcu_assign_pointer(mn->mr64.slot[slot], val);
		break;
	case maple_arange_64:
		BUG_ON(slot >= 5);
		rcu_assign_pointer(mn->ma64.slot[slot], val);
		break;
	}
}
static inline void mte_set_rcu_slot(const struct maple_enode *mn,
				 unsigned char slot, void *val)
{
	ma_set_rcu_slot(mte_to_node(mn), slot, mte_node_type(mn), val);
}

static inline void mas_dup_state(struct ma_state *dst, struct ma_state *src)
{
	dst->tree = src->tree;
	dst->index = src->index;
	dst->last = src->last;
	dst->node = src->node;
	dst->max = src->max;
	dst->min = src->min;
	mas_set_slot(dst, mas_get_slot(src));
}
static inline void mas_descend(struct ma_state *mas)
{
	unsigned char slot = mas_get_slot(mas);

	if (slot)
		mas->min = mas_get_safe_pivot(mas, slot - 1) + 1;
	mas->max = mas_get_safe_pivot(mas, slot);
	mas->node = mas_get_rcu_slot(mas, mas_get_slot(mas));
}

static inline void mte_update_rcu_slot(const struct maple_enode *mn,
				 unsigned char slot, void *val)
{
	enum maple_type type = mte_node_type(mn);

	switch (type) {
	case maple_range_64:
	case maple_leaf_64:
		rcu_assign_pointer(mte_to_node(mn)->mr64.slot[slot], val);
		break;
	default:
	case maple_dense:
		rcu_assign_pointer(mte_to_node(mn)->slot[slot], val);
		break;
	case maple_arange_64:
		rcu_assign_pointer(mte_to_node(mn)->ma64.slot[slot], val);
		break;
	case maple_sparse_6:
		rcu_assign_pointer(mte_to_node(mn)->ms6.slot[slot], val);
		break;
	case maple_sparse_9:
		rcu_assign_pointer(mte_to_node(mn)->ms9.slot[slot], val);
		break;
	case maple_sparse_16:
		rcu_assign_pointer(mte_to_node(mn)->ms16.slot[slot], val);
		break;
	case maple_sparse_21:
		rcu_assign_pointer(mte_to_node(mn)->ms21.slot[slot], val);
		break;
	case maple_sparse_32:
		rcu_assign_pointer(mte_to_node(mn)->ms32.slot[slot], val);
		break;
	case maple_sparse_64:
		rcu_assign_pointer(mte_to_node(mn)->ms64.slot[slot], val);
		break;
	case maple_range_16:
	case maple_leaf_16:
		rcu_assign_pointer(mte_to_node(mn)->mr16.slot[slot], val);
		break;
	case maple_range_32:
	case maple_leaf_32:
		rcu_assign_pointer(mte_to_node(mn)->mr32.slot[slot], val);
		break;
	}
}

static inline unsigned long ma_get_gap(const struct maple_node *mn,
				 unsigned char gap, enum maple_type type)
{
	switch (type) {
	case maple_arange_64:
		return mn->ma64.gap[gap];
	default:
		return 0;
	}
}
static inline unsigned long mte_get_gap(const struct maple_enode *mn,
				 unsigned char gap)
{
	return ma_get_gap(mte_to_node(mn), gap, mte_node_type(mn));
}

static inline void ma_set_gap(struct maple_node *mn, unsigned char gap,
		enum maple_type type, unsigned long val)
{
	switch (type) {
	default:
		break;
	case maple_arange_64:
		mn->ma64.gap[gap] = val;
		break;
	}
}
static inline void mte_set_gap(const struct maple_enode *mn,
				 unsigned char gap, unsigned long val)
{
	ma_set_gap(mte_to_node(mn), gap, mte_node_type(mn), val);
}
static inline void mte_cp_gap(struct maple_enode *dst,
		unsigned char dloc, struct maple_enode *src, unsigned long sloc)
{
	mte_set_gap(dst, dloc, mte_get_gap(src, sloc));
}

static inline void mas_update_limits(struct ma_state *mas, unsigned char slot,
		enum maple_type type)
{
	if (slot > 0)
		mas->min = _mte_get_pivot(mas->node, slot - 1, type) + 1;

	if (slot < mt_pivots[type])
		mas->max = _mte_get_pivot(mas->node, slot, type);
}

/**
 * mas_retry() - Retry the operation if appropriate.
 * @mas: Maple Tree operation state.
 * @entry: Entry from tree.
 *
 * The advanced functions may sometimes return an internal entry, such as
 * a retry entry or a zero entry.  This function sets up the @mas to restart
 * the walk from the head of the array if needed.
 *
 * Context: Any context.
 * Return: true if the operation needs to be retried.
 */
bool mas_retry(struct ma_state *mas, const void *entry)
{
	if (xa_is_skip(entry))
		return true;
	if (xa_is_deleted(entry))
		return true;
	if (xa_is_zero(entry))
		return true;
	if (!xa_is_retry(entry))
		return false;
	mas_reset(mas);
	return true;
}

static inline void mas_ascend(struct ma_state *mas)
{
	struct maple_enode *p_enode; // parent enode.
	struct maple_enode *a_enode = mas->node; // ancestor enode.
	struct maple_node *a_node = mas_mn(mas); // ancestor node.
	unsigned char a_slot = 0;
	enum maple_type a_type = mte_node_type(mas->node);
	unsigned long max = 0, min = ULONG_MAX;
	bool set_max = false, set_min = false;

	p_enode = mt_mk_node(mte_parent(mas->node),
			mas_parent_enum(mas, mas->node));


	if (_ma_is_root(a_node))
		goto no_parent;

	a_type = mas_parent_enum(mas, mas->node);
	a_enode = p_enode;

	if (mte_is_root(a_enode)) {
		a_node = mte_to_node(a_enode);
		goto no_parent;
	}

	mas->node = p_enode;
ascend:
	a_type = mas_parent_enum(mas, mas->node);
	a_node = mte_parent(mas->node);
	a_slot = mte_parent_slot(mas->node);
	a_enode = mt_mk_node(a_node, a_type);

	if (!set_min && a_slot) {
		set_min = true;
		min = mte_get_pivot(a_enode, a_slot - 1) + 1;
	}

	if (!set_max && a_slot < mt_pivots[a_type]) {
		set_max = true;
		max = mte_get_pivot(a_enode, a_slot);
	}

no_parent:
	if (_ma_is_root(a_node)) {
		if (!set_min)
			min = 0;
		if (!set_max)
			max = mt_max[a_type];
	}

	if (!max || min == ULONG_MAX) {
		mas->node = a_enode;
		goto ascend;
	}

	mas->max = max;
	mas->min = min;
	mas->node = p_enode;
}

static inline void mas_set_safe_pivot(struct ma_state *mas, unsigned char slot,
		unsigned long val)
{
	MA_STATE(safe_mas, mas->tree, mas->index, mas->last);
	mas_dup_state(&safe_mas, mas);

restart:
	if (slot >= mt_pivot_count(safe_mas.node)) {
		if (mte_is_root(safe_mas.node))
			return;

		slot = mte_parent_slot(safe_mas.node);
		mas_ascend(&safe_mas);
		goto restart;
	}
	mte_set_pivot(safe_mas.node, slot, val);
}

/** Private
 * mas_shift_pivot() - Shift a pivot from one node to the next.
 * @left - the left node with mas slot set to the pivot location.
 * @right - the right node with mas slot set to the pivot location.
 *
 * This exists when moving gaps across many levels of a tree.  Basically, walk
 * backwards until the nodes meet and set the pivots accordingly.
 *
 * Special cases for XA_SKIP_ENTRY is needed.
 */
void mte_destroy_walk(struct maple_enode *mn, struct maple_tree *mtree);
static inline void mas_shift_pivot(struct ma_state *curr,
		struct ma_state *next, unsigned long piv)
{
	unsigned char l_p_slot; // left parent slot.
	unsigned char r_p_slot; // right parent slot.

	MA_STATE(left, curr->tree, curr->index, curr->last);
	MA_STATE(right, next->tree, next->index, next->last);

	mas_dup_state(&left, curr);
	mas_dup_state(&right, next);
	do {
		bool leaf = true;
		void *entry, *adv_ent = XA_RETRY_ENTRY;

		// Ends with NULL side
		l_p_slot = mte_parent_slot(left.node);
		mas_set_slot(&left, l_p_slot);
		mas_ascend(&left);

		// Starts with NULL side
		r_p_slot = mte_parent_slot(right.node);
		mas_set_slot(&right, r_p_slot);
		mas_ascend(&right);

		mas_set_safe_pivot(&left, l_p_slot, piv);
		if (!mte_is_leaf(left.node)) {
			leaf = false;
			adv_ent = XA_SKIP_ENTRY;
		}

		if (left.node == right.node) {
			if (r_p_slot - 1 != l_p_slot) {
				int slot = r_p_slot - 1;
				do {
					entry = mas_get_rcu_slot(&left, slot);
					mte_set_pivot(left.node, slot, piv);
					mte_set_rcu_slot(left.node, slot, adv_ent);
					if (!leaf) {
						if (mt_is_alloc(left.tree))
							mte_set_gap(left.node, slot, 0);
						if (!mt_is_advanced(entry))
							mte_free(entry); // Destroy not needed.
					}
				} while (--slot > l_p_slot);
			}
			return;
		} else {
			/* Work right to left to ensure RCU-safe states. */
			while (r_p_slot--) {
				entry = mas_get_rcu_slot(&right, r_p_slot);
				mte_set_pivot(right.node, r_p_slot, piv);
				mte_set_rcu_slot(right.node, r_p_slot, adv_ent);
				if (!leaf ) {
					if (mt_is_alloc(right.tree))
						mte_set_gap(right.node, r_p_slot, 0);
					if (!mt_is_advanced(entry))
						mte_free(entry);
				}
			}

			/* Now the left */
			while (++l_p_slot < mt_slot_count(left.node)) {
				entry = mas_get_rcu_slot(&left, l_p_slot);
				if (l_p_slot < mt_pivot_count(left.node) &&
				    !mte_get_pivot(left.node, l_p_slot))
					break; // end of left.

				if ((l_p_slot == mt_slot_count(left.node) - 1) &&
				    (!entry))
					break; // last entry and it's empty.

				mte_set_pivot(left.node, l_p_slot, piv);
				mte_set_rcu_slot(left.node, l_p_slot, adv_ent);
				if (!leaf ) {
					if (mt_is_alloc(left.tree))
						mte_set_gap(left.node, l_p_slot, 0);
					if (!mt_is_advanced(entry))
						mte_free(entry);
				}

			}




		}

	} while (left.node != right.node);
}
/* mas_get_prev_pivot() - Return the previous pivot.
 *
 * Mainly for extracting the previous pivot in the case of slot = 0.
 * Walk up the tree until the minimum changes, then get the previous pivot.
 *
 */
static inline unsigned long mas_get_prev_pivot(const struct ma_state *mas,
					 unsigned char slot)
{
	unsigned char p_slot = MAPLE_NODE_SLOTS; // parent slot.

	MA_STATE(prev_piv, mas->tree, 0, 0);

	if (slot > 0)
		return mas_get_safe_pivot(mas, slot - 1);

	if (mas->min == 0)
		return 0;


	prev_piv.node = mas->node;
	prev_piv.min = mas->min;

	while (prev_piv.min == mas->min) {
		p_slot = mte_parent_slot(prev_piv.node);
		mas_ascend(&prev_piv);
		if (p_slot)
			break;
	}
	p_slot--;
	return mte_get_pivot(prev_piv.node, slot);
}

static inline struct maple_node *mas_next_alloc(struct ma_state *ms)
{
	int cnt;
	struct maple_node *mn, *smn;

	if (!ms->alloc)
		return NULL;

	cnt = mas_get_alloc_cnt(ms);
	mn = mas_get_alloc(ms);
	if (cnt == 1) {
		ms->alloc = NULL;
	} else if (cnt <= 16) {
		cnt -= 2;
		smn = mn->slot[cnt];
		mn->slot[cnt] = NULL;
		mn = smn;
	} else if (cnt > 16) {
		cnt -= 2;
		smn = mn->slot[(cnt / 15) - 1];
		mn = smn->slot[(cnt % 15)];
		smn->slot[cnt % 15] = NULL;
	}

	return mn;
}
static inline void mas_push_node(struct ma_state *mas, struct maple_enode *used)
{
	struct maple_node *reuse = mte_to_node(used);
	struct maple_node *node = mas_get_alloc(mas);
	int cnt;

	memset(reuse, 0, sizeof(*reuse));
	cnt = mas_get_alloc_cnt(mas);
	if (cnt == 0) {
		mas->alloc = reuse;
	} else if (cnt <= 15) {
		cnt--;
		node->slot[cnt] = reuse;
	} else {
		struct maple_node *smn;

		cnt--;
		smn = node->slot[(cnt/15) - 1];
		smn->slot[cnt % 15] = reuse;
	}
	cnt = mas_get_alloc_cnt(mas);

	BUG_ON(!mas_get_alloc_cnt(mas));
}
static inline void mas_node_node(struct ma_state *ms, gfp_t gfp)
{
	struct maple_node *mn, *smn;
	int req = mas_get_alloc_req(ms);
	int allocated = mas_get_alloc_cnt(ms);
	int slot;

	if (!req)
		return;

	mn = mas_get_alloc(ms);
	if (!mn) {
		mn = mt_alloc_one(gfp);
		if (!mn)
			goto list_failed;
		req--;
		allocated++;
	}

	ms->alloc = mn;
	slot = (allocated - 1);
	if (allocated - 1 >= MAPLE_NODE_SLOTS) {
		slot /= MAPLE_NODE_SLOTS;
		mn = mn->slot[slot - 1];
	}

	while (req > 0) {
		smn = mt_alloc_one(gfp);
		if (!smn)
			goto slot_failed;
		smn->parent = NULL;
		mn->slot[slot] = smn;
		req--;
		allocated++;
		slot++;
		if (slot >= MAPLE_NODE_SLOTS) {
			slot = (allocated - 1) / MAPLE_NODE_SLOTS;
			mn = ms->alloc->slot[slot - 1];
			slot = 0;
		}
	}

slot_failed:
	mas_set_alloc_req(ms, req);

list_failed:
	if (req > 0)
		mas_set_err(ms, -ENOMEM);
}

// Free the allocations.
static inline void ma_free_alloc(struct maple_node *node)
{
	int alloc = 0;

	while (alloc < MAPLE_NODE_SLOTS && node->slot[alloc]) {
		if (ma_mnode_ptr(node->slot[alloc])->slot[0])
			ma_free_alloc(node->slot[alloc]);
		else
			kfree(node->slot[alloc]);
		alloc++;
	}
	kfree(node);
}

void mas_empty_alloc(struct ma_state *mas) {
	struct maple_node *node = mas_get_alloc(mas);

	if (node)
		ma_free_alloc(node);
	mas->alloc = NULL;
}
/* Private
 * Check if there was an error allocating and do the allocation if necessary
 * If there are allocations, then free them.
 */
bool mas_nomem(struct ma_state *mas, gfp_t gfp)
	__must_hold(mas->tree->lock)
{
	if (mas->node != MA_ERROR(-ENOMEM)) {
		mas_empty_alloc(mas);
		return false;
	}

	if (gfpflags_allow_blocking(gfp)) {
		mtree_unlock(mas->tree);
		mas_node_node(mas, gfp);
		mtree_lock(mas->tree);
	} else {
		mas_node_node(mas, gfp);
	}
	if (!mas_get_alloc(mas))
		return false;
	mas->node = MAS_START;
	return true;
}
static inline struct maple_node *mas_node_cnt(struct ma_state *mas, int count)
{
	int allocated = mas_get_alloc_cnt(mas);

	BUG_ON(count > 127);

	if (allocated < count) {
		mas_set_alloc_req(mas, count - allocated);
		mas_node_node(mas, GFP_NOWAIT | __GFP_NOWARN);
	}
	return mas->alloc;
}

/** Private
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
		goto done;

	if (mas_is_start(mas)) {
		struct maple_enode *root;

		mas->node = MAS_NONE;
		mas->min = 0;
		mas->max = ULONG_MAX;
		mas_set_slot(mas, 0);
		if (!mas->tree->ma_root) // empty tree.
			goto done;

		root = mte_safe_root(mas->tree->ma_root);

		if (!xa_is_node(mas->tree->ma_root)) {
			// Single entry tree.
			if (mas->index > 0)
				goto done;

			entry = mas->tree->ma_root;
			mas->node = MAS_ROOT;
			mas_set_slot(mas, MAPLE_NODE_SLOTS);
		} else {
			mas->node = root;
		}
	}

done:
	return entry;
}

/* Private
 * mas_data_end() - Find the end of the data (slot).  Sets the value of the
 * last pivot to @last_piv, sets @coalesce to the number of slots that can be
 * removed by coalescing.
 *
 * Note: XA_RETRY entries are considered past the end, so this is not fully safe
 * to check the space a node has when coalescing and rebalancing.
 */
static inline unsigned char _mas_data_end(const struct ma_state *mas,
		const enum maple_type type, unsigned long *last_piv,
		unsigned char *coalesce)
{
	struct maple_enode *mn = mas->node;
	unsigned long piv = mas->min, prev_piv = mas->min - 1;
	unsigned char slot;
	unsigned char counted_null = 0;

	*coalesce = 0;
	for (slot = 0; slot < mt_slot_count(mn); slot++) {
		void *entry;

		piv = _mas_get_safe_pivot(mas, slot, type);
		if ((piv == 0 && slot != 0) ||
		    (piv > mas->max)) {
		    // Past the end of data.
			slot--;
			piv = prev_piv;
			// At this point, we are saying the previous slot is
			// the end.
			if (counted_null) {
				// if this node has ended in a run of NULL
				if (slot <= counted_null) {
					slot = 0;
					(*coalesce) = 0;
					piv = mas->min - 1;
					break;
				}
				(*coalesce) = (*coalesce) - counted_null + 1;
				piv = _mas_get_safe_pivot(mas,
						slot - counted_null, type);
			}
			break;
		}

		entry = _mte_get_rcu_slot(mn, slot, type, mas->tree);
		if (entry == NULL || xa_is_deleted(entry)) {
			if (counted_null)
				(*coalesce)++;
			counted_null++;

		} else if (mt_will_coalesce(entry)) {
			if (piv == prev_piv)
				(*coalesce)++;
		} else {
			counted_null = 0;
		}

		if (piv == mas->max)
			break;

		prev_piv = piv;
	}

	*last_piv = piv;
	return slot;
}

static inline unsigned char mas_data_end(const struct ma_state *mas)
{
	unsigned long l;
	unsigned char c;

	return _mas_data_end(mas, mte_node_type(mas->node), &l, &c);
}
/** Private
 * ma_hard_data - return the number of slots required to store what is
 * currently in this node.
 *
 * @end the last slot with a valid pivot/contents
 * @coalesce the number of slots that would be removed if copied/coalesced.
 *
 */
static inline int ma_hard_data(unsigned long end,
		unsigned long coalesce)
{
	if (end < coalesce)
		return 0;
	return end - coalesce;
}

// Set min/max for a given slot in mas->node.
static inline void mas_get_range(struct ma_state *mas, unsigned char slot,
		unsigned long *min, unsigned long *max)
{
	*min = mas->min;
	*max = mas_get_safe_pivot(mas, slot);
	if (!(*max)) {
		if (slot || mas->min)
			*max = mas->max;
	}

	if (slot)
		*min = mte_get_pivot(mas->node, slot - 1) + 1;

	if ((*min) == 1) // empty node.
		*min = mas->min;
}
/* mas_append_entry() - Append an entry to the target slot or overwrite a
 * porting of the last slot.
 */
static inline unsigned char mas_append_entry(struct ma_state *mas, void *entry)
{
	unsigned long wr_pivot = mas->min ? mas->min - 1 : 0;
	unsigned char coalesce, dst_slot = mas_get_slot(mas);

	if (!mas_get_rcu_slot(mas, 0) && !mte_get_pivot(mas->node, 0))
		dst_slot = 0; // empty node.
	else if (dst_slot > mt_slot_count(mas->node)) { // Should not happen.
		dst_slot = _mas_data_end(mas, mte_node_type(mas->node),
				&wr_pivot, &coalesce); // slot not set.
	} else if (dst_slot)
		wr_pivot = mas_get_safe_pivot(mas, dst_slot - 1);

	if (dst_slot && mas->index <= wr_pivot) {
		mas_set_safe_pivot(mas, dst_slot - 1, mas->index - 1);
	} else if (entry && mas->index && (mas->index - 1 != wr_pivot)) {
		if (dst_slot && !mas_get_rcu_slot(mas, dst_slot - 1))
			dst_slot--;

		mte_set_rcu_slot(mas->node, dst_slot, NULL);
		mas_set_safe_pivot(mas, dst_slot++, mas->index - 1);
	} else if (!entry) { // appending NULL value.
		if (mas_get_rcu_slot(mas, dst_slot)) {
			mas_set_safe_pivot(mas, dst_slot, mas->index - 1);
			dst_slot++;
		}
	}

	mte_set_rcu_slot(mas->node, dst_slot, entry);
	mas_set_safe_pivot(mas, dst_slot, mas->last);
	mas->max = mas->last;

	return dst_slot;
}

static inline unsigned char _mas_append(struct ma_state *mas,
		struct maple_node *smn, enum maple_type stype,
		unsigned long src_max,
		unsigned char src_start, unsigned char src_end)
{

	unsigned long src_piv;
	unsigned char src_slot = src_start;
	unsigned char dst_slot = 0;
	bool prev_null = false;
	void *src_data = NULL;

	// Find last slot in the dst.
	while (dst_slot < mt_slot_count(mas->node)) {
		unsigned long this_piv;
		void *dst_data;

		if (dst_slot < mt_pivot_count(mas->node))
			this_piv = mte_get_pivot(mas->node, dst_slot);
		else { // Last slot, no pivot..
			if (src_end >= mt_pivots[stype])
				this_piv = src_max;
			else
				this_piv = ma_get_pivot(smn, src_end, stype);
		}

		dst_data = mas_get_rcu_slot(mas, dst_slot);
		if (!dst_data) {
			if (!this_piv)
				break;

			if (dst_slot == mt_pivot_count(mas->node))
				break;

			prev_null = true;
		} else
			prev_null = false;
		dst_slot++;
	}

	// Append data from src.
	for (src_slot = src_start; src_slot <= src_end; src_slot++) {
		bool next_dst = true;

		src_data = ma_get_rcu_slot(smn, src_slot, stype, mas->tree);
		if (xa_is_retry(src_data))
			continue;

		if (src_slot >= mt_pivots[stype])
			src_piv = src_max;
		else
			src_piv = ma_get_pivot(smn, src_slot, stype);

		if (!mte_is_leaf(mas->node) && mt_will_coalesce(src_data))
			continue;

		if (!src_data || mt_will_coalesce(src_data)) {
			src_data = NULL;
			if (prev_null && dst_slot) {
				mas_set_safe_pivot(mas, dst_slot - 1, src_piv);
				next_dst = false;
				goto update_gap;
			}

			prev_null = true;
		} else {
			prev_null = false;
		}

		if (dst_slot >= mt_slot_count(mas->node) && next_dst)
			return dst_slot;

		mte_set_rcu_slot(mas->node, dst_slot, src_data);
		mas_set_safe_pivot(mas, dst_slot, src_piv);
update_gap:
		if (!mte_is_leaf(mas->node) && mt_is_alloc(mas->tree))
			mte_set_gap(mas->node, dst_slot,
					ma_get_gap(smn, src_slot, stype));

		if (next_dst)
			dst_slot++;

		if (mas->max < src_piv)
			mas->max = src_piv;
	}

	return dst_slot;
}
static inline unsigned char mas_append(struct ma_state *mas,
		struct ma_state *src, unsigned char src_start,
		unsigned char src_end)
{
	return _mas_append(mas, mas_mn(src), mte_node_type(src->node),
			src->max, src_start, src_end);
}

static inline unsigned char mas_append_calc_split(struct ma_state *mas,
		bool active)
{
	unsigned char max = 7, ret = 7;
	unsigned char slot;
	unsigned long range = mas->max - mas->min;
	unsigned long half;
	unsigned long piv = 0;
	enum maple_type mas_type = mte_node_type(mas->node);

	if (mas_type == maple_arange_64) {
		max = 5;
		ret = 5;
	}

	if (!active) {
		if (ma_is_leaf(mas_type))
			return max;
		return max - 2;
	}

	//if (mas->min == 0)
	//	max = 7;

	half = max / 2;
	if (ma_is_leaf(mas_type)) {
		if (range <= 8UL)
			return ret;

		for (slot = 0; slot <= mt_pivots[mas_type]; slot++) {
			piv = mas_get_safe_pivot(mas, slot);

			if (!piv && slot)
				return ret;

			if (piv > mas->max) // possibly a retry.
				return ret;

			if ((piv >= mas->index) && (piv <= mas->last))
				continue;

			range = piv - mas->min;
			if (range >= 8) {
				if (slot > half)
					ret = slot;
				else
					ret = half;
				goto done;
			}

		}
	} else {
		for (slot = half; slot <= mt_pivots[mas_type]; slot++) {
			piv = mas_get_safe_pivot(mas, slot);
			if ((piv >= mas->index) && (piv <= mas->last))
				half++;
			else
				break;
		}
	}

	return half;

done:
	if (ret < max) {
		bool null = false;
		if (piv == ULONG_MAX)
			ret++;

		if (mt_is_empty(mas_get_rcu_slot(mas, ret)))
		    null = true;

		while((ret < max) && // Skip deletes and retries.
		      ((piv == mas_get_safe_pivot(mas, ret + 1)) ||
		       (null && mt_is_empty(mas_get_rcu_slot(mas, ret + 1)))))
		      ret++;
	}

	return ret;
}
static inline unsigned char mas_skip_overwritten(struct ma_state *mas,
		unsigned char data_end, unsigned char slot)
{
	unsigned char ret = slot;
	void *entry;

keep_going:
	while ((data_end >= ret) &&
	      (mas_get_safe_pivot(mas, ret) <= mas->last))
		ret++;

	if (!slot) {
		// if this is a retry, then the pivot may be lower than
		// mas->last and needs to be skipped.
		entry = mas_get_rcu_slot(mas, 0);
		if (xa_is_skip(entry) || xa_is_retry(entry)) {
		    slot++;
		    goto keep_going;
		}
	}

	return ret;
}
static void mas_split_may_switch_dst(struct ma_state **dst_mas,
		struct ma_state *right, unsigned char *dst_slot,
		unsigned char split)
{
	struct ma_state *dst = *dst_mas;

	if (dst == right)
		return;

	if (*dst_slot >= mt_slot_count(dst->node) ||
	    *dst_slot > split + 1) {
		right->min = dst->max + 1;
		*dst_mas = right;
		*dst_slot = 0;
	}
}

/* Private
 *
 * mas_append_split_data() - Append the data of a split operation into either
 * the left or the right node.  If, during the append, the split limit is
 * reached, then switch the destination node to the right.  This function also
 * places the new data within the node.
 * @left: The left maple state
 * @right: The right maple state
 * @src: The source of the data
 * @split: Where to start copying to the right node
 * @start: The slot to start copying data from in @src
 * @end: The last slot to copy data from in @src
 * @entry: The new entry to be placed at @src->index - @src->last
 */
static unsigned char mas_append_split_data(struct ma_state *left,
		struct ma_state *right, struct ma_state *src,
		unsigned char split, unsigned char start, unsigned char end,
		unsigned char slot, void *entry)
{
	void *existing_entry = mas_get_rcu_sanitized(src, slot);
	struct ma_state *dst = left;
	unsigned char dst_slot = slot;
	unsigned long slot_min, slot_max;

	if (!left) {
		dst = right;
		// Adjust dst_slot to right.
		dst_slot = slot - split - 1;
	}

	while ((mte_get_pivot(src->node, start) < dst->min) &&
		(start <= end)) {
		// Skip retries, etc.
		start++;
		dst_slot--;
	}

	mas_get_range(src, slot, &slot_min, &slot_max);

	if (slot_min < dst->min)
		slot_min = dst->min;

	if (dst_slot) {
		mas_append(dst, src, start, slot - 1);
		dst->max = mte_get_pivot(dst->node, slot - 1);
	}

	if (slot_min == src->index) {
		mas_set_safe_pivot(dst, dst_slot, dst->last);
		mte_set_rcu_slot(dst->node, dst_slot++, entry);
		dst->max = dst->last;
	} else {
		mas_set_safe_pivot(dst, dst_slot, dst->index - 1);
		mte_set_rcu_slot(dst->node, dst_slot++, existing_entry);
		dst->max = dst->index - 1;
		mas_split_may_switch_dst(&dst, right, &dst_slot, split);
		mas_set_safe_pivot(dst, dst_slot, dst->last);
		mte_set_rcu_slot(dst->node, dst_slot++, entry);
		dst->max = dst->last;
	}

	// Check if it's time to switch.
	mas_split_may_switch_dst(&dst, right, &dst_slot, split);
	// Skip anything overwritten by this add
	slot = mas_skip_overwritten(src, end, slot);
	if (slot >= mt_slot_count(src->node))
		goto done;

	mas_get_range(src, slot, &slot_min, &slot_max);
	existing_entry = mas_get_rcu_sanitized(src, slot);

	if (slot_min <= src->last && slot_max > src->last) {
		mte_set_rcu_slot(dst->node, dst_slot, existing_entry);
		mas_set_safe_pivot(dst, dst_slot++, slot_max);
		dst->max = slot_max;
		slot++;
	}

	mas_split_may_switch_dst(&dst, right, &dst_slot, split);

	if (slot <= end && dst->max < src->max) {
		mas_append(dst, src, slot, end);
		dst->max = mas_get_safe_pivot(src, end);
		slot = end + 1;
	}
done:
	if (left == dst)
		right->min = dst->max + 1;
	return slot;
}

/* Private
 *
 * mas_append_split() - Helper function to set up the copy of data to two new
 * destinations.
 * @dst1: Maple state of the left side of the split.
 * @dst2: Maple state of the right side of the split.
 * @src: The source of the data to be split
 * @slot: The target slot to split data
 * @entry: The new entry for @src->index - @src->last
 * @active: If this node is currently in the tree or not.
 */
static inline unsigned char mas_append_split(struct ma_state *dst1,
		struct ma_state *dst2, struct ma_state *src,
		unsigned char slot, void *entry, bool active)
{
	unsigned char split = mas_append_calc_split(src, active);
	unsigned char data_end = mas_data_end(src);
	bool add_entry = mte_is_leaf(src->node);

	mas_set_slot(dst1, slot);
	dst1->max = mas_get_safe_pivot(src, split);
	dst2->min = dst1->max + 1;
	if (!add_entry)
		goto not_a_leaf;

	if (slot <= split) { // going into the left one, at least a little.
		slot = mas_append_split_data(dst1, dst2, src, split, 0,
				split, slot, entry);
		// overwriting last entry would cause the max to change.
		mas_append(dst2, src, slot, data_end);
	} else { // going into the right.
		mas_append(dst1, src, 0, split);
		mas_append_split_data(NULL, dst2, src, split, split + 1,
				data_end, slot, entry);
	}

	return split;

not_a_leaf:
	mas_append(dst1, src, 0, split);
	if (split != data_end)
		split++;
	mas_append(dst2, src, split, data_end);
	return split;
}


static inline unsigned char mas_dense_calc_split(struct ma_state *mas,
		struct maple_enode **left, struct maple_enode **right)
{
	char i, j;
	unsigned long min = mas->min;
	unsigned long max = min;
	enum maple_type type = mte_node_type(mas->node);
	unsigned long pivot_cnt = mt_pivots[type];
	unsigned long half = mt_slots[type] / 2;
	unsigned char data_end = mas_data_end(mas);

	if (mte_is_root(mas->node)) {
		i = half;
		*left = (struct maple_enode *)mas_next_alloc(mas);
		*right = (struct maple_enode *)mas_next_alloc(mas);
		goto even_split;
	}

	*left = (struct maple_enode *)mas_next_alloc(mas);
	for (i = 0; i < data_end; i++) {
		max = mte_get_pivot(mas->node, i);
		if ((max - min) > 15) {
			if (i)
				i--;
			break;
		}
	}

	if (i >= data_end) {
		*left = mt_mk_node(ma_mnode_ptr(*left), maple_dense);
		if (mas->last >= mas->min + mt_max[type]) {
			*right = (struct maple_enode *)mas_next_alloc(mas);
			*right = mt_mk_node(ma_mnode_ptr(*right), type);
		}
		if (!i)
			i = mt_max[type];
		return i;
	}

	*right = (struct maple_enode *)mas_next_alloc(mas);
	if (i >= half) {
		*left = mt_mk_node(ma_mnode_ptr(*left), maple_dense);
		*right = mt_mk_node(ma_mnode_ptr(*right), type);
		return i;
	}

	if (data_end < pivot_cnt)
		max = mte_get_pivot(mas->node, data_end);
	else
		max = mas->max;

	j = data_end;
	do {
		j--;
		min = mte_get_pivot(mas->node, j);
		if ((max - min) > 15) {
			j++;
			break;
		}
	} while (j > 0);

	if (data_end - j >= half) {
		*left = mt_mk_node(ma_mnode_ptr(*left), type);
		*right = mt_mk_node(ma_mnode_ptr(*right), maple_dense);
		return j;
	}
even_split:
	*left = mt_mk_node(ma_mnode_ptr(*left), type);
	*right = mt_mk_node(ma_mnode_ptr(*right), type);

	return i > 2 ? i : half - 1;
}

static inline unsigned long mas_leaf_max_gap(struct ma_state *mas)
{
	enum maple_type mt = mte_node_type(mas->node);
	unsigned long pstart, pend;
	unsigned long prev_gap = 0;
	unsigned long max_gap = 0;
	unsigned long gap = 0;
	void *entry = NULL;
	int i;

	if (ma_is_dense(mt)) {
		for (i = 0; i < mt_slot_count(mas->node); i++) {
			entry = mas_get_rcu_slot(mas, i);
			if (!mt_is_empty(entry) || xa_is_retry(entry)) {
				if (gap > max_gap)
					max_gap = gap;
				gap = 0;
			} else {
				gap++;
			}
		}
		if (gap > max_gap)
			max_gap = gap;
		goto done;
	}

	pstart = mas->min;
	for (i = 0; i < mt_slots[mt]; i++) {
		pend = mas_get_safe_pivot(mas, i);
		if (!pend && i)
			pend = mas->max;

		if (pend > mas->max) // possibly a retry.
			break;

		gap = pend - pstart + 1;
		entry = mas_get_rcu_slot(mas, i);

		if (!mt_is_empty(entry) || xa_is_retry(entry)) {
			prev_gap = 0;
			goto next;
		}

		prev_gap += gap;
		if (prev_gap > max_gap)
			max_gap = prev_gap;

next:
		if (pend >= mas->max)
			break;

		pstart = pend + 1;
	}
done:
	return max_gap;

}
static inline unsigned long mas_max_gap(struct ma_state *mas,
		unsigned char *slot)
{
	unsigned long max_gap = 0;
	unsigned char i;

	for (i = 0; i < mt_slot_count(mas->node); i++) {
		unsigned long gap;

		gap = mte_get_gap(mas->node, i);
		if (gap >  max_gap) {
			*slot = i;
			max_gap = gap;
		}
	}

	return max_gap;
}
static inline void mas_parent_gap(struct ma_state *mas, unsigned char slot,
		unsigned long new, bool force)
{
	unsigned char max_slot = 0;
	unsigned long old_max_gap;

	/* Don't mess with mas state, use a new state */
	MA_STATE(gaps, mas->tree, mas->index, mas->last);
	mas_dup_state(&gaps, mas);

ascend:
	/* Go to the parent node. */
	mas_ascend(&gaps);
	old_max_gap = mas_max_gap(&gaps, &max_slot);
	mte_set_gap(gaps.node, slot, new);
	new = mas_max_gap(&gaps, &slot);

	if (!force && new == old_max_gap)
		return;

	if (mte_is_root(gaps.node))
		return;

	slot = mte_parent_slot(gaps.node);
	goto ascend;
}
/* Private
 *
 * mas_update_gap() - Update a nodes gaps and propagate up if necessary or
 * force by setting @force to true.
 */
static inline void mas_update_gap(struct ma_state *mas, bool force)
{
	unsigned char pslot;
	unsigned long p_gap, max_gap = 0;
	unsigned char slot = 0;

	/* Get the largest gap in mas->node */
	if (mte_is_root(mas->node))
		return;

	if (mte_is_leaf(mas->node))
		max_gap = mas_leaf_max_gap(mas);
	else
		max_gap = mas_max_gap(mas, &slot);

	/* Get the gap reported in the parent */
	pslot = mte_parent_slot(mas->node);
	p_gap = ma_get_gap(mte_parent(mas->node), pslot,
			mas_parent_enum(mas, mas->node));

	if (force || p_gap != max_gap)
		mas_parent_gap(mas, pslot, max_gap, force);
}


/* Private
 * mas_first_node() - Finds the first node in mas->node and returns the pivot,
 * mas->max if no node is found.  Node is returned as mas->node which may be
 * MAS_NONE.
 *
 * Note, if we descend to a leaf, then the slot is not valid.
 *
 * @mas: maple state
 * @limit: The maximum index to consider valid.
 */
static inline unsigned long mas_first_node(struct ma_state *mas,
		unsigned long limit)
{
	int slot = mas_get_slot(mas) - 1;
	unsigned char count = mt_slot_count(mas->node);
	unsigned long min = mas->min;

	while (++slot < count) {
		struct maple_enode *mn;
		unsigned long pivot;

		pivot = mas_get_safe_pivot(mas, slot);
		if (pivot > limit)
			goto no_entry;

		mn = mas_get_rcu_slot(mas, slot);

		if (mt_is_empty(mn)) {
			min = pivot + 1;
			continue;
		}

		// Non-leaf nodes need to descend.
		if (!mte_is_leaf(mas->node)) {
			mas->max = pivot;
			mas->min = min;
			mas->node = mn;
		}
		mas_set_slot(mas, slot);
		return pivot;
	}

no_entry:
	mas->node = MAS_NONE;
	return mas->max;
}
/* Private
 *
 * Returns the pivot which points to the entry with the lowest index.
 * @mas slot is set to the entry location.
 * @limit is the maximum index to check.
 *
 */
static inline unsigned long mas_first_entry(struct ma_state *mas,
		unsigned long limit)
{
	unsigned long pivot;

	while (1) {
		pivot = mas_first_node(mas, limit);
		if (mas_is_none(mas))
			return pivot;

		if (mte_is_leaf(mas->node)) {
			// Get the leaf slot.
			mas_set_slot(mas, 0);
			mas_first_node(mas, limit);
			if (mas_is_none(mas))
				return limit;
			return mas_get_safe_pivot(mas,
					mas_get_slot(mas));
		}

		mas_set_slot(mas, 0);
	}
}


/* Private
 *  mte_destroy_walk: Free the sub-tree from @mn and below.
 */
void mte_destroy_walk(struct maple_enode *mn, struct maple_tree *mtree)
{
	struct maple_enode *node;
	unsigned int type = mte_node_type(mn);
	unsigned char slot_cnt = mt_slot_count(mn);
	int i;

	switch (type) {
	case maple_range_16:
	case maple_range_32:
	case maple_range_64:
	case maple_arange_64:
		for (i = 0; i < slot_cnt; i++) {
			node = mte_get_rcu_slot(mn, i, mtree);
			if (!mt_is_empty(node) && !xa_is_retry(node))
				mte_destroy_walk(node, mtree);
		}
		break;
	default:
		break;
	}
	mte_free(mn);

}

static inline void mas_adopt_children(struct ma_state *mas,
		struct maple_enode *parent)
{

	enum maple_type type = mte_node_type(parent);
	unsigned char slot_cnt = mt_slots[type];
	struct maple_enode *child;
	unsigned char slot;

	for (slot = 0; slot < slot_cnt; slot++) {
		if (slot != 0 && slot < slot_cnt - 1 &&
		    _mte_get_pivot(parent, slot, type) == 0)
			break;

		child = _mte_get_rcu_slot(parent, slot, type, mas->tree);
		if (!mt_is_empty(child))
			mte_set_parent(child, parent, slot);
	}
}
/* Private
 * _mas_replace() - Replace a maple node in the tree with mas->node.  Uses the
 * parent encoding to locate the maple node in the tree.
 * @free: Free the old node
 * @push: push the old node onto the allocated nodes in mas->alloc
 *
 */
static inline void _mas_replace(struct ma_state *mas, bool free, bool push)
{
	struct maple_node *mn = mas_mn(mas);
	struct maple_enode *parent = NULL;
	struct maple_enode *prev;
	unsigned char slot = 0;

	if (mte_is_root(mas->node)) {
		prev = mas->tree->ma_root;
	} else {
		enum maple_type ptype = mas_parent_enum(mas, mas->node);

		parent = mt_mk_node(mte_parent(mas->node), ptype);
		slot = mte_parent_slot(mas->node);
		prev = mte_get_rcu_slot(parent, slot, mas->tree);
	}

	if (mte_to_node(prev) == mn)
		return;

	if (!mte_is_leaf(mas->node))
		mas_adopt_children(mas, mas->node);

	if (mte_is_root(mas->node)) {
		mn->parent = ma_parent_ptr(
			      ((unsigned long)mas->tree | MA_ROOT_PARENT));
		rcu_assign_pointer(mas->tree->ma_root, mte_mk_root(mas->node));
	} else {
		mte_update_rcu_slot(parent, slot, mas->node);
	}

	if (free) {
		mte_free(prev);
		return;
	}

	if (push)
		mas_push_node(mas, prev);

}
static inline void mas_replace(struct ma_state *mas)
{
	_mas_replace(mas, true, false);
}

static inline void mas_gap_link(struct ma_state *mas, struct maple_enode *parent,
		unsigned char slot, unsigned long pivot)
{
	unsigned long gap, max;
	unsigned char max_slot;

	max = mas->max;
	if (slot)
		mas->min = mte_get_pivot(parent, slot - 1) + 1;

	mas->max = pivot;
	if (!mte_is_leaf(mas->node))
		gap = mas_max_gap(mas, &max_slot);
	else
		gap = mas_leaf_max_gap(mas);

	mte_set_gap(parent, slot, gap);
	mas->max = max;
}
static inline void mas_link(struct ma_state *mas, struct maple_enode *new,
		struct maple_enode *parent, unsigned char slot,
		unsigned long pivot, enum maple_type type)
{
	unsigned char pivot_cnt = mt_pivots[type];

	mte_set_parent(new, parent, slot);
	if (slot < pivot_cnt)
		mte_set_pivot(parent, slot, pivot);

	mte_set_rcu_slot(parent, slot, new);
	if (!mte_is_leaf(new))
		mas_adopt_children(mas, new);

}
static inline enum maple_type mas_ptype_leaf(struct ma_state *mas)
{
	enum maple_type pt = mte_node_type(mas->node);

	switch (pt) {
	case maple_arange_64:
	case maple_range_64:
	default:
		return maple_leaf_64;
	}
}
/*
 * split late, that is to say.. the parent may be full and need to be split.
 * Once we know there is space (we need only a single location), then we can
 * continue.
 *
 * 1. Allocate 3 nodes: left, right, parent
 * 2. If it's not root, copy all data from the old parent to the new one and
 *    leave a hole.
 * 3. Calculate the location to split the nodes.
 * 4. Figure out the type of the node
 * 5. Copy the data to the new nodes
 * 6. Link in the nodes
 * 7. replace old_parent
 * 8. set up ma_state for return.
 *
 */
static inline int mas_split(struct ma_state *mas, unsigned char slot,
		bool active, unsigned char entry_cnt, void *entry)
{
	struct maple_enode *full = mas->node;
	unsigned char split, p_slot = 0, p_end = 0, link = 0;
	struct maple_enode *old_parent;
	enum maple_type ptype; // parent type.
	enum maple_type type; // split type.

	MA_STATE(parent, mas->tree, mas->index, mas->last);
	MA_STATE(left, mas->tree, mas->index, mas->last);
	MA_STATE(right, mas->tree, mas->index, mas->last);
	MA_STATE(new_p_mas, mas->tree, mas->index, mas->last);

	type = mte_node_type(mas->node);
	if (mte_is_root(mas->node)) {
		old_parent = full;
		mas_dup_state(&parent, mas);
		if (mt_is_alloc(mas->tree))
			ptype = maple_arange_64;
		else
			ptype = maple_range_64;
		p_slot = 0;
	} else {
		unsigned long last_pivot;
		unsigned char coalesce;

		p_slot = mte_parent_slot(mas->node);
		mas_dup_state(&parent, mas);
		mas_ascend(&parent);
		old_parent = parent.node;
		ptype = mas_parent_enum(mas, mas->node);
		p_end = _mas_data_end(&parent, ptype, &last_pivot, &coalesce);
		if (p_end - coalesce >= mt_slots[ptype] - 1) {
			/* Must split the parent */
			mas_dup_state(mas, &parent);
			split = mas_split(mas, p_slot, active,
					p_end - coalesce + 1, entry);
			if (mas_is_err(mas))
				return 0;

			mas_dup_state(&parent, mas);
			ptype = mte_node_type(mas->node);
			for (p_slot = 0; p_slot < mt_slots[ptype];p_slot++) {
				if (mte_to_node(mas_get_rcu_slot(mas, p_slot)) ==
				   mte_to_node(full))
					break;
			}
			mas_set_slot(&parent, p_slot);
		}
		ptype = mas_parent_enum(mas, mas->node);
		p_end = mas_data_end(&parent);
		mas_dup_state(mas, &parent);
		mas_set_slot(mas, p_slot);
		mas_descend(mas);
	}

	mas_node_cnt(mas, 4);
	if (mas_is_err(mas))
		return 0;

	// Allocations.
	mas_dup_state(&new_p_mas, &parent);
	new_p_mas.node = mt_mk_node(mas_next_alloc(mas), ptype);

	// Copy grand parent to the parent, including slot encoding.
	mas_mn(&new_p_mas)->parent = mas_mn(&parent)->parent;

	mas_dup_state(&left, mas);
	mas_dup_state(&right, mas);
	left.node = mt_mk_node(ma_mnode_ptr(mas_next_alloc(mas)), type);
	right.node  = mt_mk_node(ma_mnode_ptr(mas_next_alloc(mas)), type);

	mte_set_parent(left.node, new_p_mas.node, p_slot);
	mte_set_parent(right.node, new_p_mas.node, p_slot+1);
	// split the data into left & right and do the insert.
	split = mas_append_split(&left, &right, mas, slot, entry, active);

	// Copy the parent data up to p_slot - 1.
	if (!mte_is_root(full) && p_slot)
		link = mas_append(&new_p_mas, &parent, 0, p_slot - 1);

	// left will be placed in link, not p_slot as coalescing may occur.
	mas_link(mas, left.node, new_p_mas.node, link, left.max, ptype);

	// right will be placed in link + 1;
	mas_link(mas, right.node, new_p_mas.node, link + 1,
		 right.max, ptype);

	// Append data from p_slot + 1 to the end.
	if (!mte_is_root(full) && (p_slot + 1 <= p_end))
		mas_append(&new_p_mas, &parent, p_slot + 1, p_end);

	// Update encoded slots in children
	mas_adopt_children(&new_p_mas, new_p_mas.node);

	// Replace the parent node & free the old parent.
	_mas_replace(&new_p_mas, active, true);

	if (mt_is_alloc(mas->tree))
		mas_update_gap(&new_p_mas, false);

	// Set up the ma_state for the return.  Point to the correct node for
	// the insert or subsequent split.
	if (mas->index <= left.max) {
		mas_dup_state(mas, &left);
		p_slot += 1;
	} else {
		mas_dup_state(mas, &right);
		p_slot += 2;
	}

	// Free the full node, this may have happened in _mas_replace
	if (old_parent != full) {  // not root?
		if (!active)
			mas_push_node(mas, full);
		else
			mte_free(full);
	}

	if (mt_is_alloc(mas->tree)) {
		mas_update_gap(&left, false);
		mas_update_gap(&right, false);
	}

	return split;
}

/* Private
 *
 * When inserting into non-leaf nodes in _mas_insert, a type is needed.
 *
 * Try to determine that type here.
 */
static inline enum maple_type mas_determine_type(struct ma_state *mas,
		unsigned long min, unsigned char slot)
{
	struct maple_enode *sibling;
	unsigned char sibling_slot = slot;
	enum maple_type stype, mt = mas_ptype_leaf(mas);

	if (slot > 0)
		sibling_slot -= 1;
	else
		sibling_slot += 1;
	sibling = mas_get_rcu_slot(mas, sibling_slot);
	if (!sibling)
		return mt;

	stype = mte_node_type(sibling);
	if (mt_max[stype] >= min - mas->index)
		return stype;

	return mt;
}

/** Private
 * mas_may_move_gap() - May move the gap to the proceeding node.
 *
 * 1. Check back for a gap and move it
 * 2. Check front for a gap.
 * Ensure we cover the scenarios:
 * 3. There is an empty node due to allocation failures - Move the gap wherever
 * it can go and free this node.
 * 4. There is a gap at the back and front of a node.
 *
 */
static inline void mas_rebalance(struct ma_state *mas);
static inline void mas_move_gap_fwd(struct ma_state *mas, struct ma_state *curr,
				    unsigned long end, unsigned char new_end,
				    struct ma_state *next, unsigned char next_start,
				    bool empty)
{
	unsigned long last_piv = mas_get_safe_pivot(curr, new_end);
	unsigned char slot = 0;

	MA_STATE(parent, mas->tree, mas->index, mas->last);

	if (empty) {
		last_piv = --curr->min;
	} else {
		while (new_end++ != end) {
			if (new_end < mt_pivot_count(curr->node))
				mte_set_pivot(curr->node, new_end, last_piv);
			// The location storing these values has moved.
			mte_set_rcu_slot(curr->node, new_end, XA_RETRY_ENTRY);
		}

	}
	if (curr->node == mas->node)
		mas->max = last_piv;
	else
		mas->min = last_piv + 1;

	next->min = last_piv + 1;
	curr->max = last_piv;
	if (next_start) {
		unsigned char next_end = 0;
		MA_STATE(new, mas->tree, mas->index, mas->last);

		mas_dup_state(&new, next);
		next_end = mas_data_end(next);
		new.node = mt_mk_node(mas_next_alloc(mas),
				       mte_node_type(next->node));
		mas_mn(&new)->parent = mas_mn(next)->parent;
		new.min = last_piv + 1;
		mas_append(&new, next, 0, next_end);
		mas_dup_state(next, &new);
		mas_replace(&new);
	}

	mas_set_slot(next, next_start);
	mas_shift_pivot(curr, next, last_piv);

	if (empty) {
		slot = mte_parent_slot(curr->node);
		mas_dup_state(&parent, curr);
		mas_ascend(&parent);
		mte_set_rcu_slot(parent.node, slot, XA_RETRY_ENTRY);
		mas_set_safe_pivot(&parent, slot, last_piv);
		if (mt_is_alloc(mas->tree))
			mte_set_gap(parent.node, slot, 0);
	}

	if (mt_is_alloc(mas->tree)) {
		mas_update_gap(curr, true);
		mas_update_gap(next, true);
	}

	if (empty) {
		mte_free(curr->node);
		mas_dup_state(mas, next);
	}
}

static inline bool mas_move_gap_swap(struct ma_state *curr,
				     struct ma_state *next)
{
	mas_dup_state(next, curr); // make next == curr
	mas_set_slot(curr, 0);
	mas_prev(curr, 0);
	if (mas_is_none(curr))
		return false;

	return true;
}
static inline void mas_may_move_gap(struct ma_state *mas)
{

	unsigned long last_piv;
	unsigned char coalesce;
	unsigned char end;
	unsigned char new_end;
	unsigned char next_start = 0;
	void *entry = NULL;
	void *next_entry = NULL;

	// node that starts with NULL
	MA_STATE(next, mas->tree, mas->index, mas->last);
	// node that ends with NULL
	MA_STATE(curr, mas->tree, mas->index, mas->last);
	MA_STATE(tmp, mas->tree, mas->index, mas->last);

	if (mte_is_root(mas->node))
		return;

	mas_dup_state(&next, mas);
	mas_dup_state(&curr, mas);
	mas_dup_state(&tmp, mas);
	mas_set_slot(&next, mt_slot_count(next.node) - 1);
	mas_next(&next, ULONG_MAX);

	// Check both the gap from curr -> next and prev -> curr.
	// First, check curr -> next, then redefine next = curr and curr -> prev
	do {
		bool empty = false;
		next_start = 0;

		if (mas_is_none(&next))
			continue;

		/* Start by checking the back of the current node. */
		end = _mas_data_end(&curr, mte_node_type(curr.node), &last_piv,
				    &coalesce);
		new_end = end;
		do {
			entry = mas_get_rcu_slot(&curr, new_end);
			if (entry && !xa_is_deleted(entry))
				break;
		} while (new_end--);

		if (new_end == U8_MAX) {
			// underflow.
			new_end = 0;
			empty = true;
		}

		if (!empty && end == new_end) // no gap at back.
			continue;

		next_entry = mas_get_rcu_slot(&next, next_start);
		while ((xa_is_retry(next_entry)) &&
		       (next_start < mt_slot_count(next.node) - 1)) {
			next_entry = mas_get_rcu_slot(&next, ++next_start);
		}

		if (next_entry != NULL && !mt_will_coalesce(next_entry))
			continue; // Next does not start with null.

		if (next_start) {
			mas_dup_state(&tmp, mas);
			mas_node_cnt(mas, 1);
			if (mas_is_err(mas)) {
				mas_dup_state(mas, &tmp);
				continue;
			}
		}

		mas_move_gap_fwd(mas, &curr, end, new_end, &next, next_start, empty);

	} while ((curr.node == mas->node) && (mas_move_gap_swap(&curr, &next)));
}
static inline int mas_add(struct ma_state *mas, void *entry, bool overwrite,
		bool active);
static inline int _mas_add_dense(struct ma_state *mas, void *entry,
		unsigned char slot, bool overwrite, enum maple_type this_type,
		bool active)
{
	int ret = 0;
	unsigned long min = mas->index - mas->min;
	unsigned long max = mas->last - mas->min;

	if (max > mt_max[this_type])
		max = mt_max[this_type];

	// FIXME: Check entire range, not what we would insert this time.
	if (!overwrite) {
		do {
			if (mas_get_rcu_slot(mas, min++))
				return 0;
		} while (min < max);
	}

	do {
		mte_update_rcu_slot(mas->node, min++, entry);
	} while (min < max);

	if (max != mas->last - mas->min) {
		mas->index = mas->min + max + 1;
		mas_add(mas, entry, overwrite, active);
	}

	ret = max - min + 1;

	return ret;
}


static inline int __mas_add_slot_cnt(struct ma_state *mas,
		unsigned long prev_piv, unsigned char this_slot,
		const unsigned char slot, bool prev_null, bool start)
{
	unsigned long this_piv = mas->min;
	int slot_cnt = 0;
	void *data;

	while (this_slot < slot) {
		this_piv = mas_get_safe_pivot(mas, this_slot);
		if (!this_piv && this_slot)
			break;

		if (this_piv > mas->max) // possibly a retry.
			break;

		if (this_piv == prev_piv && this_slot)
			goto skip_slot;

		if (this_piv < prev_piv)
			goto skip_slot;

		data = mas_get_rcu_slot(mas, this_slot);
		if (!data || mt_will_coalesce(data)) {
			if (xa_is_retry(data))
			    goto skip_slot;

			if (prev_null)
				goto skip_slot;

			prev_null = true;
		} else
			prev_null = false;

		slot_cnt++;
skip_slot:
		prev_piv = this_piv;
		this_slot++;
	}

	if (start)
		return slot_cnt;

	if (prev_null != true && this_piv != mas->max)
		slot_cnt++;

	return slot_cnt;
}

static inline int _mas_add_slot_cnt(struct ma_state *mas,
		const unsigned char slot, const unsigned long min,
		const unsigned long max, void *entry)
{
	int slot_cnt;
	unsigned char slot_max = mt_slot_count(mas->node);
	bool prev_null = false;
	unsigned long prev_piv = (mas->min ? mas->min - 1 : mas->min);

	slot_cnt = __mas_add_slot_cnt(mas, prev_piv, 0, slot, false, true);
	slot_cnt++; // maintains the same slot (this_slot) (1)
	if (min < mas->index) // starts after this_slot.
		slot_cnt++; // (2?)

	if (max > mas->last) { // ends before this_slot.
		void *prev_val = mas_get_rcu_slot(mas, slot);

		slot_cnt++; // (2 or 3?)
		prev_piv = max;
		if (!prev_val || mt_will_coalesce(prev_val))
			prev_null = true;
	} else {
		if (!entry)
			prev_null = true;
		prev_piv = mas->last;
	}

	if (max == mas->max)
		return slot_cnt;

	slot_cnt += __mas_add_slot_cnt(mas, prev_piv, slot + 1, slot_max,
				       prev_null, false);

	return slot_cnt;
}

static inline int __mas_add(struct ma_state *mas, void *entry,
		int entry_cnt, bool active, bool append)
{
	enum maple_type mas_type = mte_node_type(mas->node);
	struct maple_node space;
	struct maple_node *mn = NULL;
	unsigned char data_end = mas_data_end(mas);
	unsigned char slot = mas_get_slot(mas);
	unsigned char end_slot = slot;
	unsigned long src_max = mas->max;
	unsigned long piv, prev_piv = mas->min - 1;
	void *existing_entry = NULL;
	int ret = 0;

	MA_STATE(cp, mas->tree, mas->index, mas->last);

	/* Append only if we are appending AND the slot is truly empty.
	 * If it's delete, skip, etc, then RCU requires a new node.
	 */
	if (append && !mas_get_rcu_slot(mas, data_end + 1)) {
		mas_set_slot(mas, data_end + 1);
		mas_append_entry(mas, entry);
		return ret;
	}

	mas_dup_state(&cp, mas);

	if (slot)
		prev_piv = mte_get_pivot(mas->node, slot - 1);

	if (active) {
		cp.node = mt_mk_node(ma_mnode_ptr(mas_next_alloc(mas)),
				mas_type);
		mn = mas_mn(mas);
	} else {
		// Note cp.node == mas->node here.
		mn = &space;
		memcpy(mn, mas_mn(mas), sizeof(struct maple_node));
		memset(mas_mn(&cp), 0, sizeof(struct maple_node));
	}
	mas_mn(&cp)->parent = mn->parent;
	if (prev_piv == mas->index - 1) {
		if (slot) // slot - 1 will translate to slot - 1 + 1.
			end_slot = _mas_append(&cp, mn, mas_type, src_max, 0,
					slot - 1);
	} else {
		end_slot = _mas_append(&cp, mn, mas_type, src_max, 0, slot);
		if (end_slot < mt_pivot_count(cp.node))
			mte_set_pivot(cp.node, end_slot, mas->index - 1);
	}

	mas_set_slot(&cp, end_slot);
	end_slot = mas_append_entry(&cp, entry) + 1;

	// Partial slot overwrite
	slot = mas_skip_overwritten(mas, data_end, slot);
	if (slot >= mt_slot_count(mas->node))
		goto done; // potential spanning add.

	mas_get_range(mas, slot, &prev_piv, &piv);
	existing_entry = mas_get_rcu_sanitized(mas, slot);
	if (prev_piv <= mas->last && piv > mas->last) {
		mte_set_rcu_slot(cp.node, end_slot, existing_entry);
		mas_set_safe_pivot(&cp, end_slot++, piv);
		cp.max = piv;
		slot++;
	}
	if (slot <= data_end && cp.max < mas->max)
		_mas_append(&cp, mn, mas_type, src_max, slot, data_end);

done:
	if (active)
		mas->node = cp.node;

	return ret;
}
static inline bool _mas_walk(struct ma_state *mas);
static inline int mas_replace_tree(struct ma_state *mas, void *new_entry);
static inline bool mas_rebalance_node(struct ma_state *mas);
static inline unsigned long mas_next_node(struct ma_state *mas,
		unsigned long max);

/* Private
 *
 * mas_rebalance_gaps() - walk down to the mas->index location and update the
 * gaps.
 *
 *
 */
static inline void mas_rebalance_gaps(struct ma_state *mas)
{
	if (mt_is_alloc(mas->tree)) {
		MA_STATE(r_mas, mas->tree, mas->index, mas->last);
		mas->node = MAS_START;
		_mas_walk(mas); // return to the updated location in the tree.
		mas_dup_state(&r_mas, mas);
		mas_update_gap(mas, true);
		mas_dup_state(mas, &r_mas);
		mas_set_slot(&r_mas, mte_parent_slot(mas->node));
		mas_next_node(&r_mas, ULONG_MAX);
		if (!mas_is_none(&r_mas))
			mas_update_gap(&r_mas, true);

	}
}
/* Private
 *
 * mas_spanning_add() - Add a value which spans the nodes range.  This is
 * handled separately than other adds because the tree may need significant
 * alterations.
 *
 * Current plan:
 * Alter in-node data to use the new maximum, walk up the tree setting the
 * pivots & inserting skip/retry values as well as rebalance once the nodes
 * have been altered.
 *
 *
 */
static inline void mas_spanning_cleanup(struct ma_state *p, struct ma_state *c,
					unsigned long new_pivot)
{
	struct ma_state prev, curr;
	unsigned char p_pslot, p_cslot; // parent previous and current slot.
	enum maple_type p_type;
	struct maple_node *parent;

	mas_dup_state(&prev, p);
	mas_dup_state(&curr, c);
	p_type = mas_parent_enum(&prev, prev.node);
	parent = mte_parent(prev.node);
	p_pslot = mte_parent_slot(prev.node);
	p_cslot = mte_parent_slot(curr.node);

	if (mte_parent(prev.node) == mte_parent(curr.node)) {
		// Set all pivots up to p_cslot to new_pivot.
		while (++p_pslot < p_cslot)
			ma_set_pivot(parent, p_pslot, p_type, new_pivot);

		return;
	}

	// Not the same parent, clear out to the end of p_pslot and the start of
	// p_cslot.
	while(++p_pslot < mt_pivots[p_type]) {
		if (!ma_get_pivot(parent, p_pslot, p_type))
			break;
		ma_set_pivot(parent, p_pslot, p_type, new_pivot);
	}

	if (!p_cslot)
		return;

	parent = mte_parent(curr.node);
	p_type = mas_parent_enum(&curr, curr.node);

	do {
		ma_set_pivot(parent, --p_cslot, p_type, new_pivot);
	} while (p_cslot);
}
static inline int mas_spanning_add(struct ma_state *mas, void *entry,
		unsigned long old_max)
{
	unsigned char p_slot;
	unsigned long new_pivot = mas->last;
	int i;

	MA_STATE(r_mas, mas->tree, mas->index, mas->last); // right mas.
	MA_STATE(p_mas, mas->tree, mas->index, mas->last); // parent mas.
	mas_dup_state(&p_mas, mas); // point to the start node.
	mas_ascend(&p_mas);

	p_slot = mte_parent_slot(mas->node);
	do {
		MA_STATE(tmp, mas->tree, mas->index, mas->last); // prev mas.

		mas_set_slot(mas, p_slot); // for mas_next_node.
		mas_set_slot(&p_mas, p_slot); // for pivot changes in parent.

		mas_dup_state(&r_mas, mas); // point to the start node.
		mas_dup_state(&tmp, &r_mas);
		mas_set_slot(&r_mas, mte_parent_slot(r_mas.node));

		mas_next_node(&r_mas, ULONG_MAX);
		// Update the pivots.
		mas->max = new_pivot;
		mas_set_safe_pivot(&p_mas, p_slot, mas->max);

		if (mas_is_none(&r_mas))
		    goto done;

		mas_set_slot(&r_mas, mte_parent_slot(r_mas.node));

		while (!mas_is_none(&r_mas)) {
			mas_spanning_cleanup(&tmp, &r_mas, new_pivot);
			if (r_mas.max <= r_mas.last) {
				struct maple_enode *enode = r_mas.node;

				i = mte_parent_slot(enode);
				mas_ascend(&r_mas);
				mte_set_rcu_slot(r_mas.node, i, XA_SKIP_ENTRY);
				mas_set_safe_pivot(&r_mas, i, r_mas.last);
				if (mt_is_alloc(r_mas.tree))
					mte_set_gap(r_mas.node, i, 0);
				mas_dup_state(&r_mas, &tmp);
				mte_free(enode);
			} else {
				unsigned long piv = mas->min;

				for (i = 0; i < mt_slot_count(r_mas.node); i++) {
					void *val = XA_RETRY_ENTRY;

					piv = mas_get_safe_pivot(&r_mas, i);
					if (!piv)
						break;

					if (piv > r_mas.last)
						break;

					if (!mte_is_leaf(r_mas.node))
						val = XA_SKIP_ENTRY;

					mte_set_rcu_slot(r_mas.node, i, val);
					if (i < mt_pivot_count(r_mas.node))
						mte_set_pivot(r_mas.node, i,
							      r_mas.last);

					if (!mte_is_leaf(r_mas.node) &&
					    mt_is_alloc(r_mas.tree))
						mte_set_gap(r_mas.node, i, 0);

				}
				break;
			}
			mas_dup_state(&tmp, &r_mas);
			mas_set_slot(&r_mas, mte_parent_slot(r_mas.node));
			mas_next_node(&r_mas, ULONG_MAX);
		}

		if (mas_is_none(&r_mas))
			mas_dup_state(&r_mas, &tmp);

		if (r_mas.max > mas->last && !mas_rebalance_node(mas)) {
			// Best effort, no allocation required.
			if (mt_is_alloc(mas->tree))
				mas_update_gap(&r_mas, true);

			if (mas_is_err(mas))
				return 0;
		}

		if (mas_is_err(mas))
			return 0;

		mas_dup_state(&p_mas, mas); // parent may be replaced.
		mas_ascend(&p_mas);

		if (mas_is_err(mas))
			return 0; // FIXME: Broken tree?

		// parent slot may have changed during rebalance.
		p_slot = mte_parent_slot(mas->node);
		//  Set up for the next loop.
		if (!mte_is_root(mas->node)) {
			// Set the current parent slot for ascend.
			mas_set_slot(mas, p_slot);
			mas_ascend(mas);
			// Get the new levels parent slot (grand-parent slot)
			p_slot = mte_parent_slot(mas->node);

			if (!mte_is_root(p_mas.node)) {
				// Set the slot for ascending.
				mas_set_slot(&p_mas, p_slot);
				mas_ascend(&p_mas);
			}
		}

		if (mas->max > new_pivot)
			new_pivot = mas->max;

	} while (mas->max <= mas->last);

done:

	if (!mte_is_root(mas->node))
		mas_set_safe_pivot(&p_mas, p_slot, mas->max);

	mas_rebalance_node(mas);
	if (mas_is_err(mas))
		return 0; // FIXME: Broken tree?

	mas_rebalance_gaps(mas);

	return 1;
}
/* Private
 *
 * Insert entry into a node.
 * If this is not an append, a new node will be generated.
 * If this node is full, split the node & insert or overwrite
 *
 * This is done by:
 * 1. Calculating the range of slot.
 * 2. Figure out how many slots are needed for the entry. (0, 1, 2)
 * 3. Copy the data over
 * 4. Write the entry.
 *
 * Returns the number of slots used on success, the slot number on failure.
 */
static inline int _mas_add(struct ma_state *mas, void *entry, bool overwrite,
		bool active)
{
	enum maple_type this_type = mte_node_type(mas->node);
	unsigned long last_piv;
	unsigned char coalesce;
	unsigned char old_end, new_end;
	unsigned long max = mas->max;
	unsigned long min = mas->min;
	unsigned char slot = mas_get_slot(mas);
	unsigned char slot_cnt = mt_slots[this_type] - 1;
	struct maple_enode *prev_enode = NULL;
	void *contents = NULL;
	bool append = false;
	unsigned long spans_node = 0;
	int ret = 0;


	if (ma_is_dense(this_type)) {
		ret = _mas_add_dense(mas, entry, slot, this_type, overwrite,
				active);
		if (!ret)
			return ret;
		old_end = 0; // fixme.
		goto update_gap;
	}


	// Bug if we are adding an entry to a non-leaf node.
	MT_BUG_ON(mas->tree, !ma_is_leaf(this_type));

	old_end = _mas_data_end(mas, this_type, &last_piv, &coalesce);
	if (slot > slot_cnt) // search returned MAPLE_NODE_SLOTS
		slot = old_end + 1;

	mas_get_range(mas, slot, &min, &max);
	if (mas_get_slot(mas) > slot_cnt)
		max = mas->max;

	if (slot <= old_end)
		contents = mas_get_rcu_slot(mas, slot);


	// Check early failures.
	if (!overwrite) {
		if (mas->last > max) { // spans range.
			// FIXME, this may be fine if the range isn't
			// coalesced, or such?
			mas_set_err(mas, -ERANGE);
			return 0;
		}
		if (!mt_is_empty(contents)) {
			mas_set_err(mas, -EBUSY);
			return 0;
		}
	}


	if (mas->last > mas->max) // spans node.
		spans_node = mas->max;

	// At this point, the we can perform the add.
	if (!mte_is_leaf(mas->node)) {
		// An allocation failed previously during a rebalance.  There
		// is no way to know how broken things are, so try to rebuild
		// the tree.
		mas_reset(mas);
		mas_first_node(mas, ULONG_MAX);
		return mas_replace_tree(mas, entry);
	}

	// Fits neatly into a slot.
	if (mas->index == min && mas->last == max) {
		mte_set_rcu_slot(mas->node, slot, entry);
		if (slot < slot_cnt)
			mte_set_pivot(mas->node, slot, mas->last);
		ret = 1;
		goto complete;
	}
	new_end = _mas_add_slot_cnt(mas, slot, min, max, entry);
	if (new_end > slot_cnt + 1) {
		mas_split(mas, slot, active, old_end, entry);
		if (mas_is_err(mas))
			return 0;

		ret = old_end - new_end;
		goto complete;
	}

	if (active) {
		mas_node_cnt(mas, 1);
		if (mas_is_err(mas))
			return 0;
	}
	prev_enode = mas->node;
	if (slot > old_end && !coalesce)
		append = true;

	mas_set_slot(mas, slot);
	__mas_add(mas, entry, old_end, active, append);
	mas_set_slot(mas, slot);

complete:
	if (prev_enode != mas->node)
		_mas_replace(mas, active, true);

	// Spanning a node can be complex.
	if (spans_node)
		ret = mas_spanning_add(mas, entry, spans_node);

	// FIXME: Allocation failures from mas_spanning_add?

update_gap:
	if (mt_is_alloc(mas->tree)) {
		mas_update_gap(mas, false);
		if (!entry && (slot >= old_end || !slot))
			mas_may_move_gap(mas);
	}

	return ret;
}

static inline void ma_inactive_insert(struct ma_state *mas, void *entry)
{
	// Restart search for where to insert.
	mas->node = MAS_START;
	mas_start(mas);
	mas_add(mas, entry, true, false);
}
static inline void mas_insert(struct ma_state *mas, void *entry)
{
	mas_add(mas, entry, false, true);
}

static inline int _mas_insert(struct ma_state *mas, void *entry,
		unsigned char slot, bool active)
{
	mas_set_slot(mas, slot);
	return _mas_add(mas, entry, false, active);
}

static inline void mas_root_expand(struct ma_state *mas, void *entry)
{
	void *r_entry = rcu_dereference_protected(mas->tree->ma_root,
				lockdep_is_held(&mas->tree->ma_lock));
	struct maple_node *mn;
	enum maple_type mt = mas_ptype_leaf(mas);
	int slot = 0;

	mas_node_cnt(mas, 1);
	if (mas_is_err(mas))
		return;

	mn = mas_next_alloc(mas);
	mas->node = mt_mk_node(mn, mt);
	mn->parent = ma_parent_ptr(
		      ((unsigned long)mas->tree | MA_ROOT_PARENT));

	mte_set_rcu_slot(mas->node, slot, r_entry);
	mte_set_pivot(mas->node, slot, 0);
	if (r_entry)
		mas_set_slot(mas, 1);

	// FIXME: When task_size / page_size -1 works, check to ensure we are
	// not inserting above this.
	__mas_add(mas, entry, slot++, false, false);
	if (mas_is_err(mas))
		return;

	if (mas->last != 1)
		slot++;
	//_mas_insert(mas, entry, slot, false);

	if (mas_is_err(mas))
		return;

	if (mt_is_alloc(mas->tree)) {
		//FIXME: arch_get_mmap_end? mas->index = TASK_SIZE / PAGE_SIZE - 1;
		mas_set_slot(mas, 2);
		mas->index = 0x2000000000000UL;
		mas->last = mt_max[mt];
		__mas_add(mas, XA_ZERO_ENTRY, slot, false, false);
		if (mas_is_err(mas))
			return;
	}

	/* swap the new root into the tree */
	rcu_assign_pointer(mas->tree->ma_root, mte_mk_root(mas->node));
}

static inline int mas_safe_slot(struct ma_state *mas, int *slot, int delta);
static inline int mas_dead_node(struct ma_state *mas, unsigned long index);

static inline void mas_next_slot(struct ma_state *mas, unsigned long max)
	__must_hold(mas->tree->lock)
{
	unsigned char slot;

	// walk up.
	while (1) {
		slot = mte_parent_slot(mas->node);
walk_again:
		if (mte_is_root(mas->node))
			goto no_entry;

		mas_ascend(mas);
		if (mas->max > max)
			goto no_entry;

		if (slot < mt_slot_count(mas->node) - 1) {
			if (!mas_get_safe_pivot(mas, slot + 1))
				continue;
			slot++;
			goto walk_down;
		}

		if (mte_is_root(mas->node))
			goto no_entry;
	}


walk_down:
	do {
		void *entry = NULL;
		if (slot)
			mas->min = mas_get_safe_pivot(mas, slot - 1) + 1;
		mas->max = mas_get_safe_pivot(mas, slot);
		entry = mas_get_rcu_slot(mas, slot);
		if (xa_is_skip(entry)) {
			if (mas->max >= max) {
				goto no_entry;
			} else if (slot < mt_slot_count(mas->node)) {
				slot++;
				goto walk_down;
			} else if (mte_is_root(mas->node)) {
				goto no_entry;
			} else {
				goto walk_again;
			}
		}

		mas->node = entry;
		if (mt_is_empty(mas->node))
			goto no_entry;

		if (mte_is_leaf(mas->node)) {
			goto done;
		}
		slot = 0;

	} while (1);

done:
	mas_set_slot(mas, slot);
	return;

no_entry:
	mas->node = MAS_NONE;
}
/** Private
 * mas_prev_slot() - Find the previous leaf slot, regardless of having an
 * entry or not
 *
 * NOTE: Not read safe - does not check for dead nodes.
 *       Not root safe, cannot be the root node.
 */
static inline void mas_prev_slot(struct ma_state *mas, unsigned long min)
	__must_hold(ms->tree->lock)
{
	unsigned char slot, coalesce;

	if (mte_is_root(mas->node))
		goto no_entry;

	// Walk up.
	while (1) {
		slot = mte_parent_slot(mas->node);
		mas_ascend(mas);
		if (mas->min < min)
			goto no_entry;

		if (slot) {
			slot--;
			goto walk_down;
		}
		if (mte_is_root(mas->node))
			goto no_entry;
	}

walk_down:
	do {
		if (slot)
			mas->min = mas_get_safe_pivot(mas, slot - 1);
		mas->max = mas_get_safe_pivot(mas, slot);
		mas->node = mas_get_rcu_slot(mas, slot);
		if (mt_is_empty(mas->node))
			goto done;

		if (mte_is_leaf(mas->node))
			goto done;

		slot = _mas_data_end(mas, mte_node_type(mas->node), &mas->max,
				&coalesce);
	} while (1);

done:
	mas_set_slot(mas, slot);
	return;

no_entry:
	mas->node = MAS_NONE;
}

/** Private
 * mas_prev_node() - Find the prev non-null entry at the same level in the
 * tree.  The prev value will be mas->node[mas_get_slot(mas)] or MAS_NONE.
 */
static inline void mas_prev_node(struct ma_state *mas, unsigned long limit)
{
	int level;
	int slot = mas_get_slot(mas);
	unsigned long start_piv;

	start_piv = mas_get_safe_pivot(mas, slot);
restart_prev_node:
	level = 0;
	if (mte_is_root(mas->node) || mas->node == MAS_NONE)
		goto no_entry;

	while (1) {
		unsigned long min;
		slot = mte_parent_slot(mas->node);
		mas_ascend(mas);
		level++;

		if (!mas_safe_slot(mas, &slot, -1))
			goto ascend;

		if (mas_dead_node(mas, start_piv))
			goto restart_prev_node;

		if (!slot)
			goto ascend;

		slot--;
		do {
			struct maple_enode *mn;
			unsigned long last_pivot;
			unsigned long pivot = mas_get_safe_pivot(mas, slot);
			unsigned char coalesce;

			if (slot)
				min = mas_get_safe_pivot(mas, slot - 1) + 1;
			else
				min = mas->min;

			if (pivot < limit)
				goto no_entry;

			if (slot != 0 && pivot == 0)
				break;

			mn = mas_get_rcu_slot(mas, slot);
			if (mt_is_empty(mn) || xa_is_retry(mn))
				continue;

			if (level == 1) {
				mas_set_slot(mas, slot);
				mas->node = mn;
				mas->max = pivot;
				mas->min = min;
				if (mas_dead_node(mas, start_piv))
					goto restart_prev_node;
				return;
			}

			level--;
			mas->node = mn;
			mas->max = pivot;
			mas->min = min;
			slot = _mas_data_end(mas, mte_node_type(mn),
					&last_pivot, &coalesce) + 1;
		} while (slot-- > 0);

ascend:
		if (mte_is_root(mas->node))
			goto no_entry;
	}

no_entry:
	mas->node = MAS_NONE;
}
/*
 * Find the next non-null entry at the same level in the tree.  The next value
 * will be mas->node[mas_get_slot(mas)] or MAS_NONE.
 *
 *
 * Node: Not safe to call with mas->node == root
 */

static inline unsigned long mas_next_node(struct ma_state *mas,
		unsigned long max)
{
	int level;
	unsigned long start_piv;

restart_next_node:
	level = 0;
	while (1) {
		unsigned char count;
		int slot;
		struct maple_enode *mn;
		unsigned long prev_piv;

		if (mte_is_root(mas->node) || mas->node == MAS_NONE)
			goto no_entry;

		mn = mas->node;
		slot = mas_get_slot(mas);
		start_piv = mas_get_safe_pivot(mas, slot);
		level++;
		mas_ascend(mas);

		if (!mas_safe_slot(mas, &slot, 1))
			goto ascend;

		if (mas_dead_node(mas, start_piv))
			goto restart_next_node;

		count = mt_slot_count(mas->node);
		prev_piv = mas_get_safe_pivot(mas, slot);
		while (++slot < count) {
			unsigned long pivot = mas_get_safe_pivot(mas, slot);

			if (prev_piv > max)
				goto no_entry;

			if (slot != 0 && pivot == 0)
				break;

			mn = mas_get_rcu_slot(mas, slot);
			if (mt_is_empty(mn) || xa_is_retry(mn)) {
				prev_piv = pivot;
				continue;
			}

			mas->min = prev_piv + 1;
			mas->max = pivot;

			if (level == 1) {
				mas_set_slot(mas, slot);
				mas->node = mn;
				if (mas_dead_node(mas, start_piv))
					goto restart_next_node;
				return pivot;
			}

			level--;
			mas->node = mn;
			slot = -1;
			count = mt_slot_count(mas->node);
		}

ascend:
		if (mte_is_root(mas->node))
			goto no_entry;
		mas_set_slot(mas, mte_parent_slot(mas->node));
	}

no_entry:
	mas->node = MAS_NONE;
	return mas->max;

}

/** Private
 * prev node entry
 */
static inline bool mas_prev_nentry(struct ma_state *mas, unsigned long limit,
		unsigned long *max)
{
	unsigned long pivot = mas->max;
	unsigned char slot = mas_get_slot(mas);
	void *entry;

	if (!slot)
		return false;

	slot--;
	do {
		pivot = mas_get_safe_pivot(mas, slot);
		if (pivot < limit)
			goto no_entry;

		entry = mas_get_rcu_slot(mas, slot);
		if (!mt_is_empty(entry))
			goto found;
	} while (slot--);

no_entry:
	return false;

found:
	*max = pivot;
	mas_set_slot(mas, slot);
	return true;
}

/** Private
 * mas_next_nentry() - Next node entry.  Set the @mas slot to the next valid
 * entry and range_start to the start value for that entry.  If there is no
 * entry, returns false.
 */
static inline bool mas_next_nentry(struct ma_state *mas, unsigned long max,
		unsigned long *range_start)
{
	unsigned long pivot = mas->min;
	unsigned long r_start = mas->min;
	unsigned char slot = mas_get_slot(mas);
	unsigned char count = mt_slot_count(mas->node);
	void *entry;

	if (slot)
		r_start = mas_get_safe_pivot(mas, slot - 1) + 1;

	while (slot < count) {
		pivot = mas_get_safe_pivot(mas, slot);

		if (pivot > mas->max) // possibly a retry.
			goto no_entry;

		if (slot != 0 && pivot == 0)
			goto no_entry;

		if (r_start > max)
			goto no_entry;

		if (r_start > mas->max)
			goto no_entry;

		entry = mas_get_rcu_slot(mas, slot);
		if (!mt_is_empty(entry))
			goto found;

		/* Ran over the limit, this is was the last slot to try */
		if (pivot >= max)
			goto no_entry;

		r_start = pivot + 1;
		slot++;
	}

no_entry:
	*range_start = r_start;
	return false;

found:
	mas->last = pivot;
	*range_start = r_start;
	mas_set_slot(mas, slot);
	return true;
}
/* Private
 *
 * Returns the pivot which points to the entry with the highest index.
 * @mas slot is set to the entry location.
 * @limit is the minimum index to check.
 *
 */
static inline void* mas_last_entry(struct ma_state *mas,
		unsigned long limit)
{
	unsigned long prev_min, prev_max, range_start = 0;
	unsigned char slot = 1;

	if (mas_start(mas) || mas_is_none(mas))
		return NULL;

	prev_min = mas->min;
	prev_max = mas->max;
	while (range_start < limit) {
		mas_set_slot(mas, slot);
		if (!mas_next_nentry(mas, limit, &range_start)) {
			void *entry = mas_get_rcu_slot(mas, slot - 1);
			if (mte_is_leaf(mas->node)) {
				mas->index = range_start - 1;
				mas->index = mte_get_pivot(mas->node, slot - 1);
				return entry;
			}
			mas->max = prev_max;
			mas->min = prev_min;
			mas->node = entry;
			slot = 0;
		} else {
			slot = mas_get_slot(mas) + 1;
			prev_min = prev_max + 1;
			if (range_start > prev_min)
				prev_min = range_start;
			range_start = prev_min;
			prev_max = mas->last;
		}
	}
	return NULL;
}

/** Private
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
	unsigned long index = mas->index;
	unsigned char slot = mas_get_slot(mas);
	mas_set_slot(mas, slot + 1);

retry:
	*range_start = mas->last + 1;

	while (!mas_is_none(mas)) {
		unsigned char p_slot = 0;
		struct maple_enode *last_node = mas->node;

		slot = mas_get_slot(mas);
		if (slot > mt_slot_count(mas->node))
			goto next_node;

		if (!mte_is_leaf(mas->node) || !mas_get_slot(mas)) {
			*range_start = mas_first_entry(mas, limit);
			if (mas_is_none(mas)) {
				mas->node = last_node;
				goto next_node;
			}
		}

		if (mas_next_nentry(mas, limit, range_start))
			break;

		if (*range_start > limit)
			return NULL;

next_node:
		p_slot = mte_parent_slot(mas->node);
		mas_set_slot(mas, p_slot);
		mas_next_node(mas, limit);
		mas_set_slot(mas, 0);
	}

	if (mas_is_none(mas))
		return NULL;

	entry = mas_get_rcu_slot(mas, mas_get_slot(mas));
	if (mas_dead_node(mas, index))
		goto retry;

	return entry;
}

void *mas_range_load(struct ma_state *mas, unsigned long *range_min,
		unsigned long *range_max, bool skip_retry);
/* Private
 *
 * _mas_next() - Finds the next entry, sets index to the start of the range.
 *
 */
static inline void *_mas_next(struct ma_state *mas, unsigned long limit,
		unsigned long *range_start)
{
	void *entry = NULL;
	unsigned long range_max;

	if (mas->node && !mas_searchable(mas))
		return NULL;

	if (!mas->node || mas_is_start(mas)) {// First run.
		*range_start = 0;
		mas_start(mas);
		entry = mas_range_load(mas, range_start, &range_max, false);
		mas->last = range_max;
	}

	if (entry)
		return entry;

	return __mas_next(mas, limit, range_start);
}

/*
 * mas_next() - Get the next entry.  Can return the zero entry.  mas->node
 * must be a valid node and not a special value.  Unsafe for single entry
 * trees.
 *
 */
void *mas_next(struct ma_state *mas, unsigned long max)
{
	unsigned long index = 0;

	return _mas_next(mas, max, &index);
}
EXPORT_SYMBOL_GPL(mas_next);

/* Private
 *
 * _mas_prev() - Find the previous entry from the current ma state.
 * @mas the current maple state (must have a valid slot)
 */
static inline void* _mas_prev(struct ma_state *mas, unsigned long limit)
{
	unsigned long max = mas->max;
	unsigned char slot;

	while (!mas_is_none(mas)) {
		if (mas_prev_nentry(mas, limit, &max))
			break;

		mas_prev_node(mas, limit);
		mas_set_slot(mas, mt_slot_count(mas->node));
	}

	if (mas_is_none(mas))
		return NULL;

	mas->last = max;
	slot = mas_get_slot(mas);
	if (slot)
		mas->index = mas_get_safe_pivot(mas, slot - 1) + 1;
	else
		mas->index = mas->min;

	return mas_get_rcu_slot(mas, mas_get_slot(mas));
}

/*
 * mas_prev() - Get the previous entry.  Can return the zero entry.
 *
 *
 */
void *mas_prev(struct ma_state *mas, unsigned long min)
{
	void *entry;
	if (mas->node && !mas_searchable(mas))
		return NULL;

	if (!mas->node)
		mas->node = MAS_START;

	if (mas_is_start(mas)) {
		mas_start(mas);
		return mas_last_entry(mas, ULONG_MAX);
	}

	do {
		entry = _mas_prev(mas, min);
		if (!mas_searchable(mas))
			break;

	} while (!entry || mt_will_coalesce(entry));

	return entry;
}
EXPORT_SYMBOL_GPL(mas_prev);

/** Private
 *
 */
static inline void mas_coalesce_root(struct ma_state *mas)
{
	struct maple_enode *this_enode = mas->node;
	enum maple_type this_type = mte_node_type(this_enode);
	unsigned long piv;
	unsigned long min, max;
	unsigned char coalesce, hard_data;
	unsigned char end = _mas_data_end(mas, this_type, &piv, &coalesce);

	MA_STATE(old_mas, mas->tree, mas->index, mas->last);

	hard_data = ma_hard_data(end, coalesce);
	if (hard_data > mt_min_slots[this_type] - 1)
		return;

	/* Check for a single entry in the root node.
	 * 1. 0-oo => node
	 * 2. slot count == coalesce
	 * 3. one entry and one null.
	 */
	if (!hard_data ||
		(end + 1 == coalesce) ||
		(end  == 1 && !mte_get_rcu_slot(this_enode, 1, mas->tree))) {
		unsigned long piv;

		min = mas->min;
		max = mas->max;
		mas_set_slot(mas, 0);
		piv = mas_first_node(mas, ULONG_MAX);
		if (mte_is_leaf(this_enode)) {
			if (!piv) {
				void *entry = mte_get_rcu_slot(this_enode,
						mas_get_slot(mas), mas->tree);

				rcu_assign_pointer(mas->tree->ma_root,
						entry);
				mte_free(this_enode);
				return;
			}
			// coalesce the node..
			mas->min = min;
			mas->max = max;
			mas->node = this_enode;
			goto coalesce;
		} else if (mas_is_none(mas)) {
			/* allocation failed to create a leaf for this empty
			 * node.
			 */
			rcu_assign_pointer(mas->tree->ma_root, NULL);
			mte_free(this_enode);
			return;
		}
		/* it's not a leaf, remove a level from the tree. */
		goto remove_level;
	} else if (hard_data <= mt_min_slots[this_type] - 1) {
		goto coalesce; // Compact the node.
	}

	return;

coalesce:
	mas_dup_state(&old_mas, mas);
	mas_node_cnt(mas, 1);
	if (mas_is_err(mas))
		return;

	mas->node = mt_mk_node(mas_next_alloc(mas), this_type);
	mas_append(mas, &old_mas, 0, end);


remove_level:
	mas_mn(mas)->parent = mte_to_node(this_enode)->parent;
	mas->node = mte_mk_root(mas->node);
	mas_replace(mas);
}

/** Private
 * mas_coalesce() -
 *
 * coalesce completely consumes the right node into this node.
 *
 */
static inline bool mas_coalesce(struct ma_state *mas, unsigned char l_end_slot,
		unsigned char l_coalesce, enum maple_type l_type,
		struct ma_state *r_mas, unsigned char r_end_slot,
		struct ma_state *p_mas, unsigned long total_slots)
{
	struct maple_node *mn;
	struct maple_enode *this_node = mas->node;
	bool free_left = false, alloc_failed = false, empty_left = false;
	bool usable_left = false; // Can use left if there isn't dirty slots after the end of data.
	int alloc_cnt = 2;
	unsigned char r_p_slot = mte_parent_slot(r_mas->node);

	MA_STATE(dst, mas->tree, mas->index, mas->last);
	// it is possible that all of the right node can be appended to the
	// left.
	if (l_end_slot - l_coalesce == 0) {
		void *entry = mte_get_rcu_slot(r_mas->node, 0, r_mas->tree);

		if (entry == NULL) { // Can only be null.
			empty_left = true;
			alloc_cnt = 1;
		}
	} else if ((mas_get_rcu_slot(mas, l_end_slot + 1) == 0) &&
		   (total_slots + 1 + l_coalesce < mt_slots[l_type])) {
		usable_left = true;
		alloc_cnt = 1;
	}

	mas_node_cnt(mas, alloc_cnt); // ensure we have a node, or allocate one.
	if (mas_is_err(mas)) {
		if (alloc_cnt > 1)
			return false;

		alloc_failed = true;
		mas->node = this_node;
	}

	if (empty_left) {
		//The left can become a skip and the right can take the left
		//into the first slot which is empty.
		mas_set_safe_pivot(p_mas, mte_parent_slot(mas->node),
				   mas->min);
		mte_set_rcu_slot(p_mas->node, mte_parent_slot(mas->node),
				XA_SKIP_ENTRY);
		if (mt_is_alloc(mas->tree))
			mte_set_gap(p_mas->node, mte_parent_slot(mas->node),
					0);
		free_left = true;
		mte_free(this_node);
		mas->node = r_mas->node;
		this_node = mas->node;
		goto empty_left;
	} else if (usable_left) {
		goto use_left;
	} else {
		free_left = true;
		mn = mas_next_alloc(mas);
		mas_dup_state(&dst, mas);
		mn->parent = mas_mn(mas)->parent;
		dst.node = mt_mk_node(mn, l_type);
		l_end_slot = mas_append(&dst, mas, 0, l_end_slot);

		// If there is no entry or pivot, then set one to avoid a
		// first entry in r_mas being incorrect.
		if (!l_end_slot && !mte_get_pivot(dst.node, 0)) {
			mte_set_pivot(dst.node, 0, mas->max);
			l_end_slot++;
		}
		mas->node = dst.node;
	}


use_left:
	// Copy data to the left node.
	mas_append(mas, r_mas, 0, r_end_slot);

	if (!mte_is_leaf(mas->node))
		mas_adopt_children(mas, mas->node);

	// Redirect reads to the new node.
	mas_set_safe_pivot(p_mas, mte_parent_slot(mas->node), r_mas->max);
	// indicate to skip this slot.
	mte_set_rcu_slot(p_mas->node, mte_parent_slot(r_mas->node),
			 XA_SKIP_ENTRY);
	if (mt_is_alloc(mas->tree))
		mte_set_gap(p_mas->node, mte_parent_slot(r_mas->node), 0);

	mte_free(r_mas->node);

empty_left:
	// There is a chance that the left and right node are not next to each
	// other and separated by a skip entry.
	while(mte_parent_slot(mas->node) < --r_p_slot)
		mas_set_safe_pivot(p_mas, r_p_slot, r_mas->max);

	mas->max = r_mas->max; // update limits.

	// Remove the skip entry if the allocation was okay.
	if (!alloc_failed) {
		mas_dup_state(&dst, p_mas);
		mn = mas_next_alloc(mas);
		dst.node = mt_mk_node(mn, mte_node_type(p_mas->node));
		mas_append(&dst, p_mas, 0, mas_data_end(p_mas));
		mte_to_node(dst.node)->parent = mas_mn(p_mas)->parent;
		p_mas->node = dst.node;
		mas_replace(p_mas);
		mas_mn(mas)->parent = mte_to_node(this_node)->parent;
	}

	return free_left;
}
/* Private
 * mas_rebalance_node() - rebalance a single node.
 * Returns: true if rebalancing was necessary.
 */
static inline bool mas_rebalance_node(struct ma_state *mas)
{
	unsigned char l_end_slot, l_coalesce, r_end_slot, r_coalesce;
	unsigned char l_p_slot; // parent slot of left node
	unsigned char r_p_slot; // parent slot of right node.
	unsigned char total_slots;
	int copy_count;
	unsigned long l_end_piv, r_end_piv;
	enum maple_type l_type, r_type;
	bool try_anyways = false;
	bool free;
	bool ret = false;

	MA_STATE(r_mas, mas->tree, mas->index, mas->last); // right state
	MA_STATE(p_mas, mas->tree, mas->index, mas->last); // parent state
	MA_STATE(src_mas, mas->tree, mas->index, mas->last);

start:
	free = false;
	l_type = mte_node_type(mas->node);
	if (mte_is_root(mas->node)) {
		mas_coalesce_root(mas); // height reduction and such.
		return false;
	}

	mas_dup_state(&p_mas, mas);
	mas_ascend(&p_mas);
	l_p_slot = mte_parent_slot(mas->node);
	l_end_slot = _mas_data_end(mas, l_type, &l_end_piv, &l_coalesce);
	if (!try_anyways &&
	    (ma_hard_data(l_end_slot, l_coalesce) >= mt_min_slots[l_type])) {
		goto no_rebalancing; // Everything's perfectly all right now.
	}

	try_anyways = false;

	// Make sure there is a right node.
	mas_dup_state(&r_mas, &p_mas);
	mas_set_slot(&r_mas, l_p_slot + 1);
	if (!mas_next_nentry(&r_mas, ULONG_MAX, &r_end_piv)) {
		// Right-most node coalescing.
		mas_dup_state(&r_mas, &p_mas);
		mas_set_slot(&r_mas, l_p_slot);
		if (!mas_prev_nentry(&r_mas, 0, &r_end_piv)) {
			// Single entry in the parent.
			if (l_end_slot < l_coalesce) { // Single entry is empty.
				free = true;
			} else if (l_end_slot == l_coalesce &&
				   mas->max == ULONG_MAX) {
				// Possible single entry of null for ULONG_MAX
				free = true;
			}
			if (free) {
				mte_set_rcu_slot(p_mas.node, l_p_slot,
						XA_DELETED_ENTRY);
				if (mt_is_alloc(p_mas.tree)) {
					mte_set_gap(p_mas.node, l_p_slot, 0);
					mas_update_gap(&r_mas, false);
				}
			}
			goto single_entry;
		}
		// Not really r_mas, previous node is left.
		mas_descend(&r_mas);
		r_type = mte_node_type(r_mas.node);
		r_end_slot = _mas_data_end(&r_mas, r_type, &r_end_piv,
					   &r_coalesce);
		if (r_end_slot - r_coalesce + l_end_slot - l_coalesce + 2
				< mt_slots[l_type]) {
			// Force a coalesce of these nodes
			try_anyways = true;
			mas_dup_state(mas, &r_mas);
			goto start; // restart with new left.
		}
		// right-most node is okay to be sparse.
		goto no_rebalancing;
	}
	mas_descend(&r_mas);

	// We have a left and a right, check if they can be coalesced.
	r_type = mte_node_type(r_mas.node); // not for racing.
	r_end_slot = _mas_data_end(&r_mas, r_type, &r_end_piv, &r_coalesce);
	r_p_slot = mte_parent_slot(r_mas.node);

	// end_slot values don't count slot 0, so add one.
	total_slots = l_end_slot + 1 - l_coalesce;
	total_slots += r_end_slot + 1 - r_coalesce;
	if (l_end_piv + 1 != r_mas.min)
		total_slots++; // will need a null entry between the two.

	mas_dup_state(&p_mas, mas);
	mas_ascend(&p_mas);

	if (total_slots <= mt_slots[l_type]) {
		// Totally consume the right node; coalesce.
		free = mas_coalesce(mas, l_end_slot, l_coalesce, l_type,
				&r_mas, r_end_slot, &p_mas, total_slots);

		if (mas_is_err(mas))
			return ret;

		ret = true;
		goto coalesced;
	}

	// Rebalance between mas and r_mas nodes.
	mas_node_cnt(mas, 1); // Try to allocate.
	if (mas_is_err(mas)) {
		// Allocation failed, we could try to append as much
		// as possible here?
		return ret;
	}

	free = true; // free parent.node after the operation.
	mas_dup_state(&src_mas, mas);
	mas->node = mt_mk_node(mas_next_alloc(mas), l_type);
	mas_mn(mas)->parent = mas_mn(&src_mas)->parent;
	mas_append(mas, &src_mas, 0, l_end_slot);


	// Put 1/2 of the contents into the left if not all of them can fit.
	copy_count = (total_slots / 2) - (l_end_slot + 1 - l_coalesce);
	mas_append(mas, &r_mas, 0, copy_count);
	// There is a chance that the left and right node are not next to each
	// other and separated by a skip entry.
	while(l_p_slot < --r_p_slot)
		mas_set_safe_pivot(&p_mas, r_p_slot, mas->max);

	/* All relocations *must* be committed before removing real data */
	wmb();
	do {
		// relocated.
		mte_set_rcu_slot(r_mas.node, copy_count, XA_RETRY_ENTRY);
		if (mt_is_alloc(r_mas.tree))
			mte_set_gap(r_mas.node, copy_count, 0);
		mte_set_pivot(r_mas.node, copy_count, mas->max);

	} while (copy_count-- > 0);

	if (mt_is_alloc(mas->tree)) {
		mas_update_gap(mas, true);
		mas_update_gap(&r_mas, true);
	}

	ret = true;

coalesced:
	if (!mte_is_leaf(mas->node))
		mas_adopt_children(mas, mas->node);

single_entry:
	if (free)
		mas_replace(mas);

	mas_dup_state(&p_mas, mas);
	l_p_slot = mte_parent_slot(mas->node); //may have changed.
	mas_set_slot(&p_mas, l_p_slot);
	mas_ascend(&p_mas);
	mas_set_slot(&p_mas, l_p_slot);
	mas_set_safe_pivot(&p_mas, l_p_slot, mas->max);

	if (mt_is_alloc(mas->tree))
		mas_update_gap(mas, true);


	if (free && _ma_is_root(mte_parent(mas->node))) {
		mas_coalesce_root(&p_mas);
		mas_dup_state(mas, &p_mas);
	}

no_rebalancing:
	return ret;
}

/** Private
 * mas_rebalance() -
 *
 * rebalance moves data from the node to the right to this node if the
 * low watermark of data is not met.  It also calls coalesce if the right data
 * can fully be moved to the left.
 *
 */
static inline void mas_rebalance(struct ma_state *mas)
{
	bool at_root = false;

	do {
		if (!mas_rebalance_node(mas))
			break; // We're all done here.

		if (mas_is_err(mas))
			return;

		// Check parent for rebalancing.
		if (mte_is_root(mas->node))
			break;

		mas_ascend(mas);
	} while (!at_root);

	mas_rebalance_gaps(mas);
	if (mas_is_err(mas))
		return;

	mas->node = MAS_START;
	_mas_walk(mas); // return to the updated location in the tree.
}

static inline bool _mas_rev_awalk(struct ma_state *mas, unsigned long size)
{
	enum maple_type type;
	unsigned long max, min;
	unsigned char i, start;
	bool found = false;
	unsigned long this_gap = 0;

	type = mte_node_type(mas->node);
	i = mas_get_slot(mas);

	min = mas->min;
	max = _mas_get_safe_pivot(mas, i, type);

	switch (type) {
	case maple_leaf_64:
		start = i;
		do {
			void *entry = NULL;

			if (!i)
				min = mas->min;
			else
				min = _mte_get_pivot(mas->node, i - 1,
						type) + 1;

			/* last is below this range */
			if (mas->last < min)
				goto next_slot;

			/* index is above this range.*/
			if (mas->index > max) {
				mas_set_err(mas, -EBUSY);
				return false;
			}

			/* check if this slot is full */
			entry = mas_get_rcu_slot(mas, i);
			if (entry && !xa_is_deleted(entry)) {
				this_gap = 0;
				goto next_slot;
			}

			if (!this_gap)
				start = i;

			this_gap += max - min + 1;
			if (this_gap >= size) {
				/* within range and large enough */
				if (mas->last - min + 1 < size) {
					/* It is possible that the gap is
					 * sufficient and within range, but
					 * the size does not fit within the
					 * maximum value and the min of gap
					 */
					goto next_slot;
				}
				mas->min = min;
				mas->max = min + this_gap - 1;
				i = start;
				found = true;
				break;
			}
next_slot:
			if (!i)
				goto ascend;

			max = min - 1;
		} while (i--);
		break;
	default:

		do {
			if (!i)
				min = mas->min;
			else
				min = _mte_get_pivot(mas->node, i - 1,
						type) + 1;


			/* last is too little for this range */
			if (mas->last < min)
				goto next;


			/* index is too large for this range */
			if (mas->index > max) {
				mas_set_err(mas, -EBUSY);
				return false;
			}

			this_gap = mte_get_gap(mas->node, i);
			/* Not big enough */
			if (size > this_gap)
				goto next;

			break;

next:
			/* Not found in this node.*/
			if (!i)
				goto ascend;

			max = min - 1;
			if (mas->index > max) {
				mas_set_err(mas, -EBUSY);
				return false;
			}
		} while (i--);
		break;

	case maple_dense:
		// FIXME: find a line of nulls...
		i = mas->index - mas->min;
		found = true;
		break;
	}


	if (!ma_is_leaf(type)) { //descend
		struct maple_enode *next;
		unsigned char coalesce;

		next = mas_get_rcu_slot(mas, i);
		mas->min = min;
		mas->max = max;
		if (!mt_is_empty(next)) {
			mas->node = next;
			i = _mas_data_end(mas, mte_node_type(next), &max,
					&coalesce);
		} else {
			goto ascend;
		}
	}

	mas_set_slot(mas, i);
	return found;
ascend:
	if (mte_is_root(mas->node))
		mas_set_err(mas, -EBUSY);

	mas_set_slot(mas, i);
	return found;
}

static inline bool _mas_awalk(struct ma_state *mas, unsigned long size)
{
	enum maple_type type;
	unsigned long pivot, max, min;
	unsigned char pivot_cnt, i;
	bool found = false;

	min = mas->min;
	max = mas->max;

	type = mte_node_type(mas->node);
	pivot_cnt = mt_pivots[type];

	switch (type) {
	case maple_leaf_64:
		for (i = 0; i <= pivot_cnt; i++) {
			unsigned long this_gap = 0;
			void *entry = NULL;

			pivot = _mas_get_safe_pivot(mas, i, type);

			/* End of data in this leaf */
			if (i && !pivot) {
				if (min > mas->max)
					break;
				pivot = mas->max;
			}

			/* Not within lower bounds */
			if (mas->index > pivot)
				goto next;

			entry = mas_get_rcu_slot(mas, i);
			if (unlikely(xa_is_skip(entry)))
				goto next;

			if (!mt_is_empty(entry))
				goto next;

			this_gap = pivot - mas->index;
			if (!this_gap) // No entry, pivot = index.
				this_gap = 1;

			/* out of upper bounds */
			if (mas->last + size < pivot - this_gap) {
				mas_set_err(mas, -EBUSY);
				return true;
			}
			/* Does not fit in this gap or node */
			if (mas->last < pivot - this_gap)
				goto ascend;

			if (this_gap >= size) {
				found = true;
				break;
			}
next:
			min = pivot + 1;
		}
		if (!found)
			goto ascend; // leaf exhausted.
		break;
	default:
		pivot = 0;
		i = mas_get_slot(mas);
		for (; i <= pivot_cnt; i++) {
			unsigned long this_gap;

			pivot = _mas_get_safe_pivot(mas, i, type);
			if (i && !pivot)
				goto ascend;

			this_gap = mte_get_gap(mas->node, i);
			if (size <= this_gap) {
				if (mas->index <= pivot) {
					max = pivot;
					goto descend;
				}
			}

			min = pivot + 1;
			if (mas->last < min) {
				mas_set_err(mas, -EBUSY);
				return true;
			}
		}
		goto ascend; // exhausted internal node.

		break;

	case maple_dense:
		// FIXME: find a line of nulls...
		i = mas->index - mas->min;
		found = true;
		break;
	}

descend:

	if (!ma_is_leaf(type)) { //descend
		struct maple_enode *next;

		next = mas_get_rcu_slot(mas, i);
		mas->min = min;
		mas->max = max;
		if (!mt_is_empty(next)) {
			mas->node = next;
			i = 0;
		} else {
			found = true; // this is a non-leaf hole.
		}
	}

	mas_set_slot(mas, i);
	return found;
ascend:
	if (mte_is_root(mas->node))
		found = true;

	mas_set_slot(mas, i);
	return found;
}

/*
 * Private
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
	enum maple_type type;
	struct maple_enode *next;
	unsigned long pivot = 0;
	unsigned long max, min;
	unsigned char i;
	bool ret = false;

	min = mas->min;
	max = mas->max;

	while (true) {
		type = mte_node_type(mas->node);

		if (ma_is_leaf(type)) // Leaf.
			ret = true;

skip_entry:
		switch (type) {
		default:
			for (i = mas_get_slot(mas); i < mt_slots[type]; i++) {
				pivot = _mas_get_safe_pivot(mas, i, type);

				if (i != 0 && pivot == 0) {
					i = MAPLE_NODE_SLOTS;
					goto done;
				}

				if (min > pivot) // coalescing value was in the last slot.
					min = pivot;

				if (mas->index <= pivot) {
					max = pivot;
					break;
				}
				min = pivot + 1;
			}

			if (ret)
				goto done;
			break;

		case maple_dense:
			// Linear node.
			i = mas->index - mas->min;
			mas->min = mas->max = mas->index;
			goto done;
		}

		next = mas_get_rcu_slot(mas, i);
		if (unlikely(xa_is_skip(next))) {
			if (unlikely(i == mt_slots[type] - 1)) {
				i = MAPLE_NODE_SLOTS;
				goto done;
			}
			mas_set_slot(mas, i + 1);
			goto skip_entry;
		}

		// Traverse.
		mas->max = max;
		mas->min = min;
		if (mt_is_empty(next)) // Not found.
			goto done;

		mas->node = next;
		mas_set_slot(mas, 0);
	}
done:
	mas_set_slot(mas, i);
	*range_max = max;
	*range_min = min;
	return ret;
}
/** Private
 *  _mas_range_walk(): A walk that supports returning the range in which an
 *  index is located.
 *
 */
static inline bool _mas_range_walk(struct ma_state *mas,
		unsigned long *range_min, unsigned long *range_max)
{

	void *entry = mas_start(mas);

	if (entry)
		return true;

	if (mas_is_none(mas)) {
		mas_set_slot(mas, MAPLE_NODE_SLOTS);
		return false;
	}

	if (mas_is_ptr(mas))
		return true;

	mas_set_slot(mas, 0);
	return __mas_walk(mas, range_min, range_max);
}

static inline bool _mas_walk(struct ma_state *mas)
{
	unsigned long range_max, range_min;

	return _mas_range_walk(mas, &range_min, &range_max);
}

/* Private
 * Skip any slots that have special values.
 * If the limit of the slot is hit, then return false.
 */
static inline int mas_safe_slot(struct ma_state *mas, int *slot,
		int delta)
{
	unsigned char max = mt_slot_count(mas->node);
	unsigned char limit = max;
	if (0 > delta)
		limit = 0;
	while (*slot != limit) {
		void *entry;
		if (!mas_get_safe_pivot(mas, (*slot) + delta))
			return false;

		entry = mas_get_rcu_slot(mas, (*slot) + delta);
		if (!mt_is_empty(entry) && !xa_is_retry(entry))
			return true;
		*slot += delta;
	}
	return false;
}
static inline int mas_dead_node(struct ma_state *mas, unsigned long index)
{
	if (!mas_searchable(mas))
		return 0;

	if (!mte_dead_node(mas->node))
		return 0;

	mas->index = index;
	mas->node = MAS_START;
	_mas_walk(mas);
	return 1;
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
/**
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

	while (mas_search_cont(mas, index, max, entry)) {
		entry = _mas_next(mas, max, &index);
		if (mt_is_empty(entry))
			entry = NULL;
	}

	if (entry)
		mas->index = index;

	return entry;
}
EXPORT_SYMBOL_GPL(mas_find);

/**
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
	unsigned char slot;
	MA_STATE(mas, mt, *index, *index);

	if (!start && !(*index))
		return NULL;

	rcu_read_lock();
	leaf = _mas_range_walk(&mas, &range_start, &range_end);
	slot = mas_get_slot(&mas);
	if (leaf == true && slot != MAPLE_NODE_SLOTS)
		entry = mas_get_rcu_slot(&mas, slot);

	mas.last = range_end;
	if (mt_is_empty(entry) || xa_is_zero(entry) || xa_is_retry(entry))
		entry = NULL;

	while (mas_search_cont(&mas, range_start, max, entry)) {
		entry = _mas_next(&mas, max, &range_start);
		if (mt_is_empty(entry) || xa_is_zero(entry) ||
		    xa_is_retry(entry))
			entry = NULL;
	}

	rcu_read_unlock();
	if (entry)
		*index = mas.last + 1;

	return entry;
}
void *mt_find(struct maple_tree *mt, unsigned long *index, unsigned long max) {
	return _mt_find(mt, index, max, true);
}
EXPORT_SYMBOL(mt_find);

static inline int mas_build_replacement(struct ma_state *mas, void *new_entry,
		long node_cnt)

{
	struct maple_enode *last = NULL;
	unsigned long new_index, new_last;
	unsigned long r_index, r_last;
	struct maple_tree new_tree = MTREE_INIT(name, mas->tree->ma_flags);
	void *entry;

	MA_STATE(new_mas, &new_tree, 0, 0);


	if (!node_cnt)
		return 0;
	node_cnt += 3; // Room for an extra split.

	mas_node_cnt(mas, node_cnt);
	if (mas_is_err(mas))
		return 0;

	new_index = mas->index;
	new_last = mas->last;

	/* Move allocations from mas to new_mas.
	 * NOTE: This is necessary as mas will pass back errors and will retry
	 * the allocation, so it has to be done in mas and has to be moved for
	 * below.
	 */
	new_mas.alloc = mas->alloc;
	mas->alloc = NULL;

	// Copy left side
	mas_reset(mas);
	mas->index = 0;
	mas->last = 0;
	mas_for_each(mas, entry, new_index - 1) {
		new_mas.index = mas->index;
		new_mas.last = mas_get_safe_pivot(mas, mas_get_slot(mas));
		MT_BUG_ON(mas->tree, entry ==  XA_DELETED_ENTRY);
		ma_inactive_insert(&new_mas, entry);
		if (mas_is_err(&new_mas))
			goto error;
	}

	// Insert the new value.
	new_mas.index = new_index;
	new_mas.last = new_last;
	ma_inactive_insert(&new_mas, new_entry);
	if (mas_is_err(&new_mas))
		goto error;


	/*
	 * We need to run through a few things:
	 * - new_mas.last goes beyond anything right now (no entries)
	 * - new_mas.last cuts a range
	 * - new_mas.last ends in a null
	 * - new_mas.last has a sequentially next value
	 */

	mas_reset(mas);
	mas->index = new_last + 1;
	mas->last = new_last + 1;
	_mas_range_walk(mas, &r_index, &r_last);

	if (mas_get_slot(mas) == MAPLE_NODE_SLOTS)
		goto skip_right;


	if (mte_is_leaf(mas->node)) {
		entry = mas_get_rcu_slot(mas, mas_get_slot(mas));
		if (!mt_is_empty(entry))
		{
			new_mas.index = r_index;
			new_mas.last = r_last;
			ma_inactive_insert(&new_mas, entry);
			if (mas_is_err(&new_mas))
				goto error;
		}
	}

	mas_for_each(mas, entry, ULONG_MAX) {
		if (mas->index < new_index)
			continue;

		new_mas.index = mas->index;
		new_mas.last = mas_get_safe_pivot(mas, mas_get_slot(mas));
		ma_inactive_insert(&new_mas, entry);
		if (mas_is_err(&new_mas))
			goto error;
	}

skip_right:

	last = mas->tree->ma_root;
	mas->node = new_tree.ma_root;
	_mas_replace(mas, false, false);
	if (mt_is_alloc(mas->tree))
		mas_update_gap(mas, false);

	mas->node = MAS_START;
	mas->alloc = new_mas.alloc;
	mte_destroy_walk(last, mas->tree);

	return node_cnt;

error:
	if (new_mas.tree)
		mte_destroy_walk(new_mas.tree->ma_root, new_mas.tree);
	return 0;
}

/* Private
 * mas_replace_tree() - Build a new tree and replace the entire structure.
 *
 */
static inline int mas_replace_tree(struct ma_state *mas, void *new_entry)
{
	unsigned int slot_cnt = 0;
	long node_cnt = 0, leaves= 1;
	struct maple_enode *last = NULL;
	enum maple_type p_type = mas_parent_enum(mas, mas->node);

	// Create a new tree.
	MA_STATE(r_mas, mas->tree, mas->last + 1, mas->last + 1);

	// Count the slots that will be used in the node we landed.
	slot_cnt = 3 + mas_get_slot(mas); // 3 is the max a new entry can create.

	// Count the nodes that are currently used to the left.
	mas_set_slot(mas, mte_parent_slot(mas->node));
	while (!mas_is_none(mas)) {
		last = mas->node;
		mas_prev_node(mas, 0);
		leaves++;
	}
	// Set mas->node to a valid node.
	mas->node = last;

	// Walk down to the right side of the tree.
	_mas_walk(&r_mas);
	// Add the slots to the right of where the search landed.
	if (mas_get_slot(&r_mas) == MAPLE_NODE_SLOTS) {
		r_mas.node = MAS_NONE;
		slot_cnt++; //entry for oo
		goto skip_r_count;
	}
	slot_cnt -= mas_get_slot(&r_mas);
	slot_cnt += mas_data_end(&r_mas);

	// Count the nodes to the right.
	mas_set_slot(&r_mas, mte_parent_slot(r_mas.node));
	while (!mas_is_none(&r_mas)) {
		last = r_mas.node;
		mas_next_node(&r_mas, ULONG_MAX);
		leaves++;
	}

skip_r_count:
	// Calculate all the nodes needed for a new tree.
	if (slot_cnt > mt_slot_count(mas->node))
		leaves++;

	node_cnt = 1; // Root node. and room to split.
	while (leaves) { // add the number of nodes at each level.
		node_cnt += leaves;
		leaves /= mt_slots[p_type];
	}
	return mas_build_replacement(mas, new_entry, node_cnt);
}

static inline bool mas_rewind_node(struct ma_state *mas);
static inline void mas_rev_awalk(struct ma_state *mas, unsigned long size)
{
	struct maple_enode *last = NULL;
	unsigned char slot;

	mas_start(mas);
	if (mas_is_none(mas)) {
		mas_set_slot(mas, MAPLE_NODE_SLOTS);
		return;
	}

	if (mas_is_ptr(mas))
		return;
	if (mas_is_err(mas))
		return;

	slot = mas_data_end(mas);
	mas_set_slot(mas, slot);


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
static inline bool mas_skip_node(struct ma_state *mas);
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

static inline int ma_root_ptr(struct ma_state *mas, void *entry,
		bool overwrite)
{
	if (xa_is_node(mas->tree->ma_root))
		return 0;

	if (!overwrite)
		if (mas->tree->ma_root && mas->last == 0)
			goto exists;

	if (mas->last != 0)
		mas_root_expand(mas, entry);
	else if (((unsigned long) (entry) & 3) == 2)
		mas_root_expand(mas, entry);
	else
		rcu_assign_pointer(mas->tree->ma_root, entry);
	return 1;

exists:
	mas_set_err(mas, -EEXIST);
	return 0;
}

static inline int mas_add(struct ma_state *mas, void *entry, bool overwrite,
		bool active)
{
	unsigned char slot = MAPLE_NODE_SLOTS;
	bool leaf;
	int ret = 0;

	ret = ma_root_ptr(mas, entry, overwrite);
	if (mas_is_err(mas))
		return 0;

	if (ret)
		return ret;

	leaf = _mas_walk(mas);
	slot = mas_get_slot(mas);
	if (leaf == true) {
		if (slot == MAPLE_NODE_SLOTS) {
			if (mas->index == 0 && !overwrite)
				goto exists;
		} else if (!overwrite) {
			void *entry = mas_get_rcu_slot(mas, slot);

			if (!mt_is_empty(entry))
				goto exists;
		}
	}

	/* Do the add */
	ret = _mas_add(mas, entry, overwrite, active);
	if (mas_is_err(mas) && xa_err(mas->node) == -ERANGE)
		mas_set_err(mas, -EEXIST);

	return ret;

exists:
	mas_set_err(mas, -EEXIST);
	return 0;
}

static int mas_fill_gap(struct ma_state *mas, void *entry, unsigned char slot,
		unsigned long size, unsigned long *index)
{
	unsigned char pslot = mte_parent_slot(mas->node);
	struct maple_enode *mn = mas->node;
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
	mas->max = mas_get_safe_pivot(mas, pslot);
	if (pslot)
		mas->min = mas_get_safe_pivot(mas, pslot - 1) + 1;

	mas->node = mn;
	_mas_insert(mas, entry, slot, true);
	return 0;
}

void mas_set_fwd_index(struct ma_state *mas, unsigned long size)
{
	unsigned long min = mas->min;
	unsigned char slot = mas_get_slot(mas);
	// At this point, mas->node points to the right node and we have a
	// slot that has a sufficient gap.
	if (slot)
		min = mte_get_pivot(mas->node, slot - 1) + 1;

	mas->min = min;
	mas->max = mas_get_safe_pivot(mas, slot);

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
static void _mas_empty_or_single_unmapped_area(struct ma_state *mas,
		unsigned long min, unsigned long max, unsigned long size,
		bool fwd)
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
static inline int _mas_get_unmapped_area(struct ma_state *mas,
		unsigned long min, unsigned long max, unsigned long size, bool
		forward)
{
	mas_start(mas);
	max--; // Convert to inclusive.

	// Empty set.
	if (mas_is_none(mas) || mas_is_ptr(mas)) {
		_mas_empty_or_single_unmapped_area(mas, min, max, size, forward);
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

	if (mas_get_slot(mas) == MAPLE_NODE_SLOTS)
		return -EBUSY;

	if (forward)
		mas_set_fwd_index(mas, size);
	else
		mas_set_rev_index(mas, size);

	return 0;
}

int mas_get_unmapped_area(struct ma_state *mas, unsigned long min,
		unsigned long max, unsigned long size)
{
	return _mas_get_unmapped_area(mas, min, max, size, true);
}
int mas_get_unmapped_area_rev(struct ma_state *mas, unsigned long min,
		unsigned long max, unsigned long size)
{
	return _mas_get_unmapped_area(mas, min, max, size, false);
}
/** Private
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
	unsigned char slot = MAPLE_NODE_SLOTS;
	unsigned long min;
	mas_start(mas);

	if (mas_is_none(mas) || mas_is_ptr(mas)) {
		mas_root_expand(mas, entry);
		if (mas_is_err(mas))
			return xa_err(mas->node);

		if (!mas->index)
			return mte_get_pivot(mas->node, 0);
		return mte_get_pivot(mas->node, 1);
	}

	mas_awalk(mas, size); // Must be walking a tree.

	if (mas_is_err(mas))
		return xa_err(mas->node);

	slot = mas_get_slot(mas);
	if (slot == MAPLE_NODE_SLOTS)
		goto no_gap;

	// At this point, mas->node points to the right node and we have a
	// slot that has a sufficient gap.
	min = mas->min;
	if (slot)
		min = mte_get_pivot(mas->node, slot - 1) + 1;

	if (mas->index < min)
		mas->index = min;

	return mas_fill_gap(mas, entry, slot, size, index);

no_gap:
	return -EBUSY;
}
/** Private
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
	unsigned char slot = MAPLE_NODE_SLOTS;
	int ret = 0;

	ret = _mas_get_unmapped_area(mas, min, max, size, false);
	if (ret)
		return ret;

	if (mas_is_err(mas))
		return xa_err(mas->node);

	slot = mas_get_slot(mas);
	if (slot == MAPLE_NODE_SLOTS)
		goto no_gap;

	return mas_fill_gap(mas, entry, slot, size, index);

no_gap:
	return -EBUSY;
}

/**
 *
 * Must hold rcu_read_lock or the write lock.
 *
 * Find where ms->index is located and return the entry.
 * mas->node will point to the node containing the entry.
 *
 * range_min and range_max will be set accordingly.
 *
 */
void *mas_range_load(struct ma_state *mas, unsigned long *range_min,
		unsigned long *range_max, bool skip_retry)
{
	void *entry = NULL;

retry:
	if (_mas_range_walk(mas, range_min, range_max)) {
		unsigned char slot = MAPLE_NODE_SLOTS;

		if (mas_is_ptr(mas) && mas->last == 0)
			return mte_safe_root(mas->tree->ma_root);

		slot = mas_get_slot(mas);
		if (slot >= MAPLE_NODE_SLOTS)
			return NULL;

		entry = mas_get_rcu_slot(mas, slot);
		if (mte_dead_node(mas->node))
			goto retry;
	}

	if (mas_is_none(mas))
		return NULL;

	if (!entry || xa_is_deleted(entry))
		return NULL;

	if (skip_retry && xa_is_retry(entry))
		goto retry;

	return entry;
}

void *mas_load(struct ma_state *mas)
{
	unsigned long range_max, range_min;

	return mas_range_load(mas, &range_min, &range_max, true);
}
static inline bool mas_rewind_node(struct ma_state *mas)
{
	unsigned char slot;

	do {
		if (mte_is_root(mas->node)) {
			slot = mas_get_slot(mas);
			if (!slot) {
				mas_set_err(mas, -EBUSY);
				return false;
			}
		} else {
			slot = mte_parent_slot(mas->node);
			mas_ascend(mas);
		}
	} while (!slot);

	mas_set_slot(mas, --slot);
	return true;
}
/* Skip this slot in the parent. */
static inline bool mas_skip_node(struct ma_state *mas)
{
	unsigned char slot;

	do {
		if (mte_is_root(mas->node)) {
			slot = mas_get_slot(mas);
			if (slot > mt_slot_count(mas->node) - 1) {
				mas_set_err(mas, -EBUSY);
				return false;
			}
		} else {
			slot = mte_parent_slot(mas->node);
			mas_ascend(mas);
		}
	} while (slot > mt_slot_count(mas->node) - 1);

	mas_set_slot(mas, ++slot);
	mas_update_limits(mas, slot, mte_node_type(mas->node));
	return true;
}
/* Private
 * mas_erase() - Find the range in which index resides and erase the entire
 * range.
 *
 * Any previous pivots with no value will be set to the same pivot value.
 * Return: the entry that was erased
 */
static inline void *mas_erase(struct ma_state *mas)
{
	int slot;
	void *entry = NULL;

	_mas_walk(mas);
	if (mas_is_ptr(mas)) {
		entry = mas->tree->ma_root;
		mas->tree->ma_root = NULL;
		return entry;
	}

	slot = mas_get_slot(mas);
	if (slot == MAPLE_NODE_SLOTS)
		return NULL;

	entry = mas_get_rcu_slot(mas, slot);
	mte_update_rcu_slot(mas->node, slot, XA_DELETED_ENTRY);
	// dense nodes only need to set a single value.

	mas_rebalance(mas);
	if (mas_is_err(mas)) {
		mas_empty_alloc(mas);
		return entry;
	}

	if (mt_is_alloc(mas->tree))
		mas_may_move_gap(mas);
	return entry;
}


/* Interface */
void __init maple_tree_init(void)
{
	maple_node_cache = kmem_cache_create("maple_node",
			sizeof(struct maple_node), sizeof(struct maple_node),
			SLAB_PANIC | SLAB_RECLAIM_ACCOUNT, NULL);
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

	if (WARN_ON_ONCE(mt_is_advanced(entry)))
		return -EINVAL;

	if (index > last)
		return -EINVAL;

	mas_lock(&mas);
retry:
	mas_add(&mas, entry, true, true);
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

	if (WARN_ON_ONCE(mt_is_advanced(entry)))
		return -EINVAL;

	if (first > last)
		return -EINVAL;

	mtree_lock(ms.tree);
retry:
	mas_add(&ms, entry, false, true);
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
	mas_set_slot(&mas, 0);
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

int mtree_next(struct maple_tree *mt, unsigned long index, unsigned long *next)
{
	int ret = -ENOENT;

	MA_STATE(mas, mt, index, index);
	rcu_read_lock();
	//mas_walk_next(&mas);
	rcu_read_unlock();

	if (mas.node)
		return 0;
	return ret;
}

void *mtree_erase(struct maple_tree *mt, unsigned long index)
{
	void *entry = NULL;

	MA_STATE(mas, mt, index, index);

	mtree_lock(mt);
	entry = mas_erase(&mas);
	mtree_unlock(mt);

	return entry;
}
EXPORT_SYMBOL(mtree_erase);

void mtree_destroy(struct maple_tree *mt)
{
	struct maple_enode *destroyed;

	mtree_lock(mt);
	destroyed = mt->ma_root;
	if (xa_is_node(destroyed))
		mte_destroy_walk(destroyed, mt);

	mt->ma_flags = 0;
	rcu_assign_pointer(mt->ma_root, NULL);
	mtree_unlock(mt);
}
EXPORT_SYMBOL(mtree_destroy);

#ifdef CONFIG_DEBUG_MAPLE_TREE
unsigned int maple_tree_tests_run;
unsigned int maple_tree_tests_passed;
EXPORT_SYMBOL_GPL(maple_tree_tests_run);
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
#else
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
	else if (xa_is_deleted(entry))
		pr_cont("deleted (%ld)\n", xa_to_internal(entry));
	else if (xa_is_skip(entry))
		pr_cont("skip (%ld)\n", xa_to_internal(entry));
	else if (xa_is_retry(entry))
		pr_cont("retry (%ld)\n", xa_to_internal(entry));
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
		else if (node->slot[i] == NULL && max != mt_max[mte_node_type(entry)])
			break;
		if (last == 0 && i > 0)
			break;
		if (leaf)
			mt_dump_entry(node->slot[i], first, last, depth + 1);
		else if (xa_is_deleted(node->slot[i]))
			mt_dump_entry(node->slot[i], first, last, depth + 1);
		else if (xa_is_skip(node->slot[i]))
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
	pr_cont("| ");
	for (i = 0; i < MAPLE_ARANGE64_SLOTS - 1; i++)
		pr_cont(MA_PTR" %lu ", node->slot[i], node->pivot[i]);
	pr_cont(MA_PTR"\n", node->slot[i]);
	for (i = 0; i < MAPLE_ARANGE64_SLOTS; i++) {
		unsigned long last = max;

		if (i < (MAPLE_ARANGE64_SLOTS - 1))
			last = node->pivot[i];
		else if (node->slot[i] == NULL)
			break;
		if (last == 0 && i > 0)
			break;
		if (leaf)
			mt_dump_entry(node->slot[i], first, last, depth + 1);
		else if (xa_is_deleted(node->slot[i]))
			mt_dump_entry(node->slot[i], first, last, depth + 1);
		else if (xa_is_skip(node->slot[i]))
			mt_dump_entry(node->slot[i], first, last, depth + 1);
		else if (xa_is_retry(node->slot[i]))
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

	pr_info("maple_tree("MA_PTR") flags %X, root "MA_PTR"\n",
		 mt, mt->ma_flags, entry);
	if (!xa_is_node(entry))
		mt_dump_entry(entry, 0, 0, 0);
	else if (entry)
		mt_dump_node(entry, 0, mt_max[mte_node_type(entry)], 0);
}

/**
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
	int i;

	if (mte_is_dense(mte)) {
		for (i = 0; i < mt_slot_count(mte); i++) {
			if (!mt_is_empty(mas_get_rcu_slot(mas, i))) {
				if (gap > max_gap)
					max_gap = gap;
				gap = 0;
				continue;
			}
			gap++;
		}
		goto counted;
	}

	for (i = 0; i < mt_slot_count(mte); i++) {
		p_end = mas_get_safe_pivot(mas, i);
		if (!p_end && i)
			p_end = mas->max;

		if (mte_is_leaf(mte)) {
			if (!mt_is_empty(mas_get_rcu_slot(mas, i))) {
				gap = 0;
				goto not_empty;
			}

			gap += p_end - p_start + 1;
		} else {
			void *entry = mas_get_rcu_slot(mas, i);
			gap = mte_get_gap(mte, i);
			if (xa_is_skip(entry)) {
				//pr_err("%s: skip entry missed by spanning add?\n");
			} else if (mt_is_empty(entry) || xa_is_retry(entry)) {
				if (gap != p_end - p_start + 1) {
					if (xa_is_retry(entry))
						pr_err("retry\n");

					pr_err(MA_PTR"[%u] -> "MA_PTR" %lu != %lu - %lu + 1\n",
						mas_mn(mas), i,
						mas_get_rcu_slot(mas, i), gap,
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
	if (ma_get_gap(p_mn, p_slot, mas_parent_enum(mas, mte)) != max_gap) {
		pr_err("gap "MA_PTR"[%u] != %lu\n", p_mn, p_slot, max_gap);
		mt_dump(mas->tree);
	}

	MT_BUG_ON(mas->tree,
		ma_get_gap(p_mn, p_slot, mas_parent_enum(mas, mte)) !=
		max_gap);
}

void mas_validate_parent_slot(struct ma_state *mas)
{
	struct maple_node *parent;
	enum maple_type p_type = mas_parent_enum(mas, mas->node);
	unsigned char p_slot = mte_parent_slot(mas->node);
	int i;

	if (mte_is_root(mas->node))
		return;

	parent = mte_parent(mas->node);
	MT_BUG_ON(mas->tree, mas_mn(mas) == parent);

	// Check prev/next parent slot for duplicate node entry

	for (i = 0; i < mt_slots[p_type]; i++) {
		if (i == p_slot) {
			MT_BUG_ON(mas->tree,
				ma_get_rcu_slot(parent, i, p_type, mas->tree) !=
				mas->node);
		} else if (ma_get_rcu_slot(parent, i, p_type, mas->tree) ==
				 mas->node) {
			pr_err("parent contains invalid child at "MA_PTR"[%u] "
				MA_PTR"\n", parent, i, mas_mn(mas));
			MT_BUG_ON(mas->tree,
			       ma_get_rcu_slot(parent, i, p_type, mas->tree) ==
			       mas->node);
		}
	}
}
/**
 * Validate all pivots are within mas->min and mas->max.
 */
void mas_validate_limits(struct ma_state *mas)
{
	int i;
	unsigned long prev_piv = 0;

	if (mte_is_root(mas->node))
		return; // all limits are fine here.

	for (i = 0; i < mt_slot_count(mas->node); i++) {
		unsigned long piv = mas_get_safe_pivot(mas, i);
		void *entry;

		if (!piv)
			break;

		entry = mas_get_rcu_slot(mas, i);
		if (prev_piv > piv) {
			if (!mt_will_coalesce(entry)) {
				pr_err(MA_PTR"[%u] piv %lu < prev_piv %lu\n",
					mas_mn(mas), i, piv, prev_piv);
				mt_dump(mas->tree);
				MT_BUG_ON(mas->tree, piv < prev_piv);
			}
		}

		if (piv < mas->min) {

			if (!mt_will_coalesce(entry)) {
				if (piv < mas->min)
					mt_dump(mas->tree);
				pr_err(MA_PTR"[%u] %lu < %lu\n", mas_mn(mas), i,
						piv, mas->min);
				mt_dump(mas->tree);
				MT_BUG_ON(mas->tree, piv < mas->min);
			}
		}
		if (!xa_is_retry(entry)) {
			if ((piv > mas->max)) {
				pr_err(MA_PTR"[%u] %lu > %lu\n", mas_mn(mas), i,
					piv, mas->max);
				mt_dump(mas->tree);
				MT_BUG_ON(mas->tree, piv > mas->max);
			}
			prev_piv = piv;
		}
	}
}

/* Depth first search, post-order */
static inline void mas_dfs_postorder(struct ma_state *mas, unsigned long max)
{

	struct maple_enode *p = MAS_NONE, *mn = mas->node;
	unsigned long p_min, p_max;

	mas_next_node(mas, max);
	if (mas->node != MAS_NONE)
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
/**
 * validate a maple tree by checking:
 * 1. The limits (pivots are within mas->min to mas->max)
 * 2. The gap is correctly set in the parents
 */
void mt_validate(struct maple_tree *mt)
{
	MA_STATE(mas, mt, 0, 0);
	rcu_read_lock();
	mas_start(&mas);
	mas_first_entry(&mas, ULONG_MAX);
	while (mas.node != MAS_NONE) {
		mas_validate_parent_slot(&mas);
		mas_validate_limits(&mas);
		if (mt_is_alloc(mt))
			mas_validate_gaps(&mas);
		mas_dfs_postorder(&mas, ULONG_MAX);
	}
	rcu_read_unlock();

}
#endif /* MT_DEBUG */
