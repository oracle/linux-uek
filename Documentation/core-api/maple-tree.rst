.. SPDX-License-Identifier: GPL-2.0+


==========
Maple Tree
==========

:Author: Liam R. Howlett
:Date: May 20, 2021

Overview
========

The Maple Tree is an RCU-safe range based B-tree designed to use modern
processor cache efficiently.  There are a number of places in the kernel
that a non-overlapping range-based tree would be beneficial, especially
one with a simple interface.

The tree has a branching factor of 10 for non-leaf nodes and 16 for leaf
nodes.  With the increased branching factor, it is significantly shorter than
the rbtree so it has fewer cache misses.  The removal of the linked list
between subsequent entries also reduces the cache misses and the need to pull
in the previous and next VMA during many tree alterations.

Multiple node types are supported with the plan of expanding the types and
supporting dynamic decision on which node type to use.

The maple tree operations share the basic tree ideas with other b-trees; the
leaves the same height, balanced once writes are done, each node has a limited
number of entries, every leaf node has a minimum amount.The Maple Tree is
probably the most similiar to the b+ tree;  All data is in the leaf nodes, bulk
loading is used for quicker copying of the data, searches start at offset 0 and
go until the inext is less than or equal to a pivot.

However, ranges complicate certain write activities.  When modifying any of the
b-tree variants, it is known that one entry will either be added or deleted.
When modifying the Maple Tree, one store operation may overwrite the entire
data set, or one half of the tree, or the middle half of the tree.

Normal API
==========

Start by initialising a maple tree, either with DEFINE_MTREE() for statically
allocated maple trees or mtree_init() for dynamically allocated ones.  A
freshly-initialised maple tree contains a ``NULL`` pointer for the range 0-oo.
There are currently two types of maple trees supported: the allocation tree and
the regular tree.  The regular tree has a higher branching factor for internal
nodes.  The allocation tree has a lower branching factor but tracks the largest
gap within each subtree.  An allocation tree can be used by passing in the
``MAPLE_ALLOC_RANGE`` flag when initialising the tree.

You can then set entries using mtree_store() or mtree_store_range().
mtree_store will overwrite any entry with the new entry and return the previous
entry stored at that index.  mtree_store_range works in the same way but only
returns the first entry that is overwritten.  You can use mtree_erase() to
erase an entire range by only knowing one value within that range.

If you want to only store a new entry to a range (or index) if that range is
currently ``NULL``, you can use mtree_insert_range() or mtree_insert() which
return -EEXISTS if the range is not empty.

You can search for an entry from an index upwards by using mt_find().

You can walk each entry within a range by calling mt_for_each().  You must
provide a temporary variable to store a cursor, the start, and the end of the
range.  If you want to walk each element of the tree then 0 and ULONG_MAX may
be used as the range.  If you do not need to drop the RCU lock, it is worth
looking at the mas_for_each() API in the Advanced API section.

Sometimes it is necessary to ensure the next call to store to a maple tree does
not allocate memory, please see the advanced API for this use case.

Finally, you can remove all entries from a maple tree by calling
mtree_destroy().  If the maple tree entries are pointers, you my wish to free
the entries first.

Allocating Nodes
----------------

Normal API allocations are handled internal to the tree.

Locking
-------

When using the Normal API, you do not have to worry about locking.
The Maple Tree uses RCU and interanl spinlock to synchronise access:

No lock needed:
 * mas_destroy()
 * mas_entry_count()
 * mas_is_none()
 * mas_reset()
 * mas_set_range()
 * mas_set()

Takes RCU read lock:
 * mtree_load()
 * mt_find()
 * mt_for_each()

Takes ma_lock internally:
 * mtree_store()
 * mtree_store_range()
 * mtree_insert()
 * mtree_insert_range()
 * mtree_erase()
 * mtree_destroy()
 * mt_set_in_rcu()
 * mt_clear_in_rcu()


Assume RCU read lock held on entry:
 * mas_walk()
 * mas_next()
 * mas_prev()
 * mas_find()
 * mas_pause()

Assume ma_lock held on entry:
 * mas_store()
 * mas_store_gfp()
 * mas_nomem()

Assumes ma_lock or RCU read lock is held on entry:
 * mas_for_each()


If you want to take advantage of the lock to protect the data structures that
you are storing in the Maple Tree, you can call mas_lock() before calling
mas_walk(), then take a reference count on the object you have found before
calling the mas_unlock().  This will prevent stores from removing the object
from the tree between looking up the object and incrementing the refcount.  You
can also use RCU to avoid dereferencing freed memory, but an explaination of
that is beyond the scope of this document.

If it is necessary to drop the locks during an iteration, then mas_pause()
provides this functionality.  It is worth noting that dropping the locks allows
for other tasks to alter the tree so your code may get a split view of the past
and the current state of a tree in this scenario.  Note that the next call
using the maple state will re-walk the tree from the root.

Advanced API
============

The advanced API offers more flexibility and better performance at the cost of
an interface which can be harder to use and has fewer safeguards.  No locking
is done for you by the advanced API, and you are required to use the mas_lock
while modifying the tree.  You can choose whether to use the mas_lokc or the
RCU lock while doing read-only operations on the tree.  You can mix advanced
and normal operations on the same array and the normal API is implemented in
terms of the advanced API.

The advanced API is based around the ma_state, this is where the 'mas' prefix
originates.

Initialising the maple tree is the same as in the normal API.  Please see above.

mas_walk() will walk the tree to the location of index and set the index and
last according to the range for the entry.

You can set entries using mas_store().  mas_store will overwrite any entry with
the new entry and return the first existing entry that is overwritten.  The
range is passed in as members of the maple state: index and last.

You can use mas_erase() to erase an entire range by setting index and last of
the maple state to the desired range to erase.  This will erase the first range
that is found in that range, set the maple state index and last as the range
that was erased and return the entry that existed at that location.

You can walk each entry within a range by using mas_for_each().  If you want to
walk each element of the tree then 0 and ULONG_MAX may be used as the range.
If the lock needs to be periodically dropped, see the locking section
mas_pause().

Using a maple state allows mas_next() and mas_prev() to function as if the tree
was a linked list.  With such a high branching factor the amortized performance
penalty is outweighed by cache optimization.

There are a few extra interfaces provided when using an allocation tree.  If
you wish to search for a gap within a range, then mas_empty_area() or
mas_empty_area_rev() can be used.  mas_empty_area searches for a gap starting
at the lowest index given up to the maximum of the range.  mas_empty_area_rev
searches for a gap starting at the highest index given and continues downward
to the lower bounds of the range.


Allocating Nodes
----------------

Allocations are attempted to be handled internally to the tree, however if
allocations need to occur before a write occurs then calling mas_entry_count()
will allocate the worst-case number of needed nodes to insert the provided
number of ranges.  This also causes the tree to enter mass insertion mode.
Once insertions are complete calling mas_destroy() on the maple state will free
the unused allocations.

Maple Tree Implementation Details
=================================

The Maple Tree squeezes various bits in at various points which aren't
necessarily obvious.  Usually, this is done by observing that pointers are
N-byte aligned and thus the bottom log_2(N) bits are available for use.
We don't use the high bits of pointers to store additional information
because we don't know what bits are unused on any given architecture.

Nodes
-----

Nodes are 256 bytes in size and are also aligned to 256 bytes, giving us 8 low
bits for our own purposes.  Nodes are currently of 4 types:

1. Single pointer (Range is 0-0)
2. Non-leaf Allocation Range nodes
3. Non-leaf Range nodes
4. Leaf Range nodes

All nodes consist of a number of node slots, pivots, and a parent pointer.

Tree Root
---------

If the tree contains a single entry at index 0, it is usually stored in
tree->ma_root.  To optimise for the page cache, an entry which ends in
'00', '01' or '11' is stored in the root, but an entry which ends in '10'
will be stored in a node.  Bits 3-6 are used to store enum maple_type.

The flags are used both to store some immutable information about this tree
(set at tree creation time) and dynamic information set under the spinlock.

Another use of flags are to indicate global states of the tree.  This is the
case with the MAPLE_USE_RCU flag, which indicates the tree is currently in RCU
mode.  This mode was added to allow the tree to reuse nodes instead of
re-allocating and RCU freeing nodes when there is a single user.

Node Slots & Node Pivots
------------------------

Leaf nodes do not store pointers to nodes, they store user data.  Users may
store almost any bit pattern.  As noted above, the optimisation of storing an
entry at 0 in the root pointer cannot be done for data which have the bottom
two bits set to '10'.  We also reserve values with the bottom two bits set to
'10' which are below 4096 (ie 2, 6, 10 .. 4094) for internal use.  Some APIs
return errnos as a negative errno shifted right by two bits and the bottom two
bits set to '10', and while choosing to store these values in the array is not
an error, it may lead to confusion if you're testing for an error with
mas_is_err().

Non-leaf nodes store the type of the node pointed to (enum maple_type
in bits 3-6), bit 2 is reserved.  That leaves bits 0-1 unused for now.

In regular B-Tree terms, pivots are called keys.  The term pivot is used to
indicate that the tree is specifying ranges,  Pivots may appear in the subtree
with an entry attached to the value where as keys are unique to a specific
position of a B-tree.  Pivot values are inclusive of the slot with the same
index.


The following illustrates a partial layout of a range64 nodes slots and pivots.

          _________________________________
 Slots -> | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
          ┬   ┬   ┬   ┬   ┬   ┬   ┬   ┬   ┬
          │   │   │   │   │   │   │   │   └─ Implied maximum
          │   │   │   │   │   │   │   └─ Pivot 6
          │   │   │   │   │   │   └─ Pivot 5
          │   │   │   │   │   └─ Pivot 4
          │   │   │   │   └─ Pivot 3
          │   │   │   └─ Pivot 2
          │   │   └─ Pivot 1
          │   └─ Pivot 0
          └─  Implied minimum

Slot contents:
 Internal (non-leaf) nodes contain pointers to other nodes.
 Leaf nodes contain entries.


Node Parent
-----------

The node->parent of the root node has bit 0 set and the rest of the
pointer is a pointer to the tree itself.  No more bits are available in
this pointer (on m68k, the data structure may only be 2-byte aligned).

Internal non-root nodes can only have maple_range_* nodes as parents.  The
parent pointer is 256B aligned like all other tree nodes.  When storing a 32 or
64 bit values, the offset can fit into 4 bits.  The 16 bit values need an extra
bit to store the offset.  This extra bit comes from a reuse of the last bit in
the node type.  This is possible by using bit 1 to indicate if bit 2 is part of
the type or the slot.

Once the type is decided, the decision of an allocation range type or a range
type is done by examining the immutable tree flag for the MAPLE_ALLOC_RANGE
flag.

 Node types:
  0x??1 = Root
  0x?00 = 16 bit nodes
  0x010 = 32 bit nodes
  0x110 = 64 bit nodes

 Slot size and location in the parent pointer:
  type  : slot location
  0x??1 : Root
  0x?00 : 16 bit values, type in 0-1, slot in 2-6
  0x010 : 32 bit values, type in 0-2, slot in 3-6
  0x110 : 64 bit values, type in 0-2, slot in 3-6

Node Metadata
-------------

The node->meta is currently only supported in allocation range 64 (arange_64)
node type.  As a result of tracking gaps, there is a small area that is not
used for data storage in this node type.  This area is reused to store metadata
related to the node itself including the data end and the largest gap location.
This metadata is used to optimize the gap updating code and in reverse
searching for gaps or any other code that needs to find the end of the data.

Auxiliary Data
--------------

At tree creation time, the user can specify that they're willing to
trade off storing fewer entries in a tree in return for storing more
information in each node.

The maple tree supports recording the largest range of NULL entries available
in this node, also called gaps.  This optimises the tree for allocating a
range.


Maple State
-----------

The maple state is defined in the struct ma_state and is used to keep track of
information during operations, and even between operations when using the
advanced API.

If state->node has bit 0 set then it references a tree location which
is not a node (eg the root).  If bit 1 is set, the rest of the bits
are a negative errno.  Bit 2 (the 'unallocated slots' bit) is clear.
Bits 3-6 indicate the node type.

state->alloc either has a request number of nodes or an allocated node.  If
stat->alloc has a requested number of nodes, the first bit will be set (0x1)
and the remaining bits are the value.  If state->alloc is a node, then the node
will be of type maple_alloc.  maple_alloc has MAPLE_NODE_SLOTS - 1 for storing
more allocated nodes, a total, and the node_count in this node.  total is the
number of nodes allocated.  node_count is the number of allocated nodes in this
node.  The scaling beyond MAPLE_NODE_SLOTS - 1 is handled by storing further
nodes into state->alloc->slot[0]'s node.  Nodes are taken from state->alloc by
removing a node from the state->alloc node until state->alloc->node_count is 1,
when state->alloc is returned and the state->alloc->slot[0] is promoted to
state->alloc.  Nodes are pushed onto state->alloc by putting the current
state->alloc into the pushed node's slot[0].

The state also contains the implied min/max of the state->node, the depth of
this search, and the offset. The implied min/max are either from the parent
node or are 0-oo for the root node.  The depth is incremented or decremented
every time a node is walked down or up.  The offset is the slot/pivot of
interest in the node - either for reading or writing.

When returning a value the maple state index and last respectively contain the start and end
of the range for the entry.  Ranges are inclusive in the Maple Tree.

Tree Operations
===============

Inserting
---------

Inserting a new range inserts either 0, 1, or 2 pivots within the tree.  If the
insert fits exactly into an existing gap with a value of NULL, then the slot
only needs to be written with the new value.  If the range being inserted is
adjacent to another range, then only a single pivot needs to be inserted (as
well as writing the entry).  If the new range is within a gap but does not
touch any other ranges, then two pivots need to be inserted: the start - 1, and
the end.  As usual, the entry must be written.  Most operations require a new
node to be allocated and replace an existing node to ensure RCU safety, when in
RCU mode.  The exception to requiring a newly allocated node is when inserting
at the end of a node (appending).  When done carefully, appending can reuse the
node in place.

Storing
-------

Storing is the same operation as insert with the added caveat that it can
overwrite entries.  Although this seems simple enough, one may want to examine
what happens if a single store operation was to overwrite multiple entries
within a self-balancing B-Tree.

Erasing
-------

Erasing is the same as a walk to an entry then a store of a NULL to that entry.
In fact, it is implemented as such using the advanced API.

Splitting
---------

Splitting is handled differently than any other b-tree; the Maple Tree splits
up.  Splitting up means that the split operation occurs when the walk of the
tree hits the leaves and not on the way down.  The reason for splitting up is
that it is impossible to know how much space will be needed until the leaf (or
leaves) are reached.  Since overwriting data is allowed and a range could
overwrite more than one range or result in changing one entry into 3 entries,
it is impossible to know if a split is required until the data is examined.

Splitting is a balancing act between keeping allocations to a minimum and
avoiding a 'jitter' event where a tree is expanded to make room for an entry
followed by a contraction when the entry is removed.  To accomplish the
balance, there are empty slots remaining in both left and right nodes after a
split.

Another way that 'jitter' is avoided is to terminate a spit up early if the
left or right node has space to spare.  This is referred to as "pushing left"
or "pushing right" and is similar to the b* tree, except the nodes left or
right can rarely be reused due to RCU, but the ripple upwards is halted which
is a significant savings.

To support gap tracking, all NULL entries are kept together and a node cannot
end on a NULL entry, with the exception of the left-most leaf.  The limitation
means that the split of a node must be checked for this condition and be able
to put more data in one direction or the other.

3-way Split
-----------

Although extremely rare, it is possible to enter what is known as the 3-way
split scenario.  The 3-way split comes about by means of a store of a range
that overwrites the end and beginning of two full nodes.  The result is a set
of entries that cannot be stored in 2 nodes.  Sometimes, these two nodes can
also be located in different parent nodes which are also full.  This can carry
upwards all the way to the root in the worst case.

Spanning Store
--------------

A store operation that spans multiple nodes is called a spanning store and is
handled early in the store call stack by the function mas_is_span_wr().  When a
spanning store is identified, the maple state is duplicated.  The first maple
state walks the left tree path to ``index``, the duplicate walks the right tree
path to ``last``.  The data in the two nodes are combined into a single node,
two nodes, or possibly three nodes (see the 3-way split above).  A ``NULL``
written to the last entry of a node is considered a spanning store as a
rebalance is required for the operation to complete and an overflow of data may
happen.

The tree needs to be rebalanced and leaves need to be kept at the same level.
Rebalancing is done by use of the ``struct maple_topiary``.  The maple_topiary
struct keeps track of which nodes to free and which to destroy (free the
subtree).  See mas_spanning_rebalance().

Each level of the tree is examined and balanced in mas_spanning_rebalance().
Again, pushing data to the left or right, or rebalancing against left or right
nodes is employed to avoid rippling up the tree to limit the amount of churn.
Once a new sub-section of the tree is created, there may be a mix of new and
old nodes.  The old nodes will have the incorrect parent pointers and currently
be in two trees: the original tree and the partially new tree.  To remedy the
parent pointers in the old tree, the new data is swapped into the active tree
and a walk down the tree is performed and the parent pointers are updated.  At
each level there may be up to 3 correct parent pointers which indicates the new
nodes which need to be walked to find any new nodes at a lower level.  See
mas_descend_adopt().

Rebalance
---------

Rebalancing occurs if a node is insufficient.  Data is rebalanced against the
node to the right if it exists, otherwise the node to the left of this node is
rebalanced against this node.  If rebalancing causes just one node to be
produced instead of two, then the parent is also examined and rebalanced if it
is insufficient.  Every level tries to combine the data in the same way.  If
one node contains the entire range of the tree, then that node is used as a new
root node.

Bulk Loading
------------

Sometimes it is necessary to duplicate a tree to a new tree, such as forking a
process and duplicating the VMAs from one tree to a new tree.  When such a
situation arises, it is known that the new tree is not going to be used until
the entire tree is populated.  For performance reasons, it is best to use a
bulk load with RCU disabled.  This allows for optimistic splitting that favours
the left and reuse of nodes during the operation.  Upon completion, the
mas_destroy() operation on the maple state will check the left-most node and
rebalance against the node to the right if necessary.  mas_destroy() will also
free any unused nodes.


The Maple State
===============

The ma_state struct keeps track of tree operations to make life easier for both
internal and external tree users.

Functions and structures
========================

.. kernel-doc:: include/linux/maple_tree.h
.. kernel-doc:: lib/maple_tree.c

