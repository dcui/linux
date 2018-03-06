/*
 * Resizable, Scalable, Concurrent Hash Table
 *
 * Copyright (c) 2015-2016 Herbert Xu <herbert@gondor.apana.org.au>
 * Copyright (c) 2014-2015 Thomas Graf <tgraf@suug.ch>
 * Copyright (c) 2008-2014 Patrick McHardy <kaber@trash.net>
 *
 * Code partially derived from nft_hash
 * Rewritten with rehash code from br_multicast plus single list
 * pointer as suggested by Josh Triplett
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _MLNX_LINUX_RHASHTABLE_H
#define _MLNX_LINUX_RHASHTABLE_H

/* use our own implementaiton when the rhltable struct is not avaialbe in the
 * kerenl
*/

#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/jhash.h>
#include <linux/list_nulls.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>

#include <linux/mlx_compat.h>

#ifndef NULLS_MARKER
#define NULLS_MARKER(value) (1UL | (((long)value) << 1))
#endif

/*
 * The end of the chain is marked with a special nulls marks which has
 * the following format:
 *
 * +-------+-----------------------------------------------------+-+
 * | Base  |                      Hash                           |1|
 * +-------+-----------------------------------------------------+-+
 *
 * Base (4 bits) : Reserved to distinguish between multiple tables.
 *                 Specified via &struct rhashtable_params.nulls_base.
 * Hash (27 bits): Full hash (unmasked) of first element added to bucket
 * 1 (1 bit)     : Nulls marker (always set)
 *
 * The remaining bits of the next pointer remain unused for now.
 */
#define RHT_BASE_BITS		4
#define RHT_HASH_BITS		27
#define RHT_BASE_SHIFT		RHT_HASH_BITS

/* Base bits plus 1 bit for nulls marker */
#define RHT_HASH_RESERVED_SPACE	(RHT_BASE_BITS + 1)

struct rhash_head {
	struct rhash_head __rcu		*next;
};

struct rhlist_head {
	struct rhash_head		rhead;
	struct rhlist_head __rcu	*next;
};

/**
 * struct bucket_table - Table of hash buckets
 * @size: Number of hash buckets
 * @rehash: Current bucket being rehashed
 * @hash_rnd: Random seed to fold into hash
 * @locks_mask: Mask to apply before accessing locks[]
 * @locks: Array of spinlocks protecting individual buckets
 * @walkers: List of active walkers
 * @rcu: RCU structure for freeing the table
 * @future_tbl: Table under construction during rehashing
 * @buckets: size * hash buckets
 */
struct bucket_table {
	unsigned int		size;
	unsigned int		rehash;
	u32			hash_rnd;
	unsigned int		locks_mask;
	spinlock_t		*locks;
	struct list_head	walkers;
	struct rcu_head		rcu;

	struct bucket_table __rcu *future_tbl;

	struct rhash_head __rcu	*buckets[] ____cacheline_aligned_in_smp;
};

/**
 * struct rhashtable_compare_arg - Key for the function rhashtable_compare
 * @ht: Hash table
 * @key: Key to compare against
 */
struct rhashtable_compare_arg {
	struct rhashtable *ht;
	const void *key;
};

typedef u32 (*rht_hashfn_t)(const void *data, u32 len, u32 seed);
typedef u32 (*rht_obj_hashfn_t)(const void *data, u32 len, u32 seed);
typedef int (*rht_obj_cmpfn_t)(struct rhashtable_compare_arg *arg,
			       const void *obj);

struct rhashtable;

/**
 * struct rhashtable_params - Hash table construction parameters
 * @nelem_hint: Hint on number of elements, should be 75% of desired size
 * @key_len: Length of key
 * @key_offset: Offset of key in struct to be hashed
 * @head_offset: Offset of rhash_head in struct to be hashed
 * @insecure_max_entries: Maximum number of entries (may be exceeded)
 * @max_size: Maximum size while expanding
 * @min_size: Minimum size while shrinking
 * @nulls_base: Base value to generate nulls marker
 * @insecure_elasticity: Set to true to disable chain length checks
 * @automatic_shrinking: Enable automatic shrinking of tables
 * @locks_mul: Number of bucket locks to allocate per cpu (default: 128)
 * @hashfn: Hash function (default: jhash2 if !(key_len % 4), or jhash)
 * @obj_hashfn: Function to hash object
 * @obj_cmpfn: Function to compare key with object
 */
struct rhashtable_params {
	size_t			nelem_hint;
	size_t			key_len;
	size_t			key_offset;
	size_t			head_offset;
	unsigned int		insecure_max_entries;
	unsigned int		max_size;
	unsigned int		min_size;
	u32			nulls_base;
	bool			insecure_elasticity;
	bool			automatic_shrinking;
	size_t			locks_mul;
	rht_hashfn_t		hashfn;
	rht_obj_hashfn_t	obj_hashfn;
	rht_obj_cmpfn_t		obj_cmpfn;
};

/**
 * struct rhashtable - Hash table handle
 * @tbl: Bucket table
 * @nelems: Number of elements in table
 * @key_len: Key length for hashfn
 * @elasticity: Maximum chain length before rehash
 * @p: Configuration parameters
 * @rhlist: True if this is an rhltable
 * @run_work: Deferred worker to expand/shrink asynchronously
 * @mutex: Mutex to protect current/future table swapping
 * @lock: Spin lock to protect walker list
 */
struct rhashtable {
	struct bucket_table __rcu	*tbl;
	atomic_t			nelems;
	unsigned int			key_len;
	unsigned int			elasticity;
	struct rhashtable_params	p;
	bool				rhlist;
	struct work_struct		run_work;
	struct mutex                    mutex;
	spinlock_t			lock;
};

/**
 * struct rhltable - Hash table with duplicate objects in a list
 * @ht: Underlying rhtable
 */
struct rhltable {
	struct rhashtable ht;
};

/**
 * struct rhashtable_walker - Hash table walker
 * @list: List entry on list of walkers
 * @tbl: The table that we were walking over
 */
struct rhashtable_walker {
	struct list_head list;
	struct bucket_table *tbl;
};

/**
 * struct rhashtable_iter - Hash table iterator
 * @ht: Table to iterate through
 * @p: Current pointer
 * @list: Current hash list pointer
 * @walker: Associated rhashtable walker
 * @slot: Current slot
 * @skip: Number of entries to skip in slot
 */
struct rhashtable_iter {
	struct rhashtable *ht;
	struct rhash_head *p;
	struct rhlist_head *list;
	struct rhashtable_walker walker;
	unsigned int slot;
	unsigned int skip;
};

static inline unsigned long rht_marker(const struct rhashtable *ht, u32 hash)
{
	return NULLS_MARKER(ht->p.nulls_base + hash);
}

#define INIT_RHT_NULLS_HEAD(ptr, ht, hash) \
	((ptr) = (typeof(ptr)) rht_marker(ht, hash))

static inline bool rht_is_a_nulls(const struct rhash_head *ptr)
{
	return ((unsigned long) ptr & 1);
}

static inline unsigned long rht_get_nulls_value(const struct rhash_head *ptr)
{
	return ((unsigned long) ptr) >> 1;
}

static inline void *rht_obj(const struct rhashtable *ht,
			    const struct rhash_head *he)
{
	return (char *)he - ht->p.head_offset;
}

static inline unsigned int rht_bucket_index(const struct bucket_table *tbl,
					    unsigned int hash)
{
	return (hash >> RHT_HASH_RESERVED_SPACE) & (tbl->size - 1);
}

static inline unsigned int rht_key_hashfn(
	struct rhashtable *ht, const struct bucket_table *tbl,
	const void *key, const struct rhashtable_params params)
{
	unsigned int hash;

	/* params must be equal to ht->p if it isn't constant. */
	if (!__builtin_constant_p(params.key_len))
		hash = ht->p.hashfn(key, ht->key_len, tbl->hash_rnd);
	else if (params.key_len) {
		unsigned int key_len = params.key_len;

		if (params.hashfn)
			hash = params.hashfn(key, key_len, tbl->hash_rnd);
		else if (key_len & (sizeof(u32) - 1))
			hash = jhash(key, key_len, tbl->hash_rnd);
		else
			hash = jhash2(key, key_len / sizeof(u32),
				      tbl->hash_rnd);
	} else {
		unsigned int key_len = ht->p.key_len;

		if (params.hashfn)
			hash = params.hashfn(key, key_len, tbl->hash_rnd);
		else
			hash = jhash(key, key_len, tbl->hash_rnd);
	}

	return rht_bucket_index(tbl, hash);
}

static inline unsigned int rht_head_hashfn(
	struct rhashtable *ht, const struct bucket_table *tbl,
	const struct rhash_head *he, const struct rhashtable_params params)
{
	const char *ptr = rht_obj(ht, he);

	return likely(params.obj_hashfn) ?
	       rht_bucket_index(tbl, params.obj_hashfn(ptr, params.key_len ?:
							    ht->p.key_len,
						       tbl->hash_rnd)) :
	       rht_key_hashfn(ht, tbl, ptr + params.key_offset, params);
}

/**
 * rht_grow_above_75 - returns true if nelems > 0.75 * table-size
 * @ht:		hash table
 * @tbl:	current table
 */
static inline bool rht_grow_above_75(const struct rhashtable *ht,
				     const struct bucket_table *tbl)
{
	/* Expand table when exceeding 75% load */
	return atomic_read(&ht->nelems) > (tbl->size / 4 * 3) &&
	       (!ht->p.max_size || tbl->size < ht->p.max_size);
}

/**
 * rht_shrink_below_30 - returns true if nelems < 0.3 * table-size
 * @ht:		hash table
 * @tbl:	current table
 */
static inline bool rht_shrink_below_30(const struct rhashtable *ht,
				       const struct bucket_table *tbl)
{
	/* Shrink table beneath 30% load */
	return atomic_read(&ht->nelems) < (tbl->size * 3 / 10) &&
	       tbl->size > ht->p.min_size;
}

/**
 * rht_grow_above_100 - returns true if nelems > table-size
 * @ht:		hash table
 * @tbl:	current table
 */
static inline bool rht_grow_above_100(const struct rhashtable *ht,
				      const struct bucket_table *tbl)
{
	return atomic_read(&ht->nelems) > tbl->size &&
		(!ht->p.max_size || tbl->size < ht->p.max_size);
}

/**
 * rht_grow_above_max - returns true if table is above maximum
 * @ht:		hash table
 * @tbl:	current table
 */
static inline bool rht_grow_above_max(const struct rhashtable *ht,
				      const struct bucket_table *tbl)
{
	return ht->p.insecure_max_entries &&
	       atomic_read(&ht->nelems) >= ht->p.insecure_max_entries;
}

/* The bucket lock is selected based on the hash and protects mutations
 * on a group of hash buckets.
 *
 * A maximum of tbl->size/2 bucket locks is allocated. This ensures that
 * a single lock always covers both buckets which may both contains
 * entries which link to the same bucket of the old table during resizing.
 * This allows to simplify the locking as locking the bucket in both
 * tables during resize always guarantee protection.
 *
 * IMPORTANT: When holding the bucket lock of both the old and new table
 * during expansions and shrinking, the old bucket lock must always be
 * acquired first.
 */
static inline spinlock_t *rht_bucket_lock(const struct bucket_table *tbl,
					  unsigned int hash)
{
	return &tbl->locks[hash & tbl->locks_mask];
}

#ifdef CONFIG_PROVE_LOCKING
#define ASSERT_RHT_MUTEX(HT) BUG_ON(!lockdep_rht_mutex_is_held(HT))

static inline int lockdep_rht_mutex_is_held(struct rhashtable *ht)
{
	return (debug_locks) ? lockdep_is_held(&ht->mutex) : 1;
}

static inline int lockdep_rht_bucket_is_held(const struct bucket_table *tbl, u32 hash)
{
	spinlock_t *lock = rht_bucket_lock(tbl, hash);

	return (debug_locks) ? lockdep_is_held(lock) : 1;
}
#else
#define ASSERT_RHT_MUTEX(HT)
static inline int lockdep_rht_mutex_is_held(struct rhashtable *ht)
{
	return 1;
}

static inline int lockdep_rht_bucket_is_held(const struct bucket_table *tbl,
					     u32 hash)
{
	return 1;
}
#endif /* CONFIG_PROVE_LOCKING */

#define HASH_DEFAULT_SIZE	64UL
#define HASH_MIN_SIZE		4U
#define BUCKET_LOCKS_PER_CPU	32UL

static u32 head_hashfn(struct rhashtable *ht,
		       const struct bucket_table *tbl,
		       const struct rhash_head *he)
{
	return rht_head_hashfn(ht, tbl, he, ht->p);
}

static int alloc_bucket_locks(struct rhashtable *ht, struct bucket_table *tbl,
			      gfp_t gfp)
{
	unsigned int i, size;
#if defined(CONFIG_PROVE_LOCKING)
	unsigned int nr_pcpus = 2;
#else
	unsigned int nr_pcpus = num_possible_cpus();
#endif

	nr_pcpus = min_t(unsigned int, nr_pcpus, 64UL);
	size = roundup_pow_of_two(nr_pcpus * ht->p.locks_mul);

	/* Never allocate more than 0.5 locks per bucket */
	size = min_t(unsigned int, size, tbl->size >> 1);

	if (sizeof(spinlock_t) != 0) {
		tbl->locks = NULL;
#ifdef CONFIG_NUMA
		if (size * sizeof(spinlock_t) > PAGE_SIZE &&
		    gfp == GFP_KERNEL)
			tbl->locks = vmalloc(size * sizeof(spinlock_t));
#endif
		if (gfp != GFP_KERNEL)
			gfp |= __GFP_NOWARN | __GFP_NORETRY;

		if (!tbl->locks)
			tbl->locks = kmalloc_array(size, sizeof(spinlock_t),
						   gfp);
		if (!tbl->locks)
			return -ENOMEM;
		for (i = 0; i < size; i++)
			spin_lock_init(&tbl->locks[i]);
	}
	tbl->locks_mask = size - 1;

	return 0;
}

static void bucket_table_free(const struct bucket_table *tbl)
{
	if (tbl)
		kvfree(tbl->locks);

	kvfree(tbl);
}

static void bucket_table_free_rcu(struct rcu_head *head)
{
	bucket_table_free(container_of(head, struct bucket_table, rcu));
}

static struct bucket_table *bucket_table_alloc(struct rhashtable *ht,
					       size_t nbuckets,
					       gfp_t gfp)
{
	struct bucket_table *tbl = NULL;
	size_t size;
	int i;

	size = sizeof(*tbl) + nbuckets * sizeof(tbl->buckets[0]);
	if (size <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER) ||
	    gfp != GFP_KERNEL)
		tbl = kzalloc(size, gfp | __GFP_NOWARN | __GFP_NORETRY);
	if (tbl == NULL && gfp == GFP_KERNEL)
		tbl = vzalloc(size);
	if (tbl == NULL)
		return NULL;

	tbl->size = nbuckets;

	if (alloc_bucket_locks(ht, tbl, gfp) < 0) {
		bucket_table_free(tbl);
		return NULL;
	}

	INIT_LIST_HEAD(&tbl->walkers);

	get_random_bytes(&tbl->hash_rnd, sizeof(tbl->hash_rnd));

	for (i = 0; i < nbuckets; i++)
		INIT_RHT_NULLS_HEAD(tbl->buckets[i], ht, i);

	return tbl;
}

static struct bucket_table *rhashtable_last_table(struct rhashtable *ht,
						  struct bucket_table *tbl)
{
	struct bucket_table *new_tbl;

	do {
		new_tbl = tbl;
		tbl = rht_dereference_rcu(tbl->future_tbl, ht);
	} while (tbl);

	return new_tbl;
}

static int rhashtable_rehash_one(struct rhashtable *ht, unsigned int old_hash)
{
	struct bucket_table *old_tbl = rht_dereference(ht->tbl, ht);
	struct bucket_table *new_tbl = rhashtable_last_table(ht,
		rht_dereference_rcu(old_tbl->future_tbl, ht));
	struct rhash_head __rcu **pprev = &old_tbl->buckets[old_hash];
	int err = -ENOENT;
	struct rhash_head *head, *next, *entry;
	spinlock_t *new_bucket_lock;
	unsigned int new_hash;

	rht_for_each(entry, old_tbl, old_hash) {
		err = 0;
		next = rht_dereference_bucket(entry->next, old_tbl, old_hash);

		if (rht_is_a_nulls(next))
			break;

		pprev = &entry->next;
	}

	if (err)
		goto out;

	new_hash = head_hashfn(ht, new_tbl, entry);

	new_bucket_lock = rht_bucket_lock(new_tbl, new_hash);

	spin_lock_nested(new_bucket_lock, SINGLE_DEPTH_NESTING);
	head = rht_dereference_bucket(new_tbl->buckets[new_hash],
				      new_tbl, new_hash);

	RCU_INIT_POINTER(entry->next, head);

	rcu_assign_pointer(new_tbl->buckets[new_hash], entry);
	spin_unlock(new_bucket_lock);

	rcu_assign_pointer(*pprev, next);

out:
	return err;
}

static void rhashtable_rehash_chain(struct rhashtable *ht,
				    unsigned int old_hash)
{
	struct bucket_table *old_tbl = rht_dereference(ht->tbl, ht);
	spinlock_t *old_bucket_lock;

	old_bucket_lock = rht_bucket_lock(old_tbl, old_hash);

	spin_lock_bh(old_bucket_lock);
	while (!rhashtable_rehash_one(ht, old_hash))
		;
	old_tbl->rehash++;
	spin_unlock_bh(old_bucket_lock);
}

static int rhashtable_rehash_attach(struct rhashtable *ht,
				    struct bucket_table *old_tbl,
				    struct bucket_table *new_tbl)
{
	/* Protect future_tbl using the first bucket lock. */
	spin_lock_bh(old_tbl->locks);

	/* Did somebody beat us to it? */
	if (rcu_access_pointer(old_tbl->future_tbl)) {
		spin_unlock_bh(old_tbl->locks);
		return -EEXIST;
	}

	/* Make insertions go into the new, empty table right away. Deletions
	 * and lookups will be attempted in both tables until we synchronize.
	 */
	rcu_assign_pointer(old_tbl->future_tbl, new_tbl);

	spin_unlock_bh(old_tbl->locks);

	return 0;
}

static int rhashtable_rehash_table(struct rhashtable *ht)
{
	struct bucket_table *old_tbl = rht_dereference(ht->tbl, ht);
	struct bucket_table *new_tbl;
	struct rhashtable_walker *walker;
	unsigned int old_hash;

	new_tbl = rht_dereference(old_tbl->future_tbl, ht);
	if (!new_tbl)
		return 0;

	for (old_hash = 0; old_hash < old_tbl->size; old_hash++)
		rhashtable_rehash_chain(ht, old_hash);

	/* Publish the new table pointer. */
	rcu_assign_pointer(ht->tbl, new_tbl);

	spin_lock(&ht->lock);
	list_for_each_entry(walker, &old_tbl->walkers, list)
		walker->tbl = NULL;
	spin_unlock(&ht->lock);

	/* Wait for readers. All new readers will see the new
	 * table, and thus no references to the old table will
	 * remain.
	 */
	call_rcu(&old_tbl->rcu, bucket_table_free_rcu);

	return rht_dereference(new_tbl->future_tbl, ht) ? -EAGAIN : 0;
}

/**
 * rhashtable_expand - Expand hash table while allowing concurrent lookups
 * @ht:		the hash table to expand
 *
 * A secondary bucket array is allocated and the hash entries are migrated.
 *
 * This function may only be called in a context where it is safe to call
 * synchronize_rcu(), e.g. not within a rcu_read_lock() section.
 *
 * The caller must ensure that no concurrent resizing occurs by holding
 * ht->mutex.
 *
 * It is valid to have concurrent insertions and deletions protected by per
 * bucket locks or concurrent RCU protected lookups and traversals.
 */
static int rhashtable_expand(struct rhashtable *ht)
{
	struct bucket_table *new_tbl, *old_tbl = rht_dereference(ht->tbl, ht);
	int err;

	ASSERT_RHT_MUTEX(ht);

	old_tbl = rhashtable_last_table(ht, old_tbl);

	new_tbl = bucket_table_alloc(ht, old_tbl->size * 2, GFP_KERNEL);
	if (new_tbl == NULL)
		return -ENOMEM;

	err = rhashtable_rehash_attach(ht, old_tbl, new_tbl);
	if (err)
		bucket_table_free(new_tbl);

	return err;
}

/**
 * rhashtable_shrink - Shrink hash table while allowing concurrent lookups
 * @ht:		the hash table to shrink
 *
 * This function shrinks the hash table to fit, i.e., the smallest
 * size would not cause it to expand right away automatically.
 *
 * The caller must ensure that no concurrent resizing occurs by holding
 * ht->mutex.
 *
 * The caller must ensure that no concurrent table mutations take place.
 * It is however valid to have concurrent lookups if they are RCU protected.
 *
 * It is valid to have concurrent insertions and deletions protected by per
 * bucket locks or concurrent RCU protected lookups and traversals.
 */
static int rhashtable_shrink(struct rhashtable *ht)
{
	struct bucket_table *new_tbl, *old_tbl = rht_dereference(ht->tbl, ht);
	unsigned int nelems = atomic_read(&ht->nelems);
	unsigned int size = 0;
	int err;

	ASSERT_RHT_MUTEX(ht);

	if (nelems)
		size = roundup_pow_of_two(nelems * 3 / 2);
	if (size < ht->p.min_size)
		size = ht->p.min_size;

	if (old_tbl->size <= size)
		return 0;

	if (rht_dereference(old_tbl->future_tbl, ht))
		return -EEXIST;

	new_tbl = bucket_table_alloc(ht, size, GFP_KERNEL);
	if (new_tbl == NULL)
		return -ENOMEM;

	err = rhashtable_rehash_attach(ht, old_tbl, new_tbl);
	if (err)
		bucket_table_free(new_tbl);

	return err;
}

static void rht_deferred_worker(struct work_struct *work)
{
	struct rhashtable *ht;
	struct bucket_table *tbl;
	int err = 0;

	ht = container_of(work, struct rhashtable, run_work);
	mutex_lock(&ht->mutex);

	tbl = rht_dereference(ht->tbl, ht);
	tbl = rhashtable_last_table(ht, tbl);

	if (rht_grow_above_75(ht, tbl))
		rhashtable_expand(ht);
	else if (ht->p.automatic_shrinking && rht_shrink_below_30(ht, tbl))
		rhashtable_shrink(ht);

	err = rhashtable_rehash_table(ht);

	mutex_unlock(&ht->mutex);

	if (err)
		schedule_work(&ht->run_work);
}

static int rhashtable_insert_rehash(struct rhashtable *ht,
				    struct bucket_table *tbl)
{
	struct bucket_table *old_tbl;
	struct bucket_table *new_tbl;
	unsigned int size;
	int err;

	old_tbl = rht_dereference_rcu(ht->tbl, ht);

	size = tbl->size;

	err = -EBUSY;

	if (rht_grow_above_75(ht, tbl))
		size *= 2;
	/* Do not schedule more than one rehash */
	else if (old_tbl != tbl)
		goto fail;

	err = -ENOMEM;

	new_tbl = bucket_table_alloc(ht, size, GFP_ATOMIC);
	if (new_tbl == NULL)
		goto fail;

	err = rhashtable_rehash_attach(ht, tbl, new_tbl);
	if (err) {
		bucket_table_free(new_tbl);
		if (err == -EEXIST)
			err = 0;
	} else
		schedule_work(&ht->run_work);

	return err;

fail:
	/* Do not fail the insert if someone else did a rehash. */
	if (likely(rcu_dereference_raw(tbl->future_tbl)))
		return 0;

	/* Schedule async rehash to retry allocation in process context. */
	if (err == -ENOMEM)
		schedule_work(&ht->run_work);

	return err;
}

static inline int rhashtable_compare(struct rhashtable_compare_arg *arg,
				     const void *obj)
{
	struct rhashtable *ht = arg->ht;
	const char *ptr = obj;

	return memcmp(ptr + ht->p.key_offset, arg->key, ht->p.key_len);
}

static void *rhashtable_lookup_one(struct rhashtable *ht,
				   struct bucket_table *tbl, unsigned int hash,
				   const void *key, struct rhash_head *obj)
{
	struct rhashtable_compare_arg arg = {
		.ht = ht,
		.key = key,
	};
	struct rhash_head __rcu **pprev;
	struct rhash_head *head;
	int elasticity;

	elasticity = ht->elasticity;
	pprev = &tbl->buckets[hash];
	rht_for_each(head, tbl, hash) {
		struct rhlist_head *list;
		struct rhlist_head *plist;

		elasticity--;
		if (!key ||
		    (ht->p.obj_cmpfn ?
		     ht->p.obj_cmpfn(&arg, rht_obj(ht, head)) :
		     rhashtable_compare(&arg, rht_obj(ht, head))))
			continue;

		if (!ht->rhlist)
			return rht_obj(ht, head);

		list = container_of(obj, struct rhlist_head, rhead);
		plist = container_of(head, struct rhlist_head, rhead);

		RCU_INIT_POINTER(list->next, plist);
		head = rht_dereference_bucket(head->next, tbl, hash);
		RCU_INIT_POINTER(list->rhead.next, head);
		rcu_assign_pointer(*pprev, obj);

		return NULL;
	}

	if (elasticity <= 0)
		return ERR_PTR(-EAGAIN);

	return ERR_PTR(-ENOENT);
}

static struct bucket_table *rhashtable_insert_one(struct rhashtable *ht,
						  struct bucket_table *tbl,
						  unsigned int hash,
						  struct rhash_head *obj,
						  void *data)
{
	struct bucket_table *new_tbl;
	struct rhash_head *head;

	if (!IS_ERR_OR_NULL(data))
		return ERR_PTR(-EEXIST);

	if (PTR_ERR(data) != -EAGAIN && PTR_ERR(data) != -ENOENT)
		return ERR_CAST(data);

	new_tbl = rcu_dereference(tbl->future_tbl);
	if (new_tbl)
		return new_tbl;

	if (PTR_ERR(data) != -ENOENT)
		return ERR_CAST(data);

	if (unlikely(rht_grow_above_max(ht, tbl)))
		return ERR_PTR(-E2BIG);

	if (unlikely(rht_grow_above_100(ht, tbl)))
		return ERR_PTR(-EAGAIN);

	head = rht_dereference_bucket(tbl->buckets[hash], tbl, hash);

	RCU_INIT_POINTER(obj->next, head);
	if (ht->rhlist) {
		struct rhlist_head *list;

		list = container_of(obj, struct rhlist_head, rhead);
		RCU_INIT_POINTER(list->next, NULL);
	}

	rcu_assign_pointer(tbl->buckets[hash], obj);

	atomic_inc(&ht->nelems);
	if (rht_grow_above_75(ht, tbl))
		schedule_work(&ht->run_work);

	return NULL;
}

static void *rhashtable_try_insert(struct rhashtable *ht, const void *key,
				   struct rhash_head *obj)
{
	struct bucket_table *new_tbl;
	struct bucket_table *tbl;
	unsigned int hash;
	spinlock_t *lock;
	void *data;

	tbl = rcu_dereference(ht->tbl);

	/* All insertions must grab the oldest table containing
	 * the hashed bucket that is yet to be rehashed.
	 */
	for (;;) {
		hash = rht_head_hashfn(ht, tbl, obj, ht->p);
		lock = rht_bucket_lock(tbl, hash);
		spin_lock_bh(lock);

		if (tbl->rehash <= hash)
			break;

		spin_unlock_bh(lock);
		tbl = rcu_dereference(tbl->future_tbl);
	}

	data = rhashtable_lookup_one(ht, tbl, hash, key, obj);
	new_tbl = rhashtable_insert_one(ht, tbl, hash, obj, data);
	if (PTR_ERR(new_tbl) != -EEXIST)
		data = ERR_CAST(new_tbl);

	while (!IS_ERR_OR_NULL(new_tbl)) {
		tbl = new_tbl;
		hash = rht_head_hashfn(ht, tbl, obj, ht->p);
		spin_lock_nested(rht_bucket_lock(tbl, hash),
				 SINGLE_DEPTH_NESTING);

		data = rhashtable_lookup_one(ht, tbl, hash, key, obj);
		new_tbl = rhashtable_insert_one(ht, tbl, hash, obj, data);
		if (PTR_ERR(new_tbl) != -EEXIST)
			data = ERR_CAST(new_tbl);

		spin_unlock(rht_bucket_lock(tbl, hash));
	}

	spin_unlock_bh(lock);

	if (PTR_ERR(data) == -EAGAIN)
		data = ERR_PTR(rhashtable_insert_rehash(ht, tbl) ?:
			       -EAGAIN);

	return data;
}

static inline void *rhashtable_insert_slow(struct rhashtable *ht, const void *key,
			     struct rhash_head *obj)
{
	void *data;

	do {
		rcu_read_lock();
		data = rhashtable_try_insert(ht, key, obj);
		rcu_read_unlock();
	} while (PTR_ERR(data) == -EAGAIN);

	return data;
}

/**
 * rhashtable_walk_enter - Initialise an iterator
 * @ht:		Table to walk over
 * @iter:	Hash table Iterator
 *
 * This function prepares a hash table walk.
 *
 * Note that if you restart a walk after rhashtable_walk_stop you
 * may see the same object twice.  Also, you may miss objects if
 * there are removals in between rhashtable_walk_stop and the next
 * call to rhashtable_walk_start.
 *
 * For a completely stable walk you should construct your own data
 * structure outside the hash table.
 *
 * This function may sleep so you must not call it from interrupt
 * context or with spin locks held.
 *
 * You must call rhashtable_walk_exit after this function returns.
 */
static inline void rhashtable_walk_enter(struct rhashtable *ht, struct rhashtable_iter *iter)
{
	iter->ht = ht;
	iter->p = NULL;
	iter->slot = 0;
	iter->skip = 0;

	spin_lock(&ht->lock);
	iter->walker.tbl =
		rcu_dereference_protected(ht->tbl, lockdep_is_held(&ht->lock));
	list_add(&iter->walker.list, &iter->walker.tbl->walkers);
	spin_unlock(&ht->lock);
}

/**
 * rhashtable_walk_exit - Free an iterator
 * @iter:	Hash table Iterator
 *
 * This function frees resources allocated by rhashtable_walk_init.
 */
static inline void rhashtable_walk_exit(struct rhashtable_iter *iter)
{
	spin_lock(&iter->ht->lock);
	if (iter->walker.tbl)
		list_del(&iter->walker.list);
	spin_unlock(&iter->ht->lock);
}

/**
 * rhashtable_walk_start - Start a hash table walk
 * @iter:	Hash table iterator
 *
 * Start a hash table walk.  Note that we take the RCU lock in all
 * cases including when we return an error.  So you must always call
 * rhashtable_walk_stop to clean up.
 *
 * Returns zero if successful.
 *
 * Returns -EAGAIN if resize event occured.  Note that the iterator
 * will rewind back to the beginning and you may use it immediately
 * by calling rhashtable_walk_next.
 */
static inline int rhashtable_walk_start(struct rhashtable_iter *iter)
	__acquires(RCU)
{
	struct rhashtable *ht = iter->ht;

	rcu_read_lock();

	spin_lock(&ht->lock);
	if (iter->walker.tbl)
		list_del(&iter->walker.list);
	spin_unlock(&ht->lock);

	if (!iter->walker.tbl) {
		iter->walker.tbl = rht_dereference_rcu(ht->tbl, ht);
		return -EAGAIN;
	}

	return 0;
}

/**
 * rhashtable_walk_next - Return the next object and advance the iterator
 * @iter:	Hash table iterator
 *
 * Note that you must call rhashtable_walk_stop when you are finished
 * with the walk.
 *
 * Returns the next object or NULL when the end of the table is reached.
 *
 * Returns -EAGAIN if resize event occured.  Note that the iterator
 * will rewind back to the beginning and you may continue to use it.
 */
static inline void *rhashtable_walk_next(struct rhashtable_iter *iter)
{
	struct bucket_table *tbl = iter->walker.tbl;
	struct rhlist_head *list = iter->list;
	struct rhashtable *ht = iter->ht;
	struct rhash_head *p = iter->p;
	bool rhlist = ht->rhlist;

	if (p) {
		if (!rhlist || !(list = rcu_dereference(list->next))) {
			p = rcu_dereference(p->next);
			list = container_of(p, struct rhlist_head, rhead);
		}
		goto next;
	}

	for (; iter->slot < tbl->size; iter->slot++) {
		int skip = iter->skip;

		rht_for_each_rcu(p, tbl, iter->slot) {
			if (rhlist) {
				list = container_of(p, struct rhlist_head,
						    rhead);
				do {
					if (!skip)
						goto next;
					skip--;
					list = rcu_dereference(list->next);
				} while (list);

				continue;
			}
			if (!skip)
				break;
			skip--;
		}

next:
		if (!rht_is_a_nulls(p)) {
			iter->skip++;
			iter->p = p;
			iter->list = list;
			return rht_obj(ht, rhlist ? &list->rhead : p);
		}

		iter->skip = 0;
	}

	iter->p = NULL;

	/* Ensure we see any new tables. */
	smp_rmb();

	iter->walker.tbl = rht_dereference_rcu(tbl->future_tbl, ht);
	if (iter->walker.tbl) {
		iter->slot = 0;
		iter->skip = 0;
		return ERR_PTR(-EAGAIN);
	}

	return NULL;
}

/**
 * rhashtable_walk_stop - Finish a hash table walk
 * @iter:	Hash table iterator
 *
 * Finish a hash table walk.
 */
static inline void rhashtable_walk_stop(struct rhashtable_iter *iter)
	__releases(RCU)
{
	struct rhashtable *ht;
	struct bucket_table *tbl = iter->walker.tbl;

	if (!tbl)
		goto out;

	ht = iter->ht;

	spin_lock(&ht->lock);
	if (tbl->rehash < tbl->size)
		list_add(&iter->walker.list, &tbl->walkers);
	else
		iter->walker.tbl = NULL;
	spin_unlock(&ht->lock);

	iter->p = NULL;

out:
	rcu_read_unlock();
}

static size_t rounded_hashtable_size(const struct rhashtable_params *params)
{
	return max(roundup_pow_of_two(params->nelem_hint * 4 / 3),
		   (unsigned long)params->min_size);
}

static u32 rhashtable_jhash2(const void *key, u32 length, u32 seed)
{
	return jhash2(key, length, seed);
}

/**
 * rhashtable_init - initialize a new hash table
 * @ht:		hash table to be initialized
 * @params:	configuration parameters
 *
 * Initializes a new hash table based on the provided configuration
 * parameters. A table can be configured either with a variable or
 * fixed length key:
 *
 * Configuration Example 1: Fixed length keys
 * struct test_obj {
 *	int			key;
 *	void *			my_member;
 *	struct rhash_head	node;
 * };
 *
 * struct rhashtable_params params = {
 *	.head_offset = offsetof(struct test_obj, node),
 *	.key_offset = offsetof(struct test_obj, key),
 *	.key_len = sizeof(int),
 *	.hashfn = jhash,
 *	.nulls_base = (1U << RHT_BASE_SHIFT),
 * };
 *
 * Configuration Example 2: Variable length keys
 * struct test_obj {
 *	[...]
 *	struct rhash_head	node;
 * };
 *
 * u32 my_hash_fn(const void *data, u32 len, u32 seed)
 * {
 *	struct test_obj *obj = data;
 *
 *	return [... hash ...];
 * }
 *
 * struct rhashtable_params params = {
 *	.head_offset = offsetof(struct test_obj, node),
 *	.hashfn = jhash,
 *	.obj_hashfn = my_hash_fn,
 * };
 */
static inline int rhashtable_init(struct rhashtable *ht,
		    const struct rhashtable_params *params)
{
	struct bucket_table *tbl;
	size_t size;

	size = HASH_DEFAULT_SIZE;

	if ((!params->key_len && !params->obj_hashfn) ||
	    (params->obj_hashfn && !params->obj_cmpfn))
		return -EINVAL;

	if (params->nulls_base && params->nulls_base < (1U << RHT_BASE_SHIFT))
		return -EINVAL;

	memset(ht, 0, sizeof(*ht));
	mutex_init(&ht->mutex);
	spin_lock_init(&ht->lock);
	memcpy(&ht->p, params, sizeof(*params));

	if (params->min_size)
		ht->p.min_size = roundup_pow_of_two(params->min_size);

	if (params->max_size)
		ht->p.max_size = rounddown_pow_of_two(params->max_size);

	if (params->insecure_max_entries)
		ht->p.insecure_max_entries =
			rounddown_pow_of_two(params->insecure_max_entries);
	else
		ht->p.insecure_max_entries = ht->p.max_size * 2;

	ht->p.min_size = max(ht->p.min_size, HASH_MIN_SIZE);

	if (params->nelem_hint)
		size = rounded_hashtable_size(&ht->p);

	/* The maximum (not average) chain length grows with the
	 * size of the hash table, at a rate of (log N)/(log log N).
	 * The value of 16 is selected so that even if the hash
	 * table grew to 2^32 you would not expect the maximum
	 * chain length to exceed it unless we are under attack
	 * (or extremely unlucky).
	 *
	 * As this limit is only to detect attacks, we don't need
	 * to set it to a lower value as you'd need the chain
	 * length to vastly exceed 16 to have any real effect
	 * on the system.
	 */
	if (!params->insecure_elasticity)
		ht->elasticity = 16;

	if (params->locks_mul)
		ht->p.locks_mul = roundup_pow_of_two(params->locks_mul);
	else
		ht->p.locks_mul = BUCKET_LOCKS_PER_CPU;

	ht->key_len = ht->p.key_len;
	if (!params->hashfn) {
		ht->p.hashfn = jhash;

		if (!(ht->key_len & (sizeof(u32) - 1))) {
			ht->key_len /= sizeof(u32);
			ht->p.hashfn = rhashtable_jhash2;
		}
	}

	tbl = bucket_table_alloc(ht, size, GFP_KERNEL);
	if (tbl == NULL)
		return -ENOMEM;

	atomic_set(&ht->nelems, 0);

	RCU_INIT_POINTER(ht->tbl, tbl);

	INIT_WORK(&ht->run_work, rht_deferred_worker);

	return 0;
}

/**
 * rhltable_init - initialize a new hash list table
 * @hlt:	hash list table to be initialized
 * @params:	configuration parameters
 *
 * Initializes a new hash list table.
 *
 * See documentation for rhashtable_init.
 */
static inline int rhltable_init(struct rhltable *hlt, const struct rhashtable_params *params)
{
	int err;

	/* No rhlist NULLs marking for now. */
	if (params->nulls_base)
		return -EINVAL;

	err = rhashtable_init(&hlt->ht, params);
	hlt->ht.rhlist = true;
	return err;
}

static void rhashtable_free_one(struct rhashtable *ht, struct rhash_head *obj,
				void (*free_fn)(void *ptr, void *arg),
				void *arg)
{
	struct rhlist_head *list;

	if (!ht->rhlist) {
		free_fn(rht_obj(ht, obj), arg);
		return;
	}

	list = container_of(obj, struct rhlist_head, rhead);
	do {
		obj = &list->rhead;
		list = rht_dereference(list->next, ht);
		free_fn(rht_obj(ht, obj), arg);
	} while (list);
}

/**
 * rhashtable_free_and_destroy - free elements and destroy hash table
 * @ht:		the hash table to destroy
 * @free_fn:	callback to release resources of element
 * @arg:	pointer passed to free_fn
 *
 * Stops an eventual async resize. If defined, invokes free_fn for each
 * element to releasal resources. Please note that RCU protected
 * readers may still be accessing the elements. Releasing of resources
 * must occur in a compatible manner. Then frees the bucket array.
 *
 * This function will eventually sleep to wait for an async resize
 * to complete. The caller is responsible that no further write operations
 * occurs in parallel.
 */
static inline void rhashtable_free_and_destroy(struct rhashtable *ht,
				 void (*free_fn)(void *ptr, void *arg),
				 void *arg)
{
	const struct bucket_table *tbl;
	unsigned int i;

	cancel_work_sync(&ht->run_work);

	mutex_lock(&ht->mutex);
	tbl = rht_dereference(ht->tbl, ht);
	if (free_fn) {
		for (i = 0; i < tbl->size; i++) {
			struct rhash_head *pos, *next;

			for (pos = rht_dereference(tbl->buckets[i], ht),
			     next = !rht_is_a_nulls(pos) ?
					rht_dereference(pos->next, ht) : NULL;
			     !rht_is_a_nulls(pos);
			     pos = next,
			     next = !rht_is_a_nulls(pos) ?
					rht_dereference(pos->next, ht) : NULL)
				rhashtable_free_one(ht, pos, free_fn, arg);
		}
	}

	bucket_table_free(tbl);
	mutex_unlock(&ht->mutex);
}

static inline void rhashtable_destroy(struct rhashtable *ht)
{
	return rhashtable_free_and_destroy(ht, NULL, NULL);
}

#define rht_dereference(p, ht) \
	rcu_dereference_protected(p, lockdep_rht_mutex_is_held(ht))

#define rht_dereference_rcu(p, ht) \
	rcu_dereference_check(p, lockdep_rht_mutex_is_held(ht))

#define rht_dereference_bucket(p, tbl, hash) \
	rcu_dereference_protected(p, lockdep_rht_bucket_is_held(tbl, hash))

#define rht_dereference_bucket_rcu(p, tbl, hash) \
	rcu_dereference_check(p, lockdep_rht_bucket_is_held(tbl, hash))

#define rht_entry(tpos, pos, member) \
	({ tpos = container_of(pos, typeof(*tpos), member); 1; })

/**
 * rht_for_each_continue - continue iterating over hash chain
 * @pos:	the &struct rhash_head to use as a loop cursor.
 * @head:	the previous &struct rhash_head to continue from
 * @tbl:	the &struct bucket_table
 * @hash:	the hash value / bucket index
 */
#define rht_for_each_continue(pos, head, tbl, hash) \
	for (pos = rht_dereference_bucket(head, tbl, hash); \
	     !rht_is_a_nulls(pos); \
	     pos = rht_dereference_bucket((pos)->next, tbl, hash))

/**
 * rht_for_each - iterate over hash chain
 * @pos:	the &struct rhash_head to use as a loop cursor.
 * @tbl:	the &struct bucket_table
 * @hash:	the hash value / bucket index
 */
#define rht_for_each(pos, tbl, hash) \
	rht_for_each_continue(pos, (tbl)->buckets[hash], tbl, hash)

/**
 * rht_for_each_entry_continue - continue iterating over hash chain
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct rhash_head to use as a loop cursor.
 * @head:	the previous &struct rhash_head to continue from
 * @tbl:	the &struct bucket_table
 * @hash:	the hash value / bucket index
 * @member:	name of the &struct rhash_head within the hashable struct.
 */
#define rht_for_each_entry_continue(tpos, pos, head, tbl, hash, member)	\
	for (pos = rht_dereference_bucket(head, tbl, hash);		\
	     (!rht_is_a_nulls(pos)) && rht_entry(tpos, pos, member);	\
	     pos = rht_dereference_bucket((pos)->next, tbl, hash))

/**
 * rht_for_each_entry - iterate over hash chain of given type
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct rhash_head to use as a loop cursor.
 * @tbl:	the &struct bucket_table
 * @hash:	the hash value / bucket index
 * @member:	name of the &struct rhash_head within the hashable struct.
 */
#define rht_for_each_entry(tpos, pos, tbl, hash, member)		\
	rht_for_each_entry_continue(tpos, pos, (tbl)->buckets[hash],	\
				    tbl, hash, member)

/**
 * rht_for_each_entry_safe - safely iterate over hash chain of given type
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct rhash_head to use as a loop cursor.
 * @next:	the &struct rhash_head to use as next in loop cursor.
 * @tbl:	the &struct bucket_table
 * @hash:	the hash value / bucket index
 * @member:	name of the &struct rhash_head within the hashable struct.
 *
 * This hash chain list-traversal primitive allows for the looped code to
 * remove the loop cursor from the list.
 */
#define rht_for_each_entry_safe(tpos, pos, next, tbl, hash, member)	    \
	for (pos = rht_dereference_bucket((tbl)->buckets[hash], tbl, hash), \
	     next = !rht_is_a_nulls(pos) ?				    \
		       rht_dereference_bucket(pos->next, tbl, hash) : NULL; \
	     (!rht_is_a_nulls(pos)) && rht_entry(tpos, pos, member);	    \
	     pos = next,						    \
	     next = !rht_is_a_nulls(pos) ?				    \
		       rht_dereference_bucket(pos->next, tbl, hash) : NULL)

/**
 * rht_for_each_rcu_continue - continue iterating over rcu hash chain
 * @pos:	the &struct rhash_head to use as a loop cursor.
 * @head:	the previous &struct rhash_head to continue from
 * @tbl:	the &struct bucket_table
 * @hash:	the hash value / bucket index
 *
 * This hash chain list-traversal primitive may safely run concurrently with
 * the _rcu mutation primitives such as rhashtable_insert() as long as the
 * traversal is guarded by rcu_read_lock().
 */
#define rht_for_each_rcu_continue(pos, head, tbl, hash)			\
	for (({barrier(); }),						\
	     pos = rht_dereference_bucket_rcu(head, tbl, hash);		\
	     !rht_is_a_nulls(pos);					\
	     pos = rcu_dereference_raw(pos->next))

/**
 * rht_for_each_rcu - iterate over rcu hash chain
 * @pos:	the &struct rhash_head to use as a loop cursor.
 * @tbl:	the &struct bucket_table
 * @hash:	the hash value / bucket index
 *
 * This hash chain list-traversal primitive may safely run concurrently with
 * the _rcu mutation primitives such as rhashtable_insert() as long as the
 * traversal is guarded by rcu_read_lock().
 */
#define rht_for_each_rcu(pos, tbl, hash)				\
	rht_for_each_rcu_continue(pos, (tbl)->buckets[hash], tbl, hash)

/**
 * rht_for_each_entry_rcu_continue - continue iterating over rcu hash chain
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct rhash_head to use as a loop cursor.
 * @head:	the previous &struct rhash_head to continue from
 * @tbl:	the &struct bucket_table
 * @hash:	the hash value / bucket index
 * @member:	name of the &struct rhash_head within the hashable struct.
 *
 * This hash chain list-traversal primitive may safely run concurrently with
 * the _rcu mutation primitives such as rhashtable_insert() as long as the
 * traversal is guarded by rcu_read_lock().
 */
#define rht_for_each_entry_rcu_continue(tpos, pos, head, tbl, hash, member) \
	for (({barrier(); }),						    \
	     pos = rht_dereference_bucket_rcu(head, tbl, hash);		    \
	     (!rht_is_a_nulls(pos)) && rht_entry(tpos, pos, member);	    \
	     pos = rht_dereference_bucket_rcu(pos->next, tbl, hash))

/**
 * rht_for_each_entry_rcu - iterate over rcu hash chain of given type
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct rhash_head to use as a loop cursor.
 * @tbl:	the &struct bucket_table
 * @hash:	the hash value / bucket index
 * @member:	name of the &struct rhash_head within the hashable struct.
 *
 * This hash chain list-traversal primitive may safely run concurrently with
 * the _rcu mutation primitives such as rhashtable_insert() as long as the
 * traversal is guarded by rcu_read_lock().
 */
#define rht_for_each_entry_rcu(tpos, pos, tbl, hash, member)		\
	rht_for_each_entry_rcu_continue(tpos, pos, (tbl)->buckets[hash],\
					tbl, hash, member)

/**
 * rhl_for_each_rcu - iterate over rcu hash table list
 * @pos:	the &struct rlist_head to use as a loop cursor.
 * @list:	the head of the list
 *
 * This hash chain list-traversal primitive should be used on the
 * list returned by rhltable_lookup.
 */
#define rhl_for_each_rcu(pos, list)					\
	for (pos = list; pos; pos = rcu_dereference_raw(pos->next))

/**
 * rhl_for_each_entry_rcu - iterate over rcu hash table list of given type
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct rlist_head to use as a loop cursor.
 * @list:	the head of the list
 * @member:	name of the &struct rlist_head within the hashable struct.
 *
 * This hash chain list-traversal primitive should be used on the
 * list returned by rhltable_lookup.
 */
#define rhl_for_each_entry_rcu(tpos, pos, list, member)			\
	for (pos = list; pos && rht_entry(tpos, pos, member);		\
	     pos = rcu_dereference_raw(pos->next))


/* Internal function, do not use. */
static inline struct rhash_head *__rhashtable_lookup(
	struct rhashtable *ht, const void *key,
	const struct rhashtable_params params)
{
	struct rhashtable_compare_arg arg = {
		.ht = ht,
		.key = key,
	};
	const struct bucket_table *tbl;
	struct rhash_head *he;
	unsigned int hash;

	tbl = rht_dereference_rcu(ht->tbl, ht);
restart:
	hash = rht_key_hashfn(ht, tbl, key, params);
	rht_for_each_rcu(he, tbl, hash) {
		if (params.obj_cmpfn ?
		    params.obj_cmpfn(&arg, rht_obj(ht, he)) :
		    rhashtable_compare(&arg, rht_obj(ht, he)))
			continue;
		return he;
	}

	/* Ensure we see any new tables. */
	smp_rmb();

	tbl = rht_dereference_rcu(tbl->future_tbl, ht);
	if (unlikely(tbl))
		goto restart;

	return NULL;
}

/**
 * rhashtable_lookup - search hash table
 * @ht:		hash table
 * @key:	the pointer to the key
 * @params:	hash table parameters
 *
 * Computes the hash value for the key and traverses the bucket chain looking
 * for a entry with an identical key. The first matching entry is returned.
 *
 * This must only be called under the RCU read lock.
 *
 * Returns the first entry on which the compare function returned true.
 */
static inline void *rhashtable_lookup(
	struct rhashtable *ht, const void *key,
	const struct rhashtable_params params)
{
	struct rhash_head *he = __rhashtable_lookup(ht, key, params);

	return he ? rht_obj(ht, he) : NULL;
}

/**
 * rhashtable_lookup_fast - search hash table, without RCU read lock
 * @ht:		hash table
 * @key:	the pointer to the key
 * @params:	hash table parameters
 *
 * Computes the hash value for the key and traverses the bucket chain looking
 * for a entry with an identical key. The first matching entry is returned.
 *
 * Only use this function when you have other mechanisms guaranteeing
 * that the object won't go away after the RCU read lock is released.
 *
 * Returns the first entry on which the compare function returned true.
 */
static inline void *rhashtable_lookup_fast(
	struct rhashtable *ht, const void *key,
	const struct rhashtable_params params)
{
	void *obj;

	rcu_read_lock();
	obj = rhashtable_lookup(ht, key, params);
	rcu_read_unlock();

	return obj;
}

/**
 * rhltable_lookup - search hash list table
 * @hlt:	hash table
 * @key:	the pointer to the key
 * @params:	hash table parameters
 *
 * Computes the hash value for the key and traverses the bucket chain looking
 * for a entry with an identical key.  All matching entries are returned
 * in a list.
 *
 * This must only be called under the RCU read lock.
 *
 * Returns the list of entries that match the given key.
 */
static inline struct rhlist_head *rhltable_lookup(
	struct rhltable *hlt, const void *key,
	const struct rhashtable_params params)
{
	struct rhash_head *he = __rhashtable_lookup(&hlt->ht, key, params);

	return he ? container_of(he, struct rhlist_head, rhead) : NULL;
}

/* Internal function, please use rhashtable_insert_fast() instead. This
 * function returns the existing element already in hashes in there is a clash,
 * otherwise it returns an error via ERR_PTR().
 */
static inline void *__rhashtable_insert_fast(
	struct rhashtable *ht, const void *key, struct rhash_head *obj,
	const struct rhashtable_params params, bool rhlist)
{
	struct rhashtable_compare_arg arg = {
		.ht = ht,
		.key = key,
	};
	struct rhash_head __rcu **pprev;
	struct bucket_table *tbl;
	struct rhash_head *head;
	spinlock_t *lock;
	unsigned int hash;
	int elasticity;
	void *data;

	rcu_read_lock();

	tbl = rht_dereference_rcu(ht->tbl, ht);
	hash = rht_head_hashfn(ht, tbl, obj, params);
	lock = rht_bucket_lock(tbl, hash);
	spin_lock_bh(lock);

	if (unlikely(rht_dereference_bucket(tbl->future_tbl, tbl, hash))) {
slow_path:
		spin_unlock_bh(lock);
		rcu_read_unlock();
		return rhashtable_insert_slow(ht, key, obj);
	}

	elasticity = ht->elasticity;
	pprev = &tbl->buckets[hash];
	rht_for_each(head, tbl, hash) {
		struct rhlist_head *plist;
		struct rhlist_head *list;

		elasticity--;
		if (!key ||
		    (params.obj_cmpfn ?
		     params.obj_cmpfn(&arg, rht_obj(ht, head)) :
		     rhashtable_compare(&arg, rht_obj(ht, head))))
			continue;

		data = rht_obj(ht, head);

		if (!rhlist)
			goto out;


		list = container_of(obj, struct rhlist_head, rhead);
		plist = container_of(head, struct rhlist_head, rhead);

		RCU_INIT_POINTER(list->next, plist);
		head = rht_dereference_bucket(head->next, tbl, hash);
		RCU_INIT_POINTER(list->rhead.next, head);
		rcu_assign_pointer(*pprev, obj);

		goto good;
	}

	if (elasticity <= 0)
		goto slow_path;

	data = ERR_PTR(-E2BIG);
	if (unlikely(rht_grow_above_max(ht, tbl)))
		goto out;

	if (unlikely(rht_grow_above_100(ht, tbl)))
		goto slow_path;

	head = rht_dereference_bucket(tbl->buckets[hash], tbl, hash);

	RCU_INIT_POINTER(obj->next, head);
	if (rhlist) {
		struct rhlist_head *list;

		list = container_of(obj, struct rhlist_head, rhead);
		RCU_INIT_POINTER(list->next, NULL);
	}

	rcu_assign_pointer(tbl->buckets[hash], obj);

	atomic_inc(&ht->nelems);
	if (rht_grow_above_75(ht, tbl))
		schedule_work(&ht->run_work);

good:
	data = NULL;

out:
	spin_unlock_bh(lock);
	rcu_read_unlock();

	return data;
}

/**
 * rhashtable_insert_fast - insert object into hash table
 * @ht:		hash table
 * @obj:	pointer to hash head inside object
 * @params:	hash table parameters
 *
 * Will take a per bucket spinlock to protect against mutual mutations
 * on the same bucket. Multiple insertions may occur in parallel unless
 * they map to the same bucket lock.
 *
 * It is safe to call this function from atomic context.
 *
 * Will trigger an automatic deferred table resizing if the size grows
 * beyond the watermark indicated by grow_decision() which can be passed
 * to rhashtable_init().
 */
static inline int rhashtable_insert_fast(
	struct rhashtable *ht, struct rhash_head *obj,
	const struct rhashtable_params params)
{
	void *ret;

	ret = __rhashtable_insert_fast(ht, NULL, obj, params, false);
	if (IS_ERR(ret))
		return PTR_ERR(ret);

	return ret == NULL ? 0 : -EEXIST;
}

/**
 * rhltable_insert_key - insert object into hash list table
 * @hlt:	hash list table
 * @key:	the pointer to the key
 * @list:	pointer to hash list head inside object
 * @params:	hash table parameters
 *
 * Will take a per bucket spinlock to protect against mutual mutations
 * on the same bucket. Multiple insertions may occur in parallel unless
 * they map to the same bucket lock.
 *
 * It is safe to call this function from atomic context.
 *
 * Will trigger an automatic deferred table resizing if the size grows
 * beyond the watermark indicated by grow_decision() which can be passed
 * to rhashtable_init().
 */
static inline int rhltable_insert_key(
	struct rhltable *hlt, const void *key, struct rhlist_head *list,
	const struct rhashtable_params params)
{
	return PTR_ERR(__rhashtable_insert_fast(&hlt->ht, key, &list->rhead,
						params, true));
}

/**
 * rhltable_insert - insert object into hash list table
 * @hlt:	hash list table
 * @list:	pointer to hash list head inside object
 * @params:	hash table parameters
 *
 * Will take a per bucket spinlock to protect against mutual mutations
 * on the same bucket. Multiple insertions may occur in parallel unless
 * they map to the same bucket lock.
 *
 * It is safe to call this function from atomic context.
 *
 * Will trigger an automatic deferred table resizing if the size grows
 * beyond the watermark indicated by grow_decision() which can be passed
 * to rhashtable_init().
 */
static inline int rhltable_insert(
	struct rhltable *hlt, struct rhlist_head *list,
	const struct rhashtable_params params)
{
	const char *key = rht_obj(&hlt->ht, &list->rhead);

	key += params.key_offset;

	return rhltable_insert_key(hlt, key, list, params);
}

/**
 * rhashtable_lookup_insert_fast - lookup and insert object into hash table
 * @ht:		hash table
 * @obj:	pointer to hash head inside object
 * @params:	hash table parameters
 *
 * Locks down the bucket chain in both the old and new table if a resize
 * is in progress to ensure that writers can't remove from the old table
 * and can't insert to the new table during the atomic operation of search
 * and insertion. Searches for duplicates in both the old and new table if
 * a resize is in progress.
 *
 * This lookup function may only be used for fixed key hash table (key_len
 * parameter set). It will BUG() if used inappropriately.
 *
 * It is safe to call this function from atomic context.
 *
 * Will trigger an automatic deferred table resizing if the size grows
 * beyond the watermark indicated by grow_decision() which can be passed
 * to rhashtable_init().
 */
static inline int rhashtable_lookup_insert_fast(
	struct rhashtable *ht, struct rhash_head *obj,
	const struct rhashtable_params params)
{
	const char *key = rht_obj(ht, obj);
	void *ret;

	BUG_ON(ht->p.obj_hashfn);

	ret = __rhashtable_insert_fast(ht, key + ht->p.key_offset, obj, params,
				       false);
	if (IS_ERR(ret))
		return PTR_ERR(ret);

	return ret == NULL ? 0 : -EEXIST;
}

/**
 * rhashtable_lookup_insert_key - search and insert object to hash table
 *				  with explicit key
 * @ht:		hash table
 * @key:	key
 * @obj:	pointer to hash head inside object
 * @params:	hash table parameters
 *
 * Locks down the bucket chain in both the old and new table if a resize
 * is in progress to ensure that writers can't remove from the old table
 * and can't insert to the new table during the atomic operation of search
 * and insertion. Searches for duplicates in both the old and new table if
 * a resize is in progress.
 *
 * Lookups may occur in parallel with hashtable mutations and resizing.
 *
 * Will trigger an automatic deferred table resizing if the size grows
 * beyond the watermark indicated by grow_decision() which can be passed
 * to rhashtable_init().
 *
 * Returns zero on success.
 */
static inline int rhashtable_lookup_insert_key(
	struct rhashtable *ht, const void *key, struct rhash_head *obj,
	const struct rhashtable_params params)
{
	void *ret;

	BUG_ON(!ht->p.obj_hashfn || !key);

	ret = __rhashtable_insert_fast(ht, key, obj, params, false);
	if (IS_ERR(ret))
		return PTR_ERR(ret);

	return ret == NULL ? 0 : -EEXIST;
}

/**
 * rhashtable_lookup_get_insert_key - lookup and insert object into hash table
 * @ht:		hash table
 * @obj:	pointer to hash head inside object
 * @params:	hash table parameters
 * @data:	pointer to element data already in hashes
 *
 * Just like rhashtable_lookup_insert_key(), but this function returns the
 * object if it exists, NULL if it does not and the insertion was successful,
 * and an ERR_PTR otherwise.
 */
static inline void *rhashtable_lookup_get_insert_key(
	struct rhashtable *ht, const void *key, struct rhash_head *obj,
	const struct rhashtable_params params)
{
	BUG_ON(!ht->p.obj_hashfn || !key);

	return __rhashtable_insert_fast(ht, key, obj, params, false);
}

/* Internal function, please use rhashtable_remove_fast() instead */
static inline int __rhashtable_remove_fast_one(
	struct rhashtable *ht, struct bucket_table *tbl,
	struct rhash_head *obj, const struct rhashtable_params params,
	bool rhlist)
{
	struct rhash_head __rcu **pprev;
	struct rhash_head *he;
	spinlock_t * lock;
	unsigned int hash;
	int err = -ENOENT;

	hash = rht_head_hashfn(ht, tbl, obj, params);
	lock = rht_bucket_lock(tbl, hash);

	spin_lock_bh(lock);

	pprev = &tbl->buckets[hash];
	rht_for_each(he, tbl, hash) {
		struct rhlist_head *list;

		list = container_of(he, struct rhlist_head, rhead);

		if (he != obj) {
			struct rhlist_head __rcu **lpprev;

			pprev = &he->next;

			if (!rhlist)
				continue;

			do {
				lpprev = &list->next;
				list = rht_dereference_bucket(list->next,
							      tbl, hash);
			} while (list && obj != &list->rhead);

			if (!list)
				continue;

			list = rht_dereference_bucket(list->next, tbl, hash);
			RCU_INIT_POINTER(*lpprev, list);
			err = 0;
			break;
		}

		obj = rht_dereference_bucket(obj->next, tbl, hash);
		err = 1;

		if (rhlist) {
			list = rht_dereference_bucket(list->next, tbl, hash);
			if (list) {
				RCU_INIT_POINTER(list->rhead.next, obj);
				obj = &list->rhead;
				err = 0;
			}
		}

		rcu_assign_pointer(*pprev, obj);
		break;
	}

	spin_unlock_bh(lock);

	if (err > 0) {
		atomic_dec(&ht->nelems);
		if (unlikely(ht->p.automatic_shrinking &&
			     rht_shrink_below_30(ht, tbl)))
			schedule_work(&ht->run_work);
		err = 0;
	}

	return err;
}

/* Internal function, please use rhashtable_remove_fast() instead */
static inline int __rhashtable_remove_fast(
	struct rhashtable *ht, struct rhash_head *obj,
	const struct rhashtable_params params, bool rhlist)
{
	struct bucket_table *tbl;
	int err;

	rcu_read_lock();

	tbl = rht_dereference_rcu(ht->tbl, ht);

	/* Because we have already taken (and released) the bucket
	 * lock in old_tbl, if we find that future_tbl is not yet
	 * visible then that guarantees the entry to still be in
	 * the old tbl if it exists.
	 */
	while ((err = __rhashtable_remove_fast_one(ht, tbl, obj, params,
						   rhlist)) &&
	       (tbl = rht_dereference_rcu(tbl->future_tbl, ht)))
		;

	rcu_read_unlock();

	return err;
}

/**
 * rhashtable_remove_fast - remove object from hash table
 * @ht:		hash table
 * @obj:	pointer to hash head inside object
 * @params:	hash table parameters
 *
 * Since the hash chain is single linked, the removal operation needs to
 * walk the bucket chain upon removal. The removal operation is thus
 * considerable slow if the hash table is not correctly sized.
 *
 * Will automatically shrink the table via rhashtable_expand() if the
 * shrink_decision function specified at rhashtable_init() returns true.
 *
 * Returns zero on success, -ENOENT if the entry could not be found.
 */
static inline int rhashtable_remove_fast(
	struct rhashtable *ht, struct rhash_head *obj,
	const struct rhashtable_params params)
{
	return __rhashtable_remove_fast(ht, obj, params, false);
}

/**
 * rhltable_remove - remove object from hash list table
 * @hlt:	hash list table
 * @list:	pointer to hash list head inside object
 * @params:	hash table parameters
 *
 * Since the hash chain is single linked, the removal operation needs to
 * walk the bucket chain upon removal. The removal operation is thus
 * considerable slow if the hash table is not correctly sized.
 *
 * Will automatically shrink the table via rhashtable_expand() if the
 * shrink_decision function specified at rhashtable_init() returns true.
 *
 * Returns zero on success, -ENOENT if the entry could not be found.
 */
static inline int rhltable_remove(
	struct rhltable *hlt, struct rhlist_head *list,
	const struct rhashtable_params params)
{
	return __rhashtable_remove_fast(&hlt->ht, &list->rhead, params, true);
}

/* Internal function, please use rhashtable_replace_fast() instead */
static inline int __rhashtable_replace_fast(
	struct rhashtable *ht, struct bucket_table *tbl,
	struct rhash_head *obj_old, struct rhash_head *obj_new,
	const struct rhashtable_params params)
{
	struct rhash_head __rcu **pprev;
	struct rhash_head *he;
	spinlock_t *lock;
	unsigned int hash;
	int err = -ENOENT;

	/* Minimally, the old and new objects must have same hash
	 * (which should mean identifiers are the same).
	 */
	hash = rht_head_hashfn(ht, tbl, obj_old, params);
	if (hash != rht_head_hashfn(ht, tbl, obj_new, params))
		return -EINVAL;

	lock = rht_bucket_lock(tbl, hash);

	spin_lock_bh(lock);

	pprev = &tbl->buckets[hash];
	rht_for_each(he, tbl, hash) {
		if (he != obj_old) {
			pprev = &he->next;
			continue;
		}

		rcu_assign_pointer(obj_new->next, obj_old->next);
		rcu_assign_pointer(*pprev, obj_new);
		err = 0;
		break;
	}

	spin_unlock_bh(lock);

	return err;
}

/**
 * rhashtable_replace_fast - replace an object in hash table
 * @ht:		hash table
 * @obj_old:	pointer to hash head inside object being replaced
 * @obj_new:	pointer to hash head inside object which is new
 * @params:	hash table parameters
 *
 * Replacing an object doesn't affect the number of elements in the hash table
 * or bucket, so we don't need to worry about shrinking or expanding the
 * table here.
 *
 * Returns zero on success, -ENOENT if the entry could not be found,
 * -EINVAL if hash is not the same for the old and new objects.
 */
static inline int rhashtable_replace_fast(
	struct rhashtable *ht, struct rhash_head *obj_old,
	struct rhash_head *obj_new,
	const struct rhashtable_params params)
{
	struct bucket_table *tbl;
	int err;

	rcu_read_lock();

	tbl = rht_dereference_rcu(ht->tbl, ht);

	/* Because we have already taken (and released) the bucket
	 * lock in old_tbl, if we find that future_tbl is not yet
	 * visible then that guarantees the entry to still be in
	 * the old tbl if it exists.
	 */
	while ((err = __rhashtable_replace_fast(ht, tbl, obj_old,
						obj_new, params)) &&
	       (tbl = rht_dereference_rcu(tbl->future_tbl, ht)))
		;

	rcu_read_unlock();

	return err;
}

/* Obsolete function, do not use in new code. */
static inline int rhashtable_walk_init(struct rhashtable *ht,
				       struct rhashtable_iter *iter, gfp_t gfp)
{
	rhashtable_walk_enter(ht, iter);
	return 0;
}

/**
 * rhltable_walk_enter - Initialise an iterator
 * @hlt:	Table to walk over
 * @iter:	Hash table Iterator
 *
 * This function prepares a hash table walk.
 *
 * Note that if you restart a walk after rhashtable_walk_stop you
 * may see the same object twice.  Also, you may miss objects if
 * there are removals in between rhashtable_walk_stop and the next
 * call to rhashtable_walk_start.
 *
 * For a completely stable walk you should construct your own data
 * structure outside the hash table.
 *
 * This function may sleep so you must not call it from interrupt
 * context or with spin locks held.
 *
 * You must call rhashtable_walk_exit after this function returns.
 */
static inline void rhltable_walk_enter(struct rhltable *hlt,
				       struct rhashtable_iter *iter)
{
	return rhashtable_walk_enter(&hlt->ht, iter);
}

/**
 * rhltable_free_and_destroy - free elements and destroy hash list table
 * @hlt:	the hash list table to destroy
 * @free_fn:	callback to release resources of element
 * @arg:	pointer passed to free_fn
 *
 * See documentation for rhashtable_free_and_destroy.
 */
static inline void rhltable_free_and_destroy(struct rhltable *hlt,
					     void (*free_fn)(void *ptr,
							     void *arg),
					     void *arg)
{
	return rhashtable_free_and_destroy(&hlt->ht, free_fn, arg);
}

static inline void rhltable_destroy(struct rhltable *hlt)
{
	return rhltable_free_and_destroy(hlt, NULL, NULL);
}

#endif /* _MLNX_LINUX_RHASHTABLE_H */
