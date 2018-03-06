/*
 * Copyright (c) 2018 Mellanox Technologies.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef MLX_COMPAT_H
#define MLX_COMPAT_H

#include <linux/uaccess.h>
#define uaccess_kernel() segment_eq(get_fs(), KERNEL_DS)

#include <net/netlink.h>
#define nla_parse(p1, p2, p3, p4, p5, p6) nla_parse(p1, p2, p3, p4, p5)
#define nlmsg_parse(p1, p2, p3, p4, p5, p6) nlmsg_parse(p1, p2, p3, p4, p5)
#define nla_put_u64_64bit(p1, p2, p3, p4) nla_put_u64(p1, p2, p3)
#define nlmsg_validate(p1, p2, p3, p4, p5) nlmsg_validate(p1, p2, p3, p4)

#include <linux/cdev.h>
static inline void cdev_set_parent(struct cdev *p, struct kobject *kobj)
{
	WARN_ON(!kobj->state_initialized);
	p->kobj.parent = kobj;
}
static inline int cdev_device_add(struct cdev *cdev, struct device *dev)
{
	int rc = 0;

	if (dev->devt) {
		cdev_set_parent(cdev, &dev->kobj);

		rc = cdev_add(cdev, dev->devt, 1);
		if (rc)
			return rc;
	}

	rc = device_add(dev);
	if (rc)
		cdev_del(cdev);

	return rc;
}
static inline void cdev_device_del(struct cdev *cdev, struct device *dev)
{
	device_del(dev);
	if (dev->devt)
		cdev_del(cdev);
}

#include <linux/pci_ids.h>
#ifndef PCI_VENDOR_ID_MELLANOX
#define PCI_VENDOR_ID_MELLANOX		0x15b3
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_CONNECTX3
#define PCI_DEVICE_ID_MELLANOX_CONNECTX3	0x1003
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_CONNECTX3_PRO
#define PCI_DEVICE_ID_MELLANOX_CONNECTX3_PRO	0x1007
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_CONNECTIB
#define PCI_DEVICE_ID_MELLANOX_CONNECTIB	0x1011
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_CONNECTX4
#define PCI_DEVICE_ID_MELLANOX_CONNECTX4	0x1013
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_CONNECTX4_LX
#define PCI_DEVICE_ID_MELLANOX_CONNECTX4_LX	0x1015
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_TAVOR
#define PCI_DEVICE_ID_MELLANOX_TAVOR		0x5a44
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_TAVOR_BRIDGE
#define PCI_DEVICE_ID_MELLANOX_TAVOR_BRIDGE	0x5a46
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_SINAI_OLD
#define PCI_DEVICE_ID_MELLANOX_SINAI_OLD	0x5e8c
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_SINAI
#define PCI_DEVICE_ID_MELLANOX_SINAI		0x6274
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_ARBEL_COMPAT
#define PCI_DEVICE_ID_MELLANOX_ARBEL_COMPAT	0x6278
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_ARBEL
#define PCI_DEVICE_ID_MELLANOX_ARBEL		0x6282
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_HERMON_SDR
#define PCI_DEVICE_ID_MELLANOX_HERMON_SDR	0x6340
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_HERMON_DDR
#define PCI_DEVICE_ID_MELLANOX_HERMON_DDR	0x634a
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_HERMON_QDR
#define PCI_DEVICE_ID_MELLANOX_HERMON_QDR	0x6354
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_HERMON_EN
#define PCI_DEVICE_ID_MELLANOX_HERMON_EN	0x6368
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_CONNECTX_EN
#define PCI_DEVICE_ID_MELLANOX_CONNECTX_EN	0x6372
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_HERMON_DDR_GEN2
#define PCI_DEVICE_ID_MELLANOX_HERMON_DDR_GEN2	0x6732
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_HERMON_QDR_GEN2
#define PCI_DEVICE_ID_MELLANOX_HERMON_QDR_GEN2	0x673c
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_CONNECTX_EN_5_GEN2
#define PCI_DEVICE_ID_MELLANOX_CONNECTX_EN_5_GEN2 0x6746
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_HERMON_EN_GEN2
#define PCI_DEVICE_ID_MELLANOX_HERMON_EN_GEN2	0x6750
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_CONNECTX_EN_T_GEN2
#define PCI_DEVICE_ID_MELLANOX_CONNECTX_EN_T_GEN2 0x675a
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_CONNECTX_EN_GEN2
#define PCI_DEVICE_ID_MELLANOX_CONNECTX_EN_GEN2	0x6764
#endif

#ifndef PCI_DEVICE_ID_MELLANOX_CONNECTX2
#define PCI_DEVICE_ID_MELLANOX_CONNECTX2	0x676e
#endif

#include <linux/string.h>
#define strnicmp strncasecmp

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
static inline void *kvmalloc_array(size_t n, size_t size,...) {
	void *rtn;

	rtn = kcalloc(n, size, GFP_KERNEL | __GFP_NOWARN);
	if (!rtn)
		rtn = vzalloc(n * size);
	return rtn;
}
static inline void *kvmalloc_node(size_t size, gfp_t flags, int node) {
	void *rtn;

	rtn = kmalloc_node(size, GFP_KERNEL | __GFP_NOWARN, node);
	if (!rtn)
		rtn = vmalloc(size);
	return rtn;
}

//#include <linux/net_tstamp.h>
#define HWTSTAMP_FILTER_NTP_ALL	15


#include <linux/netdev_features.h>
#define NETIF_F_CSUM_MASK	(NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | \
				NETIF_F_HW_CSUM)

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
static inline void *kvzalloc(unsigned long size,...) {
	void *rtn;

	rtn = kzalloc(size, GFP_KERNEL | __GFP_NOWARN);
	if (!rtn)
		rtn = vzalloc(size);
	return rtn;
}

#include <linux/skbuff.h>
static inline void *skb_put_zero(struct sk_buff *skb, unsigned int len)
{
	void *tmp = skb_put(skb, len);

	memset(tmp, 0, len);

	return tmp;
}

#include <net/vxlan.h>
#if IS_ENABLED(CONFIG_VXLAN)
#define HAVE_KERNEL_WITH_VXLAN_SUPPORT_ON
#endif

#include <linux/rcupdate.h>
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


#endif /* MLX_COMPAT_H */
