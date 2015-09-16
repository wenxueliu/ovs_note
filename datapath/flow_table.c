/*
 * Copyright (c) 2007-2013 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include "flow.h"
#include "datapath.h"
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <net/llc_pdu.h>
#include <linux/kernel.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/llc.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/rcupdate.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sctp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/rculist.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ndisc.h>

#include "vlan.h"

#define TBL_MIN_BUCKETS		1024
#define MASK_ARRAY_SIZE_MIN	16
#define REHASH_INTERVAL		(10 * 60 * HZ)

#define MC_HASH_SHIFT		8
#define MC_HASH_ENTRIES		(1u << MC_HASH_SHIFT)
#define MC_HASH_SEGS		((sizeof(uint32_t) * 8) / MC_HASH_SHIFT)

//新建流表都从 flow_cache 分配的内存中获取
static struct kmem_cache *flow_cache;
//NUMA 节点的统计信息从 flow_stats_cache 分配的内存中获取
struct kmem_cache *flow_stats_cache __read_mostly;

static u16 range_n_bytes(const struct sw_flow_key_range *range)
{
	return range->end - range->start;
}

//将 src 与 mask 掩码后的赋值给 dst
void ovs_flow_mask_key(struct sw_flow_key *dst, const struct sw_flow_key *src,
		       const struct sw_flow_mask *mask)
{
	const long *m = (const long *)((const u8 *)&mask->key +
				mask->range.start);
	const long *s = (const long *)((const u8 *)src +
				mask->range.start);
	long *d = (long *)((u8 *)dst + mask->range.start);
	int i;

	/* The memory outside of the 'mask->range' are not set since
	 * further operations on 'dst' only uses contents within
	 * 'mask->range'.
	 */
	for (i = 0; i < range_n_bytes(&mask->range); i += sizeof(long))
		*d++ = *s++ & *m++;
}

/*
 * 从 flow_cache 中分配以一条 flow
 * flow = kmem_cache_alloc(flow_cache, GFP_KERNEL);
 * flow->sf_acts = NULL;
 * flow->mask = NULL;
 * flow->id.ufid_len = 0;
 * flow->id.unmasked_key = NULL;
 * flow->stats_last_writer = NUMA_NO_NODE;
 * NOTE: 没有初始化的成员 flow_table, ufid_table, key
 */
struct sw_flow *ovs_flow_alloc(void)
{
	struct sw_flow *flow;
	struct flow_stats *stats;
	int node;

	flow = kmem_cache_alloc(flow_cache, GFP_KERNEL);
	if (!flow)
		return ERR_PTR(-ENOMEM);

	flow->sf_acts = NULL;
	flow->mask = NULL;
	flow->id.ufid_len = 0;
	flow->id.unmasked_key = NULL;
	flow->stats_last_writer = NUMA_NO_NODE;

	/* Initialize the default stat node. */
	stats = kmem_cache_alloc_node(flow_stats_cache,
				      GFP_KERNEL | __GFP_ZERO, 0);
	if (!stats)
		goto err;

	spin_lock_init(&stats->lock);

	RCU_INIT_POINTER(flow->stats[0], stats);

	for_each_node(node)
		if (node != 0)
			RCU_INIT_POINTER(flow->stats[node], NULL);

	return flow;
err:
	kmem_cache_free(flow_cache, flow);
	return ERR_PTR(-ENOMEM);
}

int ovs_flow_tbl_count(const struct flow_table *table)
{
	return table->count;
}

//申请 n_buckets 个链表头, 并且初始化
static struct flex_array *alloc_buckets(unsigned int n_buckets)
{
	struct flex_array *buckets;
	int i, err;

	buckets = flex_array_alloc(sizeof(struct hlist_head),
				   n_buckets, GFP_KERNEL);
	if (!buckets)
		return NULL;

	err = flex_array_prealloc(buckets, 0, n_buckets, GFP_KERNEL);
	if (err) {
		flex_array_free(buckets);
		return NULL;
	}

	for (i = 0; i < n_buckets; i++)
		INIT_HLIST_HEAD((struct hlist_head *)
					flex_array_get(buckets, i));

	return buckets;
}

static void flow_free(struct sw_flow *flow)
{
	int node;

	if (ovs_identifier_is_key(&flow->id))
		kfree(flow->id.unmasked_key);
	kfree(rcu_dereference_raw(flow->sf_acts));
	for_each_node(node)
		if (flow->stats[node])
			kmem_cache_free(flow_stats_cache,
					rcu_dereference_raw(flow->stats[node]));
	kmem_cache_free(flow_cache, flow);
}

static void rcu_free_flow_callback(struct rcu_head *rcu)
{
	struct sw_flow *flow = container_of(rcu, struct sw_flow, rcu);

	flow_free(flow);
}

static void rcu_free_sw_flow_mask_cb(struct rcu_head *rcu)
{
	struct sw_flow_mask *mask = container_of(rcu, struct sw_flow_mask, rcu);

	kfree(mask);
}

void ovs_flow_free(struct sw_flow *flow, bool deferred)
{
	if (!flow)
		return;

	if (deferred)
		call_rcu(&flow->rcu, rcu_free_flow_callback);
	else
		flow_free(flow);
}

static void free_buckets(struct flex_array *buckets)
{
	flex_array_free(buckets);
}


static void __table_instance_destroy(struct table_instance *ti)
{
	free_buckets(ti->buckets);
	kfree(ti);
}

//分配 new_size 个 flex_array 给 table->ti->buckets, 并初始化
static struct table_instance *table_instance_alloc(int new_size)
{
	struct table_instance *ti = kmalloc(sizeof(*ti), GFP_KERNEL);

	if (!ti)
		return NULL;

	ti->buckets = alloc_buckets(new_size);

	if (!ti->buckets) {
		kfree(ti);
		return NULL;
	}
	ti->n_buckets = new_size;
	ti->node_ver = 0;
	ti->keep_flows = false;
	get_random_bytes(&ti->hash_seed, sizeof(u32));

	return ti;
}

static void mask_array_rcu_cb(struct rcu_head *rcu)
{
	struct mask_array *ma = container_of(rcu, struct mask_array, rcu);

	kfree(ma);
}

//为 table->mask_array 分配内存及初始化
static struct mask_array *tbl_mask_array_alloc(int size)
{
	struct mask_array *new;

	size = max(MASK_ARRAY_SIZE_MIN, size);
	new = kzalloc(sizeof(struct mask_array) +
		      sizeof(struct sw_flow_mask *) * size, GFP_KERNEL);
	if (!new)
		return NULL;

	new->count = 0;
	new->max = size;

	return new;
}

//tbl->mask_array 的空间重新分配大小为 size, 并将旧数据拷贝到新的 masks 中. 
//主要用于 tbl 空间扩容.
static int tbl_mask_array_realloc(struct flow_table *tbl, int size)
{
	struct mask_array *old;
	struct mask_array *new;

	new = tbl_mask_array_alloc(size);
	if (!new)
		return -ENOMEM;

	old = ovsl_dereference(tbl->mask_array);
	if (old) {
		int i, count = 0;

        //仅将不为 null 的赋值到 new
		for (i = 0; i < old->max; i++) {
			if (ovsl_dereference(old->masks[i]))
				new->masks[count++] = old->masks[i];
		}

		new->count = count;
	}
	rcu_assign_pointer(tbl->mask_array, new);

	if (old)
		call_rcu(&old->rcu, mask_array_rcu_cb);

	return 0;
}

/*
 * 初始化 flow_table
 * //TBL_MIN_BUCKETS=1024
 * table->ti = kmalloc(sizeof(*ti), GFP_KERNEL);
 * table->ti->buckets = alloc_buckets(TBL_MIN_BUCKETS)
 * table->ti->n_buckets = TBL_MIN_BUCKETS;
 * table->ti->node_ver = 0;
 * table->ti->keep_flows = false;
 * get_random_bytes(&table->ti->hash_seed, sizeof(u32));
 *
 * //TBL_MIN_BUCKETS=1024
 * table->ufid_ti = kmalloc(sizeof(*ti), GFP_KERNEL)
 * table->ufid_ti->buckets = alloc_buckets(new_size);
 * table->ufid_ti->n_buckets = TBL_MIN_BUCKETS;
 * table->ufid_ti->node_ver = 0;
 * table->ufid_ti->keep_flows = false;
 * get_random_bytes(&table->ufid_ti->hash_seed, sizeof(u32));
 *
 * //MASK_ARRAY_SIZE_MIN=16
 * table->mask_array = new  kzalloc(sizeof(struct mask_array) +
 * 	      sizeof(struct sw_flow_mask *) * MASK_ARRAY_SIZE_MIN, GFP_KERNEL);
 * table->mask_array->count = 0
 * table->mask_array->max = MASK_ARRAY_SIZE_MIN
 *
 * table->last_rehash = jiffies
 * table->count = 0;
 * table->ufid_count = 0;
 */
int ovs_flow_tbl_init(struct flow_table *table)
{
	struct table_instance *ti, *ufid_ti;
	struct mask_array *ma;

	table->mask_cache = __alloc_percpu(sizeof(struct mask_cache_entry) *
					  MC_HASH_ENTRIES, __alignof__(struct mask_cache_entry));
	if (!table->mask_cache)
		return -ENOMEM;

	ma = tbl_mask_array_alloc(MASK_ARRAY_SIZE_MIN);
	if (!ma)
		goto free_mask_cache;

	ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!ti)
		goto free_mask_array;

	ufid_ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!ufid_ti)
		goto free_ti;

	rcu_assign_pointer(table->ti, ti);
	rcu_assign_pointer(table->ufid_ti, ufid_ti);
	rcu_assign_pointer(table->mask_array, ma);
    //系统最近一次启动以来的时钟滴答数
	table->last_rehash = jiffies;
	table->count = 0;
	table->ufid_count = 0;
	return 0;

free_ti:
	__table_instance_destroy(ti);
free_mask_array:
	kfree(ma);
free_mask_cache:
	free_percpu(table->mask_cache);
	return -ENOMEM;
}

static void flow_tbl_destroy_rcu_cb(struct rcu_head *rcu)
{
	struct table_instance *ti = container_of(rcu, struct table_instance, rcu);

	__table_instance_destroy(ti);
}

static void table_instance_destroy(struct table_instance *ti,
				   struct table_instance *ufid_ti,
				   bool deferred)
{
	int i;

	if (!ti)
		return;

	BUG_ON(!ufid_ti);
	if (ti->keep_flows)
		goto skip_flows;

	for (i = 0; i < ti->n_buckets; i++) {
		struct sw_flow *flow;
		struct hlist_head *head = flex_array_get(ti->buckets, i);
		struct hlist_node *n;
		int ver = ti->node_ver;
		int ufid_ver = ufid_ti->node_ver;

		hlist_for_each_entry_safe(flow, n, head, flow_table.node[ver]) {
			hlist_del_rcu(&flow->flow_table.node[ver]);
			if (ovs_identifier_is_ufid(&flow->id))
				hlist_del_rcu(&flow->ufid_table.node[ufid_ver]);
			ovs_flow_free(flow, deferred);
		}
	}

skip_flows:
	if (deferred) {
		call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
		call_rcu(&ufid_ti->rcu, flow_tbl_destroy_rcu_cb);
	} else {
		__table_instance_destroy(ti);
		__table_instance_destroy(ufid_ti);
	}
}

/* No need for locking this function is called from RCU callback or
 * error path.
 */
void ovs_flow_tbl_destroy(struct flow_table *table)
{
	struct table_instance *ti = rcu_dereference_raw(table->ti);
	struct table_instance *ufid_ti = rcu_dereference_raw(table->ufid_ti);

	free_percpu(table->mask_cache);
	kfree(rcu_dereference_raw(table->mask_array));
	table_instance_destroy(ti, ufid_ti, false);
}

/*
 * 找到 ti->buckets 中索引为 bucket, 链表索引为 last 的 flow
 *
 *
 * TODO:这里遍历的代价太大, 待优化
 */
struct sw_flow *ovs_flow_tbl_dump_next(struct table_instance *ti,
				       u32 *bucket, u32 *last)
{
	struct sw_flow *flow;
	struct hlist_head *head;
	int ver;
	int i;

	ver = ti->node_ver;
	while (*bucket < ti->n_buckets) {
		i = 0;
		head = flex_array_get(ti->buckets, *bucket);
		hlist_for_each_entry_rcu(flow, head, flow_table.node[ver]) {
			if (i < *last) {
				i++;
				continue;
			}
			*last = i + 1;
			return flow;
		}
		(*bucket)++;
		*last = 0;
	}

	return NULL;
}

static struct hlist_head *find_bucket(struct table_instance *ti, u32 hash)
{
	hash = jhash_1word(hash, ti->hash_seed);
	return flex_array_get(ti->buckets,
				(hash & (ti->n_buckets - 1)));
}

// flow->flow_table.node[ti->node_ver] 加入 ti->buckets[jhash_1word(jhash(flow->key, flow->mask->range->end - flow->mask->range->start, 0), ti->hash_seed) & (ti->n_buckets - 1)] 的链表中
static void table_instance_insert(struct table_instance *ti,
				  struct sw_flow *flow)
{
	struct hlist_head *head;

	head = find_bucket(ti, flow->flow_table.hash);
	hlist_add_head_rcu(&flow->flow_table.node[ti->node_ver], head);
}

//将 flow->ufid_table.node[ti->node_ver] 加入 ti->buckets[jhash_1word(ti->hash_seed, flow->ufid_table.hash)] 中
static void ufid_table_instance_insert(struct table_instance *ti,
				       struct sw_flow *flow)
{
	struct hlist_head *head;

	head = find_bucket(ti, flow->ufid_table.hash);
	hlist_add_head_rcu(&flow->ufid_table.node[ti->node_ver], head);
}

// 将 old 的每个 buckets 中的每个链表中的值拷贝到 new 中, new->node_ver 为 old->node_ver
// 注: 如果 ufid 为 true, 根据 ufid 查找 bucket 拷贝
static void flow_table_copy_flows(struct table_instance *old,
				  struct table_instance *new, bool ufid)
{
	int old_ver;
	int i;

	old_ver = old->node_ver;
	new->node_ver = !old_ver;

	/* Insert in new table. */
	for (i = 0; i < old->n_buckets; i++) {
		struct sw_flow *flow;
		struct hlist_head *head;

		head = flex_array_get(old->buckets, i);

		if (ufid)
			hlist_for_each_entry(flow, head,
					     ufid_table.node[old_ver])
				ufid_table_instance_insert(new, flow);
		else
			hlist_for_each_entry(flow, head,
					     flow_table.node[old_ver])
				table_instance_insert(new, flow);
	}

	old->keep_flows = true;
}

/*
 * 分配 n_buckets 个 flex_array 给 new_ti, 并初始化
 * 将 ti 的每个 buckets 中的每个链表中的值拷贝到 new_ti 中, new_ti->node_ver 为 ti->node_ver
 * 注: 如果 ufid 为 true, 根据 ufid 查找 bucket 拷贝
 */
static struct table_instance *table_instance_rehash(struct table_instance *ti,
						    int n_buckets, bool ufid)
{
	struct table_instance *new_ti;

    //分配 n_buckets 个 flex_array 给 new_ti, 并初始化
	new_ti = table_instance_alloc(n_buckets);
	if (!new_ti)
		return NULL;

    //将 old 的每个 buckets 中的每个链表中的值拷贝到 new 中, new->node_ver 为 old->node_ver
	flow_table_copy_flows(ti, new_ti, ufid);

	return new_ti;
}

int ovs_flow_tbl_flush(struct flow_table *flow_table)
{
	struct table_instance *old_ti, *new_ti;
	struct table_instance *old_ufid_ti, *new_ufid_ti;

	new_ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!new_ti)
		return -ENOMEM;
	new_ufid_ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!new_ufid_ti)
		goto err_free_ti;

	old_ti = ovsl_dereference(flow_table->ti);
	old_ufid_ti = ovsl_dereference(flow_table->ufid_ti);

	rcu_assign_pointer(flow_table->ti, new_ti);
	rcu_assign_pointer(flow_table->ufid_ti, new_ufid_ti);
    //系统最近一次启动以来的时钟滴答数
	flow_table->last_rehash = jiffies;
	flow_table->count = 0;
	flow_table->ufid_count = 0;

	table_instance_destroy(old_ti, old_ufid_ti, true);
	return 0;

err_free_ti:
	__table_instance_destroy(new_ti);
	return -ENOMEM;
}

//返回流表的 hash 值 = jhash2(key + mask->range->start, mask->range->end - mask->range->start)
static u32 flow_hash(const struct sw_flow_key *key,
		     const struct sw_flow_key_range *range)
{
	int key_start = range->start;
	int key_end = range->end;
	const u32 *hash_key = (const u32 *)((const u8 *)key + key_start);
    //因为 key_end-key_end 是字节数, 而 jhash2 是 u32,　因此除以 4
	int hash_u32s = (key_end - key_start) >> 2;

	/* Make sure number of hash bytes are multiple of u32. */
	BUILD_BUG_ON(sizeof(long) % sizeof(u32));

	return jhash2(hash_key, hash_u32s, 0);
}

static int flow_key_start(const struct sw_flow_key *key)
{
	if (key->tun_key.ipv4_dst)
		return 0;
	else
		return rounddown(offsetof(struct sw_flow_key, phy),
					  sizeof(long));
}

static bool cmp_key(const struct sw_flow_key *key1,
		    const struct sw_flow_key *key2,
		    int key_start, int key_end)
{
	const long *cp1 = (const long *)((const u8 *)key1 + key_start);
	const long *cp2 = (const long *)((const u8 *)key2 + key_start);
	long diffs = 0;
	int i;

	for (i = key_start; i < key_end;  i += sizeof(long))
		diffs |= *cp1++ ^ *cp2++;

	return diffs == 0;
}

//flow->key 与 keys 是否完全一致
static bool flow_cmp_masked_key(const struct sw_flow *flow,
				const struct sw_flow_key *key,
				const struct sw_flow_key_range *range)
{
	return cmp_key(&flow->key, key, range->start, range->end);
}

//比较 flow->id.unmasked_key = match-key, 返回 true, 否则返回false
static bool ovs_flow_cmp_unmasked_key(const struct sw_flow *flow,
				      const struct sw_flow_match *match)
{
	struct sw_flow_key *key = match->key;
	int key_start = flow_key_start(key);
	int key_end = match->range.end;

	BUG_ON(ovs_identifier_is_ufid(&flow->id));
	return cmp_key(flow->id.unmasked_key, key, key_start, key_end);
}

/*
 * 在 ti->buckets 中找到 flow->key = unmasked 掩码 mask 和 flow->mask = mask 的 flow.
 * 1. unmasked 与 mask 掩码之后的 key 为 mask_key
 * 2. hash = jhash2(key + mask->range->start, mask->range->end - mask->range->start)
 * 3. 在 ti->buckets[jhash_1word(hash, ti->hash_seed) & ti->n_buckets] 中找符合条件的 flow
 *
 * 两条流表不仅 key 要相等, mask 也要相等
 */
static struct sw_flow *masked_flow_lookup(struct table_instance *ti,
					  const struct sw_flow_key *unmasked,
					  const struct sw_flow_mask *mask,
					  u32 *n_mask_hit)
{
	struct sw_flow *flow;
	struct hlist_head *head;
	u32 hash;
	struct sw_flow_key masked_key;

    //masked_key 是 unmasked 与 mask 掩码后的 key
	ovs_flow_mask_key(&masked_key, unmasked, mask);
	hash = flow_hash(&masked_key, &mask->range);
	head = find_bucket(ti, hash);
	(*n_mask_hit)++;
	hlist_for_each_entry_rcu(flow, head, flow_table.node[ti->node_ver]) {
		if (flow->mask == mask && flow->flow_table.hash == hash &&
		    flow_cmp_masked_key(flow, &masked_key, &mask->range))
			return flow;
	}
	return NULL;
}

/* Flow lookup does full lookup on flow table. It starts with
 * mask from index passed in *index.
 */
/*
 * 遍历 ma 中的每一个 mask, 从 ti 中查找匹配 flow->key=key & mask, flow->mask = mask 的流表项目
 *
 * 优先确认 ma->masks[*index] 是否符号条件, 如果不符合, 遍历 ma 中的 masks 的每个元素 mask,
 * 从 ti 中找到 flow->key= key & mask, flow->mask = mask
 */
static struct sw_flow *flow_lookup(struct flow_table *tbl,
				   struct table_instance *ti,
				   const struct mask_array *ma,
				   const struct sw_flow_key *key,
				   u32 *n_mask_hit,
				   u32 *index)
{
	struct sw_flow_mask *mask;
	struct sw_flow *flow;
	int i;

	if (*index < ma->max) {
		mask = rcu_dereference_ovsl(ma->masks[*index]);
		if (mask) {
            // 在 ti->buckets 中找到 flow->key = key & mask 和 flow->mask = mask 的 flow.
			flow = masked_flow_lookup(ti, key, mask, n_mask_hit);
			if (flow)
				return flow;
		}
	}

	for (i = 0; i < ma->max; i++)  {

		if (i == *index)
			continue;

		mask = rcu_dereference_ovsl(ma->masks[i]);
		if (!mask)
			continue;

        // 在 ti->buckets 中找到 flow->key = key 掩码 mask 和 flow->mask = mask 的 flow.
		flow = masked_flow_lookup(ti, key, mask, n_mask_hit);
		if (flow) { /* Found */
			*index = i;
			return flow;
		}
	}

	return NULL;
}

/*
 * mask_cache maps flow to probable mask. This cache is not tightly
 * coupled cache, It means updates to  mask list can result in inconsistent
 * cache entry in mask cache.
 * This is per cpu cache and is divided in MC_HASH_SEGS segments.
 * In case of a hash collision the entry is hashed in next segment.
 */
struct sw_flow *ovs_flow_tbl_lookup_stats(struct flow_table *tbl,
					  const struct sw_flow_key *key,
					  u32 skb_hash,
					  u32 *n_mask_hit)
{
	struct mask_array *ma = rcu_dereference(tbl->mask_array);
	struct table_instance *ti = rcu_dereference(tbl->ti);
	struct mask_cache_entry *entries, *ce;
	struct sw_flow *flow;
	u32 hash;
	int seg;

	*n_mask_hit = 0;
	if (unlikely(!skb_hash)) {
		u32 mask_index = 0;

		return flow_lookup(tbl, ti, ma, key, n_mask_hit, &mask_index);
	}

	/* Pre and post recirulation flows usually have the same skb_hash
	 * value. To avoid hash collisions, rehash the 'skb_hash' with
	 * 'recirc_id'.  */
	if (key->recirc_id)
		skb_hash = jhash_1word(skb_hash, key->recirc_id);

	ce = NULL;
	hash = skb_hash;
	entries = this_cpu_ptr(tbl->mask_cache);

	/* Find the cache entry 'ce' to operate on. */
	for (seg = 0; seg < MC_HASH_SEGS; seg++) {
		int index = hash & (MC_HASH_ENTRIES - 1);
		struct mask_cache_entry *e;

		e = &entries[index];
		if (e->skb_hash == skb_hash) {
			flow = flow_lookup(tbl, ti, ma, key, n_mask_hit,
					   &e->mask_index);
			if (!flow)
				e->skb_hash = 0;
			return flow;
		}

		if (!ce || e->skb_hash < ce->skb_hash)
			ce = e;  /* A better replacement cache candidate. */

		hash >>= MC_HASH_SHIFT;
	}

	/* Cache miss, do full lookup. */
	flow = flow_lookup(tbl, ti, ma, key, n_mask_hit, &ce->mask_index);
	if (flow)
		ce->skb_hash = skb_hash;

	return flow;
}

/*
 * 遍历 tbl->mask_array 中的每一个 mask, 从 tlb->ti 中查找匹配 flow->key=key & mask, flow->mask = mask 的流表项
 *
 * 优先确认 tbl->mask_array->masks[*index] 是否符号条件, 如果不符合, 遍历 tbl->mask_array 中的 masks 的每个元素 mask,
 * 从 tlb->ti 中找到 flow->key= key & mask, flow->mask = mask
 */
struct sw_flow *ovs_flow_tbl_lookup(struct flow_table *tbl,
				    const struct sw_flow_key *key)
{
	struct table_instance *ti = rcu_dereference_ovsl(tbl->ti);
	struct mask_array *ma = rcu_dereference_ovsl(tbl->mask_array);
    //目前用处似乎没有体现除了
	u32 __always_unused n_mask_hit;
	u32 index = 0;

	return flow_lookup(tbl, ti, ma, key, &n_mask_hit, &index);
}

/*
 * 在 tbl->buckets 中找到与 match->key 精确匹配的 flow
 *
 *
 * 遍历 tbl->ti->masks 的每个元素 mask,
 * 在 ti->buckets 中找到 flow->key = matach-key & mask 和 flow->mask = mask 的 flow.
 * 如果 flow->id->ufid_len = 0 & flow->unmasked_key == match-key, 返回 flow,
 * 否则返回 NULL
 *
 */
struct sw_flow *ovs_flow_tbl_lookup_exact(struct flow_table *tbl,
					  const struct sw_flow_match *match)
{
	struct mask_array *ma = ovsl_dereference(tbl->mask_array);
	int i;

	/* Always called under ovs-mutex. */
	for (i = 0; i < ma->max; i++) {
		struct table_instance *ti = ovsl_dereference(tbl->ti);
		u32 __always_unused n_mask_hit;
		struct sw_flow_mask *mask;
		struct sw_flow *flow;

		mask = ovsl_dereference(ma->masks[i]);
		if (!mask)
			continue;
        /*
        * 在 ti->buckets 中找到 flow->key = match->key & mask 和 flow->mask = mask 的 flow.
        * 1. unmasked 与 mask 掩码之后的 key 为 mask_key
        * 2. hash = jhash2(key + mask->range->start, mask->range->end - mask->range->start)
        * 3. 在 ti->buckets[jhash_1word(hash, ti->hash_seed) & ti->n_buckets] 中找符合条件的 flow
        *
        * 两条流表不仅 key 要相等, mask 也要相等
        */
		flow = masked_flow_lookup(ti, match->key, mask, &n_mask_hit);
		If (flow && ovs_identifier_is_key(&flow->id) &&
		    ovs_flow_cmp_unmasked_key(flow, match))
			return flow;
	}
	return NULL;
}

static u32 ufid_hash(const struct sw_flow_id *sfid)
{
	return jhash(sfid->ufid, sfid->ufid_len, 0);
}

static bool ovs_flow_cmp_ufid(const struct sw_flow *flow,
			      const struct sw_flow_id *sfid)
{
	if (flow->id.ufid_len != sfid->ufid_len)
		return false;

	return !memcmp(flow->id.ufid, sfid->ufid, sfid->ufid_len);
}

/*
 * 如果 flow->id->ufid_len != 0, flow->key 与 match->key 是否完全一致
 * 否则 flow->unmasked_key 与 match->key 是否完全一致
 */
bool ovs_flow_cmp(const struct sw_flow *flow, const struct sw_flow_match *match)
{
	if (ovs_identifier_is_ufid(&flow->id))
        //flow->key 与 match->key 是否完全一致
		return flow_cmp_masked_key(flow, match->key, &match->range);

    //flow->unmasked_key 与 match->key 是否完全一致
	return ovs_flow_cmp_unmasked_key(flow, match);
}

/*
 * 从 tbl->ufid_ti->buckets 中查找 ufid 对应的流表是否存在
 *
 * 遍历 tbl->ufid_ti->buckets[jhash_1word(jhash(ufid->ufid, ufid->ufid_len, 0), ti->hash_seed)] 中每一个元素 flow, 
 * 找到满足 flow->ufid = ufid, 返回 flow; 找不到返回 NULL
 *
 */
struct sw_flow *ovs_flow_tbl_lookup_ufid(struct flow_table *tbl,
					 const struct sw_flow_id *ufid)
{
	struct table_instance *ti = rcu_dereference_ovsl(tbl->ufid_ti);
	struct sw_flow *flow;
	struct hlist_head *head;
	u32 hash;

    //计算flow 的 hash: jhash(ufid->ufid, ufid->ufid_len, 0)
	hash = ufid_hash(ufid);
    //从 ti->buckets[jhash_1word(hash, ti->hash_seed) & (ti->n_buckets - 1)]
    //中找到 id 和 ufid 相同的 flow
	head = find_bucket(ti, hash);
	hlist_for_each_entry_rcu(flow, head, ufid_table.node[ti->node_ver]) {
        //BUG:这里 ovs_flow_cmp_ufid() 包含了前面的条件
		if (flow->ufid_table.hash == hash &&
		    ovs_flow_cmp_ufid(flow, ufid))
			return flow;
	}
	return NULL;
}

int ovs_flow_tbl_num_masks(const struct flow_table *table)
{
	struct mask_array *ma;

	ma = rcu_dereference_ovsl(table->mask_array);
	return ma->count;
}

/*
 * 分配 ti->n_buckets * 2 个 flex_array 给 new_ti, 并初始化
 * 将 ti 的每个 buckets 中的每个链表中的值拷贝到 new_ti 中, new_ti->node_ver 为 ti->node_ver
 * 注: 如果 ufid 为 true, 根据 ufid 查找 bucket 拷贝
 */
static struct table_instance *table_instance_expand(struct table_instance *ti,
						    bool ufid)
{
	return table_instance_rehash(ti, ti->n_buckets * 2, ufid);
}

static void tbl_mask_array_delete_mask(struct mask_array *ma,
				       struct sw_flow_mask *mask)
{
	int i;

	/* Remove the deleted mask pointers from the array */
	for (i = 0; i < ma->max; i++) {
		if (mask == ovsl_dereference(ma->masks[i])) {
			RCU_INIT_POINTER(ma->masks[i], NULL);
			ma->count--;
			call_rcu(&mask->rcu, rcu_free_sw_flow_mask_cb);
			return;
		}
	}
	BUG();
}

/* Remove 'mask' from the mask list, if it is not needed any more. */
/*
 * mask 引用计数减一或删除
 * 如果 mask != null :
 * mask 的引用计数减一, 如果该 mask 引用计数为 0, 从 tbl->mask_array 中删除
 * 如果 mask 数量大于 32 并且容量是实际使用的 3 倍, 进行容量缩减.
 *
 */
static void flow_mask_remove(struct flow_table *tbl, struct sw_flow_mask *mask)
{
	if (mask) {
		/* ovs-lock is required to protect mask-refcount and
		 * mask list.
		 */
		ASSERT_OVSL();
		BUG_ON(!mask->ref_count);
		mask->ref_count--;

		if (!mask->ref_count) {
			struct mask_array *ma;

			ma = ovsl_dereference(tbl->mask_array);
			tbl_mask_array_delete_mask(ma, mask);

			/* Shrink the mask array if necessary. */
			if (ma->max >= (MASK_ARRAY_SIZE_MIN * 2) &&
			    ma->count <= (ma->max / 3))
				tbl_mask_array_realloc(tbl, ma->max / 2);

		}
	}
}

/* Must be called with OVS mutex held. */
/*
 * 1. 从 table->ti->bucket 中删除 flow->flow_table.node[table->ti->node_ver]
 * 2. 从 table->ufid_ti->bucket 中删除 flow->ufid_table.node[table->ufid_ti->node_ver]
 * 3. flow->mask 引用计数减一或删除
 */
void ovs_flow_tbl_remove(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *ti = ovsl_dereference(table->ti);
	struct table_instance *ufid_ti = ovsl_dereference(table->ufid_ti);

	BUG_ON(table->count == 0);
	hlist_del_rcu(&flow->flow_table.node[ti->node_ver]);
	table->count--;
	if (ovs_identifier_is_ufid(&flow->id)) {
		hlist_del_rcu(&flow->ufid_table.node[ufid_ti->node_ver]);
		table->ufid_count--;
	}

	/* RCU delete the mask. 'flow->mask' is not NULLed, as it should be
	 * accessible as long as the RCU read lock is held.
	 */
    // flow->mask 引用计数减一或删除
	flow_mask_remove(table, flow->mask);
}

static struct sw_flow_mask *mask_alloc(void)
{
	struct sw_flow_mask *mask;

	mask = kmalloc(sizeof(*mask), GFP_KERNEL);
	if (mask)
		mask->ref_count = 1;

	return mask;
}

//两个 mask 是否相等
static bool mask_equal(const struct sw_flow_mask *a,
		       const struct sw_flow_mask *b)
{
	const u8 *a_ = (const u8 *)&a->key + a->range.start;
	const u8 *b_ = (const u8 *)&b->key + b->range.start;

	return  (a->range.end == b->range.end)
		&& (a->range.start == b->range.start)
		&& (memcmp(a_, b_, range_n_bytes(&a->range)) == 0);
}

//遍历 tbl->mask_array 找到 mask[i] = mask 的 sw_flow_mask
static struct sw_flow_mask *flow_mask_find(const struct flow_table *tbl,
					   const struct sw_flow_mask *mask)
{
	struct mask_array *ma;
	int i;

	ma = ovsl_dereference(tbl->mask_array);
	for (i = 0; i < ma->max; i++) {
		struct sw_flow_mask *t;

		t = ovsl_dereference(ma->masks[i]);
		if (t && mask_equal(mask, t))
			return t;
	}

	return NULL;
}

/* Add 'mask' into the mask list, if it is not already there. */
/*
 * 将　new 加入 tbl->mask_array 中
 *
 * 1. 如果已经存在, 只有修改 ref_count
 * 2. 如果不存在, 加入 tbl->mask_array 并初始化各个成员. 期间 tbl->mask_array
 *    空间不够, 还涉及到要空间重分配
 *
 * TODO: 假设 mask 不多的情况下通过链表来实现更好
 */
static int flow_mask_insert(struct flow_table *tbl, struct sw_flow *flow,
			    const struct sw_flow_mask *new)
{
	struct sw_flow_mask *mask;

    //new 是否已经存在与 tbl 中
	mask = flow_mask_find(tbl, new);
	if (!mask) {
		struct mask_array *ma;
		int i;

		/* Allocate a new mask if none exsits. */
		mask = mask_alloc();
		if (!mask)
			return -ENOMEM;

		mask->key = new->key;
		mask->range = new->range;

		/* Add mask to mask-list. */
		ma = ovsl_dereference(tbl->mask_array);
        //如果 tbl->mask_array 空间已经用完, 重新分配
		if (ma->count >= ma->max) {
			int err;

            //tbl->mask_array 空间重分配, 如果不够, 每次多分配 16 个
			err = tbl_mask_array_realloc(tbl, ma->max +
							  MASK_ARRAY_SIZE_MIN);
			if (err) {
				kfree(mask);
				return err;
			}
			ma = ovsl_dereference(tbl->mask_array);
		}

        //ma->masks 中找到没有分配的 mask
		for (i = 0; i < ma->max; i++) {
			struct sw_flow_mask *t;

			t = ovsl_dereference(ma->masks[i]);
			if (!t) {
				rcu_assign_pointer(ma->masks[i], mask);
				ma->count++;
				break;
			}
		}

	} else {
		BUG_ON(!mask->ref_count);
		mask->ref_count++;
	}

	flow->mask = mask;
	return 0;
}

/* Must be called with OVS mutex held. */
/*
 * 将 flow 插入 table->ti->buckets 中的一个链表中
 *
 * 1. 初始化 flow->flow_table.hash
 * 2. flow->flow_table.node[ti->node_ver] 加入 ti->buckets
 * 3. 如果新插入流表数目导致 table->count 大于 table->ti->buckets, 对 table->ti 进行重分配
 * 4. 如果当前 jiffies 到 table->last_rehash 超过 600 HZ, 重分配
 * 5. 更新 table->count, table->last_rehash
 *
 */
static void flow_key_insert(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *new_ti = NULL;
	struct table_instance *ti;

	flow->flow_table.hash = flow_hash(&flow->key, &flow->mask->range);
	ti = ovsl_dereference(table->ti);
    // flow->flow_table.node[ti->node_ver] 加入 ti->buckets[jhash_1word(jhash(flow->key,
    // flow->mask->range->end - flow->mask->range->start, 0), ti->hash_seed) & (ti->n_buckets - 1)] 的链表中
	table_instance_insert(ti, flow);
	table->count++;

	/* Expand table, if necessary, to make room. */
	if (table->count > ti->n_buckets) {
        // 分配 ti->n_buckets * 2 个 flex_array 给 new_ti, 并初始化
        // 将 ti 的每个 buckets 中的每个链表中的值拷贝到 new_ti 中, new_ti->node_ver 为 ti->node_ver
		new_ti = table_instance_expand(ti, false);
    } else if (time_after(jiffies, table->last_rehash + REHASH_INTERVAL)) {
        //重新分配 ti->buckets,
        //??? 为什么?
		new_ti = table_instance_rehash(ti, ti->n_buckets, false);
    }

	if (new_ti) {
		rcu_assign_pointer(table->ti, new_ti);
		call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
        //系统最近一次启动以来的时钟滴答数
		table->last_rehash = jiffies;
	}
}

/* Must be called with OVS mutex held. */
/*
 * 将 flow 插入 table->ufid_ti->buckets 中的一个链表中
 *
 * 1. 将 flow->ufid_table.node[table->ufid_ti->node_ver] 加入 table->ufid_ti->buckets[jhash_1word(table->ufid_ti->hash_seed, flow->ufid_table.hash)] 中
 * 2. 如果 table->ufid_count 大于 table->ufid_ti->n_buckets 重分配
 *
 */
static void flow_ufid_insert(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *ti;

	flow->ufid_table.hash = ufid_hash(&flow->id);
	ti = ovsl_dereference(table->ufid_ti);
    //将 flow->ufid_table.node[ti->node_ver] 加入 ti->buckets[jhash_1word(ti->hash_seed, flow->ufid_table.hash)] 中
	ufid_table_instance_insert(ti, flow);
	table->ufid_count++;

	/* Expand table, if necessary, to make room. */
	if (table->ufid_count > ti->n_buckets) {
		struct table_instance *new_ti;

        /*
        * 分配 ti->n_buckets * 2 个 flex_array 给 new_ti, 并初始化
        * 将 ti 的每个 buckets 中的每个链表中的值拷贝到 new_ti 中, new_ti->node_ver 为 ti->node_ver
        * 注: 如果 ufid 为 true, 根据 ufid 查找 bucket 拷贝
        */
		new_ti = table_instance_expand(ti, true);
		if (new_ti) {
			rcu_assign_pointer(table->ufid_ti, new_ti);
			call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
		}
	}
}

/* Must be called with OVS mutex held. */
/*
 *
 * 1. 将 mask 加入 table->mask_array 中
 * 2. 将 flow->flow_table->node[table->ti->node_ver] 插入 table->ti->buckets 中的一个链表中
 * 3. 如果 flow->id 存在, 将 flow->ufid_table->node[table->ufid_ti->node_ver] 插入 table->ufid_ti->buckets 中的一个链表中
 *
 */
int ovs_flow_tbl_insert(struct flow_table *table, struct sw_flow *flow,
			const struct sw_flow_mask *mask)
{
	int err;

    // 将 mask 加入 tbl->mask_array 中
	err = flow_mask_insert(table, flow, mask);
	if (err)
		return err;

    // 将 flow->flow_table->node[table->ti->node_ver] 插入 table->ti->buckets 中的一个链表中
	flow_key_insert(table, flow);
	if (ovs_identifier_is_ufid(&flow->id)) {
        //将 flow->ufid_table->node[table->ufid_ti->node_ver] 插入 table->ufid_ti->buckets 中的一个链表中
		flow_ufid_insert(table, flow);
    }

	return 0;
}

/* Initializes the flow module.
 * Returns zero if successful or a negative error code.
 */
int ovs_flow_init(void)
{
	BUILD_BUG_ON(__alignof__(struct sw_flow_key) % __alignof__(long));
	BUILD_BUG_ON(sizeof(struct sw_flow_key) % sizeof(long));

	flow_cache = kmem_cache_create("sw_flow", sizeof(struct sw_flow)
				       + (nr_node_ids
					  * sizeof(struct flow_stats *)),
				       0, 0, NULL);
	if (flow_cache == NULL)
		return -ENOMEM;

	flow_stats_cache
		= kmem_cache_create("sw_flow_stats", sizeof(struct flow_stats),
				    0, SLAB_HWCACHE_ALIGN, NULL);
	if (flow_stats_cache == NULL) {
		kmem_cache_destroy(flow_cache);
		flow_cache = NULL;
		return -ENOMEM;
	}

	return 0;
}

/* Uninitializes the flow module. */
void ovs_flow_exit(void)
{
	kmem_cache_destroy(flow_stats_cache);
	kmem_cache_destroy(flow_cache);
}
