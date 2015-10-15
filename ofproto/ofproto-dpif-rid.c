/*
 * Copyright (c) 2014, 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "ofpbuf.h"
#include "ofproto-dpif.h"
#include "ofproto-dpif-rid.h"
#include "ofproto-provider.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_rid);

static struct ovs_mutex mutex;

static struct cmap id_map;
static struct cmap metadata_map;

static struct ovs_list expiring OVS_GUARDED_BY(mutex);
static struct ovs_list expired OVS_GUARDED_BY(mutex);

static uint32_t next_id OVS_GUARDED_BY(mutex); /* Possible next free id. */

#define RECIRC_POOL_STATIC_IDS 1024

void
recirc_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        ovs_mutex_init(&mutex);
        ovs_mutex_lock(&mutex);
        next_id = 1; /* 0 is not a valid ID. */
        cmap_init(&id_map);
        cmap_init(&metadata_map);
        list_init(&expiring);
        list_init(&expired);
        ovs_mutex_unlock(&mutex);

        ovsthread_once_done(&once);
    }

}

/* This should be called by the revalidator once at each round (every 500ms or
 * more). */
/*
 * 流表过期清除动作. 每秒最多执行 4 次
 * 将 expired 列表的节点从 id_map 中删除
 * 将 expiring 列表节点移到 expired 列表中
 */
void
recirc_run(void)
{
    static long long int last = 0;
    long long int now = time_msec();

    /* Do maintenance at most 4 times / sec. */
    ovs_mutex_lock(&mutex);
    if (now - last > 250) {
        struct recirc_id_node *node;

        last = now;

        /* Nodes in 'expiring' and 'expired' lists have the refcount of zero,
         * which means that while they can still be found (by id), no new
         * references can be taken on them.  We have removed the entry from the
         * 'metadata_map', at the time when refcount reached zero, causing any
         * new translations to allocate a new ID.  This allows the expiring
         * entry to be safely deleted while any sudden new use of the similar
         * recirculation will safely start using a new recirculation ID.  When
         * the refcount gets to zero, the node is also added to the 'expiring'
         * list.  At any time after that the nodes in the 'expiring' list can
         * be moved to the 'expired' list, from which they are deleted at least
         * 250ms afterwards. */

        /* Delete the expired.  These have been lingering for at least 250 ms,
         * which should be enough for any ongoing recirculations to be
         * finished. */
        LIST_FOR_EACH_POP (node, exp_node, &expired) {
            cmap_remove(&id_map, &node->id_node, node->id);
            ovsrcu_postpone(free, node);
        }

        if (!list_is_empty(&expiring)) {
            /* 'expired' is now empty, move nodes in 'expiring' to it. */
            list_splice(&expired, list_front(&expiring), &expiring);
        }
    }
    ovs_mutex_unlock(&mutex);
}

/* We use the id as the hash value, which works due to cmap internal rehashing.
 * We also only insert nodes with unique IDs, so all possible hash collisions
 * remain internal to the cmap. */
static struct recirc_id_node *
recirc_find__(uint32_t id)
    OVS_REQUIRES(mutex)
{
    struct cmap_node *node = cmap_find_protected(&id_map, id);

    return node ? CONTAINER_OF(node, struct recirc_id_node, id_node) : NULL;
}

/* Lockless RCU protected lookup.  If node is needed accross RCU quiescent
 * state, caller should copy the contents. */
const struct recirc_id_node *
recirc_id_node_find(uint32_t id)
{
    const struct cmap_node *node = cmap_find(&id_map, id);

    return node
        ? CONTAINER_OF(node, const struct recirc_id_node, id_node)
        : NULL;
}

/*
 * 返回把 state 每个成员进行 hash 之后的值
 */
static uint32_t
recirc_metadata_hash(const struct recirc_state *state)
{
    uint32_t hash;

    hash = hash_pointer(state->ofproto, 0);
    hash = hash_int(state->table_id, hash);
    hash = hash_words64((const uint64_t *) &state->metadata,
                        sizeof state->metadata / sizeof(uint64_t),
                        hash);
    if (state->stack && state->stack->size != 0) {
        hash = hash_words64((const uint64_t *) state->stack->data,
                            state->stack->size / sizeof(uint64_t), hash);
    }
    hash = hash_int(state->mirrors, hash);
    hash = hash_int(state->action_set_len, hash);
    if (state->ofpacts_len) {
        hash = hash_words64(ALIGNED_CAST(const uint64_t *, state->ofpacts),
                            state->ofpacts_len / sizeof(uint64_t),
                            hash);
    }
    return hash;
}

/*
 * a 与 b 的值是否完全一样
 */
static bool
recirc_metadata_equal(const struct recirc_state *a,
                      const struct recirc_state *b)
{
    return (a->table_id == b->table_id
            && a->ofproto == b->ofproto
            && !memcmp(&a->metadata, &b->metadata, sizeof a->metadata)
            && (((!a->stack || !a->stack->size) &&
                 (!b->stack || !b->stack->size))
                || (a->stack && b->stack && ofpbuf_equal(a->stack, b->stack)))
            && a->mirrors == b->mirrors
            && a->action_set_len == b->action_set_len
            && ofpacts_equal(a->ofpacts, a->ofpacts_len,
                             b->ofpacts, b->ofpacts_len));
}

/* Lockless RCU protected lookup.  If node is needed accross RCU quiescent
 * state, caller should take a reference. */
/*
 * 在 metadata_map 中找到和 target 在对象内容一样的节点
 */
static struct recirc_id_node *
recirc_find_equal(const struct recirc_state *target, uint32_t hash)
{
    struct recirc_id_node *node;

    CMAP_FOR_EACH_WITH_HASH (node, metadata_node, hash, &metadata_map) {
        if (recirc_metadata_equal(&node->state, target)) {
            return node;
        }
    }
    return NULL;
}

/*
 * 在 metadata_map 中找到和 target 的 hash 一样并且引用计数不为 0 的节点,
 */
static struct recirc_id_node *
recirc_ref_equal(const struct recirc_state *target, uint32_t hash)
{
    struct recirc_id_node *node;

    do {
        node = recirc_find_equal(target, hash);

        /* Try again if the node was released before we get the reference. */
    } while (node && !ovs_refcount_try_ref_rcu(&node->refcount));

    return node;
}

/*
 * 把 old 克隆给 new
 *
 * TODO: new->ofproto 没有克隆
 */
static void
recirc_state_clone(struct recirc_state *new, const struct recirc_state *old)
{
    *new = *old;
    if (new->stack) {
        new->stack = new->stack->size ? ofpbuf_clone(new->stack) : NULL;
    }
    if (new->ofpacts) {
        new->ofpacts = (new->ofpacts_len
                        ? xmemdup(new->ofpacts, new->ofpacts_len)
                        : NULL);
    }
}

/* Allocate a unique recirculation id for the given set of flow metadata.
 * The ID space is 2^^32, so there should never be a situation in which all
 * the IDs are used up.  We loop until we find a free one.
 * hash is recomputed if it is passed in as 0. */
/*
 * 分配一个 struct recirc_state 对象 node, 用 state 初始化, 将该节点加入 id_map, metadata_map
 */
static struct recirc_id_node *
recirc_alloc_id__(const struct recirc_state *state, uint32_t hash)
{
    ovs_assert(state->action_set_len <= state->ofpacts_len);

    struct recirc_id_node *node = xzalloc(sizeof *node);
    node->hash = hash;
    ovs_refcount_init(&node->refcount);
    recirc_state_clone(CONST_CAST(struct recirc_state *, &node->state), state);

    ovs_mutex_lock(&mutex);
    //找到一个没有用过的 id
    for (;;) {
        /* Claim the next ID.  The ID space should be sparse enough for the
           allocation to succeed at the first try.  We do skip the first
           RECIRC_POOL_STATIC_IDS IDs on the later rounds, though, as some of
           the initial allocations may be for long term uses (like bonds). */
        node->id = next_id++;
        if (OVS_UNLIKELY(!node->id)) {
            next_id = RECIRC_POOL_STATIC_IDS + 1;
            node->id = next_id++;
        }
        /* Find if the id is free. */
        if (OVS_LIKELY(!recirc_find__(node->id))) {
            break;
        }
    }
    cmap_insert(&id_map, &node->id_node, node->id);
    cmap_insert(&metadata_map, &node->metadata_node, node->hash);
    ovs_mutex_unlock(&mutex);
    return node;
}

/* Look up an existing ID for the given flow's metadata and optional actions.
 */

/*
 * 在 metadata_map 中找到和 target 在对象内容一样的节点:
 * 如果找到, 返回节点 id
 * 如果没有找到, 返回 0
 */
uint32_t
recirc_find_id(const struct recirc_state *target)
{
    uint32_t hash = recirc_metadata_hash(target);
    struct recirc_id_node *node = recirc_find_equal(target, hash);
    return node ? node->id : 0;
}

/* Allocate a unique recirculation id for the given set of flow metadata and
   optional actions. */
/*
 * 在 metadata_map 中找到和 state 的 hash 一样并且引用计数不为 0 的节点,
 * 如果找到, 返回该节点
 * 如果没有找到, 生成一个新的节点, 并返回节点的 id
 *
 */
uint32_t
recirc_alloc_id_ctx(const struct recirc_state *state)
{
    uint32_t hash = recirc_metadata_hash(state);
    /*
    * 在 metadata_map 中找到和 state 的 hash 一样并且引用计数不为 0 的节点,
    */
    struct recirc_id_node *node = recirc_ref_equal(state, hash);
    if (!node) {
        node = recirc_alloc_id__(state, hash);
    }
    return node->id;
}

/* Allocate a unique recirculation id. */
/*
 * 通过 ofproto 分配一个 node. 返回分配 struct recirc_id_node 的 id
 *
 */
uint32_t
recirc_alloc_id(struct ofproto_dpif *ofproto)
{
    struct recirc_state state = {
        .table_id = TBL_INTERNAL,
        .ofproto = ofproto,
        .metadata = { .in_port = OFPP_NONE },
    };
    return recirc_alloc_id__(&state, recirc_metadata_hash(&state))->id;
}

/*
 * 将 node_ 的引用计数减一, 如果引用计数减到 1, 从 metadata_map 中删除
 * node_, 并将其加入 expiring 列表 中
 *
 *
 */
void
recirc_id_node_unref(const struct recirc_id_node *node_)
    OVS_EXCLUDED(mutex)
{
    struct recirc_id_node *node = CONST_CAST(struct recirc_id_node *, node_);

    if (node && ovs_refcount_unref(&node->refcount) == 1) {
        ovs_mutex_lock(&mutex);
        /* Prevent re-use of this node by removing the node from 'metadata_map'
         */
        cmap_remove(&metadata_map, &node->metadata_node, node->hash);
        /* We keep the node in the 'id_map' so that it can be found as long
         * as it lingers, and add it to the 'expiring' list. */
        list_insert(&expiring, &node->exp_node);
        ovs_mutex_unlock(&mutex);
    }
}

/*
 * 从 id_map 找到 id　对应的 recirc_id_node 对象 node:
 * 如果找不到, 打印错误日志.
 * 如果找到, node 的引用计数减一, 如果引用计数减到 1, 从 metadata_map 中删除
 * node, 并将其加入 expiring 列表 中
 */
void
recirc_free_id(uint32_t id)
{
    const struct recirc_id_node *node;

    node = recirc_id_node_find(id);
    if (node) {
        recirc_id_node_unref(node);
    } else {
        VLOG_ERR("Freeing nonexistent recirculation ID: %"PRIu32, id);
    }
}

/* Called when 'ofproto' is destructed.  Checks for and clears any
 * recirc_id leak.
 * No other thread may have access to the 'ofproto' being destructed.
 * All related datapath flows must be deleted before calling this. */
/*
 * 如果 ofproto 在 metadata_map 中, 打印错误日志
 */
void
recirc_free_ofproto(struct ofproto_dpif *ofproto, const char *ofproto_name)
{
    struct recirc_id_node *n;

    CMAP_FOR_EACH (n, metadata_node, &metadata_map) {
        if (n->state.ofproto == ofproto) {
            VLOG_ERR("recirc_id %"PRIu32
                     " left allocated when ofproto (%s)"
                     " is destructed", n->id, ofproto_name);
        }
    }
}
