/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include "pinsched.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include "flow.h"
#include "hash.h"
#include "hmap.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "random.h"
#include "rconn.h"
#include "sat-math.h"
#include "timeval.h"
#include "openvswitch/token-bucket.h"
#include "openvswitch/vconn.h"

//PACKET_IN Message Queue
struct pinqueue {
    struct hmap_node node;      /* In struct pinsched's 'queues' hmap. */
    ofp_port_t port_no;         /* Port number. */
    struct ovs_list packets;    /* Contains "struct ofpbuf"s. */
    int n;                      /* Number of packets in 'packets'. */
};

struct pinsched {
    struct token_bucket token_bucket;

    /* One queue per physical port. */
    struct hmap queues;         /* Contains "struct pinqueue"s. */
    unsigned int n_queued;      /* Sum over queues[*].n. */
    struct pinqueue *next_txq;  /* Next pinqueue check in round-robin. */

    /* Statistics reporting. */
    unsigned long long n_normal;        /* # txed w/o rate limit queuing. */
    unsigned long long n_limited;       /* # queued for rate limiting. */
    unsigned long long n_queue_dropped; /* # dropped due to queue overflow. */
};

/*
 * 初始化 ps->next_txq
 *
 * 轮询从 ps->queues 中取出一个 pinqueue 对象初始化 ps->next_txq 对象
 *
 * 如果 ps->next_txq != NULL, ps->next_txq->node->next = NULL, 从 ps->queues->buckets 索引 (node->hash & hmap->mask) + 1) 到 hmap->mask中找到不为 NULL 的节点 node(可能为 NULL), ps->next_txq = node, 否则为 ps->next_txq = ps->next_txq->node->next;
 * 如果 ps->next_txq == NULL, 从 ps->queues->buckets 索引 0 开始找到不为 NULL 的节点 node, ps->next_txq = node, 否则为 ps->next_txq = NULL;
 */
static void
advance_txq(struct pinsched *ps)
{
    struct hmap_node *next;

    next = (ps->next_txq
            ? hmap_next(&ps->queues, &ps->next_txq->node)
            : hmap_first(&ps->queues));
    ps->next_txq = next ? CONTAINER_OF(next, struct pinqueue, node) : NULL;
}

/* Removes the front element from 'q->packets' Undefined behavior if
   'p->packets' is empty before removal. */

//删除 q->packets 第一个数据. 返回被删除的数据包
static struct ofpbuf *
dequeue_packet(struct pinsched *ps, struct pinqueue *q)
{
    struct ofpbuf *packet = ofpbuf_from_list(list_pop_front(&q->packets));
    q->n--;
    ps->n_queued--;
    return packet;
}

static void
adjust_limits(int *rate_limit, int *burst_limit)
{
    if (*rate_limit <= 0) {
        *rate_limit = 1000;
    }
    if (*burst_limit <= 0) {
        *burst_limit = *rate_limit / 4;
    }
    if (*burst_limit < 1) {
        *burst_limit = 1;
    }
}

/* Destroys 'q' and removes it from 'ps''s set of queues.
 * (The caller must ensure that 'q' is empty.) */
static void
pinqueue_destroy(struct pinsched *ps, struct pinqueue *q)
{
    hmap_remove(&ps->queues, &q->node);
    free(q);
}

//从 ps 中获取 port_no 对应的 pinqueue
static struct pinqueue *
pinqueue_get(struct pinsched *ps, ofp_port_t port_no)
{
    uint32_t hash = hash_ofp_port(port_no);
    struct pinqueue *q;

    HMAP_FOR_EACH_IN_BUCKET (q, node, hash, &ps->queues) {
        if (port_no == q->port_no) {
            return q;
        }
    }

    q = xmalloc(sizeof *q);
    hmap_insert(&ps->queues, &q->node, hash);
    q->port_no = port_no;
    list_init(&q->packets);
    q->n = 0;
    return q;
}

/* Drop a packet from the longest queue in 'ps'. */
//找到 ps->queues 中最长的队列(如果有多个一样长的,随机选择一个)删除一个包
static void
drop_packet(struct pinsched *ps)
{
    struct pinqueue *longest;   /* Queue currently selected as longest. */
    int n_longest = 0;          /* # of queues of same length as 'longest'. */
    struct pinqueue *q;

    ps->n_queue_dropped++;

    longest = NULL;
    //找到 ps->queues 中最长的队列, 如果有多个一样长的, 随机选择一个
    HMAP_FOR_EACH (q, node, &ps->queues) {
        if (!longest || longest->n < q->n) {
            longest = q;
            n_longest = 1;
        } else if (longest->n == q->n) {
            n_longest++;

            /* Randomly select one of the longest queues, with a uniform
             * distribution (Knuth algorithm 3.4.2R). */
            if (!random_range(n_longest)) {
                longest = q;
            }
        }
    }

    /* FIXME: do we want to pop the tail instead? */
    ofpbuf_delete(dequeue_packet(ps, longest));
    if (longest->n == 0) {
        pinqueue_destroy(ps, longest);
    }
}

/* Remove and return the next packet to transmit (in round-robin order). */
/*
 * 从 ps->next_txq->packets 中删除一个数据包. 返回该数据包
 *
 * TODO 如果 pinsched 进行了 hash 重分配, 会有什么样的影响 ?
 */
static struct ofpbuf *
get_tx_packet(struct pinsched *ps)
{
    struct ofpbuf *packet;
    struct pinqueue *q;

    if (!ps->next_txq) {
        advance_txq(ps);
    }

    //TODO 如果 q = NULL
    q = ps->next_txq;
    //删除 q->packets 第一个数据. 返回被删除的数据包
    packet = dequeue_packet(ps, q);
    advance_txq(ps);
    if (q->n == 0) {
        pinqueue_destroy(ps, q);
    }

    return packet;
}

/* Attempts to remove enough tokens from 'ps' to transmit a packet.  Returns
 * true if successful, false otherwise.  (In the latter case no tokens are
 * removed.) */
//TODO
//ps->token_bucket->tokens 是否大于 1000
static bool
get_token(struct pinsched *ps)
{
    //ps->token_bucket->tokens 是否大于 1000
    return token_bucket_withdraw(&ps->token_bucket, 1000);
}

/*
 * 如果 ps 为 NULL, 将 packet 加入 txq
 * 如果 ps->n_queued = 0 && ps->token_bucket->tokens > 1000, 表明不进行速率限制, 将 ps->n_normal++, packet 加入 txq
 * 否则, 进行速率限制, 将 packet 加入 port_no 对应的 pinqueue.
 *
 * NOTE:
 * 如果超过速率, 找到 ps->queues 中最长的队列(如果有多个一样长的,随机选择一个)删除一个包
 */
void
pinsched_send(struct pinsched *ps, ofp_port_t port_no,
              struct ofpbuf *packet, struct ovs_list *txq)
{
    list_init(txq);
    if (!ps) {
        list_push_back(txq, &packet->list_node);
    } else if (!ps->n_queued && get_token(ps)) {
        /* In the common case where we are not constrained by the rate limit,
         * let the packet take the normal path. */
        ps->n_normal++;
        list_push_back(txq, &packet->list_node);
    } else {
        /* Otherwise queue it up for the periodic callback to drain out. */
        struct pinqueue *q;

        /* We might be called with a buffer obtained from dpif_recv() that has
         * much more allocated space than actual content most of the time.
         * Since we're going to store the packet for some time, free up that
         * otherwise wasted space. */
        ofpbuf_trim(packet);

        /*
         * 初始化时 burst * 1000 因此, 这里 ps->n_queued * 1000
         *
         * NOTE:
         * ps->n_queued * 1000 溢出的概率并不大
         *
         */
        if (ps->n_queued * 1000 >= ps->token_bucket.burst) {
            //找到 ps->queues 中最长的队列(如果有多个一样长的,随机选择一个)删除一个包
            drop_packet(ps);
        }
        q = pinqueue_get(ps, port_no);
        list_push_back(&q->packets, &packet->list_node);
        q->n++;
        ps->n_queued++;
        ps->n_limited++;
    }
}

/*
 * 在满足限速的条件下, 从 ps 中取出　50 个数据包加入 txq 中
 *
 * NOTE:
 * 50 是经验值?
 */
void
pinsched_run(struct pinsched *ps, struct ovs_list *txq)
{
    list_init(txq);
    if (ps) {
        int i;

        /* Drain some packets out of the bucket if possible, but limit the
         * number of iterations to allow other code to get work done too. */
        for (i = 0; ps->n_queued && get_token(ps) && i < 50; i++) {
            struct ofpbuf *packet = get_tx_packet(ps);
            list_push_back(txq, &packet->list_node);
        }
    }
}

/*
 * 如果没有达到速率限制, 退出, 否则, 等待直到达到速率限制
 *
 * 如果 ps->token_bucket 超过 1000, 直接返回
 * 否则 等待 ps->token_bucket->last_fill + (1000 - ps->token_bucket->token)/ps->token_bucket->rate + 1 秒
 *
 * NOTE:
 * 1000 是经验值?
 */
void
pinsched_wait(struct pinsched *ps)
{
    if (ps && ps->n_queued) {
        token_bucket_wait(&ps->token_bucket, 1000);
    }
}

/* Creates and returns a scheduler for sending packet-in messages. */
struct pinsched *
pinsched_create(int rate_limit, int burst_limit)
{
    struct pinsched *ps;

    ps = xzalloc(sizeof *ps);

    adjust_limits(&rate_limit, &burst_limit);
    token_bucket_init(&ps->token_bucket,
                      rate_limit, sat_mul(burst_limit, 1000));

    hmap_init(&ps->queues);
    ps->n_queued = 0;
    ps->next_txq = NULL;
    ps->n_normal = 0;
    ps->n_limited = 0;
    ps->n_queue_dropped = 0;

    return ps;
}

void
pinsched_destroy(struct pinsched *ps)
{
    if (ps) {
        struct pinqueue *q, *next;

        HMAP_FOR_EACH_SAFE (q, next, node, &ps->queues) {
            hmap_remove(&ps->queues, &q->node);
            ofpbuf_list_delete(&q->packets);
            free(q);
        }
        hmap_destroy(&ps->queues);
        free(ps);
    }
}

void
pinsched_get_limits(const struct pinsched *ps,
                    int *rate_limit, int *burst_limit)
{
    *rate_limit = ps->token_bucket.rate;
    *burst_limit = ps->token_bucket.burst / 1000;
}

void
pinsched_set_limits(struct pinsched *ps, int rate_limit, int burst_limit)
{
    adjust_limits(&rate_limit, &burst_limit);
    token_bucket_set(&ps->token_bucket,
                     rate_limit, sat_mul(burst_limit, 1000));
    while (ps->n_queued > burst_limit) {
        drop_packet(ps);
    }
}

/* Retrieves statistics for 'ps'.  The statistics will be all zero if 'ps' is
 * null. */
void
pinsched_get_stats(const struct pinsched *ps, struct pinsched_stats *stats)
{
    if (ps) {
        stats->n_queued = ps->n_queued;
        stats->n_normal = ps->n_normal;
        stats->n_limited = ps->n_limited;
        stats->n_queue_dropped = ps->n_queue_dropped;
    } else {
        memset(stats, 0, sizeof *stats);
    }
}
