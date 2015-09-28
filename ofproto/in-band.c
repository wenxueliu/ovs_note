/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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
#include "in-band.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include "classifier.h"
#include "dhcp.h"
#include "flow.h"
#include "netdev.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofp-actions.h"
#include "ofproto.h"
#include "ofpbuf.h"
#include "ofproto-provider.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "timeval.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(in_band);

/* Priorities used in classifier for in-band rules.  These values are higher
 * than any that may be set with OpenFlow, and "18" kind of looks like "IB".
 * The ordering of priorities is not important because all of the rules set up
 * by in-band control have the same action.  The only reason to use more than
 * one priority is to make the kind of flow easier to see during debugging. */
enum {
    /* One set per bridge. */
    IBR_FROM_LOCAL_DHCP = 180000, /* (a) From local port, DHCP. */
    IBR_TO_LOCAL_ARP,             /* (b) To local port, ARP. */
    IBR_FROM_LOCAL_ARP,           /* (c) From local port, ARP. */

    /* One set per unique next-hop MAC. */
    IBR_TO_NEXT_HOP_ARP,          /* (d) To remote MAC, ARP. */
    IBR_FROM_NEXT_HOP_ARP,        /* (e) From remote MAC, ARP. */

    /* One set per unique remote IP address. */
    IBR_TO_REMOTE_ARP,            /* (f) To remote IP, ARP. */
    IBR_FROM_REMOTE_ARP,          /* (g) From remote IP, ARP. */

    /* One set per unique remote (IP,port) pair. */
    IBR_TO_REMOTE_TCP,            /* (h) To remote IP, TCP port. */
    IBR_FROM_REMOTE_TCP           /* (i) From remote IP, TCP port. */
};

/* Track one remote IP and next hop information. */
struct in_band_remote {
    struct sockaddr_in remote_addr; /* IP address, in network byte order. */
    uint8_t remote_mac[ETH_ADDR_LEN]; /* Next-hop MAC, all-zeros if unknown. */
    uint8_t last_remote_mac[ETH_ADDR_LEN]; /* Previous nonzero next-hop MAC. */
    struct netdev *remote_netdev; /* Device to send to next-hop MAC. */
};

/* What to do to an in_band_rule. */
enum in_band_op {
    ADD,                       /* Add the rule to ofproto's flow table. */
    DEL                        /* Delete the rule from ofproto's flow table. */
};

/* A rule to add to or delete from ofproto's flow table.  */
struct in_band_rule {
    struct hmap_node hmap_node; /* In struct in_band's "rules" hmap. */
    struct match match;
    int priority;
    enum in_band_op op;
};

struct in_band {
    struct ofproto *ofproto;
    int queue_id;               /* default -1 */

    /* Remote information. */
    time_t next_remote_refresh; /* Refresh timer. */
    struct in_band_remote *remotes;
    size_t n_remotes;

    /* Local information. */
    time_t next_local_refresh;       /* Refresh timer. */
    uint8_t local_mac[ETH_ADDR_LEN]; /* Current MAC. */
    struct netdev *local_netdev;     /* Local port's network device. */

    /* Flow tracking. */
    struct hmap rules;          /* Contains "struct in_band_rule"s. */
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

/*
 * 1. 清空 r->remote_mac
 * 2. 找到下一个 r->remote_addr.sin_addr 的下一跳地址和设备, 如果下一跳地址为空, 就用当前地址初始化
 * 3. 如果 r->remote_netdev 为 NULL 或 r->remote_netdev != next_hop_dev, 就关闭旧的 netdev, 打开新的 netdev. 并初始化 r->remote_netdev 为新的 netdev
 * 4. 查找 r->remote_netdev 的 mac 地址, 赋值给 r->remote_mac, 如果找到, 等待 10s, 如果找不到立即刷新
 */
static int
refresh_remote(struct in_band *ib, struct in_band_remote *r)
{
    struct in_addr next_hop_inaddr;
    char *next_hop_dev;
    int retval;

    /* Find the next-hop IP address. */
    //清空 r->remote_mac
    memset(r->remote_mac, 0, sizeof r->remote_mac);
    //找到下一个 r->remote_addr.sin_addr 的下一跳地址, 如果下一跳地址为空, 就用当前地址初始化
    retval = netdev_get_next_hop(ib->local_netdev, &r->remote_addr.sin_addr,
                                 &next_hop_inaddr, &next_hop_dev);
    if (retval) {
        VLOG_WARN("%s: cannot find route for controller ("IP_FMT"): %s",
                  ib->ofproto->name, IP_ARGS(r->remote_addr.sin_addr.s_addr),
                  ovs_strerror(retval));
        return 1;
    }
    if (!next_hop_inaddr.s_addr) {
        next_hop_inaddr = r->remote_addr.sin_addr;
    }

    /* Open the next-hop network device. */
    //如果 r->remote_netdev 为 NULL 或 r->remote_netdev != next_hop_dev,
    //就关闭旧的 netdev, 打开新的 netdev. 并初始化 r->remote_netdev 为新的 netdev
    if (!r->remote_netdev
        || strcmp(netdev_get_name(r->remote_netdev), next_hop_dev))
    {
        netdev_close(r->remote_netdev);

        retval = netdev_open(next_hop_dev, "system", &r->remote_netdev);
        if (retval) {
            VLOG_WARN_RL(&rl, "%s: cannot open netdev %s (next hop "
                         "to controller "IP_FMT"): %s",
                         ib->ofproto->name, next_hop_dev,
                         IP_ARGS(r->remote_addr.sin_addr.s_addr),
                         ovs_strerror(retval));
            free(next_hop_dev);
            return 1;
        }
    }
    free(next_hop_dev);

    //查找 r->remote_netdev 的 mac 地址, 赋值给 r->remote_mac
    /* Look up the MAC address of the next-hop IP address. */
    retval = netdev_arp_lookup(r->remote_netdev, next_hop_inaddr.s_addr,
                               r->remote_mac);
    if (retval) {
        VLOG_DBG_RL(&rl, "%s: cannot look up remote MAC address ("IP_FMT"): %s",
                    ib->ofproto->name, IP_ARGS(next_hop_inaddr.s_addr),
                    ovs_strerror(retval));
    }

    /* If we don't have a MAC address, then refresh quickly, since we probably
     * will get a MAC address soon (via ARP).  Otherwise, we can afford to wait
     * a little while. */
    return eth_addr_is_zero(r->remote_mac) ? 1 : 10;
}

//遍历 ib->remotes 的所有设备, 刷新下一个地址和网络设备, 并查找下一跳设备的
//MAC, 如果前后 MAC 地址发生变化, 就返回 true
static bool
refresh_remotes(struct in_band *ib)
{
    struct in_band_remote *r;
    bool any_changes;

    if (time_now() < ib->next_remote_refresh) {
        return false;
    }

    any_changes = false;
    ib->next_remote_refresh = TIME_MAX;
    for (r = ib->remotes; r < &ib->remotes[ib->n_remotes]; r++) {
        uint8_t old_remote_mac[ETH_ADDR_LEN];
        time_t next_refresh;

        /* Save old MAC. */
        memcpy(old_remote_mac, r->remote_mac, ETH_ADDR_LEN);

        /* Refresh remote information. */
        //刷新下一个地址和网络设备, 并查找下一跳设备的 MAC, //如果找到就设置刷新时间为当前直接加 10s, 否则, 立即刷新
        next_refresh = refresh_remote(ib, r) + time_now();
        ib->next_remote_refresh = MIN(ib->next_remote_refresh, next_refresh);

        /* If the MAC changed, log the changes. */
        //这里如果 r->remote_mac = NULL 是否应该警告?
        if (!eth_addr_equals(r->remote_mac, old_remote_mac)) {
            any_changes = true;
            if (!eth_addr_is_zero(r->remote_mac)
                && !eth_addr_equals(r->last_remote_mac, r->remote_mac)) {
                VLOG_DBG("%s: remote MAC address changed from "ETH_ADDR_FMT
                         " to "ETH_ADDR_FMT,
                         ib->ofproto->name,
                         ETH_ADDR_ARGS(r->last_remote_mac),
                         ETH_ADDR_ARGS(r->remote_mac));
                memcpy(r->last_remote_mac, r->remote_mac, ETH_ADDR_LEN);
            }
        }
    }

    return any_changes;
}

/* Refreshes the MAC address of the local port into ib->local_mac, if it is due
 * for a refresh.  Returns true if anything changed, otherwise false.  */
//如果 ib->next_local_refresh 小于当前时间并且 ib->local_mac 改变, 就将ib->local_netdev 新的 mac 地址复制给 ib->local_mac
static bool
refresh_local(struct in_band *ib)
{
    uint8_t ea[ETH_ADDR_LEN];
    time_t now;

    now = time_now();
    if (now < ib->next_local_refresh) {
        return false;
    }
    ib->next_local_refresh = now + 1;

    if (netdev_get_etheraddr(ib->local_netdev, ea)
        || eth_addr_equals(ea, ib->local_mac)) {
        return false;
    }

    memcpy(ib->local_mac, ea, ETH_ADDR_LEN);
    return true;
}

/* Returns true if packets in 'flow' should be directed to the local port.
 * (This keeps the flow table from preventing DHCP replies from being seen by
 * the local port.) */
bool
in_band_must_output_to_local_port(const struct flow *flow)
{
    return (flow->dl_type == htons(ETH_TYPE_IP)
            && flow->nw_proto == IPPROTO_UDP
            && flow->tp_src == htons(DHCP_SERVER_PORT)
            && flow->tp_dst == htons(DHCP_CLIENT_PORT));
}

/* Returns the number of in-band rules currently installed in the flow
 * table. */
int
in_band_count_rules(const struct in_band *ib)
{
    return hmap_count(&ib->rules);
}

//利用 match, priority 构造 in_band_rule对象, 加入 ib
static void
add_rule(struct in_band *ib, const struct match *match, int priority)
{
    uint32_t hash = match_hash(match, 0);
    struct in_band_rule *rule;

    HMAP_FOR_EACH_WITH_HASH (rule, hmap_node, hash, &ib->rules) {
        if (match_equal(&rule->match, match)) {
            rule->op = ADD;
            return;
        }
    }

    rule = xmalloc(sizeof *rule);
    rule->match = *match;
    rule->priority = priority;
    rule->op = ADD;
    hmap_insert(&ib->rules, &rule->hmap_node, hash);
}

//删除已经存在的, 重新添加一些默认规则
static void
update_rules(struct in_band *ib)
{
    struct in_band_rule *ib_rule;
    struct in_band_remote *r;
    struct match match;

    /* Mark all the existing rules for deletion.  (Afterward we will re-add any
     * rules that are still valid.) */
    HMAP_FOR_EACH (ib_rule, hmap_node, &ib->rules) {
        ib_rule->op = DEL;
    }

    //允许从 local port 发送 DHCP 请求
    //允许从 local mac 发送 ARP 请求
    //允许从 local mac 发送 ARP 应答
    if (ib->n_remotes && !eth_addr_is_zero(ib->local_mac)) {
        /* (a) Allow DHCP requests sent from the local port. */
        match_init_catchall(&match);
        match_set_in_port(&match, OFPP_LOCAL);
        match_set_dl_type(&match, htons(ETH_TYPE_IP));
        match_set_dl_src(&match, ib->local_mac);
        match_set_nw_proto(&match, IPPROTO_UDP);
        match_set_tp_src(&match, htons(DHCP_CLIENT_PORT));
        match_set_tp_dst(&match, htons(DHCP_SERVER_PORT));
        add_rule(ib, &match, IBR_FROM_LOCAL_DHCP);

        /* (b) Allow ARP replies to the local port's MAC address. */
        match_init_catchall(&match);
        match_set_dl_type(&match, htons(ETH_TYPE_ARP));
        match_set_dl_dst(&match, ib->local_mac);
        match_set_nw_proto(&match, ARP_OP_REPLY);
        add_rule(ib, &match, IBR_TO_LOCAL_ARP);

        /* (c) Allow ARP requests from the local port's MAC address.  */
        match_init_catchall(&match);
        match_set_dl_type(&match, htons(ETH_TYPE_ARP));
        match_set_dl_src(&match, ib->local_mac);
        match_set_nw_proto(&match, ARP_OP_REQUEST);
        add_rule(ib, &match, IBR_FROM_LOCAL_ARP);
    }

    //遍历ib->remotes, 如果 r->remote_mac 不为 NULL, 允许 r->remote_mac 发送 ARP
    //请求和发送 ARP 应答
    for (r = ib->remotes; r < &ib->remotes[ib->n_remotes]; r++) {
        const uint8_t *remote_mac = r->remote_mac;

        if (eth_addr_is_zero(remote_mac)) {
            continue;
        }

        /* (d) Allow ARP replies to the next hop's MAC address. */
        match_init_catchall(&match);
        match_set_dl_type(&match, htons(ETH_TYPE_ARP));
        match_set_dl_dst(&match, remote_mac);
        match_set_nw_proto(&match, ARP_OP_REPLY);
        add_rule(ib, &match, IBR_TO_NEXT_HOP_ARP);

        /* (e) Allow ARP requests from the next hop's MAC address. */
        match_init_catchall(&match);
        match_set_dl_type(&match, htons(ETH_TYPE_ARP));
        match_set_dl_src(&match, remote_mac);
        match_set_nw_proto(&match, ARP_OP_REQUEST);
        add_rule(ib, &match, IBR_FROM_NEXT_HOP_ARP);
    }

    //遍历ib->remotes, 允许 r->remote_addr 发送 ARP 应答, 发送　ARP 请求, 发送
    //TCP 包, 接受 TCP 包
    for (r = ib->remotes; r < &ib->remotes[ib->n_remotes]; r++) {
        const struct sockaddr_in *a = &r->remote_addr;

        /* (f) Allow ARP replies containing the remote's IP address as a
         * target. */
        match_init_catchall(&match);
        match_set_dl_type(&match, htons(ETH_TYPE_ARP));
        match_set_nw_proto(&match, ARP_OP_REPLY);
        match_set_nw_dst(&match, a->sin_addr.s_addr);
        add_rule(ib, &match, IBR_TO_REMOTE_ARP);

        /* (g) Allow ARP requests containing the remote's IP address as a
         * source. */
        match_init_catchall(&match);
        match_set_dl_type(&match, htons(ETH_TYPE_ARP));
        match_set_nw_proto(&match, ARP_OP_REQUEST);
        match_set_nw_src(&match, a->sin_addr.s_addr);
        add_rule(ib, &match, IBR_FROM_REMOTE_ARP);

        /* (h) Allow TCP traffic to the remote's IP and port. */
        match_init_catchall(&match);
        match_set_dl_type(&match, htons(ETH_TYPE_IP));
        match_set_nw_proto(&match, IPPROTO_TCP);
        match_set_nw_dst(&match, a->sin_addr.s_addr);
        match_set_tp_dst(&match, a->sin_port);
        add_rule(ib, &match, IBR_TO_REMOTE_TCP);

        /* (i) Allow TCP traffic from the remote's IP and port. */
        match_init_catchall(&match);
        match_set_dl_type(&match, htons(ETH_TYPE_IP));
        match_set_nw_proto(&match, IPPROTO_TCP);
        match_set_nw_src(&match, a->sin_addr.s_addr);
        match_set_tp_src(&match, a->sin_port);
        add_rule(ib, &match, IBR_FROM_REMOTE_TCP);
    }
}

/* Updates the OpenFlow flow table for the current state of in-band control.
 * Returns true ordinarily.  Returns false if no remotes are configured on 'ib'
 * and 'ib' doesn't have any rules left to remove from the OpenFlow flow
 * table.  Thus, a false return value means that the caller can destroy 'ib'
 * without leaving extra flows hanging around in the flow table. */

//更新 ib 的 local 和 remote netdev 及 rules.
//如果流表为 NULL 或 remote netdev 为 NULL, 就返回 false;
//否则返回 true;
bool
in_band_run(struct in_band *ib)
{
    uint64_t ofpacts_stub[128 / 8];
    struct ofpbuf ofpacts;

    struct in_band_rule *rule, *next;

    //初始化 ofpacts
    //ofpacts->base = ofpacts_stub
    //ofpacts->allocated = sizeof ofpacts_stub
    //ofpacts->source = OFPBUF_STUB
    ofpbuf_use_stub(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);

    if (ib->queue_id >= 0) {
        ofpact_put_SET_QUEUE(&ofpacts)->queue_id = ib->queue_id;
    }
    ofpact_put_OUTPUT(&ofpacts)->port = OFPP_NORMAL;

    //如果 ib->next_local_refresh 小于当前时间并且 ib->local_mac 改变, 就将 ib->local_netdev 新的 mac 地址复制给 ib->local_mac
    refresh_local(ib);
    //遍历 ib->remotes 的所有设备, 刷新下一个地址和网络设备, 并查找下一跳设备的 MAC, 如果前后 MAC 地址发生变化, 就返回 true
    refresh_remotes(ib);

    //删除已经存在的流表, 重新添加一些默认流表
    update_rules(ib);

    HMAP_FOR_EACH_SAFE (rule, next, hmap_node, &ib->rules) {
        switch (rule->op) {
        case ADD:
            ofproto_add_flow(ib->ofproto, &rule->match, rule->priority,
                             ofpacts.data, ofpacts.size);
            break;

        case DEL:
            ofproto_delete_flow(ib->ofproto, &rule->match, rule->priority);
            hmap_remove(&ib->rules, &rule->hmap_node);
            free(rule);
            break;
        }
    }

    ofpbuf_uninit(&ofpacts);

    return ib->n_remotes || !hmap_is_empty(&ib->rules);
}

void
in_band_wait(struct in_band *in_band)
{
    long long int wakeup
            = MIN(in_band->next_remote_refresh, in_band->next_local_refresh);
    poll_timer_wait_until(wakeup * 1000);
}

/*
 *
 * 初始化 in_band 各个数据成员, 但不包含 remotes, n_remotes, local_mac,
 *
 * 注
 * 1. local_netdev 的类型是 internal
 * 2. 借助 in_band_set_remotes 初始化 remotes, n_remotes
 *
 */
int
in_band_create(struct ofproto *ofproto, const char *local_name,
               struct in_band **in_bandp)
{
    struct in_band *in_band;
    struct netdev *local_netdev;
    int error;

    *in_bandp = NULL;
    error = netdev_open(local_name, "internal", &local_netdev);
    if (error) {
        VLOG_ERR("%s: failed to initialize in-band control: cannot open "
                 "datapath local port %s (%s)", ofproto->name,
                 local_name, ovs_strerror(error));
        return error;
    }

    in_band = xzalloc(sizeof *in_band);
    in_band->ofproto = ofproto;
    in_band->queue_id = -1;
    in_band->next_remote_refresh = TIME_MIN;
    in_band->next_local_refresh = TIME_MIN;
    in_band->local_netdev = local_netdev;
    hmap_init(&in_band->rules);

    *in_bandp = in_band;

    return 0;
}

void
in_band_destroy(struct in_band *ib)
{
    if (ib) {
        struct in_band_rule *rule, *next;

        HMAP_FOR_EACH_SAFE (rule, next, hmap_node, &ib->rules) {
            hmap_remove(&ib->rules, &rule->hmap_node);
            free(rule);
        }
        hmap_destroy(&ib->rules);
        in_band_set_remotes(ib, NULL, 0);
        netdev_close(ib->local_netdev);
        free(ib);
    }
}

static bool
any_addresses_changed(struct in_band *ib,
                      const struct sockaddr_in *addresses, size_t n)
{
    size_t i;

    if (n != ib->n_remotes) {
        return true;
    }

    for (i = 0; i < n; i++) {
        const struct sockaddr_in *old = &ib->remotes[i].remote_addr;
        const struct sockaddr_in *new = &addresses[i];

        if (old->sin_addr.s_addr != new->sin_addr.s_addr ||
            old->sin_port != new->sin_port) {
            return true;
        }
    }

    return false;
}

//清除旧的 remotes, 用 addresses 初始化 in_band 的 remotes
void
in_band_set_remotes(struct in_band *ib,
                    const struct sockaddr_in *addresses, size_t n)
{
    size_t i;

    if (!any_addresses_changed(ib, addresses, n)) {
        return;
    }

    /* Clear old remotes. */
    for (i = 0; i < ib->n_remotes; i++) {
        netdev_close(ib->remotes[i].remote_netdev);
    }
    free(ib->remotes);

    /* Set up new remotes. */
    ib->remotes = n ? xzalloc(n * sizeof *ib->remotes) : NULL;
    ib->n_remotes = n;
    for (i = 0; i < n; i++) {
        ib->remotes[i].remote_addr = addresses[i];
    }

    /* Force refresh in next call to in_band_run(). */
    ib->next_remote_refresh = TIME_MIN;
}

/* Sets the OpenFlow queue used by flows set up by 'ib' to 'queue_id'.  If
 * 'queue_id' is negative, 'ib' will not set any queue (which is also the
 * default). */
void
in_band_set_queue(struct in_band *ib, int queue_id)
{
    ib->queue_id = queue_id;
}

