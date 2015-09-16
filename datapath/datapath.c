/*
 * Copyright (c) 2007-2014 Nicira, Inc.
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/etherdevice.h>
#include <linux/genetlink.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/wait.h>
#include <asm/div64.h>
#include <linux/highmem.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/openvswitch.h>
#include <linux/rculist.h>
#include <linux/dmi.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "datapath.h"
#include "flow.h"
#include "flow_table.h"
#include "flow_netlink.h"
#include "vlan.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

int ovs_net_id __read_mostly;
EXPORT_SYMBOL_GPL(ovs_net_id);

static struct genl_family dp_packet_genl_family;
static struct genl_family dp_flow_genl_family;
static struct genl_family dp_datapath_genl_family;

static const struct nla_policy flow_policy[];

static const struct genl_multicast_group ovs_dp_flow_multicast_group = {
	.name = OVS_FLOW_MCGROUP,
};

static const struct genl_multicast_group ovs_dp_datapath_multicast_group = {
	.name = OVS_DATAPATH_MCGROUP,
};

const struct genl_multicast_group ovs_dp_vport_multicast_group = {
	.name = OVS_VPORT_MCGROUP,
};

/* Check if need to build a reply message.
 * OVS userspace sets the NLM_F_ECHO flag if it needs the reply.
 */
static bool ovs_must_notify(struct genl_family *family, struct genl_info *info,
			    unsigned int group)
{
	return info->nlhdr->nlmsg_flags & NLM_F_ECHO ||
	       genl_has_listeners(family, genl_info_net(info), group);
}

static void ovs_notify(struct genl_family *family,
		       const struct genl_multicast_group *grp,
		       struct sk_buff *skb, struct genl_info *info)
{
 /**
  * nlmsg_notify - send a notification netlink message
  * @sk: netlink socket to use
  * @skb: notification message
  * @portid: destination netlink portid for reports or 0
  * @group: destination multicast group or 0
  * @report: 1 to report back, 0 to disable
  * @flags: allocation flags
  */
  // genl_notify(family,skb, net, portid, group, nlh, flags))
  // ================
  // struct sock *sk = net->genl_sock;
  // group = family->mcgrp_offset + group;
  // report = nlmsg_report(nlh))
  // nlmsg_notify(sk, skb, portid, group, report, flags);

	genl_notify(family, skb, genl_info_net(info),
		    info->snd_portid, GROUP_ID(grp), info->nlhdr, GFP_KERNEL);
}

/**
 * DOC: Locking:
 *
 * All writes e.g. Writes to device state (add/remove datapath, port, set
 * operations on vports, etc.), Writes to other state (flow table
 * modifications, set miscellaneous datapath parameters, etc.) are protected
 * by ovs_lock.
 *
 * Reads are protected by RCU.
 *
 * There are a few special cases (mostly stats) that have their own
 * synchronization but they nest under all of above and don't interact with
 * each other.
 *
 * The RTNL lock nests inside ovs_mutex.
 */

static DEFINE_MUTEX(ovs_mutex);

void ovs_lock(void)
{
	mutex_lock(&ovs_mutex);
}

void ovs_unlock(void)
{
	mutex_unlock(&ovs_mutex);
}

#ifdef CONFIG_LOCKDEP
int lockdep_ovsl_is_held(void)
{
	if (debug_locks)
		return lockdep_is_held(&ovs_mutex);
	else
		return 1;
}
EXPORT_SYMBOL_GPL(lockdep_ovsl_is_held);
#endif

static int queue_gso_packets(struct datapath *dp, struct sk_buff *,
			     const struct sw_flow_key *,
			     const struct dp_upcall_info *);
static int queue_userspace_packet(struct datapath *dp, struct sk_buff *,
				  const struct sw_flow_key *,
				  const struct dp_upcall_info *);

/* Must be called with rcu_read_lock. */
//遍历 net->dev_index_head[ifindex & (NETDEV_HASHENTRIES - 1)] 所有元素,
//找到 dev->ifindex = ifindex 的 dev, 返回netdev_priv(dev)->vport->dp
static struct datapath *get_dp_rcu(struct net *net, int dp_ifindex)
{
    //遍历 net->dev_index_head[ifindex & (NETDEV_HASHENTRIES - 1)] 所有元素, 找到 dev->ifindex = ifindex 的 dev
	struct net_device *dev = dev_get_by_index_rcu(net, dp_ifindex);

	if (dev) {
        //netdev_priv(dev)->vport
		struct vport *vport = ovs_internal_dev_get_vport(dev);
		if (vport)
			return vport->dp;
	}

	return NULL;
}

/* The caller must hold either ovs_mutex or rcu_read_lock to keep the
 * returned dp pointer valid.
 */
//遍历 net->dev_index_head[ifindex & (NETDEV_HASHENTRIES - 1)] 所有元素,
//找到 dev->ifindex = ifindex 的 dev, 返回netdev_priv(dev)->vport->dp
static inline struct datapath *get_dp(struct net *net, int dp_ifindex)
{
	struct datapath *dp;

	WARN_ON_ONCE(!rcu_read_lock_held() && !lockdep_ovsl_is_held());
	rcu_read_lock();
	dp = get_dp_rcu(net, dp_ifindex);
	rcu_read_unlock();

	return dp;
}

/* Must be called with rcu_read_lock or ovs_mutex. */
const char *ovs_dp_name(const struct datapath *dp)
{
	struct vport *vport = ovs_vport_ovsl_rcu(dp, OVSP_LOCAL);
	return vport->ops->get_name(vport);
}

//找到 dp->ports[OVSP_LOCAL % 1024] 中端口号为 OVSP_LOCAL 的 vport,
static int get_dpifindex(const struct datapath *dp)
{
	struct vport *local;
	int ifindex;

	rcu_read_lock();

    //OVSP_LOCAL = 0
    //在 dp->ports[OVSP_LOCAL % 1024] 中找到端口号为 OVSP_LOCAL 的 vport, 找不到返回 NULL
	local = ovs_vport_rcu(dp, OVSP_LOCAL);
	if (local)
		ifindex = netdev_vport_priv(local)->dev->ifindex;
	else
		ifindex = 0;

	rcu_read_unlock();

	return ifindex;
}

static void destroy_dp_rcu(struct rcu_head *rcu)
{
	struct datapath *dp = container_of(rcu, struct datapath, rcu);

	ovs_flow_tbl_destroy(&dp->table);
	free_percpu(dp->stats_percpu);
	release_net(ovs_dp_get_net(dp));
	kfree(dp->ports);
	kfree(dp);
}

static struct hlist_head *vport_hash_bucket(const struct datapath *dp,
					    u16 port_no)
{
	return &dp->ports[port_no & (DP_VPORT_HASH_BUCKETS - 1)];
}

/* Called with ovs_mutex or RCU read lock. */
//在 dp->ports[port_no % DP_VPORT_HASH_BUCKETS] 中找到端口号为 port_no 的 vport, 找不到返回 NULL
struct vport *ovs_lookup_vport(const struct datapath *dp, u16 port_no)
{
	struct vport *vport;
	struct hlist_head *head;

    //head = dp->ports[port_no % DP_VPORT_HASH_BUCKETS]
	head = vport_hash_bucket(dp, port_no);
	hlist_for_each_entry_rcu(vport, head, dp_hash_node) {
		if (vport->port_no == port_no)
			return vport;
	}
	return NULL;
}

/* Called with ovs_mutex. */
/* 1. 创建并初始化 vport
 * * 类型为 params->type 的 ops
 * * 确保 params->type->ops->owner 的模块是 alive 的
 * * 调用 internal_dev_create(params) 创建 vport, 初始化各个数据成员及私有数据
 * * 将 vport->hash_node 加入 dev_table
 * 注: 没有初始化的 err_stats, detach_list
 *
 * 2. 如果端口创建成功, 将其加入 parms->dp->ports 中
 */
static struct vport *new_vport(const struct vport_parms *parms)
{
	struct vport *vport;

    //创建并初始化 vport:
    // 1. 类型为 params->type 的 ops
    // 2. 确保 params->type->ops->owner 的模块是 alive 的
    // 3. 调用 internal_dev_create(params) 创建 vport,
    // 4. 将 vport->hash_node 加入 dev_table
    //
    // 注: 没有初始化的 err_stats, detach_list
	vport = ovs_vport_add(parms);
    //如果端口创建成功, 将其加入 parms->dp->ports 中
	if (!IS_ERR(vport)) {
		struct datapath *dp = parms->dp;
	    //将 vport->dp_hash_node 加入 parms->dp->ports[vport->port_no & (DP_VPORT_HASH_BUCKETS - 1)] 中
		struct hlist_head *head = vport_hash_bucket(dp, vport->port_no);

		hlist_add_head_rcu(&vport->dp_hash_node, head);
	}
	return vport;
}

void ovs_dp_detach_port(struct vport *p)
{
	ASSERT_OVSL();

	/* First drop references to device. */
	hlist_del_rcu(&p->dp_hash_node);

	/* Then destroy it. */
	ovs_vport_del(p);
}

/* Must be called with rcu_read_lock. */
void ovs_dp_process_packet(struct sk_buff *skb, struct sw_flow_key *key)
{
	const struct vport *p = OVS_CB(skb)->input_vport;
	struct datapath *dp = p->dp;
	struct sw_flow *flow;
	struct sw_flow_actions *sf_acts;
	struct dp_stats_percpu *stats;
	u64 *stats_counter;
	u32 n_mask_hit;

	stats = this_cpu_ptr(dp->stats_percpu);

	/*
     * Look up flow.
     * skb_get_hash(skb) 获取一个 skb 的 hash, 唯一鉴别一条 flow, 不同的 flow
     * 应该有不同的 hash, 相同的 flow 应该有相同的 hash
     */
	flow = ovs_flow_tbl_lookup_stats(&dp->table, key, skb_get_hash(skb),
					 &n_mask_hit);
	if (unlikely(!flow)) {
		struct dp_upcall_info upcall;
		int error;

		memset(&upcall, 0, sizeof(upcall));
		upcall.cmd = OVS_PACKET_CMD_MISS;
		upcall.portid = ovs_vport_find_upcall_portid(p, skb);
		error = ovs_dp_upcall(dp, skb, key, &upcall);
		if (unlikely(error))
			kfree_skb(skb);
		else
			consume_skb(skb);
		stats_counter = &stats->n_missed;
		goto out;
	}

	ovs_flow_stats_update(flow, key->tp.flags, skb);
	sf_acts = rcu_dereference(flow->sf_acts);
	ovs_execute_actions(dp, skb, sf_acts, key);

	stats_counter = &stats->n_hit;

out:
	/* Update datapath statistics. */
	u64_stats_update_begin(&stats->syncp);
	(*stats_counter)++;
	stats->n_mask_hit += n_mask_hit;
	u64_stats_update_end(&stats->syncp);
}

int ovs_dp_upcall(struct datapath *dp, struct sk_buff *skb,
		  const struct sw_flow_key *key,
		  const struct dp_upcall_info *upcall_info)
{
	struct dp_stats_percpu *stats;
	int err;

	if (upcall_info->portid == 0) {
		err = -ENOTCONN;
		goto err;
	}

	if (!skb_is_gso(skb))
		err = queue_userspace_packet(dp, skb, key, upcall_info);
	else
		err = queue_gso_packets(dp, skb, key, upcall_info);
	if (err)
		goto err;

	return 0;

err:
	stats = this_cpu_ptr(dp->stats_percpu);

	u64_stats_update_begin(&stats->syncp);
	stats->n_lost++;
	u64_stats_update_end(&stats->syncp);

	return err;
}

static int queue_gso_packets(struct datapath *dp, struct sk_buff *skb,
			     const struct sw_flow_key *key,
			     const struct dp_upcall_info *upcall_info)
{
	unsigned short gso_type = skb_shinfo(skb)->gso_type;
	struct sw_flow_key later_key;
	struct sk_buff *segs, *nskb;
	struct ovs_skb_cb ovs_cb;
	int err;

	ovs_cb = *OVS_CB(skb);
	segs = __skb_gso_segment(skb, NETIF_F_SG, false);
	*OVS_CB(skb) = ovs_cb;
	if (IS_ERR(segs))
		return PTR_ERR(segs);
	if (segs == NULL)
		return -EINVAL;

	if (gso_type & SKB_GSO_UDP) {
		/* The initial flow key extracted by ovs_flow_key_extract()
		 * in this case is for a first fragment, so we need to
		 * properly mark later fragments.
		 */
		later_key = *key;
		later_key.ip.frag = OVS_FRAG_TYPE_LATER;
	}

	/* Queue all of the segments. */
	skb = segs;
	do {
		*OVS_CB(skb) = ovs_cb;
		if (gso_type & SKB_GSO_UDP && skb != segs)
			key = &later_key;

		err = queue_userspace_packet(dp, skb, key, upcall_info);
		if (err)
			break;

	} while ((skb = skb->next));

	/* Free all of the segments. */
	skb = segs;
	do {
		nskb = skb->next;
		if (err)
			kfree_skb(skb);
		else
			consume_skb(skb);
	} while ((skb = nskb));
	return err;
}

static size_t upcall_msg_size(const struct dp_upcall_info *upcall_info,
			      unsigned int hdrlen)
{
	size_t size = NLMSG_ALIGN(sizeof(struct ovs_header))
		+ nla_total_size(hdrlen) /* OVS_PACKET_ATTR_PACKET */
		+ nla_total_size(ovs_key_attr_size()); /* OVS_PACKET_ATTR_KEY */

	/* OVS_PACKET_ATTR_USERDATA */
	if (upcall_info->userdata)
		size += NLA_ALIGN(upcall_info->userdata->nla_len);

	/* OVS_PACKET_ATTR_EGRESS_TUN_KEY */
	if (upcall_info->egress_tun_info)
		size += nla_total_size(ovs_tun_key_attr_size());

	/* OVS_PACKET_ATTR_ACTIONS */
	if (upcall_info->actions_len)
		size += nla_total_size(upcall_info->actions_len);

	return size;
}

static int queue_userspace_packet(struct datapath *dp, struct sk_buff *skb,
				  const struct sw_flow_key *key,
				  const struct dp_upcall_info *upcall_info)
{
	struct ovs_header *upcall;
	struct sk_buff *nskb = NULL;
	struct sk_buff *user_skb = NULL; /* to be queued to userspace */
	struct nlattr *nla;
	struct genl_info info = {
#ifdef HAVE_GENLMSG_NEW_UNICAST
		.dst_sk = ovs_dp_get_net(dp)->genl_sock,
#endif
		.snd_portid = upcall_info->portid,
	};
	size_t len;
	unsigned int hlen;
	int err, dp_ifindex;

	dp_ifindex = get_dpifindex(dp);
	if (!dp_ifindex)
		return -ENODEV;

	if (skb_vlan_tag_present(skb)) {
		nskb = skb_clone(skb, GFP_ATOMIC);
		if (!nskb)
			return -ENOMEM;

		nskb = vlan_insert_tag_set_proto(nskb, nskb->vlan_proto, skb_vlan_tag_get(nskb));
		if (!nskb)
			return -ENOMEM;

		vlan_set_tci(nskb, 0);

		skb = nskb;
	}

	if (nla_attr_size(skb->len) > USHRT_MAX) {
		err = -EFBIG;
		goto out;
	}

	/* Complete checksum if needed */
	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    (err = skb_checksum_help(skb)))
		goto out;

	/* Older versions of OVS user space enforce alignment of the last
	 * Netlink attribute to NLA_ALIGNTO which would require extensive
	 * padding logic. Only perform zerocopy if padding is not required.
	 */
	if (dp->user_features & OVS_DP_F_UNALIGNED)
		hlen = skb_zerocopy_headlen(skb);
	else
		hlen = skb->len;

	len = upcall_msg_size(upcall_info, hlen); //计算 upcall_info + hlen + ovs_header 的长度
	user_skb = genlmsg_new_unicast(len, &info, GFP_ATOMIC);
	if (!user_skb) {
		err = -ENOMEM;
		goto out;
	}

	upcall = genlmsg_put(user_skb, 0, 0, &dp_packet_genl_family,
			     0, upcall_info->cmd);
	upcall->dp_ifindex = dp_ifindex;

	err = ovs_nla_put_key(key, key, OVS_PACKET_ATTR_KEY, false, user_skb);
	BUG_ON(err);

	if (upcall_info->userdata)
		__nla_put(user_skb, OVS_PACKET_ATTR_USERDATA,
			  nla_len(upcall_info->userdata),
			  nla_data(upcall_info->userdata));

	if (upcall_info->egress_tun_info) {
		nla = nla_nest_start(user_skb, OVS_PACKET_ATTR_EGRESS_TUN_KEY);
		err = ovs_nla_put_egress_tunnel_key(user_skb,
						    upcall_info->egress_tun_info);
		BUG_ON(err);
		nla_nest_end(user_skb, nla);
	}

	if (upcall_info->actions_len) {
		nla = nla_nest_start(user_skb, OVS_PACKET_ATTR_ACTIONS);
		err = ovs_nla_put_actions(upcall_info->actions,
					  upcall_info->actions_len,
					  user_skb);
		if (!err)
			nla_nest_end(user_skb, nla);
		else
			nla_nest_cancel(user_skb, nla);
	}

	/* Only reserve room for attribute header, packet data is added
	 * in skb_zerocopy()
	 */
	if (!(nla = nla_reserve(user_skb, OVS_PACKET_ATTR_PACKET, 0))) {
		err = -ENOBUFS;
		goto out;
	}
	nla->nla_len = nla_attr_size(skb->len);

	err = skb_zerocopy(user_skb, skb, skb->len, hlen);
	if (err)
		goto out;

	/* Pad OVS_PACKET_ATTR_PACKET if linear copy was performed */
	if (!(dp->user_features & OVS_DP_F_UNALIGNED)) {
		size_t plen = NLA_ALIGN(user_skb->len) - user_skb->len;

		if (plen > 0)
			memset(skb_put(user_skb, plen), 0, plen);
	}

	((struct nlmsghdr *) user_skb->data)->nlmsg_len = user_skb->len;

	err = genlmsg_unicast(ovs_dp_get_net(dp), user_skb, upcall_info->portid);
	user_skb = NULL;
out:
	if (err)
		skb_tx_error(skb);
	kfree_skb(user_skb);
	kfree_skb(nskb);
	return err;
}

 /**
  * struct genl_info - receiving information
  * @snd_seq: sending sequence number
  * @snd_portid: netlink portid of sender
  * @nlhdr: netlink message header
  * @genlhdr: generic netlink message header
  * @userhdr: user specific header
  * @attrs: netlink attributes
  * @_net: network namespace
  * @user_ptr: user pointers
  * @dst_sk: destination socket
  */
 //struct genl_info {
 //        u32                     snd_seq;
 //        u32                     snd_portid;
 //        struct nlmsghdr *       nlhdr;
 //        struct genlmsghdr *     genlhdr;
 //        void *                  userhdr;
 //        struct nlattr **        attrs;
 //        possible_net_t          _net;
 //        void *                  user_ptr[2];
 //        struct sock *           dst_sk;
 //};
 //


/*
 * 给 packet 分配 NET_IP_ALIGN + nla_len(a[OVS_PACKET_ATTR_PACKET]) 的空间
 * 初始化 a[OVS_PACKET_ATTR_PACKET]
 *
 *
 *
 */
static int ovs_packet_cmd_execute(struct sk_buff *skb, struct genl_info *info)
{
	struct ovs_header *ovs_header = info->userhdr;
	struct nlattr **a = info->attrs;
	struct sw_flow_actions *acts;
	struct sk_buff *packet;
	struct sw_flow *flow;
	struct sw_flow_actions *sf_acts;
	struct datapath *dp;
	struct ethhdr *eth;
	struct vport *input_vport;
	int len;
	int err;
	bool log = !a[OVS_PACKET_ATTR_PROBE];

	err = -EINVAL;
	if (!a[OVS_PACKET_ATTR_PACKET] || !a[OVS_PACKET_ATTR_KEY] ||
	    !a[OVS_PACKET_ATTR_ACTIONS])
		goto err;

	len = nla_len(a[OVS_PACKET_ATTR_PACKET]);
	packet = __dev_alloc_skb(NET_IP_ALIGN + len, GFP_KERNEL);
	err = -ENOMEM;
	if (!packet)
		goto err;
    //保留 NET_IP_ALIGN 大小的空间在 head, 即 packet->data += NET_IP_ALIGN
	skb_reserve(packet, NET_IP_ALIGN);

    //将 a[OVS_PACKET_ATTR_PACKET] 拷贝到packet->data 开始的地方
	nla_memcpy(__skb_put(packet, len), a[OVS_PACKET_ATTR_PACKET], len);

	skb_reset_mac_header(packet);
	eth = eth_hdr(packet);

	/* Normally, setting the skb 'protocol' field would be handled by a
	 * call to eth_type_trans(), but it assumes there's a sending
	 * device, which we may not have.
	 */
	if (eth_proto_is_802_3(eth->h_proto))
		packet->protocol = eth->h_proto;
	else
		packet->protocol = htons(ETH_P_802_2);

	/* Build an sw_flow for sending this packet. */
	flow = ovs_flow_alloc();
	err = PTR_ERR(flow);
	if (IS_ERR(flow))
		goto err_kfree_skb;

    //从 packet 中提取包信息到 flow->key
	err = ovs_flow_key_extract_userspace(a[OVS_PACKET_ATTR_KEY], packet,
					     &flow->key, log);
	if (err)
		goto err_flow_free;

    //将 a[OVS_PACKET_ATTR_ACTIONS] 初始化 acts
	err = ovs_nla_copy_actions(a[OVS_PACKET_ATTR_ACTIONS],
				   &flow->key, &acts, log);
	if (err)
		goto err_flow_free;

	rcu_assign_pointer(flow->sf_acts, acts);
	OVS_CB(packet)->egress_tun_info = NULL;
	packet->priority = flow->key.phy.priority;
	packet->mark = flow->key.phy.skb_mark;

	rcu_read_lock();
	dp = get_dp_rcu(sock_net(skb->sk), ovs_header->dp_ifindex);
	err = -ENODEV;
	if (!dp)
		goto err_unlock;

    //找到输入端口
	input_vport = ovs_vport_rcu(dp, flow->key.phy.in_port);
	if (!input_vport)
		input_vport = ovs_vport_rcu(dp, OVSP_LOCAL);

	if (!input_vport)
		goto err_unlock;

	OVS_CB(packet)->input_vport = input_vport;
	sf_acts = rcu_dereference(flow->sf_acts);

	local_bh_disable();
    //
	err = ovs_execute_actions(dp, packet, sf_acts, &flow->key);
	local_bh_enable();
	rcu_read_unlock();

	ovs_flow_free(flow, false);
	return err;

err_unlock:
	rcu_read_unlock();
err_flow_free:
	ovs_flow_free(flow, false);
err_kfree_skb:
	kfree_skb(packet);
err:
	return err;
}

static const struct nla_policy packet_policy[OVS_PACKET_ATTR_MAX + 1] = {
	[OVS_PACKET_ATTR_PACKET] = { .len = ETH_HLEN },
	[OVS_PACKET_ATTR_KEY] = { .type = NLA_NESTED },
	[OVS_PACKET_ATTR_ACTIONS] = { .type = NLA_NESTED },
	[OVS_PACKET_ATTR_PROBE] = { .type = NLA_FLAG },
};

static const struct genl_ops dp_packet_genl_ops[] = {
	{ .cmd = OVS_PACKET_CMD_EXECUTE,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = packet_policy,
	  .doit = ovs_packet_cmd_execute
	}
};

 /**
  * struct genl_family - generic netlink family
  * @id: protocol family idenfitier
  * @hdrsize: length of user specific header in bytes
  * @name: name of family
  * @version: protocol version
  * @maxattr: maximum number of attributes supported
  * @netnsok: set to true if the family can handle network
  *      namespaces and should be presented in all of them
  * @parallel_ops: operations can be called in parallel and aren't
  *      synchronized by the core genetlink code
  * @pre_doit: called before an operation's doit callback, it may
  *      do additional, common, filtering and return an error
  * @post_doit: called after an operation's doit callback, it may
  *      undo operations done by pre_doit, for example release locks
  * @mcast_bind: a socket bound to the given multicast group (which
  *      is given as the offset into the groups array)
  * @mcast_unbind: a socket was unbound from the given multicast group.
  *      Note that unbind() will not be called symmetrically if the
  *      generic netlink family is removed while there are still open
  *      sockets.
  * @attrbuf: buffer to store parsed attributes, 当 maxattr != NULL &&
  * parallel_ops = true 时, kmalloc 分配空间, 否则为 null
  * @family_list: family list
  * @mcgrps: multicast groups used by this family (private)
  * @n_mcgrps: number of multicast groups (private)
  * @mcgrp_offset: starting number of multicast group IDs in this family
  * @ops: the operations supported by this family (private)
  * @n_ops: number of operations supported by this family (private)
  */
 //struct genl_family {
 //        unsigned int            id;
 //        unsigned int            hdrsize;
 //        char                    name[GENL_NAMSIZ];
 //        unsigned int            version;
 //        unsigned int            maxattr;
 //        bool                    netnsok;
 //        bool                    parallel_ops;
 //        int                     (*pre_doit)(const struct genl_ops *ops,
 //                                            struct sk_buff *skb,
 //                                            struct genl_info *info);
 //        void                    (*post_doit)(const struct genl_ops *ops,
 //                                             struct sk_buff *skb,
 //                                             struct genl_info *info);
 //        int                     (*mcast_bind)(struct net *net, int group);
 //        void                    (*mcast_unbind)(struct net *net, int group);
 //        struct nlattr **        attrbuf;        /* private */
 //        const struct genl_ops * ops;            /* private */
 //        const struct genl_multicast_group *mcgrps; /* private */
 //        unsigned int            n_ops;          /* private */
 //        unsigned int            n_mcgrps;       /* private */
 //        unsigned int            mcgrp_offset;   /* private */
 //        struct list_head        family_list;    /* private */
 //        struct module           *module;
 //};
static struct genl_family dp_packet_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_PACKET_FAMILY,
	.version = OVS_PACKET_VERSION,
	.maxattr = OVS_PACKET_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_packet_genl_ops,
	.n_ops = ARRAY_SIZE(dp_packet_genl_ops),
};

static void get_dp_stats(const struct datapath *dp, struct ovs_dp_stats *stats,
			 struct ovs_dp_megaflow_stats *mega_stats)
{
	int i;

	memset(mega_stats, 0, sizeof(*mega_stats));

	stats->n_flows = ovs_flow_tbl_count(&dp->table);
	mega_stats->n_masks = ovs_flow_tbl_num_masks(&dp->table);

	stats->n_hit = stats->n_missed = stats->n_lost = 0;

	for_each_possible_cpu(i) {
		const struct dp_stats_percpu *percpu_stats;
		struct dp_stats_percpu local_stats;
		unsigned int start;

		percpu_stats = per_cpu_ptr(dp->stats_percpu, i);

        //主要用于状态同步
		do {
			start = u64_stats_fetch_begin_irq(&percpu_stats->syncp);
			local_stats = *percpu_stats;
		} while (u64_stats_fetch_retry_irq(&percpu_stats->syncp, start));

		stats->n_hit += local_stats.n_hit;
		stats->n_missed += local_stats.n_missed;
		stats->n_lost += local_stats.n_lost;
		mega_stats->n_mask_hit += local_stats.n_mask_hit;
	}
}

static bool should_fill_key(const struct sw_flow_id *sfid, uint32_t ufid_flags)
{
	return ovs_identifier_is_ufid(sfid) &&
	       !(ufid_flags & OVS_UFID_F_OMIT_KEY);
}

static bool should_fill_mask(uint32_t ufid_flags)
{
	return !(ufid_flags & OVS_UFID_F_OMIT_MASK);
}

static bool should_fill_actions(uint32_t ufid_flags)
{
	return !(ufid_flags & OVS_UFID_F_OMIT_ACTIONS);
}

static size_t ovs_flow_cmd_msg_size(const struct sw_flow_actions *acts,
				    const struct sw_flow_id *sfid,
				    uint32_t ufid_flags)
{
	size_t len = NLMSG_ALIGN(sizeof(struct ovs_header));

	/* OVS_FLOW_ATTR_UFID */
	if (sfid && ovs_identifier_is_ufid(sfid))
		len += nla_total_size(sfid->ufid_len);

	/* OVS_FLOW_ATTR_KEY */
	if (!sfid || should_fill_key(sfid, ufid_flags))
		len += nla_total_size(ovs_key_attr_size());

	/* OVS_FLOW_ATTR_MASK */
	if (should_fill_mask(ufid_flags))
		len += nla_total_size(ovs_key_attr_size());

	/* OVS_FLOW_ATTR_ACTIONS */
	if (should_fill_actions(ufid_flags))
		len += nla_total_size(acts->actions_len);

	return len
		+ nla_total_size(sizeof(struct ovs_flow_stats)) /* OVS_FLOW_ATTR_STATS */
		+ nla_total_size(1) /* OVS_FLOW_ATTR_TCP_FLAGS */
		+ nla_total_size(8); /* OVS_FLOW_ATTR_USED */
}

/* Called with ovs_mutex or RCU read lock. */
static int ovs_flow_cmd_fill_stats(const struct sw_flow *flow,
				   struct sk_buff *skb)
{
	struct ovs_flow_stats stats;
	__be16 tcp_flags;
	unsigned long used;

	ovs_flow_stats_get(flow, &stats, &used, &tcp_flags);

	if (used &&
	    nla_put_u64(skb, OVS_FLOW_ATTR_USED, ovs_flow_used_time(used)))
		return -EMSGSIZE;

	if (stats.n_packets &&
	    nla_put(skb, OVS_FLOW_ATTR_STATS, sizeof(struct ovs_flow_stats), &stats))
		return -EMSGSIZE;

	if ((u8)ntohs(tcp_flags) &&
	     nla_put_u8(skb, OVS_FLOW_ATTR_TCP_FLAGS, (u8)ntohs(tcp_flags)))
		return -EMSGSIZE;

	return 0;
}

/* Called with ovs_mutex or RCU read lock. */
static int ovs_flow_cmd_fill_actions(const struct sw_flow *flow,
				     struct sk_buff *skb, int skb_orig_len)
{
	struct nlattr *start;
	int err;

	/* If OVS_FLOW_ATTR_ACTIONS doesn't fit, skip dumping the actions if
	 * this is the first flow to be dumped into 'skb'.  This is unusual for
	 * Netlink but individual action lists can be longer than
	 * NLMSG_GOODSIZE and thus entirely undumpable if we didn't do this.
	 * The userspace caller can always fetch the actions separately if it
	 * really wants them.  (Most userspace callers in fact don't care.)
	 *
	 * This can only fail for dump operations because the skb is always
	 * properly sized for single flows.
	 */
	start = nla_nest_start(skb, OVS_FLOW_ATTR_ACTIONS);
	if (start) {
		const struct sw_flow_actions *sf_acts;

		sf_acts = rcu_dereference_ovsl(flow->sf_acts);
		err = ovs_nla_put_actions(sf_acts->actions,
					  sf_acts->actions_len, skb);

		if (!err)
			nla_nest_end(skb, start);
		else {
			if (skb_orig_len)
				return err;

			nla_nest_cancel(skb, start);
		}
	} else if (skb_orig_len) {
		return -EMSGSIZE;
	}

	return 0;
}

/* Called with ovs_mutex or RCU read lock. */
static int ovs_flow_cmd_fill_info(const struct sw_flow *flow, int dp_ifindex,
				  struct sk_buff *skb, u32 portid,
				  u32 seq, u32 flags, u8 cmd, u32 ufid_flags)
{
	const int skb_orig_len = skb->len;
	struct ovs_header *ovs_header;
	int err;

	ovs_header = genlmsg_put(skb, portid, seq, &dp_flow_genl_family,
				 flags, cmd);
	if (!ovs_header)
		return -EMSGSIZE;

	ovs_header->dp_ifindex = dp_ifindex;

	err = ovs_nla_put_identifier(flow, skb);
	if (err)
		goto error;

	if (should_fill_key(&flow->id, ufid_flags)) {
		err = ovs_nla_put_masked_key(flow, skb);
		if (err)
			goto error;
	}

	if (should_fill_mask(ufid_flags)) {
		err = ovs_nla_put_mask(flow, skb);
		if (err)
			goto error;
	}

	err = ovs_flow_cmd_fill_stats(flow, skb);
	if (err)
		goto error;

	if (should_fill_actions(ufid_flags)) {
		err = ovs_flow_cmd_fill_actions(flow, skb, skb_orig_len);
		if (err)
			goto error;
	}

	genlmsg_end(skb, ovs_header);
	return 0;

error:
	genlmsg_cancel(skb, ovs_header);
	return err;
}

/* May not be called with RCU read lock. */
static struct sk_buff *ovs_flow_cmd_alloc_info(const struct sw_flow_actions *acts,
					       const struct sw_flow_id *sfid,
					       struct genl_info *info,
					       bool always,
					       uint32_t ufid_flags)
{
	struct sk_buff *skb;
	size_t len;

	if (!always && !ovs_must_notify(&dp_flow_genl_family, info,
					GROUP_ID(&ovs_dp_flow_multicast_group)))
		return NULL;

	len = ovs_flow_cmd_msg_size(acts, sfid, ufid_flags);
	skb = genlmsg_new_unicast(len, info, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	return skb;
}

/* Called with ovs_mutex. */
static struct sk_buff *ovs_flow_cmd_build_info(const struct sw_flow *flow,
					       int dp_ifindex,
					       struct genl_info *info, u8 cmd,
					       bool always, u32 ufid_flags)
{
	struct sk_buff *skb;
	int retval;

	skb = ovs_flow_cmd_alloc_info(ovsl_dereference(flow->sf_acts),
				      &flow->id, info, always, ufid_flags);
	if (IS_ERR_OR_NULL(skb))
		return skb;

	retval = ovs_flow_cmd_fill_info(flow, dp_ifindex, skb,
					info->snd_portid, info->snd_seq, 0,
					cmd, ufid_flags);
	BUG_ON(retval < 0);
	return skb;
}

 /**
  * struct genl_info - receiving information
  * @snd_seq: sending sequence number
  * @snd_portid: netlink portid of sender
  * @nlhdr: netlink message header
  * @genlhdr: generic netlink message header
  * @userhdr: user specific header
  * @attrs: netlink attributes
  * @_net: network namespace
  * @user_ptr: user pointers
  * @dst_sk: destination socket
  */
 //struct genl_info {
 //        u32                     snd_seq;
 //        u32                     snd_portid;
 //        struct nlmsghdr *       nlhdr;
 //        struct genlmsghdr *     genlhdr;
 //        void *                  userhdr;
 //        struct nlattr **        attrs;
 //        possible_net_t          _net;
 //        void *                  user_ptr[2];
 //        struct sock *           dst_sk;
 //};


/*
 * 1. 为新建流表 new_flow 分配内存空间
 * 2. 初始化临时变量 match, key, mask
 * 3. a[OVS_FLOW_ATTR_KEY] 初始化 match->key, a[OVS_FLOW_ATTR_MASK] 初始化 match->mask
 * 4. 将 key 与 mask 掩码后的赋值给 new_flow->key
 * 5. 用 a[OVS_FLOW_ATTR_UFID] 初始化 new_flow->id
 * 6. 用 a[OVS_FLOW_ATTR_ACTIONS] 初始化 acts
 * 7. 如果 new_flow->id->ufid_len != 0, 从 dp->table->ufid_ti->buckets 中查找 new_flow->id->ufid 对应的流表是否存在
 * 8. 如果 new_flow->id->ufid_len == 0, 遍历 dp->table->mask_array 中的每一个 mask, 从 dp->table->ti->buckets 中查找匹配 flow->key=key & mask, flow->mask = mask 的流表项
 * 9. 正常情况下, 新创建的流表是不存在的:
 *      * 将 mask 加入 table->mask_array 中
 *      * 将 flow->flow_table->node[table->ti->node_ver] 插入 table->ti->buckets 中的一个链表中
 *      * 如果 flow->id->ufid_len != 0 , 将 flow->ufid_table->node[table->ufid_ti->node_ver] 插入 table->ufid_ti->buckets 中的一个链表中
 * 10. 异常情况是, 新创建的流表已经存在
 *      * 如果配置中不允许重复的流表, 向发送者发送错误消息
 *      * 如果配置允许重复的流表, 如果是 ufid 重复, 发送错误消息, 如果是 key 重复, 简单的用新的 action 代替原理的 action
 *
 *
 */
static int ovs_flow_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow *flow = NULL, *new_flow;
	struct sw_flow_mask mask;
	struct sk_buff *reply;
	struct datapath *dp;
	struct sw_flow_key key;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int error;
	bool log = !a[OVS_FLOW_ATTR_PROBE];

	/* Must have key and actions. */
	error = -EINVAL;
	if (!a[OVS_FLOW_ATTR_KEY]) {
		OVS_NLERR(log, "Flow key attr not present in new flow.");
		goto error;
	}
	if (!a[OVS_FLOW_ATTR_ACTIONS]) {
		OVS_NLERR(log, "Flow actions attr not present in new flow.");
		goto error;
	}

	/* Most of the time we need to allocate a new flow, do it before
	 * locking.
	 */
	new_flow = ovs_flow_alloc();
	if (IS_ERR(new_flow)) {
		error = PTR_ERR(new_flow);
		goto error;
	}

	/* Extract key. */

    /* 初始化 match, key, mask
     * match->key = key
     * match->mask = mask
     */
	ovs_match_init(&match, &key, &mask);
    /*
     * a[OVS_FLOW_ATTR_KEY] 初始化 match->key, a[OVS_FLOW_ATTR_MASK] 初始化 match->mask
     * 1. 解析 a[OVS_FLOW_ATTR_KEY] 保存在中间变量 tmp_key 中, 已经解析的 ovs_key_attr 标记保存在变量 key_attrs
     * 2. 将 key_attrs 中对应的 ovs_key_attr 从 tmp_key 中取出来赋值给 match->key
     * 3. 解析 a[OVS_FLOW_ATTR_MASK] 保存在中间变量 tmp_mask 中, 已经解析的 ovs_key_attr 标记保持变量 mask_attrs
     * 4. 将 mask_attrs 中对应的 ovs_key_attr 从 tmp_mask 中取出来赋值给 match->mask->key
     * 5. 对 match 进行有效性检查
     */
	error = ovs_nla_get_match(&match, a[OVS_FLOW_ATTR_KEY],
				  a[OVS_FLOW_ATTR_MASK], log);
	if (error)
		goto err_kfree_flow;

    //将 key 与 mask 掩码后的赋值给 new_flow->key
    //注: 此时的 key, mask 已经是被 ovs_nla_get_match() 赋值的 key, mask
	ovs_flow_mask_key(&new_flow->key, &key, &mask);

	/* Extract flow identifier. */

    //初始化 new_flow->id
    //如果 a[OVS_FLOW_ATTR_UFID] = NULL, new_flow->unmasked_key = key
    //否则
    //      new_flow->id->ufid_len = nla_len(a[OVS_FLOW_ATTR_UFID])
    //      new_flow->id->ufid = nla_data([OVS_FLOW_ATTR_UFID])
	error = ovs_nla_get_identifier(&new_flow->id, a[OVS_FLOW_ATTR_UFID],
				       &key, log);
	if (error)
		goto err_kfree_flow;

	/* Validate actions. */
    //TODO
	error = ovs_nla_copy_actions(a[OVS_FLOW_ATTR_ACTIONS], &new_flow->key,
				     &acts, log);
	if (error) {
		OVS_NLERR(log, "Flow actions may not be safe on all matching packets.");
		goto err_kfree_flow;
	}

    //初始化应答消息
	reply = ovs_flow_cmd_alloc_info(acts, &new_flow->id, info, false,
					ufid_flags);
	if (IS_ERR(reply)) {
		error = PTR_ERR(reply);
		goto err_kfree_acts;
	}

	ovs_lock();
    //获取 datapath
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		error = -ENODEV;
		goto err_unlock_ovs;
	}

	/* Check if this is a duplicate flow */
	if (ovs_identifier_is_ufid(&new_flow->id)) {
        // 从 dp->table->ufid_ti->buckets 中查找 new_flow->id->ufid 对应的流表是否存在
        //TODO 这里流表查询算法可以有提升空间
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &new_flow->id);
    }
	if (!flow) {
        // 遍历 dp->table->mask_array 中的每一个 mask, 从 dp->table->ti->buckets 中查找匹配 flow->key=key & mask, flow->mask = mask 的流表项
        //TODO 这里流表查询算法可以有提升空间
		flow = ovs_flow_tbl_lookup(&dp->table, &key);
    }
	if (likely(!flow)) {
        //初始化 sf_acts
		rcu_assign_pointer(new_flow->sf_acts, acts);


        // 1. 将 mask 加入 table->mask_array 中
        // 2. 将 flow->flow_table->node[table->ti->node_ver] 插入 table->ti->buckets 中的一个链表中
        // 3. 如果 flow->id 存在, 将 flow->ufid_table->node[table->ufid_ti->node_ver] 插入 table->ufid_ti->buckets 中的一个链表中
		/* Put flow in bucket. */
		error = ovs_flow_tbl_insert(&dp->table, new_flow, &mask);
		if (unlikely(error)) {
			acts = NULL;
			goto err_unlock_ovs;
		}

		if (unlikely(reply)) {
			error = ovs_flow_cmd_fill_info(new_flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
		ovs_unlock();
	} else {
		struct sw_flow_actions *old_acts;

		/* Bail out if we're not allowed to modify an existing flow.
		 * We accept NLM_F_CREATE in place of the intended NLM_F_EXCL
		 * because Generic Netlink treats the latter as a dump
		 * request.  We also accept NLM_F_EXCL in case that bug ever
		 * gets fixed.
		 */
		if (unlikely(info->nlhdr->nlmsg_flags & (NLM_F_CREATE
							 | NLM_F_EXCL))) {
			error = -EEXIST;
			goto err_unlock_ovs;
		}
		/* The flow identifier has to be the same for flow updates.
		 * Look for any overlapping flow.
		 */
        //如果 flow->id->ufid_len != 0, flow->key 与 match->key 是否完全一致
        //否则 flow->unmasked_key 与 match->key 是否完全一致
		if (unlikely(!ovs_flow_cmp(flow, &match))) {
            //flow->id->ufid_len == 0
			if (ovs_identifier_is_key(&flow->id))
                // 在 tbl->buckets 中找到与 match->key 精确匹配的 flow
				flow = ovs_flow_tbl_lookup_exact(&dp->table,
								 &match);
			else /* UFID matches but key is different */
				flow = NULL;
			if (!flow) {
				error = -ENOENT;
				goto err_unlock_ovs;
			}
		}
		/* Update actions. */
        //更新 actions
		old_acts = ovsl_dereference(flow->sf_acts);
		rcu_assign_pointer(flow->sf_acts, acts);

		if (unlikely(reply)) {
			error = ovs_flow_cmd_fill_info(flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
		ovs_unlock();

		ovs_nla_free_flow_actions(old_acts);
		ovs_flow_free(new_flow, false);
	}

	if (reply)
		ovs_notify(&dp_flow_genl_family, &ovs_dp_flow_multicast_group, reply, info);
	return 0;

err_unlock_ovs:
	ovs_unlock();
	kfree_skb(reply);
err_kfree_acts:
	kfree(acts);
err_kfree_flow:
	ovs_flow_free(new_flow, false);
error:
	return error;
}

/* Factor out action copy to avoid "Wframe-larger-than=1024" warning. */
//将 a 初始化 acts, 返回 acts
static struct sw_flow_actions *get_flow_actions(const struct nlattr *a,
						const struct sw_flow_key *key,
						const struct sw_flow_mask *mask,
						bool log)
{
	struct sw_flow_actions *acts;
	struct sw_flow_key masked_key;
	int error;

    //masked_key = key & mask
	ovs_flow_mask_key(&masked_key, key, mask);
	error = ovs_nla_copy_actions(a, &masked_key, &acts, log);
	if (error) {
		OVS_NLERR(log,
			  "Actions may not be safe on all matching packets");
		return ERR_PTR(error);
	}

	return acts;
}

 /**
  * struct genl_info - receiving information
  * @snd_seq: sending sequence number
  * @snd_portid: netlink portid of sender
  * @nlhdr: netlink message header
  * @genlhdr: generic netlink message header
  * @userhdr: user specific header
  * @attrs: netlink attributes
  * @_net: network namespace
  * @user_ptr: user pointers
  * @dst_sk: destination socket
  */
 //struct genl_info {
 //        u32                     snd_seq;
 //        u32                     snd_portid;
 //        struct nlmsghdr *       nlhdr;
 //        struct genlmsghdr *     genlhdr;
 //        void *                  userhdr;
 //        struct nlattr **        attrs;
 //        possible_net_t          _net;
 //        void *                  user_ptr[2];
 //        struct sock *           dst_sk;
 //};


/*
 * 1. 用 a[OVS_FLOW_ATTR_UFID] 初始化临时变量 sfid, 如果 sfid->ufid_len != 0, ufid_present = true
 * 2. 初始化临时变量 match, key, mask
 * 3. 用 a[OVS_FLOW_ATTR_KEY] 给 match->key 赋值, a[OVS_FLOW_ATTR_MASK] 给 match->mask 赋值
 * 4. 如果 a[OVS_FLOW_ATTR_ACTIONS] != NULL, 初始化临时变量 acts
 * 5. 如果 ufid_present = true, 从 dp->table->ufid_ti->buckets 中查找 ufid 的流表
 *    否则 从 dp->table->ti->buckets 中查找 match->key 的流表 flow, 如果 flow & flow->id->ufid_len = 0 & flow->unmasked_key = match->key 返回 flow
 * 6. 从 5 中找到的 flow, flow->sf_acts = acts
 * 7. 应答给发送者
 *
 *
 *
 */
static int ovs_flow_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow_key key;
	struct sw_flow *flow;
	struct sw_flow_mask mask;
	struct sk_buff *reply = NULL;
	struct datapath *dp;
	struct sw_flow_actions *old_acts = NULL, *acts = NULL;
	struct sw_flow_match match;
	struct sw_flow_id sfid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int error;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	/* Extract key. */
	error = -EINVAL;
	if (!a[OVS_FLOW_ATTR_KEY]) {
		OVS_NLERR(log, "Flow key attribute not present in set flow.");
		goto error;
	}

	ufid_present = ovs_nla_get_ufid(&sfid, a[OVS_FLOW_ATTR_UFID], log);
	ovs_match_init(&match, &key, &mask);
	error = ovs_nla_get_match(&match, a[OVS_FLOW_ATTR_KEY],
				  a[OVS_FLOW_ATTR_MASK], log);
	if (error)
		goto error;

	/* Validate actions. */
	if (a[OVS_FLOW_ATTR_ACTIONS]) {
        //用 a[OVS_FLOW_ATTR_ACTIONS] 初始化 acts
		acts = get_flow_actions(a[OVS_FLOW_ATTR_ACTIONS], &key, &mask,
					log);
		if (IS_ERR(acts)) {
			error = PTR_ERR(acts);
			goto error;
		}

		/* Can allocate before locking if have acts. */
		reply = ovs_flow_cmd_alloc_info(acts, &sfid, info, false,
						ufid_flags);
		if (IS_ERR(reply)) {
			error = PTR_ERR(reply);
			goto err_kfree_acts;
		}
	}

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		error = -ENODEV;
		goto err_unlock_ovs;
	}
	/* Check that the flow exists. */
	if (ufid_present)
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &sfid);
	else
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);
	if (unlikely(!flow)) {
		error = -ENOENT;
		goto err_unlock_ovs;
	}

	/* Update actions, if present. */
	if (likely(acts)) {
		old_acts = ovsl_dereference(flow->sf_acts);
		rcu_assign_pointer(flow->sf_acts, acts);

		if (unlikely(reply)) {
			error = ovs_flow_cmd_fill_info(flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
	} else {
		/* Could not alloc without acts before locking. */
		reply = ovs_flow_cmd_build_info(flow, ovs_header->dp_ifindex,
						info, OVS_FLOW_CMD_NEW, false,
						ufid_flags);

		if (unlikely(IS_ERR(reply))) {
			error = PTR_ERR(reply);
			goto err_unlock_ovs;
		}
	}

	/* Clear stats. */
	if (a[OVS_FLOW_ATTR_CLEAR])
		ovs_flow_stats_clear(flow);
	ovs_unlock();

	if (reply)
		ovs_notify(&dp_flow_genl_family, &ovs_dp_flow_multicast_group, reply, info);
	if (old_acts)
		ovs_nla_free_flow_actions(old_acts);

	return 0;

err_unlock_ovs:
	ovs_unlock();
	kfree_skb(reply);
err_kfree_acts:
	kfree(acts);
error:
	return error;
}

 /**
  * struct genl_info - receiving information
  * @snd_seq: sending sequence number
  * @snd_portid: netlink portid of sender
  * @nlhdr: netlink message header
  * @genlhdr: generic netlink message header
  * @userhdr: user specific header
  * @attrs: netlink attributes
  * @_net: network namespace
  * @user_ptr: user pointers
  * @dst_sk: destination socket
  */
 //struct genl_info {
 //        u32                     snd_seq;
 //        u32                     snd_portid;
 //        struct nlmsghdr *       nlhdr;
 //        struct genlmsghdr *     genlhdr;
 //        void *                  userhdr;
 //        struct nlattr **        attrs;
 //        possible_net_t          _net;
 //        void *                  user_ptr[2];
 //        struct sock *           dst_sk;
 //};

/*
 * 略
 */
static int ovs_flow_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow_key key;
	struct sk_buff *reply;
	struct sw_flow *flow;
	struct datapath *dp;
	struct sw_flow_match match;
	struct sw_flow_id ufid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int err = 0;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	ufid_present = ovs_nla_get_ufid(&ufid, a[OVS_FLOW_ATTR_UFID], log);
	if (a[OVS_FLOW_ATTR_KEY]) {
		ovs_match_init(&match, &key, NULL);
		err = ovs_nla_get_match(&match, a[OVS_FLOW_ATTR_KEY], NULL,
					log);
	} else if (!ufid_present) {
		OVS_NLERR(log,
			  "Flow get message rejected, Key attribute missing.");
		err = -EINVAL;
	}
	if (err)
		return err;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		err = -ENODEV;
		goto unlock;
	}

	if (ufid_present)
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &ufid);
	else
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);
	if (!flow) {
		err = -ENOENT;
		goto unlock;
	}

	reply = ovs_flow_cmd_build_info(flow, ovs_header->dp_ifindex, info,
					OVS_FLOW_CMD_NEW, true, ufid_flags);
	if (IS_ERR(reply)) {
		err = PTR_ERR(reply);
		goto unlock;
	}

	ovs_unlock();
	return genlmsg_reply(reply, info);
unlock:
	ovs_unlock();
	return err;
}

 /**
  * struct genl_info - receiving information
  * @snd_seq: sending sequence number
  * @snd_portid: netlink portid of sender
  * @nlhdr: netlink message header
  * @genlhdr: generic netlink message header
  * @userhdr: user specific header
  * @attrs: netlink attributes
  * @_net: network namespace
  * @user_ptr: user pointers
  * @dst_sk: destination socket
  */
 //struct genl_info {
 //        u32                     snd_seq;
 //        u32                     snd_portid;
 //        struct nlmsghdr *       nlhdr;
 //        struct genlmsghdr *     genlhdr;
 //        void *                  userhdr;
 //        struct nlattr **        attrs;
 //        possible_net_t          _net;
 //        void *                  user_ptr[2];
 //        struct sock *           dst_sk;
 //};
 /*
  *
  *
  *
  * 1. 用 a[OVS_FLOW_ATTR_UFID] 初始化临时变量 ufid, 如果 ufid->ufid_len != 0, ufid_present = true
  * 2. 初始化临时变量 match, key
  * 3. 用 a[OVS_FLOW_ATTR_KEY] 给 match->key 赋值
  * 4. 如果 ufid_present = true, 从 dp->table->ufid_ti->buckets 中查找 ufid 的流表
  *    否则 从 dp->table->ti->buckets 中查找 match->key 的流表 flow, 如果 flow & flow->id->ufid_len = 0 & flow->unmasked_key = match->key 返回 flow
  * 5. 如果 4 找到匹配的流表, 从 dp->table 中删除找到的 flow
  *    否则返回错误消息给发送者
  */
static int ovs_flow_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow_key key;
	struct sk_buff *reply;
	struct sw_flow *flow = NULL;
	struct datapath *dp;
	struct sw_flow_match match;
	struct sw_flow_id ufid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int err;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	ufid_present = ovs_nla_get_ufid(&ufid, a[OVS_FLOW_ATTR_UFID], log);
	if (a[OVS_FLOW_ATTR_KEY]) {
		ovs_match_init(&match, &key, NULL);
		err = ovs_nla_get_match(&match, a[OVS_FLOW_ATTR_KEY], NULL,
					log);
		if (unlikely(err))
			return err;
	}

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		err = -ENODEV;
		goto unlock;
	}

	if (unlikely(!a[OVS_FLOW_ATTR_KEY] && !ufid_present)) {
		err = ovs_flow_tbl_flush(&dp->table);
		goto unlock;
	}

	if (ufid_present)
        //从 dp->table->ufid_ti->buckets 中查找 ufid 的流表
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &ufid);
	else
        //从 dp->table->ti->buckets 中查找 match->key 的流表 flow, 如果 flow & flow->id->ufid_len = 0 & flow->unmasked_key = match->key 返回 flow
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);
	if (unlikely(!flow)) {
		err = -ENOENT;
		goto unlock;
	}

    // 1. 从 table->ti->bucket 中删除 flow->flow_table.node[table->ti->node_ver]
    // 2. 从 table->ufid_ti->bucket 中删除 flow->ufid_table.node[table->ufid_ti->node_ver]
    // 3. flow->mask 引用计数减一或删除
	ovs_flow_tbl_remove(&dp->table, flow);
	ovs_unlock();

	reply = ovs_flow_cmd_alloc_info(rcu_dereference_raw(flow->sf_acts),
					&flow->id, info, false, ufid_flags);

	if (likely(reply)) {
		if (likely(!IS_ERR(reply))) {
			rcu_read_lock();	/*To keep RCU checker happy. */
			err = ovs_flow_cmd_fill_info(flow, ovs_header->dp_ifindex,
						     reply, info->snd_portid,
						     info->snd_seq, 0,
						     OVS_FLOW_CMD_DEL,
						     ufid_flags);
			rcu_read_unlock();
			BUG_ON(err < 0);
			ovs_notify(&dp_flow_genl_family, &ovs_dp_flow_multicast_group, reply, info);
		} else {
			genl_set_err(&dp_flow_genl_family, sock_net(skb->sk), 0,
				     GROUP_ID(&ovs_dp_flow_multicast_group), PTR_ERR(reply));

		}
	}

	ovs_flow_free(flow, true);
	return 0;
unlock:
	ovs_unlock();
	return err;
}

/*
 * 从 skb->sk->net, genlmsg_data(nlmsg_data(cb->nlh))->dp_ifindex 找到 dp,
 * 遍历 dp->table->ti->buckets, bucket 从 cb->args[0] 开始, 每个 bucket
 * 的索引从 cb->args[1] 开始, 直到遍历完所有的 flow, 每个 flow 都加入 skb
 *
 */
static int ovs_flow_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *a[__OVS_FLOW_ATTR_MAX];
	struct ovs_header *ovs_header = genlmsg_data(nlmsg_data(cb->nlh));
	struct table_instance *ti;
	struct datapath *dp;
	u32 ufid_flags;
	int err;

	err = genlmsg_parse(cb->nlh, &dp_flow_genl_family, a,
			    OVS_FLOW_ATTR_MAX, flow_policy);
	if (err)
		return err;
	ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);

	rcu_read_lock();
	dp = get_dp_rcu(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		rcu_read_unlock();
		return -ENODEV;
	}

	ti = rcu_dereference(dp->table.ti);
    //bucket 从 cb->args[0] 开始, 每个 bucket 的索引从 cb->args[1] 开始,
    //直到遍历完所有的 flow, 每个 flow 都加入 skb
	for (;;) {
		struct sw_flow *flow;
		u32 bucket, obj;

		bucket = cb->args[0];
		obj = cb->args[1];
        // 找到 ti->buckets 中索引为 bucket, 链表索引为 last 的 flow
		flow = ovs_flow_tbl_dump_next(ti, &bucket, &obj);
		if (!flow)
			break;

		if (ovs_flow_cmd_fill_info(flow, ovs_header->dp_ifindex, skb,
					   NETLINK_CB(cb->skb).portid,
					   cb->nlh->nlmsg_seq, NLM_F_MULTI,
					   OVS_FLOW_CMD_NEW, ufid_flags) < 0)
			break;

		cb->args[0] = bucket;
		cb->args[1] = obj;
	}
	rcu_read_unlock();
	return skb->len;
}

static const struct nla_policy flow_policy[OVS_FLOW_ATTR_MAX + 1] = {
	[OVS_FLOW_ATTR_KEY] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_MASK] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_ACTIONS] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_CLEAR] = { .type = NLA_FLAG },
	[OVS_FLOW_ATTR_PROBE] = { .type = NLA_FLAG },
	[OVS_FLOW_ATTR_UFID] = { .type = NLA_UNSPEC, .len = 1 },
	[OVS_FLOW_ATTR_UFID_FLAGS] = { .type = NLA_U32 },
};

static const struct genl_ops dp_flow_genl_ops[] = {
	{ .cmd = OVS_FLOW_CMD_NEW,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_new
	},
	{ .cmd = OVS_FLOW_CMD_DEL,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_del
	},
	{ .cmd = OVS_FLOW_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_get,
	  .dumpit = ovs_flow_cmd_dump
	},
	{ .cmd = OVS_FLOW_CMD_SET,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_set,
	},
};

 /**
  * struct genl_family - generic netlink family
  * @id: protocol family idenfitier
  * @hdrsize: length of user specific header in bytes
  * @name: name of family
  * @version: protocol version
  * @maxattr: maximum number of attributes supported
  * @netnsok: set to true if the family can handle network
  *      namespaces and should be presented in all of them
  * @parallel_ops: operations can be called in parallel and aren't
  *      synchronized by the core genetlink code
  * @pre_doit: called before an operation's doit callback, it may
  *      do additional, common, filtering and return an error
  * @post_doit: called after an operation's doit callback, it may
  *      undo operations done by pre_doit, for example release locks
  * @mcast_bind: a socket bound to the given multicast group (which
  *      is given as the offset into the groups array)
  * @mcast_unbind: a socket was unbound from the given multicast group.
  *      Note that unbind() will not be called symmetrically if the
  *      generic netlink family is removed while there are still open
  *      sockets.
  * @attrbuf: buffer to store parsed attributes, 当 maxattr != NULL &&
  * parallel_ops = true 时, kmalloc 分配空间, 否则为 null
  * @family_list: family list
  * @mcgrps: multicast groups used by this family (private)
  * @n_mcgrps: number of multicast groups (private)
  * @mcgrp_offset: starting number of multicast group IDs in this family
  * @ops: the operations supported by this family (private)
  * @n_ops: number of operations supported by this family (private)
  */
 //struct genl_family {
 //        unsigned int            id;
 //        unsigned int            hdrsize;
 //        char                    name[GENL_NAMSIZ];
 //        unsigned int            version;
 //        unsigned int            maxattr;
 //        bool                    netnsok;
 //        bool                    parallel_ops;
 //        int                     (*pre_doit)(const struct genl_ops *ops,
 //                                            struct sk_buff *skb,
 //                                            struct genl_info *info);
 //        void                    (*post_doit)(const struct genl_ops *ops,
 //                                             struct sk_buff *skb,
 //                                             struct genl_info *info);
 //        int                     (*mcast_bind)(struct net *net, int group);
 //        void                    (*mcast_unbind)(struct net *net, int group);
 //        struct nlattr **        attrbuf;        /* private */
 //        const struct genl_ops * ops;            /* private */
 //        const struct genl_multicast_group *mcgrps; /* private */
 //        unsigned int            n_ops;          /* private */
 //        unsigned int            n_mcgrps;       /* private */
 //        unsigned int            mcgrp_offset;   /* private */
 //        struct list_head        family_list;    /* private */
 //        struct module           *module;
 //};
static struct genl_family dp_flow_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_FLOW_FAMILY,
	.version = OVS_FLOW_VERSION,
	.maxattr = OVS_FLOW_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_flow_genl_ops,
	.n_ops = ARRAY_SIZE(dp_flow_genl_ops),
	.mcgrps = &ovs_dp_flow_multicast_group,
	.n_mcgrps = 1,
};

static size_t ovs_dp_cmd_msg_size(void)
{
	size_t msgsize = NLMSG_ALIGN(sizeof(struct ovs_header));

	msgsize += nla_total_size(IFNAMSIZ);
	msgsize += nla_total_size(sizeof(struct ovs_dp_stats));
	msgsize += nla_total_size(sizeof(struct ovs_dp_megaflow_stats));
	msgsize += nla_total_size(sizeof(u32)); /* OVS_DP_ATTR_USER_FEATURES */

	return msgsize;
}

/* Called with ovs_mutex. */
//填充上层传递的消息到 skb
//skb = genlmsg_new_unicast()
/*
 * ovs_header->dp_ifindex = 0
 * OVS_DP_ATTR_NAME  : ovs_vport_ovsl_rcu(dp, OVSP_LOCAL)->ops->get_name(ovs_vport_ovsl_rcu(dp, OVSP_LOCAL))
 * OVS_DP_ATTR_STATS : dp_stats
 * OVS_DP_ATTR_MEGAFLOW_STATS : dp_megaflow_stats
 * OVS_DP_ATTR_USER_FEATURES  : dp->user_features
 * 其中
 * dp_megaflow_stats->n_masks = dp->table->mask_array->count
 * dp_megaflow_stats->n_mask_hit = 所有 cpu 的 n_mask_hit
 * dp_stats->n_flows = dp->table
 * dp_stats->n_hist : 所有 cpu 的 n_hit
 * dp_stats->n_missed : 所有 cpu 的 n_missed
 * dp_stats->n_lost : 所有 cpu 的 n_lost
 */
static int ovs_dp_cmd_fill_info(struct datapath *dp, struct sk_buff *skb,
				u32 portid, u32 seq, u32 flags, u8 cmd)
{
	struct ovs_header *ovs_header;
	struct ovs_dp_stats dp_stats;
	struct ovs_dp_megaflow_stats dp_megaflow_stats;
	int err;

	ovs_header = genlmsg_put(skb, portid, seq, &dp_datapath_genl_family,
				   flags, cmd);
	if (!ovs_header)
		goto error;

	ovs_header->dp_ifindex = get_dpifindex(dp);

	err = nla_put_string(skb, OVS_DP_ATTR_NAME, ovs_dp_name(dp));
	if (err)
		goto nla_put_failure;

    /*
     * dp_megaflow_stats->n_masks = dp->table->mask_array->count
     * dp_megaflow_stats->n_mask_hit = 所有 cpu 的 n_mask_hit
     * dp_stats->n_flows = dp->table
     * dp_stats->n_hist : 所有 cpu 的 n_hit
     * dp_stats->n_missed : 所有 cpu 的 n_missed
     * dp_stats->n_lost : 所有 cpu 的 n_lost
     */
	get_dp_stats(dp, &dp_stats, &dp_megaflow_stats);
	if (nla_put(skb, OVS_DP_ATTR_STATS, sizeof(struct ovs_dp_stats),
			&dp_stats))
		goto nla_put_failure;

	if (nla_put(skb, OVS_DP_ATTR_MEGAFLOW_STATS,
			sizeof(struct ovs_dp_megaflow_stats),
			&dp_megaflow_stats))
		goto nla_put_failure;

	if (nla_put_u32(skb, OVS_DP_ATTR_USER_FEATURES, dp->user_features))
		goto nla_put_failure;

	genlmsg_end(skb, ovs_header);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, ovs_header);
error:
	return -EMSGSIZE;
}

static struct sk_buff *ovs_dp_cmd_alloc_info(struct genl_info *info)
{
    /**
     * genlmsg_new_unicast - Allocate generic netlink message for unicast
     * @payload: size of the message payload
     * @info: information on destination
     * @flags: the type of memory to allocate
     *
     * Allocates a new sk_buff large enough to cover the specified payload
     * plus required Netlink headers. Will check receiving socket for
     * memory mapped i/o capability and use it if enabled. Will fall back
     * to non-mapped skb if message size exceeds the frame size of the ring.
     */
	return genlmsg_new_unicast(ovs_dp_cmd_msg_size(), info, GFP_KERNEL);
}

/* Called with rcu_read_lock or ovs_mutex. */
//如果 info->attrs[OVS_DP_ATTR_NAME] = NULL
//遍历 skb->sk-net->dev_index_head[info->userhdr->ifindex & (NETDEV_HASHENTRIES - 1)] 所有元素,
//找到 dev->ifindex = ifindex 的 dev, 返回 netdev_priv(dev)->vport->dp
//
//否则
//遍历 dev_table[jhash(name, strlen(name), (unsigned long) net) & (VPORT_HASH_BUCKETS - 1)] 的所有 vport,
//找到 vport->ops->get_name(vport）= name, vport->dp->net = net 的 vport, 返回 vport->dp
static struct datapath *lookup_datapath(struct net *net,
					const struct ovs_header *ovs_header,
					struct nlattr *a[OVS_DP_ATTR_MAX + 1])
{
	struct datapath *dp;

	if (!a[OVS_DP_ATTR_NAME])
        //遍历 net->dev_index_head[ifindex & (NETDEV_HASHENTRIES - 1)] 所有元素,
        //找到 dev->ifindex = ifindex 的 dev, 返回netdev_priv(dev)->vport->dp
		dp = get_dp(net, ovs_header->dp_ifindex);
	else {
		struct vport *vport;

        //遍历 dev_table[jhash(name, strlen(name), (unsigned long) net) & (VPORT_HASH_BUCKETS - 1)] 的所有 vport,
        //找到 vport->ops->get_name(vport）= name, vport->dp->net = net 的 vport, 返回 vport->dp
		vport = ovs_vport_locate(net, nla_data(a[OVS_DP_ATTR_NAME]));
		dp = vport && vport->port_no == OVSP_LOCAL ? vport->dp : NULL;
	}
	return dp ? dp : ERR_PTR(-ENODEV);
}

static void ovs_dp_reset_user_features(struct sk_buff *skb, struct genl_info *info)
{
	struct datapath *dp;

	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	if (IS_ERR(dp))
		return;

	WARN(dp->user_features, "Dropping previously announced user features\n");
	dp->user_features = 0;
}

static void ovs_dp_change(struct datapath *dp, struct nlattr *a[])
{
	if (a[OVS_DP_ATTR_USER_FEATURES])
		dp->user_features = nla_get_u32(a[OVS_DP_ATTR_USER_FEATURES]);
}

 /**
  * struct genl_info - receiving information
  * @snd_seq: sending sequence number
  * @snd_portid: netlink portid of sender
  * @nlhdr: netlink message header
  * @genlhdr: generic netlink message header
  * @userhdr: user specific header
  * @attrs: netlink attributes
  * @_net: network namespace
  * @user_ptr: user pointers
  * @dst_sk: destination socket
  */
 //struct genl_info {
 //        u32                     snd_seq;
 //        u32                     snd_portid;
 //        struct nlmsghdr *       nlhdr;
 //        struct genlmsghdr *     genlhdr;
 //        void *                  userhdr;
 //        struct nlattr **        attrs;
 //        possible_net_t          _net;
 //        void *                  user_ptr[2];
 //        struct sock *           dst_sk;
 //};
 //

/*
 * 1. 为一个 struct sk_buff 对象 reply 分配内存, 并根据 info 初始化该对象
 * 2. 为一个 struct datapath 对象 dp 分配内存, 并初始化
 * 3. 将 info 修改 replay 对象属性, 并将消息应答给发消息者 vswitchd
 *  其中2:
 *      dp->net = skb->sk->sk_net
 *      dp->table = ovs_flow_tbl_init(table)
 *      dp->stats_percpu 初始化
 *      dp->ports = kmalloc(DP_VPORT_HASH_BUCKETS * sizeof(struct hlist_head),GFP_KERNEL)
 *      初始化每个 dp->ports[i] (i=0,DP_VPORT_HASH_BUCKETS)
 *      dp->user_features = info->attrs[OVS_DP_ATTR_USER_FEATURES];
 *      dp->list_node  加入链表 dp->net->gen->ptr[ovs_net_id - 1]->dps
 *
 *      初始化 flow_table
 *      //TBL_MIN_BUCKETS=1024
 *      table->ti = kmalloc(sizeof(*ti), GFP_KERNEL);
 *      table->ti->buckets = alloc_buckets(TBL_MIN_BUCKETS)
 *      table->ti->n_buckets = TBL_MIN_BUCKETS;
 *      table->ti->node_ver = 0;
 *      table->ti->keep_flows = false;
 *      get_random_bytes(&table->ti->hash_seed, sizeof(u32));
 *
 *      //TBL_MIN_BUCKETS=1024
 *      table->ufid_ti = kmalloc(sizeof(*ti), GFP_KERNEL)
 *      table->ufid_ti->buckets = alloc_buckets(new_size);
 *      table->ufid_ti->n_buckets = TBL_MIN_BUCKETS;
 *      table->ufid_ti->node_ver = 0;
 *      table->ufid_ti->keep_flows = false;
 *      get_random_bytes(&table->ufid_ti->hash_seed, sizeof(u32));
 *
 *      //MASK_ARRAY_SIZE_MIN=16
 *      table->mask_array = new  kzalloc(sizeof(struct mask_array) +
 *      	      sizeof(struct sw_flow_mask *) * MASK_ARRAY_SIZE_MIN, GFP_KERNEL);
 *      table->mask_array->count = 0
 *      table->mask_array->max = MASK_ARRAY_SIZE_MIN
 *
 *      table->last_rehash = jiffies
 *      table->count = 0;
 *      table->ufid_count = 0;


 *  其中3 返回给 vswitch 的信息包含

 *      ovs_header->dp_ifindex = 0
 *      OVS_DP_ATTR_NAME  : ovs_vport_ovsl_rcu(dp, OVSP_LOCAL)->ops->get_name(ovs_vport_ovsl_rcu(dp, OVSP_LOCAL))
 *      OVS_DP_ATTR_STATS : dp_stats
 *      OVS_DP_ATTR_MEGAFLOW_STATS : dp_megaflow_stats
 *      OVS_DP_ATTR_USER_FEATURES  : dp->user_features
 *      其中
 *      dp_megaflow_stats->n_masks = dp->table->mask_array->count
 *      dp_megaflow_stats->n_mask_hit = 所有 cpu 的 n_mask_hit
 *      dp_stats->n_flows = dp->table
 *      dp_stats->n_hist : 所有 cpu 的 n_hit
 *      dp_stats->n_missed : 所有 cpu 的 n_missed
 *      dp_stats->n_lost : 所有 cpu 的 n_lost
 */
static int ovs_dp_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct vport_parms parms;
	struct sk_buff *reply;
	struct datapath *dp;
	struct vport *vport;
	struct ovs_net *ovs_net;
	int err, i;

	err = -EINVAL;
	if (!a[OVS_DP_ATTR_NAME] || !a[OVS_DP_ATTR_UPCALL_PID])
		goto err;

	reply = ovs_dp_cmd_alloc_info(info);
	if (!reply)
		return -ENOMEM;

	err = -ENOMEM;
	dp = kzalloc(sizeof(*dp), GFP_KERNEL);
	if (dp == NULL)
		goto err_free_reply;

	ovs_dp_set_net(dp, hold_net(sock_net(skb->sk)));

	/* Allocate table. */
	err = ovs_flow_tbl_init(&dp->table);
	if (err)
		goto err_free_dp;

	dp->stats_percpu = netdev_alloc_pcpu_stats(struct dp_stats_percpu);
	if (!dp->stats_percpu) {
		err = -ENOMEM;
		goto err_destroy_table;
	}

	dp->ports = kmalloc(DP_VPORT_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (!dp->ports) {
		err = -ENOMEM;
		goto err_destroy_percpu;
	}

	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++)
		INIT_HLIST_HEAD(&dp->ports[i]);

	/* Set up our datapath device. */
	parms.name = nla_data(a[OVS_DP_ATTR_NAME]);
	parms.type = OVS_VPORT_TYPE_INTERNAL;
	parms.options = NULL;
	parms.dp = dp;
	parms.port_no = OVSP_LOCAL;
	parms.upcall_portids = a[OVS_DP_ATTR_UPCALL_PID];

	ovs_dp_change(dp, a);

	/* So far only local changes have been made, now need the lock. */
	ovs_lock();

    //分配一个 OVSP_LOCAL 端口, 每个 datapath 都会有一个默认的 OVSP_LOCAL 端口.
	vport = new_vport(&parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		if (err == -EBUSY)
			err = -EEXIST;

		if (err == -EEXIST) {
			/* An outdated user space instance that does not understand
			 * the concept of user_features has attempted to create a new
			 * datapath and is likely to reuse it. Drop all user features.
			 */
			if (info->genlhdr->version < OVS_DP_VER_FEATURES)
				ovs_dp_reset_user_features(skb, info);
		}

		goto err_destroy_ports_array;
	}

    //填充应答信息头, 具体内容参考该函数注释
	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_NEW);
	BUG_ON(err < 0);

    //dp->net->gen->ptr[ovs_net_id-1]->dps = dp->list_node
	ovs_net = net_generic(ovs_dp_get_net(dp), ovs_net_id);
	list_add_tail_rcu(&dp->list_node, &ovs_net->dps);

	ovs_unlock();

	ovs_notify(&dp_datapath_genl_family, &ovs_dp_datapath_multicast_group, reply, info);
	return 0;

err_destroy_ports_array:
	ovs_unlock();
	kfree(dp->ports);
err_destroy_percpu:
	free_percpu(dp->stats_percpu);
err_destroy_table:
	ovs_flow_tbl_destroy(&dp->table);
err_free_dp:
	release_net(ovs_dp_get_net(dp));
	kfree(dp);
err_free_reply:
	kfree_skb(reply);
err:
	return err;
}

/* Called with ovs_mutex. */
// table,net 成员如何处理
static void __dp_destroy(struct datapath *dp)
{
	int i;

	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
		struct vport *vport;
		struct hlist_node *n;

		hlist_for_each_entry_safe(vport, n, &dp->ports[i], dp_hash_node)
			if (vport->port_no != OVSP_LOCAL)
				ovs_dp_detach_port(vport);
	}

	list_del_rcu(&dp->list_node);

	/* OVSP_LOCAL is datapath internal port. We need to make sure that
	 * all ports in datapath are destroyed first before freeing datapath.
	 */
	ovs_dp_detach_port(ovs_vport_ovsl(dp, OVSP_LOCAL));

	/* RCU destroy the flow table */
	call_rcu(&dp->rcu, destroy_dp_rcu);
}

 /**
  * struct genl_info - receiving information
  * @snd_seq: sending sequence number
  * @snd_portid: netlink portid of sender
  * @nlhdr: netlink message header
  * @genlhdr: generic netlink message header
  * @userhdr: user specific header
  * @attrs: netlink attributes
  * @_net: network namespace
  * @user_ptr: user pointers
  * @dst_sk: destination socket
  */
 //struct genl_info {
 //        u32                     snd_seq;
 //        u32                     snd_portid;
 //        struct nlmsghdr *       nlhdr;
 //        struct genlmsghdr *     genlhdr;
 //        void *                  userhdr;
 //        struct nlattr **        attrs;
 //        possible_net_t          _net;
 //        void *                  user_ptr[2];
 //        struct sock *           dst_sk;
 //};

 /*
  * 通过 skb->sk->net info->userhdr, info->attrs 找到待删除的 dp
  * 销毁 dp 下的每个端口
  * 向发送者通知删除操作
  */
static int ovs_dp_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	reply = ovs_dp_cmd_alloc_info(info);
	if (!reply)
		return -ENOMEM;

	ovs_lock();
    //如果 info->attrs[OVS_DP_ATTR_NAME] = NULL
    //遍历 skb->sk-net->dev_index_head[info->userhdr->ifindex & (NETDEV_HASHENTRIES - 1)] 所有元素,
    //找到 dev->ifindex = ifindex 的 dev, 返回 netdev_priv(dev)->vport->dp
    //
    //否则
    //遍历 dev_table[jhash(name, strlen(name), (unsigned long) net) & (VPORT_HASH_BUCKETS - 1)] 的所有 vport,
    //找到 vport->ops->get_name(vport）= name, vport->dp->net = net 的 vport, 返回 vport->dp
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	err = PTR_ERR(dp);
	if (IS_ERR(dp))
		goto err_unlock_free;

    //填充应答信息头, 具体内容参考该函数注释
	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_DEL);
	BUG_ON(err < 0);

    //删除 dp
	__dp_destroy(dp);
	ovs_unlock();

    //通知发送消息者
	ovs_notify(&dp_datapath_genl_family, &ovs_dp_datapath_multicast_group, reply, info);
	return 0;

err_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

 /**
  * struct genl_info - receiving information
  * @snd_seq: sending sequence number
  * @snd_portid: netlink portid of sender
  * @nlhdr: netlink message header
  * @genlhdr: generic netlink message header
  * @userhdr: user specific header
  * @attrs: netlink attributes
  * @_net: network namespace
  * @user_ptr: user pointers
  * @dst_sk: destination socket
  */
 //struct genl_info {
 //        u32                     snd_seq;
 //        u32                     snd_portid;
 //        struct nlmsghdr *       nlhdr;
 //        struct genlmsghdr *     genlhdr;
 //        void *                  userhdr;
 //        struct nlattr **        attrs;
 //        possible_net_t          _net;
 //        void *                  user_ptr[2];
 //        struct sock *           dst_sk;
 //};
 //

 /*
  * 通过 skb->sk->net info->userhdr, info->attrs 找到待删除的 dp
  * 只能修改 dp->user_features
  * 向发送者通知统计消息
  */
static int ovs_dp_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	reply = ovs_dp_cmd_alloc_info(info);
	if (!reply)
		return -ENOMEM;

	ovs_lock();
    //如果 info->attrs[OVS_DP_ATTR_NAME] = NULL
    //遍历 skb->sk-net->dev_index_head[info->userhdr->ifindex & (NETDEV_HASHENTRIES - 1)] 所有元素,
    //找到 dev->ifindex = ifindex 的 dev, 返回 netdev_priv(dev)->vport->dp
    //
    //否则
    //遍历 dev_table[jhash(name, strlen(name), (unsigned long) net) & (VPORT_HASH_BUCKETS - 1)] 的所有 vport,
    //找到 vport->ops->get_name(vport）= name, vport->dp->net = net 的 vport, 返回 vport->dp
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	err = PTR_ERR(dp);
	if (IS_ERR(dp))
		goto err_unlock_free;

	ovs_dp_change(dp, info->attrs);

    //为什么这里 cmd 为 OVS_DP_CMD_NEW
	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_NEW);
	BUG_ON(err < 0);

	ovs_unlock();

	ovs_notify(&dp_datapath_genl_family, &ovs_dp_datapath_multicast_group, reply, info);
	return 0;

err_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

 /**
  * struct genl_info - receiving information
  * @snd_seq: sending sequence number
  * @snd_portid: netlink portid of sender
  * @nlhdr: netlink message header
  * @genlhdr: generic netlink message header
  * @userhdr: user specific header
  * @attrs: netlink attributes
  * @_net: network namespace
  * @user_ptr: user pointers
  * @dst_sk: destination socket
  */
 //struct genl_info {
 //        u32                     snd_seq;
 //        u32                     snd_portid;
 //        struct nlmsghdr *       nlhdr;
 //        struct genlmsghdr *     genlhdr;
 //        void *                  userhdr;
 //        struct nlattr **        attrs;
 //        possible_net_t          _net;
 //        void *                  user_ptr[2];
 //        struct sock *           dst_sk;
 //};

 /*
  * 通过 skb->sk->net info->userhdr, info->attrs 找到待删除的 dp
  * 向发送者通知统计消息
  */
static int ovs_dp_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	reply = ovs_dp_cmd_alloc_info(info);
	if (!reply)
		return -ENOMEM;

	ovs_lock();
    //如果 info->attrs[OVS_DP_ATTR_NAME] = NULL
    //遍历 skb->sk-net->dev_index_head[info->userhdr->ifindex & (NETDEV_HASHENTRIES - 1)] 所有元素,
    //找到 dev->ifindex = ifindex 的 dev, 返回 netdev_priv(dev)->vport->dp
    //
    //否则
    //遍历 dev_table[jhash(name, strlen(name), (unsigned long) net) & (VPORT_HASH_BUCKETS - 1)] 的所有 vport,
    //找到 vport->ops->get_name(vport）= name, vport->dp->net = net 的 vport, 返回 vport->dp
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	if (IS_ERR(dp)) {
		err = PTR_ERR(dp);
		goto err_unlock_free;
	}
    //cmd 为什么是 OVS_DP_CMD_NEW
	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_NEW);
	BUG_ON(err < 0);
	ovs_unlock();

	return genlmsg_reply(reply, info);

err_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

//遍历 skb->sk->net->gen->ptr[ovs_net_id -1]->dps 中所有 dp, 将索引大于 cb->agrs[0] 的统计加入 skb
static int ovs_dp_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ovs_net *ovs_net = net_generic(sock_net(skb->sk), ovs_net_id);
	struct datapath *dp;
	int skip = cb->args[0];
	int i = 0;

	ovs_lock();
	list_for_each_entry(dp, &ovs_net->dps, list_node) {
        //为什么 cmd 为 OVS_DP_CMD_NEW
		if (i >= skip &&
		    ovs_dp_cmd_fill_info(dp, skb, NETLINK_CB(cb->skb).portid,
					 cb->nlh->nlmsg_seq, NLM_F_MULTI,
					 OVS_DP_CMD_NEW) < 0)
			break;
		i++;
	}
	ovs_unlock();

	cb->args[0] = i;

	return skb->len;
}

static const struct nla_policy datapath_policy[OVS_DP_ATTR_MAX + 1] = {
	[OVS_DP_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[OVS_DP_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_DP_ATTR_USER_FEATURES] = { .type = NLA_U32 },
};

 /**
  * struct genl_ops - generic netlink operations
  * @cmd: command identifier
  * @internal_flags: flags used by the family
  * @flags: flags
  * @policy: attribute validation policy
  * @doit: standard command callback
  * @dumpit: callback for dumpers
  * @done: completion callback for dumps
  * @ops_list: operations list
  */
 //struct genl_ops {
 //        const struct nla_policy *policy;
 //        int                    (*doit)(struct sk_buff *skb,
 //                                       struct genl_info *info);
 //        int                    (*dumpit)(struct sk_buff *skb,
 //                                         struct netlink_callback *cb);
 //        int                    (*done)(struct netlink_callback *cb);
 //        u8                      cmd;
 //        u8                      internal_flags;
 //        u8                      flags;
 //};
static const struct genl_ops dp_datapath_genl_ops[] = {
	{ .cmd = OVS_DP_CMD_NEW,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_new
	},
	{ .cmd = OVS_DP_CMD_DEL,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_del
	},
	{ .cmd = OVS_DP_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_get,
	  .dumpit = ovs_dp_cmd_dump
	},
	{ .cmd = OVS_DP_CMD_SET,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_set,
	},
};

 /**
  * struct genl_family - generic netlink family
  * @id: protocol family idenfitier
  * @hdrsize: length of user specific header in bytes
  * @name: name of family
  * @version: protocol version
  * @maxattr: maximum number of attributes supported
  * @netnsok: set to true if the family can handle network
  *      namespaces and should be presented in all of them
  * @parallel_ops: operations can be called in parallel and aren't
  *      synchronized by the core genetlink code
  * @pre_doit: called before an operation's doit callback, it may
  *      do additional, common, filtering and return an error
  * @post_doit: called after an operation's doit callback, it may
  *      undo operations done by pre_doit, for example release locks
  * @mcast_bind: a socket bound to the given multicast group (which
  *      is given as the offset into the groups array)
  * @mcast_unbind: a socket was unbound from the given multicast group.
  *      Note that unbind() will not be called symmetrically if the
  *      generic netlink family is removed while there are still open
  *      sockets.
  * @attrbuf: buffer to store parsed attributes, 当 maxattr != NULL &&
  * parallel_ops = true 时, kmalloc 分配空间, 否则为 null
  * @family_list: family list
  * @mcgrps: multicast groups used by this family (private)
  * @n_mcgrps: number of multicast groups (private)
  * @mcgrp_offset: starting number of multicast group IDs in this family
  * @ops: the operations supported by this family (private)
  * @n_ops: number of operations supported by this family (private)
  */
 //struct genl_family {
 //        unsigned int            id;
 //        unsigned int            hdrsize;
 //        char                    name[GENL_NAMSIZ];
 //        unsigned int            version;
 //        unsigned int            maxattr;
 //        bool                    netnsok;
 //        bool                    parallel_ops;
 //        int                     (*pre_doit)(const struct genl_ops *ops,
 //                                            struct sk_buff *skb,
 //                                            struct genl_info *info);
 //        void                    (*post_doit)(const struct genl_ops *ops,
 //                                             struct sk_buff *skb,
 //                                             struct genl_info *info);
 //        int                     (*mcast_bind)(struct net *net, int group);
 //        void                    (*mcast_unbind)(struct net *net, int group);
 //        struct nlattr **        attrbuf;        /* private */
 //        const struct genl_ops * ops;            /* private */
 //        const struct genl_multicast_group *mcgrps; /* private */
 //        unsigned int            n_ops;          /* private */
 //        unsigned int            n_mcgrps;       /* private */
 //        unsigned int            mcgrp_offset;   /* private */
 //        struct list_head        family_list;    /* private */
 //        struct module           *module;
 //};
static struct genl_family dp_datapath_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_DATAPATH_FAMILY,
	.version = OVS_DATAPATH_VERSION,
	.maxattr = OVS_DP_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_datapath_genl_ops,
	.n_ops = ARRAY_SIZE(dp_datapath_genl_ops),
	.mcgrps = &ovs_dp_datapath_multicast_group,
	.n_mcgrps = 1,
};

/* Called with ovs_mutex or RCU read lock. */
/*
 * OVS_VPORT_ATTR_PORT_NO : vport->port_no
 * OVS_VPORT_ATTR_TYPE : vport->ops->type
 * OVS_VPORT_ATTR_NAME : vport->ops->get_name(vport)
 * OVS_VPORT_ATTR_STATS : vport_stats
 * OVS_VPORT_ATTR_UPCALL_PID:ids->n_ids * sizeof(u32), (void *) ids->ids
 * OVS_VPORT_ATTR_OPTIONS:vport->ops->get_options(vport, skb)
 */
static int ovs_vport_cmd_fill_info(struct vport *vport, struct sk_buff *skb,
				   u32 portid, u32 seq, u32 flags, u8 cmd)
{
	struct ovs_header *ovs_header;
	struct ovs_vport_stats vport_stats;
	int err;

	ovs_header = genlmsg_put(skb, portid, seq, &dp_vport_genl_family,
				 flags, cmd);
	if (!ovs_header)
		return -EMSGSIZE;

	ovs_header->dp_ifindex = get_dpifindex(vport->dp);

	if (nla_put_u32(skb, OVS_VPORT_ATTR_PORT_NO, vport->port_no) ||
	    nla_put_u32(skb, OVS_VPORT_ATTR_TYPE, vport->ops->type) ||
	    nla_put_string(skb, OVS_VPORT_ATTR_NAME, vport->ops->get_name(vport)))
		goto nla_put_failure;

	ovs_vport_get_stats(vport, &vport_stats);
	if (nla_put(skb, OVS_VPORT_ATTR_STATS, sizeof(struct ovs_vport_stats),
		    &vport_stats))
		goto nla_put_failure;
    //OVS_VPORT_ATTR_UPCALL_PID:ids->n_ids * sizeof(u32), (void *) ids->ids
    //OVS_VPORT_ATTR_UPCALL_PID:ids->ids[0]
	if (ovs_vport_get_upcall_portids(vport, skb))
		goto nla_put_failure;

    //OVS_VPORT_ATTR_OPTIONS:vport->ops->get_options(vport, skb)
	err = ovs_vport_get_options(vport, skb);
	if (err == -EMSGSIZE)
		goto error;

	genlmsg_end(skb, ovs_header);
	return 0;

nla_put_failure:
	err = -EMSGSIZE;
error:
	genlmsg_cancel(skb, ovs_header);
	return err;
}

static struct sk_buff *ovs_vport_cmd_alloc_info(void)
{
	return nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
}

/* Called with ovs_mutex, only via ovs_dp_notify_wq(). */
struct sk_buff *ovs_vport_cmd_build_info(struct vport *vport, u32 portid,
					 u32 seq, u8 cmd)
{
	struct sk_buff *skb;
	int retval;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	retval = ovs_vport_cmd_fill_info(vport, skb, portid, seq, 0, cmd);
	BUG_ON(retval < 0);

	return skb;
}

/* Called with ovs_mutex or RCU read lock. */
/*
 * 从 net,name 找到 dp, 进而找到 vport
 *      bucket = dev_table[jhash(name, strlen(name), (unsigned long) net) & (VPORT_HASH_BUCKETS - 1)]
 *      找到 name = vport->ops->get_name(vport) 并且　vport->dp->net = net 的 vport
 * 从 net,dpifindex 找到 dp, 进而找到 vport
 */
static struct vport *lookup_vport(struct net *net,
				  const struct ovs_header *ovs_header,
				  struct nlattr *a[OVS_VPORT_ATTR_MAX + 1])
{
	struct datapath *dp;
	struct vport *vport;

	if (a[OVS_VPORT_ATTR_NAME]) {
        //以 a[OVS_VPORT_ATTR_NAME]的值 和 net 的哈希值 hash 为索引, 在 dev_table[hash] 中找对应的 vport
		vport = ovs_vport_locate(net, nla_data(a[OVS_VPORT_ATTR_NAME]));
		if (!vport)
			return ERR_PTR(-ENODEV);
        //防止 vport->dp->dpifindex != ovs_header->dp_ifindex
		if (ovs_header->dp_ifindex &&
		    ovs_header->dp_ifindex != get_dpifindex(vport->dp))
			return ERR_PTR(-ENODEV);
		return vport;
	} else if (a[OVS_VPORT_ATTR_PORT_NO]) {
		u32 port_no = nla_get_u32(a[OVS_VPORT_ATTR_PORT_NO]);

		if (port_no >= DP_MAX_PORTS)
			return ERR_PTR(-EFBIG);

        //遍历 net->dev_index_head[ifindex & (NETDEV_HASHENTRIES - 1)] 所有元素,
        //找到 dev->ifindex = ifindex 的 dev, 返回netdev_priv(dev)->vport->dp
		dp = get_dp(net, ovs_header->dp_ifindex);
		if (!dp)
			return ERR_PTR(-ENODEV);

		vport = ovs_vport_ovsl_rcu(dp, port_no);
		if (!vport)
			return ERR_PTR(-ENODEV);
		return vport;
	} else
		return ERR_PTR(-EINVAL);
}

 /**
  * struct genl_info - receiving information
  * @snd_seq: sending sequence number
  * @snd_portid: netlink portid of sender
  * @nlhdr: netlink message header
  * @genlhdr: generic netlink message header
  * @userhdr: user specific header
  * @attrs: netlink attributes
  * @_net: network namespace
  * @user_ptr: user pointers
  * @dst_sk: destination socket
  */
 //struct genl_info {
 //        u32                     snd_seq;
 //        u32                     snd_portid;
 //        struct nlmsghdr *       nlhdr;
 //        struct genlmsghdr *     genlhdr;
 //        void *                  userhdr;
 //        struct nlattr **        attrs;
 //        possible_net_t          _net;
 //        void *                  user_ptr[2];
 //        struct sock *           dst_sk;
 //};

/*
 * 1. 从 skb->sk->net, ovs_header->dp_ifindex 定位到 datapath
 * 2. 如果没有给定端口号, 在 datapath 中从头开始找到空闲的端口号 port_no.
 *    如果给定端口号, 确保端口号 port_no 与已有的端口号 port_no 不冲突.
 * 3. 创建一个 vport 并初始化各个数据成员, 包括私有数据
 * 4. 将信息应答给请求者(vswitchd)
 *
 * 创建 vport 的参数
 *
 *     parms.name = nla_data(a[OVS_VPORT_ATTR_NAME]);
 *     parms.type = nla_get_u32(a[OVS_VPORT_ATTR_TYPE]);
 *     parms.options = a[OVS_VPORT_ATTR_OPTIONS];
 *     parms.dp = dp;
 *     parms.port_no = port_no;
 *     parms.upcall_portids = a[OVS_VPORT_ATTR_UPCALL_PID];
 *
 */
static int ovs_vport_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct vport_parms parms;
	struct sk_buff *reply;
	struct vport *vport;
	struct datapath *dp;
	u32 port_no;
	int err;

	if (!a[OVS_VPORT_ATTR_NAME] || !a[OVS_VPORT_ATTR_TYPE] ||
	    !a[OVS_VPORT_ATTR_UPCALL_PID])
		return -EINVAL;

	port_no = a[OVS_VPORT_ATTR_PORT_NO]
		? nla_get_u32(a[OVS_VPORT_ATTR_PORT_NO]) : 0;
	if (port_no >= DP_MAX_PORTS)
		return -EFBIG;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
restart:
    //遍历 net->dev_index_head[ifindex & (NETDEV_HASHENTRIES - 1)] 所有元素,
    //找到 dev->ifindex = ifindex 的 dev, 返回netdev_priv(dev)->vport->dp
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	err = -ENODEV;
	if (!dp)
		goto exit_unlock_free;

	if (port_no) {
        //确保 dp 中 port_no 对应的 vport 不存在
		vport = ovs_vport_ovsl(dp, port_no);
		err = -EBUSY;
		if (vport)
			goto exit_unlock_free;
	} else {
        //找到没有使用的端口号 port_no 对应的 vport
		for (port_no = 1; ; port_no++) {
			if (port_no >= DP_MAX_PORTS) {
				err = -EFBIG;
				goto exit_unlock_free;
			}
            //在 dp->ports[port_no % DP_VPORT_HASH_BUCKETS] 中找到端口号为 port_no 的 vport, 找不到返回 NULL
			vport = ovs_vport_ovsl(dp, port_no);
			if (!vport)
				break;
		}
	}

	parms.name = nla_data(a[OVS_VPORT_ATTR_NAME]);
	parms.type = nla_get_u32(a[OVS_VPORT_ATTR_TYPE]);
	parms.options = a[OVS_VPORT_ATTR_OPTIONS];
	parms.dp = dp;
	parms.port_no = port_no;
	parms.upcall_portids = a[OVS_VPORT_ATTR_UPCALL_PID];

    /* 1. 创建并初始化 vport
    *     * 类型为 params->type 的 ops
    *     * 确保 params->type->ops->owner 的模块是 alive 的
    *     * 调用 internal_dev_create(params) 创建 vport, 初始化各个数据成员及私有数据
    *     * 将 vport->hash_node 加入 dev_table
    *   注: 没有初始化的 err_stats, detach_list
    *
    * 2. 如果端口创建成功, 将其加入 parms->dp->ports 中
    */
	vport = new_vport(&parms);
	err = PTR_ERR(vport);
	if (IS_ERR(vport)) {
		if (err == -EAGAIN)
			goto restart;
		goto exit_unlock_free;
	}

	err = ovs_vport_cmd_fill_info(vport, reply, info->snd_portid,
				      info->snd_seq, 0, OVS_VPORT_CMD_NEW);
	BUG_ON(err < 0);
	ovs_unlock();

	ovs_notify(&dp_vport_genl_family, &ovs_dp_vport_multicast_group, reply, info);
	return 0;

exit_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

 /**
  * struct genl_info - receiving information
  * @snd_seq: sending sequence number
  * @snd_portid: netlink portid of sender
  * @nlhdr: netlink message header
  * @genlhdr: generic netlink message header
  * @userhdr: user specific header
  * @attrs: netlink attributes
  * @_net: network namespace
  * @user_ptr: user pointers
  * @dst_sk: destination socket
  */
 //struct genl_info {
 //        u32                     snd_seq;
 //        u32                     snd_portid;
 //        struct nlmsghdr *       nlhdr;
 //        struct genlmsghdr *     genlhdr;
 //        void *                  userhdr;
 //        struct nlattr **        attrs;
 //        possible_net_t          _net;
 //        void *                  user_ptr[2];
 //        struct sock *           dst_sk;
 //};


/*
 * 设置 vport 的属性, 包括:
 *
 * OVS_VPORT_ATTR_OPTIONS : info->attrs[OVS_VPORT_ATTR_OPTIONS]
 * OVS_VPORT_ATTR_UPCALL_PID : info->attrs[OVS_VPORT_ATTR_UPCALL_PID]
 *
 */
static int ovs_vport_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct sk_buff *reply;
	struct vport *vport;
	int err;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
    //从 net,name 找到 dp, 进而找到 vport
    //或
    //从 net,dpifindex 找到 dp, 进而找到 vport
	vport = lookup_vport(sock_net(skb->sk), info->userhdr, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock_free;

	if (a[OVS_VPORT_ATTR_TYPE] &&
	    nla_get_u32(a[OVS_VPORT_ATTR_TYPE]) != vport->ops->type) {
		err = -EINVAL;
		goto exit_unlock_free;
	}

	if (a[OVS_VPORT_ATTR_OPTIONS]) {
		err = ovs_vport_set_options(vport, a[OVS_VPORT_ATTR_OPTIONS]);
		if (err)
			goto exit_unlock_free;
	}

	if (a[OVS_VPORT_ATTR_UPCALL_PID]) {
		struct nlattr *ids = a[OVS_VPORT_ATTR_UPCALL_PID];

		err = ovs_vport_set_upcall_portids(vport, ids);
		if (err)
			goto exit_unlock_free;
	}

	err = ovs_vport_cmd_fill_info(vport, reply, info->snd_portid,
				      info->snd_seq, 0, OVS_VPORT_CMD_NEW);
	BUG_ON(err < 0);
	ovs_unlock();

	ovs_notify(&dp_vport_genl_family, &ovs_dp_vport_multicast_group, reply, info);
	return 0;

exit_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

 /**
  * struct genl_info - receiving information
  * @snd_seq: sending sequence number
  * @snd_portid: netlink portid of sender
  * @nlhdr: netlink message header
  * @genlhdr: generic netlink message header
  * @userhdr: user specific header
  * @attrs: netlink attributes
  * @_net: network namespace
  * @user_ptr: user pointers
  * @dst_sk: destination socket
  */
 //struct genl_info {
 //        u32                     snd_seq;
 //        u32                     snd_portid;
 //        struct nlmsghdr *       nlhdr;
 //        struct genlmsghdr *     genlhdr;
 //        void *                  userhdr;
 //        struct nlattr **        attrs;
 //        possible_net_t          _net;
 //        void *                  user_ptr[2];
 //        struct sock *           dst_sk;
 //};
/*
 *
 *  1. 从 net,name 找到 dp, 进而找到 vport 或 从 net,dpifindex 找到 dp, 进而找到 vport
 *  2. 删除 vport (OVSP_LOCAL 的端口不可以删除)
 *  3. 发送消息给发送者(vswitchd)
 */
static int ovs_vport_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct sk_buff *reply;
	struct vport *vport;
	int err;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
    //从 net,name 找到 dp, 进而找到 vport
    //或
    //从 net,dpifindex 找到 dp, 进而找到 vport
	vport = lookup_vport(sock_net(skb->sk), info->userhdr, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock_free;

    //OVSP_LOCAL 端口不可删除, 在删除 datapath 的时候一起删除的
	if (vport->port_no == OVSP_LOCAL) {
		err = -EINVAL;
		goto exit_unlock_free;
	}

	err = ovs_vport_cmd_fill_info(vport, reply, info->snd_portid,
				      info->snd_seq, 0, OVS_VPORT_CMD_DEL);
	BUG_ON(err < 0);
	ovs_dp_detach_port(vport);
	ovs_unlock();

	ovs_notify(&dp_vport_genl_family, &ovs_dp_vport_multicast_group, reply, info);
	return 0;

exit_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

 /**
  * struct genl_info - receiving information
  * @snd_seq: sending sequence number
  * @snd_portid: netlink portid of sender
  * @nlhdr: netlink message header
  * @genlhdr: generic netlink message header
  * @userhdr: user specific header
  * @attrs: netlink attributes
  * @_net: network namespace
  * @user_ptr: user pointers
  * @dst_sk: destination socket
  */
 //struct genl_info {
 //        u32                     snd_seq;
 //        u32                     snd_portid;
 //        struct nlmsghdr *       nlhdr;
 //        struct genlmsghdr *     genlhdr;
 //        void *                  userhdr;
 //        struct nlattr **        attrs;
 //        possible_net_t          _net;
 //        void *                  user_ptr[2];
 //        struct sock *           dst_sk;
 //};

//获取指定 vport 的属性信息, 应答给请求者(vswitchd)
static int ovs_vport_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct vport *vport;
	int err;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	rcu_read_lock();
    //从 net,name 找到 dp, 进而找到 vport
    //或
    //从 net,dpifindex 找到 dp, 进而找到 vport
	vport = lookup_vport(sock_net(skb->sk), ovs_header, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock_free;
	err = ovs_vport_cmd_fill_info(vport, reply, info->snd_portid,
				      info->snd_seq, 0, OVS_VPORT_CMD_NEW);
	BUG_ON(err < 0);
	rcu_read_unlock();

	return genlmsg_reply(reply, info);

exit_unlock_free:
	rcu_read_unlock();
	kfree_skb(reply);
	return err;
}

//从数字 dp->ports[] 索引 cb->agrs[0] 开始, 跳过前 cb->args[1] 个 vport,
//将剩余的 vport 属性信息(见下)写入 skb
/*
 * OVS_VPORT_ATTR_PORT_NO : vport->port_no
 * OVS_VPORT_ATTR_TYPE : vport->ops->type
 * OVS_VPORT_ATTR_NAME : vport->ops->get_name(vport)
 * OVS_VPORT_ATTR_STATS : vport_stats
 * OVS_VPORT_ATTR_UPCALL_PID:ids->n_ids * sizeof(u32), (void *) ids->ids
 * OVS_VPORT_ATTR_OPTIONS:vport->ops->get_options(vport, skb)
 */
static int ovs_vport_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ovs_header *ovs_header = genlmsg_data(nlmsg_data(cb->nlh));
	struct datapath *dp;
	int bucket = cb->args[0], skip = cb->args[1];
	int i, j = 0;

	rcu_read_lock();
	dp = get_dp_rcu(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		rcu_read_unlock();
		return -ENODEV;
	}
	for (i = bucket; i < DP_VPORT_HASH_BUCKETS; i++) {
		struct vport *vport;

		j = 0;
		hlist_for_each_entry_rcu(vport, &dp->ports[i], dp_hash_node) {
			if (j >= skip &&
			    ovs_vport_cmd_fill_info(vport, skb,
						    NETLINK_CB(cb->skb).portid,
						    cb->nlh->nlmsg_seq,
						    NLM_F_MULTI,
						    OVS_VPORT_CMD_NEW) < 0)
				goto out;

			j++;
		}
		skip = 0;
	}
out:
	rcu_read_unlock();

	cb->args[0] = i;
	cb->args[1] = j;

	return skb->len;
}

static const struct nla_policy vport_policy[OVS_VPORT_ATTR_MAX + 1] = {
	[OVS_VPORT_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[OVS_VPORT_ATTR_STATS] = { .len = sizeof(struct ovs_vport_stats) },
	[OVS_VPORT_ATTR_PORT_NO] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_TYPE] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_OPTIONS] = { .type = NLA_NESTED },
};

static const struct genl_ops dp_vport_genl_ops[] = {
	{ .cmd = OVS_VPORT_CMD_NEW,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_new
	},
	{ .cmd = OVS_VPORT_CMD_DEL,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_del
	},
	{ .cmd = OVS_VPORT_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_get,
	  .dumpit = ovs_vport_cmd_dump
	},
	{ .cmd = OVS_VPORT_CMD_SET,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_set,
	},
};

 /**
  * struct genl_family - generic netlink family
  * @id: protocol family idenfitier
  * @hdrsize: length of user specific header in bytes
  * @name: name of family
  * @version: protocol version
  * @maxattr: maximum number of attributes supported
  * @netnsok: set to true if the family can handle network
  *      namespaces and should be presented in all of them
  * @parallel_ops: operations can be called in parallel and aren't
  *      synchronized by the core genetlink code
  * @pre_doit: called before an operation's doit callback, it may
  *      do additional, common, filtering and return an error
  * @post_doit: called after an operation's doit callback, it may
  *      undo operations done by pre_doit, for example release locks
  * @mcast_bind: a socket bound to the given multicast group (which
  *      is given as the offset into the groups array)
  * @mcast_unbind: a socket was unbound from the given multicast group.
  *      Note that unbind() will not be called symmetrically if the
  *      generic netlink family is removed while there are still open
  *      sockets.
  * @attrbuf: buffer to store parsed attributes, 当 maxattr != NULL &&
  * parallel_ops = true 时, kmalloc 分配空间, 否则为 null
  * @family_list: family list
  * @mcgrps: multicast groups used by this family (private)
  * @n_mcgrps: number of multicast groups (private)
  * @mcgrp_offset: starting number of multicast group IDs in this family
  * @ops: the operations supported by this family (private)
  * @n_ops: number of operations supported by this family (private)
  */
 //struct genl_family {
 //        unsigned int            id;
 //        unsigned int            hdrsize;
 //        char                    name[GENL_NAMSIZ];
 //        unsigned int            version;
 //        unsigned int            maxattr;
 //        bool                    netnsok;
 //        bool                    parallel_ops;
 //        int                     (*pre_doit)(const struct genl_ops *ops,
 //                                            struct sk_buff *skb,
 //                                            struct genl_info *info);
 //        void                    (*post_doit)(const struct genl_ops *ops,
 //                                             struct sk_buff *skb,
 //                                             struct genl_info *info);
 //        int                     (*mcast_bind)(struct net *net, int group);
 //        void                    (*mcast_unbind)(struct net *net, int group);
 //        struct nlattr **        attrbuf;        /* private */
 //        const struct genl_ops * ops;            /* private */
 //        const struct genl_multicast_group *mcgrps; /* private */
 //        unsigned int            n_ops;          /* private */
 //        unsigned int            n_mcgrps;       /* private */
 //        unsigned int            mcgrp_offset;   /* private */
 //        struct list_head        family_list;    /* private */
 //        struct module           *module;
 //};
struct genl_family dp_vport_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_VPORT_FAMILY,
	.version = OVS_VPORT_VERSION,
	.maxattr = OVS_VPORT_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_vport_genl_ops,
	.n_ops = ARRAY_SIZE(dp_vport_genl_ops),
	.mcgrps = &ovs_dp_vport_multicast_group,
	.n_mcgrps = 1,
};

static struct genl_family * const dp_genl_families[] = {
	&dp_datapath_genl_family,
	&dp_vport_genl_family,
	&dp_flow_genl_family,
	&dp_packet_genl_family,
};

static void dp_unregister_genl(int n_families)
{
	int i;

	for (i = 0; i < n_families; i++)
		genl_unregister_family(dp_genl_families[i]);
}

static int dp_register_genl(void)
{
	int err;
	int i;

	for (i = 0; i < ARRAY_SIZE(dp_genl_families); i++) {

		err = genl_register_family(dp_genl_families[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	dp_unregister_genl(i);
	return err;
}

static int __net_init ovs_init_net(struct net *net)
{
    //ovs_net = net->gen->ptr[ovs_net_id - 1]
	struct ovs_net *ovs_net = net_generic(net, ovs_net_id);

	INIT_LIST_HEAD(&ovs_net->dps);
	INIT_WORK(&ovs_net->dp_notify_work, ovs_dp_notify_wq);
	return 0;
}

/*
 *
 * 遍历 vport = net->gen->ptr[ovs_net_id-1]->dps[i]->vport[j]
 * 如果 vport->ops->type = OVS_VPORT_TYPE_INTERNAL && netdev_vport_priv(vport)->dev->net = dnet
 * 将 vport->detach_list 加入 head
 */
static void __net_exit list_vports_from_net(struct net *net, struct net *dnet,
					    struct list_head *head)
{
	struct ovs_net *ovs_net = net_generic(net, ovs_net_id);
	struct datapath *dp;

	list_for_each_entry(dp, &ovs_net->dps, list_node) {
		int i;

		for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
			struct vport *vport;

			hlist_for_each_entry(vport, &dp->ports[i], dp_hash_node) {
				struct netdev_vport *netdev_vport;

				if (vport->ops->type != OVS_VPORT_TYPE_INTERNAL)
					continue;

				netdev_vport = netdev_vport_priv(vport);
				if (dev_net(netdev_vport->dev) == dnet)
					list_add(&vport->detach_list, head);
			}
		}
	}
}

static void __net_exit ovs_exit_net(struct net *dnet)
{
	struct datapath *dp, *dp_next;
	struct ovs_net *ovs_net = net_generic(dnet, ovs_net_id);
	struct vport *vport, *vport_next;
	struct net *net;
    //head 没有定义???
	LIST_HEAD(head);

	ovs_lock();
	list_for_each_entry_safe(dp, dp_next, &ovs_net->dps, list_node)
		__dp_destroy(dp);

	rtnl_lock();
	for_each_net(net)
		list_vports_from_net(net, dnet, &head);
	rtnl_unlock();

	/* Detach all vports from given namespace. */
	list_for_each_entry_safe(vport, vport_next, &head, detach_list) {
		list_del(&vport->detach_list);
		ovs_dp_detach_port(vport);
	}

	ovs_unlock();

	cancel_work_sync(&ovs_net->dp_notify_work);
}

static struct pernet_operations ovs_net_ops = {
	.init = ovs_init_net,
	.exit = ovs_exit_net,
	.id   = &ovs_net_id,
	.size = sizeof(struct ovs_net),
};

DEFINE_COMPAT_PNET_REG_FUNC(device);

static int __init dp_init(void)
{
	int err;

	BUILD_BUG_ON(sizeof(struct ovs_skb_cb) > FIELD_SIZEOF(struct sk_buff, cb));

	pr_info("Open vSwitch switching datapath %s\n", VERSION);

	err = action_fifos_init();
	if (err)
		goto error;

	err = ovs_internal_dev_rtnl_link_register();
	if (err)
		goto error_action_fifos_exit;

	err = ovs_flow_init();
	if (err)
		goto error_unreg_rtnl_link;

	err = ovs_vport_init();
	if (err)
		goto error_flow_exit;

	err = register_pernet_device(&ovs_net_ops);
	if (err)
		goto error_vport_exit;

	err = register_netdevice_notifier(&ovs_dp_device_notifier);
	if (err)
		goto error_netns_exit;

	err = ovs_netdev_init();
	if (err)
		goto error_unreg_notifier;

	err = dp_register_genl();
	if (err < 0)
		goto error_unreg_netdev;

	return 0;

error_unreg_netdev:
	ovs_netdev_exit();
error_unreg_notifier:
	unregister_netdevice_notifier(&ovs_dp_device_notifier);
error_netns_exit:
	unregister_pernet_device(&ovs_net_ops);
error_vport_exit:
	ovs_vport_exit();
error_flow_exit:
	ovs_flow_exit();
error_unreg_rtnl_link:
	ovs_internal_dev_rtnl_link_unregister();
error_action_fifos_exit:
	action_fifos_exit();
error:
	return err;
}

static void dp_cleanup(void)
{
	dp_unregister_genl(ARRAY_SIZE(dp_genl_families));
	ovs_netdev_exit();
	unregister_netdevice_notifier(&ovs_dp_device_notifier);
	unregister_pernet_device(&ovs_net_ops);
	rcu_barrier();
	ovs_vport_exit();
	ovs_flow_exit();
	ovs_internal_dev_rtnl_link_unregister();
	action_fifos_exit();
}

module_init(dp_init);
module_exit(dp_cleanup);

MODULE_DESCRIPTION("Open vSwitch switching datapath");
MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION);
