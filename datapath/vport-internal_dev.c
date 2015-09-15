/*
 * Copyright (c) 2007-2012 Nicira, Inc.
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

#include <linux/hardirq.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/netdev_features.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#include <net/dst.h>
#include <net/xfrm.h>

#include "datapath.h"
#include "vlan.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

//net_device 的私有数据
struct internal_dev {
	struct vport *vport;
};

static struct vport_ops ovs_internal_vport_ops;

//return (char *)dev + ALIGN(sizeof(struct net_device), NETDEV_ALIGN)
static struct internal_dev *internal_dev_priv(struct net_device *netdev)
{
	return netdev_priv(netdev);
}

/* This function is only called by the kernel network layer.*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
static struct rtnl_link_stats64 *internal_dev_get_stats(struct net_device *netdev,
							struct rtnl_link_stats64 *stats)
{
#else
static struct net_device_stats *internal_dev_sys_stats(struct net_device *netdev)
{
	struct net_device_stats *stats = &netdev->stats;
#endif
	struct vport *vport = ovs_internal_dev_get_vport(netdev);
	struct ovs_vport_stats vport_stats;

	ovs_vport_get_stats(vport, &vport_stats);

	/* The tx and rx stats need to be swapped because the
	 * switch and host OS have opposite perspectives.
	 */
	stats->rx_packets	= vport_stats.tx_packets;
	stats->tx_packets	= vport_stats.rx_packets;
	stats->rx_bytes		= vport_stats.tx_bytes;
	stats->tx_bytes		= vport_stats.rx_bytes;
	stats->rx_errors	= vport_stats.tx_errors;
	stats->tx_errors	= vport_stats.rx_errors;
	stats->rx_dropped	= vport_stats.tx_dropped;
	stats->tx_dropped	= vport_stats.rx_dropped;

	return stats;
}

/* Called with rcu_read_lock_bh. */
//接受数据包
static int internal_dev_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	rcu_read_lock();
	ovs_vport_receive(internal_dev_priv(netdev)->vport, skb, NULL);
	rcu_read_unlock();
	return 0;
}

static int internal_dev_open(struct net_device *netdev)
{
    //通知上层可以调用 dev_hard_start_xmit 进行数据包发送
	netif_start_queue(netdev);
	return 0;
}

static int internal_dev_stop(struct net_device *netdev)
{
    //通知上层不可以调用 dev_hard_start_xmit 进行数据包发送
	netif_stop_queue(netdev);
	return 0;
}

static void internal_dev_getinfo(struct net_device *netdev,
				 struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, "openvswitch", sizeof(info->driver));
}

static const struct ethtool_ops internal_dev_ethtool_ops = {
	.get_drvinfo	= internal_dev_getinfo,
	.get_link	= ethtool_op_get_link,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
	.get_sg		= ethtool_op_get_sg,
	.set_sg		= ethtool_op_set_sg,
	.get_tx_csum	= ethtool_op_get_tx_csum,
	.set_tx_csum	= ethtool_op_set_tx_hw_csum,
	.get_tso	= ethtool_op_get_tso,
	.set_tso	= ethtool_op_set_tso,
#endif
};

static int internal_dev_change_mtu(struct net_device *netdev, int new_mtu)
{
	if (new_mtu < 68)
		return -EINVAL;

	netdev->mtu = new_mtu;
	return 0;
}

static void internal_dev_destructor(struct net_device *dev)
{
	struct vport *vport = ovs_internal_dev_get_vport(dev);

	ovs_vport_free(vport);
	free_netdev(dev);
}

static const struct net_device_ops internal_dev_netdev_ops = {
    //开启发送数据给驱动
	.ndo_open = internal_dev_open,
    //停止发送数据给驱动
	.ndo_stop = internal_dev_stop,
    //开始接收
	.ndo_start_xmit = internal_dev_xmit,
    //设置 MAC
	.ndo_set_mac_address = eth_mac_addr,
    //设置 MTU
	.ndo_change_mtu = internal_dev_change_mtu,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
    //获取状态如接收,传输的包数, 错误和丢弃的包数
	.ndo_get_stats64 = internal_dev_get_stats,
#else
	.ndo_get_stats = internal_dev_sys_stats,
#endif
};

static struct rtnl_link_ops internal_dev_link_ops __read_mostly = {
	.kind = "openvswitch",
};

static void do_setup(struct net_device *netdev)
{
    //dev->header_ops         = &eth_header_ops;
    //dev->type               = ARPHRD_ETHER;
    //dev->hard_header_len    = ETH_HLEN;
    //dev->mtu                = ETH_DATA_LEN;
    //dev->addr_len           = ETH_ALEN;
    //dev->tx_queue_len       = 1000; /* Ethernet wants good queues */
    //dev->flags              = IFF_BROADCAST|IFF_MULTICAST;
    //dev->priv_flags         |= IFF_TX_SKB_SHARING;
    //eth_broadcast_addr(dev->broadcast);
	ether_setup(netdev);

	netdev->netdev_ops = &internal_dev_netdev_ops;

	netdev->priv_flags &= ~IFF_TX_SKB_SHARING;
	netdev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
    // 释放 internal_dev_create 中分配的 dev 及 vport
	netdev->destructor = internal_dev_destructor;
	netdev->ethtool_ops = &internal_dev_ethtool_ops;
	netdev->rtnl_link_ops = &internal_dev_link_ops;
	netdev->tx_queue_len = 0;

	netdev->features = NETIF_F_LLTX | NETIF_F_SG | NETIF_F_FRAGLIST |
			   NETIF_F_HIGHDMA | NETIF_F_HW_CSUM |
			   NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ENCAP_ALL;

	netdev->vlan_features = netdev->features;
	netdev->features |= NETIF_F_HW_VLAN_CTAG_TX;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
	netdev->hw_features = netdev->features & ~NETIF_F_LLTX;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
	netdev->hw_enc_features = netdev->features;
#endif

    //netdev->dev_addr 分配随机的MAC地址
	eth_hw_addr_random(netdev);
}

//1. 根据 params 分配一个 vport 并初始化数据成员
//
//2. 将其私有数据对应的 dev 注册为一个网络设备(类似网卡), 并初始化
//  * 私有数据大小为 sizeof(struct internal_dev)
//  * dev->name = parms->name
//  * dev->name_assign_type = name_assign_type;
//  * 调用 do_setup(dev)
//3. 注册私有数据中的网络设备, 并设置为混杂模式, 加入内核协议栈, 处理数据包
//
//NOTE: 没有初始化的 hash_node, err_stats, detach_list
static struct vport *internal_dev_create(const struct vport_parms *parms)
{
	struct vport *vport;
	struct netdev_vport *netdev_vport;
	struct internal_dev *internal_dev;
	int err;

    //分配一个 vport 对象, 并初始化部分数据成员, 其中私有数据为 struct netdev_vport
    //没有初始化的 hash_node, err_stats, detach_list. 
    //注 : hash_node 在 ovs_vport_add 中初始化
	vport = ovs_vport_alloc(sizeof(struct netdev_vport),
				&ovs_internal_vport_ops, parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	netdev_vport = netdev_vport_priv(vport);

    //分配一个 net_device 对象, 其中的私有数据为 struct internal_dev
    /**
     *      alloc_netdev_mqs - allocate network device
     *      @sizeof_priv:           size of private data to allocate space for
     *      @name:                  device name format string
     *      @name_assign_type:      origin of device name
     *      @setup:                 callback to initialize device
     *      @txqs:                  the number of TX subqueues to allocate
     *      @rxqs:                  the number of RX subqueues to allocate
     *
     *      Allocates a struct net_device with private data area for driver use
     *      and performs basic initialization.  Also allocates subqueue structs
     *      for each queue on the device.
     *
     *  #define alloc_netdev(sizeof_priv, name, name_assign_type, setup) \
     *          alloc_netdev_mqs(sizeof_priv, name, name_assign_type, setup, 1, 1)
     *
     *  创建一个 net_device 对象 dev :
     *  * 私有数据大小为 sizeof(struct internal_dev)
     *  * dev->name = parms->name
     *  * dev->name_assign_type = name_assign_type;
     *  * 调用 do_setup(dev)
     *  * dev->nd_net->net = vport->dp->net
     *  详细参考内核代码 alloc_netdev_mqs()
     */
	netdev_vport->dev = alloc_netdev(sizeof(struct internal_dev),
					 parms->name, NET_NAME_UNKNOWN, do_setup);
	if (!netdev_vport->dev) {
		err = -ENOMEM;
		goto error_free_vport;
	}

    //netdev_vport->dev->nd_net->net = vport->dp->net
	dev_net_set(netdev_vport->dev, ovs_dp_get_net(vport->dp));
    //vport->priv_data->dev->priv_data
	internal_dev = internal_dev_priv(netdev_vport->dev);
	internal_dev->vport = vport;

	/* Restrict bridge port to current netns. */
	if (vport->port_no == OVSP_LOCAL)
		netdev_vport->dev->features |= NETIF_F_NETNS_LOCAL;

	rtnl_lock();
    //注册网络设备
	err = register_netdevice(netdev_vport->dev);
	if (err)
		goto error_free_netdev;

    //设置混杂模式
	dev_set_promiscuity(netdev_vport->dev, 1);
	rtnl_unlock();
    //允许上层设备调用 netdev_vport 的 hard_start_xmit routine
    //__QUEUE_STATE_DRV_XOFF is used by drivers to stop the transmit queue.
    //clear_bit(__QUEUE_STATE_DRV_XOFF, netdev_vport->dev->tx[0]->state)
	netif_start_queue(netdev_vport->dev);

	return vport;

error_free_netdev:
	rtnl_unlock();
	free_netdev(netdev_vport->dev);
error_free_vport:
	ovs_vport_free(vport);
error:
	return ERR_PTR(err);
}

static void internal_dev_destroy(struct vport *vport)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);

	netif_stop_queue(netdev_vport->dev);
	rtnl_lock();
	dev_set_promiscuity(netdev_vport->dev, -1);

	/* unregister_netdevice() waits for an RCU grace period. */
	unregister_netdevice(netdev_vport->dev);

	rtnl_unlock();
}

static int internal_dev_recv(struct vport *vport, struct sk_buff *skb)
{
	struct net_device *netdev = netdev_vport_priv(vport)->dev;
	int len;

	if (unlikely(!(netdev->flags & IFF_UP))) {
		kfree_skb(skb);
		return 0;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
	if (skb_vlan_tag_present(skb)) {
		if (unlikely(!vlan_insert_tag_set_proto(skb,
							skb->vlan_proto,
							skb_vlan_tag_get(skb))))
			return 0;

		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->csum = csum_add(skb->csum,
					     csum_partial(skb->data + (2 * ETH_ALEN),
							  VLAN_HLEN, 0));

		vlan_set_tci(skb, 0);
	}
#endif

	len = skb->len;

    //skb->_refdst = 0
	skb_dst_drop(skb);
    //skb->nfct = NULL
	nf_reset(skb);
    //skb->sp = NULL;
	secpath_reset(skb);

	skb->dev = netdev;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, netdev);
	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);

    /**
     *      netif_rx        -       post buffer to the network code
     *      @skb: buffer to post
     *
     *      This function receives a packet from a device driver and queues it for
     *      the upper (protocol) levels to process.  It always succeeds. The buffer
     *      may be dropped during processing for congestion control or by the
     *      protocol layers.
     *
     *      return values:
     *      NET_RX_SUCCESS  (no congestion)
     *      NET_RX_DROP     (packet was dropped)
     *
     */
    //硬件将数据包从设备内存拷贝到系统内存后, 将包放在中断所属的 CPU 的 softnet_data->input_pkt_queue 队列中
	netif_rx(skb);

	return len;
}

static struct vport_ops ovs_internal_vport_ops = {
	.type		= OVS_VPORT_TYPE_INTERNAL,
	.create		= internal_dev_create,
	.destroy	= internal_dev_destroy,
	.get_name	= ovs_netdev_get_name,
	.send		= internal_dev_recv,
};

int ovs_is_internal_dev(const struct net_device *netdev)
{
	return netdev->netdev_ops == &internal_dev_netdev_ops;
}

//netdev_priv(netdev)->vport
struct vport *ovs_internal_dev_get_vport(struct net_device *netdev)
{
	if (!ovs_is_internal_dev(netdev))
		return NULL;

	return internal_dev_priv(netdev)->vport;
}

int ovs_internal_dev_rtnl_link_register(void)
{
	int err;

    //将 internal_dev_link_ops 加入 linux/rtnetlink.h 中 link_ops
	err = rtnl_link_register(&internal_dev_link_ops);
	if (err < 0)
		return err;

    //将 ovs_internal_vport_ops 加入 vport.c 中的 vport_ops_list 中, 方便后续
    //vswitchd 通过 netlink 创建 vport
	err = ovs_vport_ops_register(&ovs_internal_vport_ops);
	if (err < 0)
		rtnl_link_unregister(&internal_dev_link_ops);

	return err;
}

void ovs_internal_dev_rtnl_link_unregister(void)
{
	ovs_vport_ops_unregister(&ovs_internal_vport_ops);
	rtnl_link_unregister(&internal_dev_link_ops);
}
