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
#include <net/geneve.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ndisc.h>
#include <net/mpls.h>

#include "datapath.h"
#include "flow.h"
#include "flow_netlink.h"
#include "vport-vxlan.h"

struct ovs_len_tbl {
	int len;
	const struct ovs_len_tbl *next;
};

#define OVS_ATTR_NESTED -1

static void update_range(struct sw_flow_match *match,
			 size_t offset, size_t size, bool is_mask)
{
	struct sw_flow_key_range *range;
	size_t start = rounddown(offset, sizeof(long));
	size_t end = roundup(offset + size, sizeof(long));

	if (!is_mask)
		range = &match->range;
	else
		range = &match->mask->range;

	if (range->start == range->end) {
		range->start = start;
		range->end = end;
		return;
	}

	if (range->start > start)
		range->start = start;

	if (range->end < end)
		range->end = end;
}

//如果 is_mask = true, 更新 mask, 否则更新 key
#define SW_FLOW_KEY_PUT(match, field, value, is_mask) \
	do { \
		update_range(match, offsetof(struct sw_flow_key, field),    \
			     sizeof((match)->key->field), is_mask);	    \
		if (is_mask)						    \
			(match)->mask->key.field = value;		    \
		else							    \
			(match)->key->field = value;		            \
	} while (0)

#define SW_FLOW_KEY_MEMCPY_OFFSET(match, offset, value_p, len, is_mask)	    \
	do {								    \
		update_range(match, offset, len, is_mask);		    \
		if (is_mask)						    \
			memcpy((u8 *)&(match)->mask->key + offset, value_p, len);\
		else							    \
			memcpy((u8 *)(match)->key + offset, value_p, len);  \
	} while (0)

#define SW_FLOW_KEY_MEMCPY(match, field, value_p, len, is_mask)		      \
	SW_FLOW_KEY_MEMCPY_OFFSET(match, offsetof(struct sw_flow_key, field), \
				  value_p, len, is_mask)

#define SW_FLOW_KEY_MEMSET_FIELD(match, field, value, is_mask)		    \
	do {								    \
		update_range(match, offsetof(struct sw_flow_key, field),    \
			     sizeof((match)->key->field), is_mask);	    \
		if (is_mask)						    \
			memset((u8 *)&(match)->mask->key.field, value,      \
			       sizeof((match)->mask->key.field));	    \
		else							    \
			memset((u8 *)&(match)->key->field, value,           \
			       sizeof((match)->key->field));                \
	} while (0)

//对 key 和 mask 的 ovs_key_attr 进行校验
static bool match_validate(const struct sw_flow_match *match,
			   u64 key_attrs, u64 mask_attrs, bool log)
{
    //期望的 key 的 ovs_key_attr
	u64 key_expected = 1ULL << OVS_KEY_ATTR_ETHERNET;
    //期望的 mask 的 ovs_key_attr, 其 bit 位 1 表示允许 的 ovs_key_attr
	u64 mask_allowed = key_attrs;  /* At most allow all key attributes */

	/* The following mask attributes allowed only if they
	 * pass the validation tests.
	 */
	mask_allowed &= ~((1ULL << OVS_KEY_ATTR_IPV4)
			| (1ULL << OVS_KEY_ATTR_IPV6)
			| (1ULL << OVS_KEY_ATTR_TCP)
			| (1ULL << OVS_KEY_ATTR_TCP_FLAGS)
			| (1ULL << OVS_KEY_ATTR_UDP)
			| (1ULL << OVS_KEY_ATTR_SCTP)
			| (1ULL << OVS_KEY_ATTR_ICMP)
			| (1ULL << OVS_KEY_ATTR_ICMPV6)
			| (1ULL << OVS_KEY_ATTR_ARP)
			| (1ULL << OVS_KEY_ATTR_ND)
			| (1ULL << OVS_KEY_ATTR_MPLS));

	/* Always allowed mask fields. */
	mask_allowed |= ((1ULL << OVS_KEY_ATTR_TUNNEL)
		       | (1ULL << OVS_KEY_ATTR_IN_PORT)
		       | (1ULL << OVS_KEY_ATTR_ETHERTYPE));

	/* Check key attributes. */
	if (match->key->eth.type == htons(ETH_P_ARP)
			|| match->key->eth.type == htons(ETH_P_RARP)) {
		key_expected |= 1ULL << OVS_KEY_ATTR_ARP;
		if (match->mask && (match->mask->key.eth.type == htons(0xffff)))
			mask_allowed |= 1ULL << OVS_KEY_ATTR_ARP;
	}

	if (eth_p_mpls(match->key->eth.type)) {
		key_expected |= 1ULL << OVS_KEY_ATTR_MPLS;
		if (match->mask && (match->mask->key.eth.type == htons(0xffff)))
			mask_allowed |= 1ULL << OVS_KEY_ATTR_MPLS;
	}

	if (match->key->eth.type == htons(ETH_P_IP)) {
		key_expected |= 1ULL << OVS_KEY_ATTR_IPV4;
		if (match->mask && (match->mask->key.eth.type == htons(0xffff)))
			mask_allowed |= 1ULL << OVS_KEY_ATTR_IPV4;

		if (match->key->ip.frag != OVS_FRAG_TYPE_LATER) {
			if (match->key->ip.proto == IPPROTO_UDP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_UDP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1ULL << OVS_KEY_ATTR_UDP;
			}

			if (match->key->ip.proto == IPPROTO_SCTP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_SCTP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1ULL << OVS_KEY_ATTR_SCTP;
			}

			if (match->key->ip.proto == IPPROTO_TCP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_TCP;
				key_expected |= 1ULL << OVS_KEY_ATTR_TCP_FLAGS;
				if (match->mask && (match->mask->key.ip.proto == 0xff)) {
					mask_allowed |= 1ULL << OVS_KEY_ATTR_TCP;
					mask_allowed |= 1ULL << OVS_KEY_ATTR_TCP_FLAGS;
				}
			}

			if (match->key->ip.proto == IPPROTO_ICMP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_ICMP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1ULL << OVS_KEY_ATTR_ICMP;
			}
		}
	}

	if (match->key->eth.type == htons(ETH_P_IPV6)) {
		key_expected |= 1ULL << OVS_KEY_ATTR_IPV6;
		if (match->mask && (match->mask->key.eth.type == htons(0xffff)))
			mask_allowed |= 1ULL << OVS_KEY_ATTR_IPV6;

		if (match->key->ip.frag != OVS_FRAG_TYPE_LATER) {
			if (match->key->ip.proto == IPPROTO_UDP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_UDP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1ULL << OVS_KEY_ATTR_UDP;
			}

			if (match->key->ip.proto == IPPROTO_SCTP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_SCTP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1ULL << OVS_KEY_ATTR_SCTP;
			}

			if (match->key->ip.proto == IPPROTO_TCP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_TCP;
				key_expected |= 1ULL << OVS_KEY_ATTR_TCP_FLAGS;
				if (match->mask && (match->mask->key.ip.proto == 0xff)) {
					mask_allowed |= 1ULL << OVS_KEY_ATTR_TCP;
					mask_allowed |= 1ULL << OVS_KEY_ATTR_TCP_FLAGS;
				}
			}

			if (match->key->ip.proto == IPPROTO_ICMPV6) {
				key_expected |= 1ULL << OVS_KEY_ATTR_ICMPV6;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1ULL << OVS_KEY_ATTR_ICMPV6;

				if (match->key->tp.src ==
						htons(NDISC_NEIGHBOUR_SOLICITATION) ||
				    match->key->tp.src == htons(NDISC_NEIGHBOUR_ADVERTISEMENT)) {
					key_expected |= 1ULL << OVS_KEY_ATTR_ND;
					if (match->mask && (match->mask->key.tp.src == htons(0xff)))
						mask_allowed |= 1ULL << OVS_KEY_ATTR_ND;
				}
			}
		}
	}

	if ((key_attrs & key_expected) != key_expected) {
		/* Key attributes check failed. */
		OVS_NLERR(log, "Missing key (keys=%llx, expected=%llx)",
			  (unsigned long long)key_attrs,
			  (unsigned long long)key_expected);
		return false;
	}

	if ((mask_attrs & mask_allowed) != mask_attrs) {
		/* Mask attributes check failed. */
		OVS_NLERR(log, "Unexpected mask (mask=%llx, allowed=%llx)",
			  (unsigned long long)mask_attrs,
			  (unsigned long long)mask_allowed);
		return false;
	}

	return true;
}

size_t ovs_tun_key_attr_size(void)
{
	/* Whenever adding new OVS_TUNNEL_KEY_ FIELDS, we should consider
	 * updating this function.
	 */
	return    nla_total_size(8)    /* OVS_TUNNEL_KEY_ATTR_ID */
		+ nla_total_size(4)    /* OVS_TUNNEL_KEY_ATTR_IPV4_SRC */
		+ nla_total_size(4)    /* OVS_TUNNEL_KEY_ATTR_IPV4_DST */
		+ nla_total_size(1)    /* OVS_TUNNEL_KEY_ATTR_TOS */
		+ nla_total_size(1)    /* OVS_TUNNEL_KEY_ATTR_TTL */
		+ nla_total_size(0)    /* OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT */
		+ nla_total_size(0)    /* OVS_TUNNEL_KEY_ATTR_CSUM */
		+ nla_total_size(0)    /* OVS_TUNNEL_KEY_ATTR_OAM */
		+ nla_total_size(256)  /* OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS */
		/* OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS is mutually exclusive with
		 * OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS and covered by it.
		 */
		+ nla_total_size(2)    /* OVS_TUNNEL_KEY_ATTR_TP_SRC */
		+ nla_total_size(2);   /* OVS_TUNNEL_KEY_ATTR_TP_DST */
}

size_t ovs_key_attr_size(void)
{
	/* Whenever adding new OVS_KEY_ FIELDS, we should consider
	 * updating this function.
	 */
	BUILD_BUG_ON(OVS_KEY_ATTR_TUNNEL_INFO != 22);

	return    nla_total_size(4)   /* OVS_KEY_ATTR_PRIORITY */
		+ nla_total_size(0)   /* OVS_KEY_ATTR_TUNNEL */
		  + ovs_tun_key_attr_size()
		+ nla_total_size(4)   /* OVS_KEY_ATTR_IN_PORT */
		+ nla_total_size(4)   /* OVS_KEY_ATTR_SKB_MARK */
		+ nla_total_size(4)   /* OVS_KEY_ATTR_DP_HASH */
		+ nla_total_size(4)   /* OVS_KEY_ATTR_RECIRC_ID */
		+ nla_total_size(12)  /* OVS_KEY_ATTR_ETHERNET */
		+ nla_total_size(2)   /* OVS_KEY_ATTR_ETHERTYPE */
		+ nla_total_size(4)   /* OVS_KEY_ATTR_VLAN */
		+ nla_total_size(0)   /* OVS_KEY_ATTR_ENCAP */
		+ nla_total_size(2)   /* OVS_KEY_ATTR_ETHERTYPE */
		+ nla_total_size(40)  /* OVS_KEY_ATTR_IPV6 */
		+ nla_total_size(2)   /* OVS_KEY_ATTR_ICMPV6 */
		+ nla_total_size(28); /* OVS_KEY_ATTR_ND */
}

static const struct ovs_len_tbl ovs_tunnel_key_lens[OVS_TUNNEL_KEY_ATTR_MAX + 1] = {
	[OVS_TUNNEL_KEY_ATTR_ID]	    = { .len = sizeof(u64) },
	[OVS_TUNNEL_KEY_ATTR_IPV4_SRC]	    = { .len = sizeof(u32) },
	[OVS_TUNNEL_KEY_ATTR_IPV4_DST]	    = { .len = sizeof(u32) },
	[OVS_TUNNEL_KEY_ATTR_TOS]	    = { .len = 1 },
	[OVS_TUNNEL_KEY_ATTR_TTL]	    = { .len = 1 },
	[OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT] = { .len = 0 },
	[OVS_TUNNEL_KEY_ATTR_CSUM]	    = { .len = 0 },
	[OVS_TUNNEL_KEY_ATTR_TP_SRC]	    = { .len = sizeof(u16) },
	[OVS_TUNNEL_KEY_ATTR_TP_DST]	    = { .len = sizeof(u16) },
	[OVS_TUNNEL_KEY_ATTR_OAM]	    = { .len = 0 },
	[OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS]   = { .len = OVS_ATTR_NESTED },
	[OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS]    = { .len = OVS_ATTR_NESTED },
};

/* The size of the argument for each %OVS_KEY_ATTR_* Netlink attribute.  */
static const struct ovs_len_tbl ovs_key_lens[OVS_KEY_ATTR_MAX + 1] = {
	[OVS_KEY_ATTR_ENCAP]	 = { .len = OVS_ATTR_NESTED },
	[OVS_KEY_ATTR_PRIORITY]	 = { .len = sizeof(u32) },
	[OVS_KEY_ATTR_IN_PORT]	 = { .len = sizeof(u32) },
	[OVS_KEY_ATTR_SKB_MARK]	 = { .len = sizeof(u32) },
	[OVS_KEY_ATTR_ETHERNET]	 = { .len = sizeof(struct ovs_key_ethernet) },
	[OVS_KEY_ATTR_VLAN]	 = { .len = sizeof(__be16) },
	[OVS_KEY_ATTR_ETHERTYPE] = { .len = sizeof(__be16) },
	[OVS_KEY_ATTR_IPV4]	 = { .len = sizeof(struct ovs_key_ipv4) },
	[OVS_KEY_ATTR_IPV6]	 = { .len = sizeof(struct ovs_key_ipv6) },
	[OVS_KEY_ATTR_TCP]	 = { .len = sizeof(struct ovs_key_tcp) },
	[OVS_KEY_ATTR_TCP_FLAGS] = { .len = sizeof(__be16) },
	[OVS_KEY_ATTR_UDP]	 = { .len = sizeof(struct ovs_key_udp) },
	[OVS_KEY_ATTR_SCTP]	 = { .len = sizeof(struct ovs_key_sctp) },
	[OVS_KEY_ATTR_ICMP]	 = { .len = sizeof(struct ovs_key_icmp) },
	[OVS_KEY_ATTR_ICMPV6]	 = { .len = sizeof(struct ovs_key_icmpv6) },
	[OVS_KEY_ATTR_ARP]	 = { .len = sizeof(struct ovs_key_arp) },
	[OVS_KEY_ATTR_ND]	 = { .len = sizeof(struct ovs_key_nd) },
	[OVS_KEY_ATTR_RECIRC_ID] = { .len = sizeof(u32) },
	[OVS_KEY_ATTR_DP_HASH]	 = { .len = sizeof(u32) },
	[OVS_KEY_ATTR_TUNNEL]	 = { .len = OVS_ATTR_NESTED,
				     .next = ovs_tunnel_key_lens, },
	[OVS_KEY_ATTR_MPLS]	 = { .len = sizeof(struct ovs_key_mpls) },
};

static bool is_all_zero(const u8 *fp, size_t size)
{
	int i;

	if (!fp)
		return false;

	for (i = 0; i < size; i++)
		if (fp[i])
			return false;

	return true;
}

/*
 * 解析 attr 写入 a, ovs_key_attr 保持在 attrsp
 *
 * @attr   : 待解析的内嵌属性
 * @a      : 保持解析 attr 后的 type:value
 * @attrsp : 保持所有已经解析的 ovs_key_attr
 * @log    : 是否记日志
 * @nz     : 应该为 false, 否则不解析
 */
static int __parse_flow_nlattrs(const struct nlattr *attr,
				const struct nlattr *a[],
				u64 *attrsp, bool log, bool nz)
{
	const struct nlattr *nla;
    //判断重复属性
	u64 attrs;
	int rem;

    //attrs = 0
	attrs = *attrsp;
    //迭代 attr 的每个属性, 将其加入 a
	nla_for_each_nested(nla, attr, rem) {
		u16 type = nla_type(nla);
		int expected_len;

		if (type > OVS_KEY_ATTR_MAX) {
			OVS_NLERR(log, "Key type %d is out of range max %d",
				  type, OVS_KEY_ATTR_MAX);
			return -EINVAL;
		}

		if (attrs & (1ULL << type)) {
			OVS_NLERR(log, "Duplicate key (type %d).", type);
			return -EINVAL;
		}

        /*
        static const struct ovs_len_tbl ovs_key_lens[OVS_KEY_ATTR_MAX + 1] = {
            [OVS_KEY_ATTR_ENCAP]	 = { .len = OVS_ATTR_NESTED },
            [OVS_KEY_ATTR_PRIORITY]	 = { .len = sizeof(u32) },
            [OVS_KEY_ATTR_IN_PORT]	 = { .len = sizeof(u32) },
            [OVS_KEY_ATTR_SKB_MARK]	 = { .len = sizeof(u32) },
            [OVS_KEY_ATTR_ETHERNET]	 = { .len = sizeof(struct ovs_key_ethernet) },
            [OVS_KEY_ATTR_VLAN]	 = { .len = sizeof(__be16) },
            [OVS_KEY_ATTR_ETHERTYPE] = { .len = sizeof(__be16) },
            [OVS_KEY_ATTR_IPV4]	 = { .len = sizeof(struct ovs_key_ipv4) },
            [OVS_KEY_ATTR_IPV6]	 = { .len = sizeof(struct ovs_key_ipv6) },
            [OVS_KEY_ATTR_TCP]	 = { .len = sizeof(struct ovs_key_tcp) },
            [OVS_KEY_ATTR_TCP_FLAGS] = { .len = sizeof(__be16) },
            [OVS_KEY_ATTR_UDP]	 = { .len = sizeof(struct ovs_key_udp) },
            [OVS_KEY_ATTR_SCTP]	 = { .len = sizeof(struct ovs_key_sctp) },
            [OVS_KEY_ATTR_ICMP]	 = { .len = sizeof(struct ovs_key_icmp) },
            [OVS_KEY_ATTR_ICMPV6]	 = { .len = sizeof(struct ovs_key_icmpv6) },
            [OVS_KEY_ATTR_ARP]	 = { .len = sizeof(struct ovs_key_arp) },
            [OVS_KEY_ATTR_ND]	 = { .len = sizeof(struct ovs_key_nd) },
            [OVS_KEY_ATTR_RECIRC_ID] = { .len = sizeof(u32) },
            [OVS_KEY_ATTR_DP_HASH]	 = { .len = sizeof(u32) },
            [OVS_KEY_ATTR_TUNNEL]	 = { .len = OVS_ATTR_NESTED,
                            .next = ovs_tunnel_key_lens, },
            [OVS_KEY_ATTR_MPLS]	 = { .len = sizeof(struct ovs_key_mpls) },
        };
        */
		expected_len = ovs_key_lens[type].len;
		if (nla_len(nla) != expected_len && expected_len != OVS_ATTR_NESTED) {
			OVS_NLERR(log, "Key %d has unexpected len %d expected %d",
				  type, nla_len(nla), expected_len);
			return -EINVAL;
		}

		if (!nz || !is_all_zero(nla_data(nla), expected_len)) {
            //标记属性已经解析
			attrs |= 1ULL << type;
			a[type] = nla;
		}
	}
	if (rem) {
		OVS_NLERR(log, "Message has %d unknown bytes.", rem);
		return -EINVAL;
	}

	*attrsp = attrs;
	return 0;
}

//解析 attr 写入 a, ovs_key_attr 保持在 attrsp
static int parse_flow_mask_nlattrs(const struct nlattr *attr,
				   const struct nlattr *a[], u64 *attrsp,
				   bool log)
{
	return __parse_flow_nlattrs(attr, a, attrsp, log, true);
}

/*
 * 解析 attr 保持在 a 中
 *
 * @attr   : 待解析的内嵌属性
 * @a      : 保持解析 attr 后的 type:value
 * @attrsp : 保持所有已经解析的 type
 * @log    : 是否记日志
 */
static int parse_flow_nlattrs(const struct nlattr *attr,
			      const struct nlattr *a[], u64 *attrsp,
			      bool log)
{
	return __parse_flow_nlattrs(attr, a, attrsp, log, false);
}

static int genev_tun_opt_from_nlattr(const struct nlattr *a,
				     struct sw_flow_match *match, bool is_mask,
				     bool log)
{
	unsigned long opt_key_offset;

	if (nla_len(a) > sizeof(match->key->tun_opts)) {
		OVS_NLERR(log, "Geneve option length err (len %d, max %zu).",
			  nla_len(a), sizeof(match->key->tun_opts));
		return -EINVAL;
	}

	if (nla_len(a) % 4 != 0) {
		OVS_NLERR(log, "Geneve opt len %d is not a multiple of 4.",
			  nla_len(a));
		return -EINVAL;
	}

	/* We need to record the length of the options passed
	 * down, otherwise packets with the same format but
	 * additional options will be silently matched.
	 */
	if (!is_mask) {
		SW_FLOW_KEY_PUT(match, tun_opts_len, nla_len(a),
				false);
	} else {
		/* This is somewhat unusual because it looks at
		 * both the key and mask while parsing the
		 * attributes (and by extension assumes the key
		 * is parsed first). Normally, we would verify
		 * that each is the correct length and that the
		 * attributes line up in the validate function.
		 * However, that is difficult because this is
		 * variable length and we won't have the
		 * information later.
		 */
		if (match->key->tun_opts_len != nla_len(a)) {
			OVS_NLERR(log, "Geneve option len %d != mask len %d",
				  match->key->tun_opts_len, nla_len(a));
			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, tun_opts_len, 0xff, true);
	}

	opt_key_offset = TUN_METADATA_OFFSET(nla_len(a));
	SW_FLOW_KEY_MEMCPY_OFFSET(match, opt_key_offset, nla_data(a),
				  nla_len(a), is_mask);
	return 0;
}

static const struct nla_policy vxlan_opt_policy[OVS_VXLAN_EXT_MAX + 1] = {
	[OVS_VXLAN_EXT_GBP]	= { .type = NLA_U32 },
};

static int vxlan_tun_opt_from_nlattr(const struct nlattr *a,
				     struct sw_flow_match *match, bool is_mask,
				     bool log)
{
	struct nlattr *tb[OVS_VXLAN_EXT_MAX+1];
	unsigned long opt_key_offset;
	struct ovs_vxlan_opts opts;
	int err;

	BUILD_BUG_ON(sizeof(opts) > sizeof(match->key->tun_opts));

	err = nla_parse_nested(tb, OVS_VXLAN_EXT_MAX, a, vxlan_opt_policy);
	if (err < 0)
		return err;

	memset(&opts, 0, sizeof(opts));

	if (tb[OVS_VXLAN_EXT_GBP])
		opts.gbp = nla_get_u32(tb[OVS_VXLAN_EXT_GBP]);

	if (!is_mask)
		SW_FLOW_KEY_PUT(match, tun_opts_len, sizeof(opts), false);
	else
		SW_FLOW_KEY_PUT(match, tun_opts_len, 0xff, true);

	opt_key_offset = TUN_METADATA_OFFSET(sizeof(opts));
	SW_FLOW_KEY_MEMCPY_OFFSET(match, opt_key_offset, &opts, sizeof(opts),
				  is_mask);
	return 0;
}

/*
 * 解析 attr 赋值给 match
 * match->key->tun_key.tun_id = a[OVS_TUNNEL_KEY_ATTR_ID]
 * match->key->tun_key.ipv4_src = a[OVS_TUNNEL_KEY_ATTR_IPV4_SRC]
 * match->key->tun_key.ipv4_dst = a[OVS_TUNNEL_KEY_ATTR_IPV4_DST]
 * match->key->tun_key.ipv4_tos = a[OVS_TUNNEL_KEY_ATTR_IPV4_TOS]
 * match->key->tun_key.ipv4_ttl = a[OVS_TUNNEL_KEY_ATTR_IPV4_TTL]
 * match->key->tun_key.tp_src   = a[OVS_TUNNEL_KEY_ATTR_TP_SRC]
 * match->key->tun_key.tp_dst   = a[OVS_TUNNEL_KEY_ATTR_TP_DST]
 * match->key->tun_key.tun_flags = TUNNEL_KEY | TUNNEL_DONT_FRAGMENT | TUNNEL_CSUM
 *                              | TUNNEL_OAM | TUNNEL_GENEVE_OPT | TUNNEL_VXLAN_OPT
 * TODO: genev, vxlan
 */
static int ipv4_tun_from_nlattr(const struct nlattr *attr,
				struct sw_flow_match *match, bool is_mask,
				bool log)
{
	struct nlattr *a;
	int rem;
	bool ttl = false;
    //TUNNEL_KEY | TUNNEL_DONT_FRAGMENT | TUNNEL_CSUM | TUNNEL_OAM | TUNNEL_GENEVE_OPT | TUNNEL_VXLAN_OPT
	__be16 tun_flags = 0;
    //只能是 OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS, OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS,OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS:
	int opts_type = 0;

    //遍历 attr 初始化 match 的 tun_key.tun_id.
	nla_for_each_nested(a, attr, rem) {
		int type = nla_type(a);
		int err;

		if (type > OVS_TUNNEL_KEY_ATTR_MAX) {
			OVS_NLERR(log, "Tunnel attr %d out of range max %d",
				  type, OVS_TUNNEL_KEY_ATTR_MAX);
			return -EINVAL;
		}

		if (ovs_tunnel_key_lens[type].len != nla_len(a) &&
		   ovs_tunnel_key_lens[type].len != OVS_ATTR_NESTED) {
			OVS_NLERR(log, "Tunnel attr %d has unexpected len %d expected %d",
				  type, nla_len(a), ovs_tunnel_key_lens[type].len);
			return -EINVAL;
		}

		switch (type) {
		case OVS_TUNNEL_KEY_ATTR_ID:
			SW_FLOW_KEY_PUT(match, tun_key.tun_id,
					nla_get_be64(a), is_mask);
			tun_flags |= TUNNEL_KEY;
			break;
		case OVS_TUNNEL_KEY_ATTR_IPV4_SRC:
			SW_FLOW_KEY_PUT(match, tun_key.ipv4_src,
					nla_get_be32(a), is_mask);
			break;
		case OVS_TUNNEL_KEY_ATTR_IPV4_DST:
			SW_FLOW_KEY_PUT(match, tun_key.ipv4_dst,
					nla_get_be32(a), is_mask);
			break;
		case OVS_TUNNEL_KEY_ATTR_TOS:
			SW_FLOW_KEY_PUT(match, tun_key.ipv4_tos,
					nla_get_u8(a), is_mask);
			break;
		case OVS_TUNNEL_KEY_ATTR_TTL:
			SW_FLOW_KEY_PUT(match, tun_key.ipv4_ttl,
					nla_get_u8(a), is_mask);
			ttl = true;
			break;
		case OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT:
			tun_flags |= TUNNEL_DONT_FRAGMENT;
			break;
		case OVS_TUNNEL_KEY_ATTR_CSUM:
			tun_flags |= TUNNEL_CSUM;
			break;
		case OVS_TUNNEL_KEY_ATTR_TP_SRC:
			SW_FLOW_KEY_PUT(match, tun_key.tp_src,
					nla_get_be16(a), is_mask);
			break;
		case OVS_TUNNEL_KEY_ATTR_TP_DST:
			SW_FLOW_KEY_PUT(match, tun_key.tp_dst,
					nla_get_be16(a), is_mask);
			break;
		case OVS_TUNNEL_KEY_ATTR_OAM:
			tun_flags |= TUNNEL_OAM;
			break;
		case OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS:
			if (opts_type) {
				OVS_NLERR(log, "Multiple metadata blocks provided");
				return -EINVAL;
			}

			err = genev_tun_opt_from_nlattr(a, match, is_mask, log);
			if (err)
				return err;

			tun_flags |= TUNNEL_GENEVE_OPT;
			opts_type = type;
			break;
		case OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS:
			if (opts_type) {
				OVS_NLERR(log, "Multiple metadata blocks provided");
				return -EINVAL;
			}

			err = vxlan_tun_opt_from_nlattr(a, match, is_mask, log);
			if (err)
				return err;

			tun_flags |= TUNNEL_VXLAN_OPT;
			opts_type = type;
			break;
		default:
			OVS_NLERR(log, "Unknown IPv4 tunnel attribute %d",
				  type);
			return -EINVAL;
		}
	}

	SW_FLOW_KEY_PUT(match, tun_key.tun_flags, tun_flags, is_mask);

	if (rem > 0) {
		OVS_NLERR(log, "IPv4 tunnel attribute has %d unknown bytes.",
			  rem);
		return -EINVAL;
	}

	if (!is_mask) {
		if (!match->key->tun_key.ipv4_dst) {
			OVS_NLERR(log, "IPv4 tunnel dst address is zero");
			return -EINVAL;
		}

		if (!ttl) {
			OVS_NLERR(log, "IPv4 tunnel TTL not specified.");
			return -EINVAL;
		}
	}

	return opts_type;
}

static int vxlan_opt_to_nlattr(struct sk_buff *skb,
			       const void *tun_opts, int swkey_tun_opts_len)
{
	const struct ovs_vxlan_opts *opts = tun_opts;
	struct nlattr *nla;

	nla = nla_nest_start(skb, OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS);
	if (!nla)
		return -EMSGSIZE;

	if (nla_put_u32(skb, OVS_VXLAN_EXT_GBP, opts->gbp) < 0)
		return -EMSGSIZE;

	nla_nest_end(skb, nla);
	return 0;
}

static int __ipv4_tun_to_nlattr(struct sk_buff *skb,
				const struct ovs_key_ipv4_tunnel *output,
				const void *tun_opts, int swkey_tun_opts_len)
{
	if (output->tun_flags & TUNNEL_KEY &&
	    nla_put_be64(skb, OVS_TUNNEL_KEY_ATTR_ID, output->tun_id))
		return -EMSGSIZE;
	if (output->ipv4_src &&
	    nla_put_be32(skb, OVS_TUNNEL_KEY_ATTR_IPV4_SRC, output->ipv4_src))
		return -EMSGSIZE;
	if (output->ipv4_dst &&
	    nla_put_be32(skb, OVS_TUNNEL_KEY_ATTR_IPV4_DST, output->ipv4_dst))
		return -EMSGSIZE;
	if (output->ipv4_tos &&
	    nla_put_u8(skb, OVS_TUNNEL_KEY_ATTR_TOS, output->ipv4_tos))
		return -EMSGSIZE;
	if (nla_put_u8(skb, OVS_TUNNEL_KEY_ATTR_TTL, output->ipv4_ttl))
		return -EMSGSIZE;
	if ((output->tun_flags & TUNNEL_DONT_FRAGMENT) &&
	    nla_put_flag(skb, OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT))
		return -EMSGSIZE;
	if ((output->tun_flags & TUNNEL_CSUM) &&
	    nla_put_flag(skb, OVS_TUNNEL_KEY_ATTR_CSUM))
		return -EMSGSIZE;
	if (output->tp_src &&
	    nla_put_be16(skb, OVS_TUNNEL_KEY_ATTR_TP_SRC, output->tp_src))
		return -EMSGSIZE;
	if (output->tp_dst &&
	    nla_put_be16(skb, OVS_TUNNEL_KEY_ATTR_TP_DST, output->tp_dst))
		return -EMSGSIZE;
	if ((output->tun_flags & TUNNEL_OAM) &&
	    nla_put_flag(skb, OVS_TUNNEL_KEY_ATTR_OAM))
		return -EMSGSIZE;
	if (tun_opts) {
		if (output->tun_flags & TUNNEL_GENEVE_OPT &&
		    nla_put(skb, OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS,
			    swkey_tun_opts_len, tun_opts))
			return -EMSGSIZE;
               else if (output->tun_flags & TUNNEL_VXLAN_OPT &&
			vxlan_opt_to_nlattr(skb, tun_opts, swkey_tun_opts_len))
			return -EMSGSIZE;
	}

	return 0;
}

static int ipv4_tun_to_nlattr(struct sk_buff *skb,
			      const struct ovs_key_ipv4_tunnel *output,
			      const void *tun_opts, int swkey_tun_opts_len)
{
	struct nlattr *nla;
	int err;

	nla = nla_nest_start(skb, OVS_KEY_ATTR_TUNNEL);
	if (!nla)
		return -EMSGSIZE;

	err = __ipv4_tun_to_nlattr(skb, output, tun_opts, swkey_tun_opts_len);
	if (err)
		return err;

	nla_nest_end(skb, nla);
	return 0;
}

int ovs_nla_put_egress_tunnel_key(struct sk_buff *skb,
				  const struct ovs_tunnel_info *egress_tun_info)
{
	return __ipv4_tun_to_nlattr(skb, &egress_tun_info->tunnel,
				    egress_tun_info->options,
				    egress_tun_info->options_len);
}

/*
 * @attrs   : 保存的是 a 中已经包含的　type
 * @a       : 保持 type:value 的数组
 * @is_mask : 如果为 true, 赋值给 match->mask.key.field,　否则赋值给 match->key->field
 * @log     :
 * 运行完之后, attrs 中为 1 的位表面是没有提取的type, 为 0 的位表面
 * 已经提取了 type
 *
 *
 *  match->key->ovs_flow_hash = a[OVS_KEY_ATTR_DP_HASH]
 *  match->key->ovs_flow_hash = a[OVS_KEY_ATTR_RECIRC_ID]
 *  match->key->phy.priority = a[OVS_KEY_ATTR_PRIORITY]
 *  match->key->phy.in_port = a[OVS_KEY_ATTR_IN_PORT]
 *  match->key->phy.skb_mark = a[OVS_KEY_ATTR_SKB_MARK]
 *  match->key->tun_key = ipv4_tun_from_nlattr()
 *
 *  match->mask->key.ovs_flow_hash = a[OVS_KEY_ATTR_DP_HASH]
 *  match->mask->key.recirc_id = a[OVS_KEY_ATTR_RECIRC_ID]
 *  match->mask->key.phy.priority = a[OVS_KEY_ATTR_PRIORITY]
 *  match->mask->key.phy.in_port = a[OVS_KEY_ATTR_IN_PORT]
 *  match->mask->key.phy.skb_mark = a[OVS_KEY_ATTR_SKB_MARK]
 *
 *  match->mask->tun_key = ipv4_tun_from_nlattr(a[OVS_KEY_ATTR_TUNNEL], match, is_mask, log)
 *
 */
static int metadata_from_nlattrs(struct sw_flow_match *match,  u64 *attrs,
				 const struct nlattr **a, bool is_mask,
				 bool log)
{
    //match->key->ovs_flow_hash = a[OVS_KEY_ATTR_DP_HASH]
    //match->mask->key.ovs_flow_hash = a[OVS_KEY_ATTR_DP_HASH]
	if (*attrs & (1ULL << OVS_KEY_ATTR_DP_HASH)) {
		u32 hash_val = nla_get_u32(a[OVS_KEY_ATTR_DP_HASH]);

		SW_FLOW_KEY_PUT(match, ovs_flow_hash, hash_val, is_mask);
		*attrs &= ~(1ULL << OVS_KEY_ATTR_DP_HASH);
	}

    //match->key->ovs_flow_hash = a[OVS_KEY_ATTR_RECIRC_ID]
    //match->mask->key.recirc_id = a[OVS_KEY_ATTR_RECIRC_ID]
	if (*attrs & (1ULL << OVS_KEY_ATTR_RECIRC_ID)) {
		u32 recirc_id = nla_get_u32(a[OVS_KEY_ATTR_RECIRC_ID]);

		SW_FLOW_KEY_PUT(match, recirc_id, recirc_id, is_mask);
		*attrs &= ~(1ULL << OVS_KEY_ATTR_RECIRC_ID);
	}

    //match->key->phy.priority = a[OVS_KEY_ATTR_PRIORITY]
    //match->mask->key.phy.priority = a[OVS_KEY_ATTR_PRIORITY]
	if (*attrs & (1ULL << OVS_KEY_ATTR_PRIORITY)) {
		SW_FLOW_KEY_PUT(match, phy.priority,
			  nla_get_u32(a[OVS_KEY_ATTR_PRIORITY]), is_mask);
		*attrs &= ~(1ULL << OVS_KEY_ATTR_PRIORITY);
	}

    //match->key->phy.in_port = a[OVS_KEY_ATTR_IN_PORT]
    //match->mask->key.phy.in_port = a[OVS_KEY_ATTR_IN_PORT]
	if (*attrs & (1ULL << OVS_KEY_ATTR_IN_PORT)) {
		u32 in_port = nla_get_u32(a[OVS_KEY_ATTR_IN_PORT]);

		if (is_mask) {
			in_port = 0xffffffff; /* Always exact match in_port. */
		} else if (in_port >= DP_MAX_PORTS) {
			OVS_NLERR(log, "Port %d exceeds max allowable %d",
				  in_port, DP_MAX_PORTS);
			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, phy.in_port, in_port, is_mask);
		*attrs &= ~(1ULL << OVS_KEY_ATTR_IN_PORT);
	} else if (!is_mask) {
		SW_FLOW_KEY_PUT(match, phy.in_port, DP_MAX_PORTS, is_mask);
	}

    //match->key->phy.skb_mark = a[OVS_KEY_ATTR_SKB_MARK]
    //match->mask->key.phy.skb_mark = a[OVS_KEY_ATTR_SKB_MARK]
	if (*attrs & (1ULL << OVS_KEY_ATTR_SKB_MARK)) {
		uint32_t mark = nla_get_u32(a[OVS_KEY_ATTR_SKB_MARK]);

		SW_FLOW_KEY_PUT(match, phy.skb_mark, mark, is_mask);
		*attrs &= ~(1ULL << OVS_KEY_ATTR_SKB_MARK);
	}
    //a[OVS_KEY_ATTR_TUNNEL] 是内嵌的 nlattr
	if (*attrs & (1ULL << OVS_KEY_ATTR_TUNNEL)) {
		if (ipv4_tun_from_nlattr(a[OVS_KEY_ATTR_TUNNEL], match,
					 is_mask, log) < 0)
			return -EINVAL;
		*attrs &= ~(1ULL << OVS_KEY_ATTR_TUNNEL);
	}
	return 0;
}

/*
 * @match : 待赋值的 match
 * @attrs : 已经被解析的 type
 * @a     : 保持已经解析的 type 对应的 value
 * @is_mask : 赋值给 match->key 还是 match->mask->key
 * @log  : 是否记录日志
 *
 * 将 attrs 中对应的 type 从 a 中取出来赋值给 match
 *
 *  match->key->eth.src = a[OVS_KEY_ATTR_ETHERNET]->eth_src
 *  match->key->eth.dst = a[OVS_KEY_ATTR_ETHERNET]->eth_dst
 *  match->key->eth.tci = a[OVS_KEY_ATTR_VLAN]
 *  match->key->eth.type = htons(ETH_P_802_2)
 *
 *  //IPV4
 *  match->key->ip.proto = a[OVS_KEY_ATTR_IPV4]->ipv4_proto
 *  match->key->ip.tos = a[OVS_KEY_ATTR_IPV4]->ipv4_tos
 *  match->key->ip.ttl = a[OVS_KEY_ATTR_IPV4]->ipv4_ttl
 *  match->key->ip.frag = a[OVS_KEY_ATTR_IPV4]->ipv4_frag
 *  match->key->ip.addr.src = a[OVS_KEY_ATTR_IPV4]->ipv4_src
 *  match->key->ip.addr.dst = a[OVS_KEY_ATTR_IPV4]->ipv4_dst
 *
 *  //IPV6
 *  match->key->ipv6_key->ipv6_label = a[OVS_KEY_ATTR_IPV6]->ipv6_label
 *  match->key->ipv6_key->ip.proto = a[OVS_KEY_ATTR_IPV6]->ipv6_proto
 *  match->key->ip.tos   = a[OVS_KEY_ATTR_IPV6]->ipv6_tclass
 *  match->key->ip.ttl   = a[OVS_KEY_ATTR_IPV6]->ipv6_hlimit
 *  match->key->ip.frag  = a[OVS_KEY_ATTR_IPV6]->ipv6_frag
 *  match->key->ipv6_key->ipv6.addr.src = a[OVS_KEY_ATTR_IPV6]->ipv6_src
 *  match->key->ipv6_key->ipv6.addr.dst = a[OVS_KEY_ATTR_IPV6]->ipv6_dst
 *
 *  //ARP
 *  match->key->ipv4.addr.src = a[OVS_KEY_ATTR_ARP]->arp_sip
 *  match->key->ipv4.addr.dst = a[OVS_KEY_ATTR_ARP]->arp_tip
 *  match->key->ip.proto = a[OVS_KEY_ATTR_ARP]->arp_op
 *  match->key->ipv4.arp.sha = a[OVS_KEY_ATTR_ARP]->arp_sha
 *  match->key->ipv4.arp.tha = a[OVS_KEY_ATTR_ARP]->arp_tha
 *
 *  //TCP
 *  match->key->mpls.top_lse = a[OVS_KEY_ATTR_MPLS]->mpls_lse
 *  match->key->tp.src = a[OVS_KEY_ATTR_TCP]->tcp_src
 *  match->key->tp.dst = a[OVS_KEY_ATTR_TCP]->tcp_dst
 *  match->key->tp.flags = a[OVS_KEY_ATTR_TCP_FLAGS]
 *
 *  //UDP
 *  match->key->tp.src = a[OVS_KEY_ATTR_UDP]->udp_src
 *  match->key->tp.dst = a[OVS_KEY_ATTR_UDP]->udp_dst
 *
 *  //UDP
 *  match->key->tp.src = a[OVS_KEY_ATTR_SCTP]->sctp_src
 *  match->key->tp.dst = a[OVS_KEY_ATTR_SCTP]->sctp_dst
 *
 *  //ICMP
 *  match->key->tp.src = a[OVS_KEY_ATTR_ICMP]->icmp_src
 *  match->key->tp.dst = a[OVS_KEY_ATTR_ICMP]->icmp_dst
 *
 *  //ICMPV6
 *  match->key->tp.src = a[OVS_KEY_ATTR_ICMPV6]->icmpv6_type
 *  match->key->tp.dst = a[OVS_KEY_ATTR_ICMPV6]->icmpv6_code
 *
 *  //
 *  match->key->ipv6.nd.target = a[OVS_KEY_ATTR_ND]->nd_target
 *  match->key->ipv6.nd.ssl = a[OVS_KEY_ATTR_ND]->nd_sll
 *  match->key->ipv6.nd.tll = a[OVS_KEY_ATTR_ND]->nd_tll
 *
 *  match->mask->key.eth.src = a[OVS_KEY_ATTR_ETHERNET]->eth_src
 *  match->mask->key.eth.dst = a[OVS_KEY_ATTR_ETHERNET]->eth_dst
 *  match->mask->key.eth.tci = a[OVS_KEY_ATTR_VLAN]
 *  match->mask->key.eth.type = htons(0xffff)
 *  match->mask->key.ip.proto = a[OVS_KEY_ATTR_IPV4]->ipv4_proto
 *  match->mask->key.ip.tos = a[OVS_KEY_ATTR_IPV4]->ipv4_tos
 *  match->mask->key.ip.ttl = a[OVS_KEY_ATTR_IPV4]->ipv4_ttl
 *  match->mask->key.ip.frag = a[OVS_KEY_ATTR_IPV4]->ipv4_frag
 *  match->mask->key.ip.addr.src = a[OVS_KEY_ATTR_IPV4]->ipv4_src
 *  match->mask->key.ip.addr.dst = a[OVS_KEY_ATTR_IPV4]->ipv4_dst
 *  
 *
 *
 *
 *  match->key->ovs_flow_hash = a[OVS_KEY_ATTR_DP_HASH]
 *  match->key->ovs_flow_hash = a[OVS_KEY_ATTR_RECIRC_ID]
 *  match->key->phy.priority = a[OVS_KEY_ATTR_PRIORITY]
 *  match->key->phy.in_port = a[OVS_KEY_ATTR_IN_PORT]
 *  match->key->phy.skb_mark = a[OVS_KEY_ATTR_SKB_MARK]
 *  match->key->tun_key = ipv4_tun_from_nlattr()
 *
 *  match->mask->key.ovs_flow_hash = a[OVS_KEY_ATTR_DP_HASH]
 *  match->mask->key.recirc_id = a[OVS_KEY_ATTR_RECIRC_ID]
 *  match->mask->key.phy.priority = a[OVS_KEY_ATTR_PRIORITY]
 *  match->mask->key.phy.in_port = a[OVS_KEY_ATTR_IN_PORT]
 *  match->mask->key.phy.skb_mark = a[OVS_KEY_ATTR_SKB_MARK]
 *
 *  match->mask->tun_key = ipv4_tun_from_nlattr(a[OVS_KEY_ATTR_TUNNEL], match, is_mask, log)
 */
static int ovs_key_from_nlattrs(struct sw_flow_match *match, u64 attrs,
				const struct nlattr **a, bool is_mask,
				bool log)
{
	int err;

    //is_mask = true 解析 attrs 中的属性, 初始化 match->mask->key
    //is_mask = false 解析 attrs 中的属性, 初始化 match->key
	err = metadata_from_nlattrs(match, &attrs, a, is_mask, log);
	if (err)
		return err;

	if (attrs & (1ULL << OVS_KEY_ATTR_ETHERNET)) {
		const struct ovs_key_ethernet *eth_key;

		eth_key = nla_data(a[OVS_KEY_ATTR_ETHERNET]);
		SW_FLOW_KEY_MEMCPY(match, eth.src,
				eth_key->eth_src, ETH_ALEN, is_mask);
		SW_FLOW_KEY_MEMCPY(match, eth.dst,
				eth_key->eth_dst, ETH_ALEN, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_ETHERNET);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_VLAN)) {
		__be16 tci;

		tci = nla_get_be16(a[OVS_KEY_ATTR_VLAN]);
		if (!(tci & htons(VLAN_TAG_PRESENT))) {
			if (is_mask)
				OVS_NLERR(log, "VLAN TCI mask does not have exact match for VLAN_TAG_PRESENT bit.");
			else
				OVS_NLERR(log, "VLAN TCI does not have VLAN_TAG_PRESENT bit set.");

			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, eth.tci, tci, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_VLAN);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_ETHERTYPE)) {
		__be16 eth_type;

		eth_type = nla_get_be16(a[OVS_KEY_ATTR_ETHERTYPE]);
		if (is_mask) {
			/* Always exact match EtherType. */
			eth_type = htons(0xffff);
		} else if (!eth_proto_is_802_3(eth_type)) {
			OVS_NLERR(log, "EtherType %x is less than min %x",
				  ntohs(eth_type), ETH_P_802_3_MIN);
			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, eth.type, eth_type, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_ETHERTYPE);
	} else if (!is_mask) {
		SW_FLOW_KEY_PUT(match, eth.type, htons(ETH_P_802_2), is_mask);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_IPV4)) {
		const struct ovs_key_ipv4 *ipv4_key;

		ipv4_key = nla_data(a[OVS_KEY_ATTR_IPV4]);
		if (!is_mask && ipv4_key->ipv4_frag > OVS_FRAG_TYPE_MAX) {
			OVS_NLERR(log, "IPv4 frag type %d is out of range max %d",
				  ipv4_key->ipv4_frag, OVS_FRAG_TYPE_MAX);
			return -EINVAL;
		}
		SW_FLOW_KEY_PUT(match, ip.proto,
				ipv4_key->ipv4_proto, is_mask);
		SW_FLOW_KEY_PUT(match, ip.tos,
				ipv4_key->ipv4_tos, is_mask);
		SW_FLOW_KEY_PUT(match, ip.ttl,
				ipv4_key->ipv4_ttl, is_mask);
		SW_FLOW_KEY_PUT(match, ip.frag,
				ipv4_key->ipv4_frag, is_mask);
		SW_FLOW_KEY_PUT(match, ipv4.addr.src,
				ipv4_key->ipv4_src, is_mask);
		SW_FLOW_KEY_PUT(match, ipv4.addr.dst,
				ipv4_key->ipv4_dst, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_IPV4);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_IPV6)) {
		const struct ovs_key_ipv6 *ipv6_key;

		ipv6_key = nla_data(a[OVS_KEY_ATTR_IPV6]);
		if (!is_mask && ipv6_key->ipv6_frag > OVS_FRAG_TYPE_MAX) {
			OVS_NLERR(log, "IPv6 frag type %d is out of range max %d",
				  ipv6_key->ipv6_frag, OVS_FRAG_TYPE_MAX);
			return -EINVAL;
		}

		if (!is_mask && ipv6_key->ipv6_label & htonl(0xFFF00000)) {
			OVS_NLERR(log,
				  "Invalid IPv6 flow label value (value=%x, max=%x).",
				  ntohl(ipv6_key->ipv6_label), (1 << 20) - 1);
			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, ipv6.label,
				ipv6_key->ipv6_label, is_mask);
		SW_FLOW_KEY_PUT(match, ip.proto,
				ipv6_key->ipv6_proto, is_mask);
		SW_FLOW_KEY_PUT(match, ip.tos,
				ipv6_key->ipv6_tclass, is_mask);
		SW_FLOW_KEY_PUT(match, ip.ttl,
				ipv6_key->ipv6_hlimit, is_mask);
		SW_FLOW_KEY_PUT(match, ip.frag,
				ipv6_key->ipv6_frag, is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv6.addr.src,
				ipv6_key->ipv6_src,
				sizeof(match->key->ipv6.addr.src),
				is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv6.addr.dst,
				ipv6_key->ipv6_dst,
				sizeof(match->key->ipv6.addr.dst),
				is_mask);

		attrs &= ~(1ULL << OVS_KEY_ATTR_IPV6);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_ARP)) {
		const struct ovs_key_arp *arp_key;

		arp_key = nla_data(a[OVS_KEY_ATTR_ARP]);
		if (!is_mask && (arp_key->arp_op & htons(0xff00))) {
			OVS_NLERR(log, "Unknown ARP opcode (opcode=%d).",
				  arp_key->arp_op);
			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, ipv4.addr.src,
				arp_key->arp_sip, is_mask);
		SW_FLOW_KEY_PUT(match, ipv4.addr.dst,
			arp_key->arp_tip, is_mask);
		SW_FLOW_KEY_PUT(match, ip.proto,
				ntohs(arp_key->arp_op), is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv4.arp.sha,
				arp_key->arp_sha, ETH_ALEN, is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv4.arp.tha,
				arp_key->arp_tha, ETH_ALEN, is_mask);

		attrs &= ~(1ULL << OVS_KEY_ATTR_ARP);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_MPLS)) {
		const struct ovs_key_mpls *mpls_key;

		mpls_key = nla_data(a[OVS_KEY_ATTR_MPLS]);
		SW_FLOW_KEY_PUT(match, mpls.top_lse,
				mpls_key->mpls_lse, is_mask);

		attrs &= ~(1ULL << OVS_KEY_ATTR_MPLS);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_TCP)) {
		const struct ovs_key_tcp *tcp_key;

		tcp_key = nla_data(a[OVS_KEY_ATTR_TCP]);
		SW_FLOW_KEY_PUT(match, tp.src, tcp_key->tcp_src, is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst, tcp_key->tcp_dst, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_TCP);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_TCP_FLAGS)) {
		SW_FLOW_KEY_PUT(match, tp.flags,
				nla_get_be16(a[OVS_KEY_ATTR_TCP_FLAGS]),
				is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_TCP_FLAGS);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_UDP)) {
		const struct ovs_key_udp *udp_key;

		udp_key = nla_data(a[OVS_KEY_ATTR_UDP]);
		SW_FLOW_KEY_PUT(match, tp.src, udp_key->udp_src, is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst, udp_key->udp_dst, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_UDP);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_SCTP)) {
		const struct ovs_key_sctp *sctp_key;

		sctp_key = nla_data(a[OVS_KEY_ATTR_SCTP]);
		SW_FLOW_KEY_PUT(match, tp.src, sctp_key->sctp_src, is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst, sctp_key->sctp_dst, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_SCTP);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_ICMP)) {
		const struct ovs_key_icmp *icmp_key;

		icmp_key = nla_data(a[OVS_KEY_ATTR_ICMP]);
		SW_FLOW_KEY_PUT(match, tp.src,
				htons(icmp_key->icmp_type), is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst,
				htons(icmp_key->icmp_code), is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_ICMP);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_ICMPV6)) {
		const struct ovs_key_icmpv6 *icmpv6_key;

		icmpv6_key = nla_data(a[OVS_KEY_ATTR_ICMPV6]);
		SW_FLOW_KEY_PUT(match, tp.src,
				htons(icmpv6_key->icmpv6_type), is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst,
				htons(icmpv6_key->icmpv6_code), is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_ICMPV6);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_ND)) {
		const struct ovs_key_nd *nd_key;

		nd_key = nla_data(a[OVS_KEY_ATTR_ND]);
		SW_FLOW_KEY_MEMCPY(match, ipv6.nd.target,
			nd_key->nd_target,
			sizeof(match->key->ipv6.nd.target),
			is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv6.nd.sll,
			nd_key->nd_sll, ETH_ALEN, is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv6.nd.tll,
				nd_key->nd_tll, ETH_ALEN, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_ND);
	}

	if (attrs != 0) {
		OVS_NLERR(log, "Unknown key attributes %llx",
			  (unsigned long long)attrs);
		return -EINVAL;
	}

	return 0;
}

static void nlattr_set(struct nlattr *attr, u8 val,
		       const struct ovs_len_tbl *tbl)
{
	struct nlattr *nla;
	int rem;

	/* The nlattr stream should already have been validated */
	nla_for_each_nested(nla, attr, rem) {
		if (tbl && tbl[nla_type(nla)].len == OVS_ATTR_NESTED)
			nlattr_set(nla, val, tbl[nla_type(nla)].next);
		else
			memset(nla_data(nla), val, nla_len(nla));
	}
}

static void mask_set_nlattr(struct nlattr *attr, u8 val)
{
	nlattr_set(attr, val, ovs_key_lens);
}

/**
 * ovs_nla_get_match - parses Netlink attributes into a flow key and
 * mask. In case the 'mask' is NULL, the flow is treated as exact match
 * flow. Otherwise, it is treated as a wildcarded flow, except the mask
 * does not include any don't care bit.
 * @match: receives the extracted flow match information.
 * @key: Netlink attribute holding nested %OVS_KEY_ATTR_* Netlink attribute
 * sequence. The fields should of the packet that triggered the creation
 * of this flow.
 * @mask: Optional. Netlink attribute holding nested %OVS_KEY_ATTR_* Netlink
 * attribute specifies the mask field of the wildcarded flow.
 * @log: Boolean to allow kernel error logging.  Normally true, but when
 * probing for feature compatibility this should be passed in as false to
 * suppress unnecessary error logging.
 */
 /*
  * 1. 解析 a[OVS_FLOW_ATTR_KEY] 保存在中间变量 tmp_key 中, 变量 key_attrs 标记已经解析的 ovs_key_attr
  * 2. 将 key_attrs 中对应的 ovs_key_attr 从 tmp_key 中取出来赋值给 match->key
  * 3. 解析 a[OVS_FLOW_ATTR_MASK] 保存在中间变量 tmp_mask 中, 变量 mask_attrs 标记已经解析的 ovs_key_attr
  * 4. 将 mask_attrs 中对应的 ovs_key_attr 从 tmp_mask 中取出来赋值给 match->mask->key
  * 5. 对 match 进行有效性检查
  */
int ovs_nla_get_match(struct sw_flow_match *match,
		      const struct nlattr *nla_key,
		      const struct nlattr *nla_mask,
		      bool log)
{
	const struct nlattr *a[OVS_KEY_ATTR_MAX + 1];
	const struct nlattr *encap;
	struct nlattr *newmask = NULL;
	u64 key_attrs = 0;
	u64 mask_attrs = 0;
	bool encap_valid = false;
	int err;

    /*
    * 解析 nal_key 保持在 a 中, key_attrs 保持已经解析的 type
    */
	err = parse_flow_nlattrs(nla_key, a, &key_attrs, log);
	if (err)
		return err;

    //如果解析后的 a 中 eth_src, eth_dst, eth_type = 8021.Q, 即包含 vlan
	if ((key_attrs & (1ULL << OVS_KEY_ATTR_ETHERNET)) &&
	    (key_attrs & (1ULL << OVS_KEY_ATTR_ETHERTYPE)) &&
	    (nla_get_be16(a[OVS_KEY_ATTR_ETHERTYPE]) == htons(ETH_P_8021Q))) {
		__be16 tci;

        //VLAN 和 ENCAP 必须包含
		if (!((key_attrs & (1ULL << OVS_KEY_ATTR_VLAN)) &&
		      (key_attrs & (1ULL << OVS_KEY_ATTR_ENCAP)))) {
			OVS_NLERR(log, "Invalid Vlan frame.");
			return -EINVAL;
		}

		key_attrs &= ~(1ULL << OVS_KEY_ATTR_ETHERTYPE);
		tci = nla_get_be16(a[OVS_KEY_ATTR_VLAN]);
		encap = a[OVS_KEY_ATTR_ENCAP];
		key_attrs &= ~(1ULL << OVS_KEY_ATTR_ENCAP);
		encap_valid = true;

        // tci = 0x0010
		if (tci & htons(VLAN_TAG_PRESENT)) {
            // 解析 encp 到 a
			err = parse_flow_nlattrs(encap, a, &key_attrs, log);
			if (err)
				return err;
		} else if (!tci) {
            //tci = xx0x, x 至少一个为非 0
			/* Corner case for truncated 802.1Q header. */
			if (nla_len(encap)) {
				OVS_NLERR(log, "Truncated 802.1Q header has non-zero encap attribute.");
				return -EINVAL;
			}
		} else {
            //tci = 0000;
			OVS_NLERR(log, "Encap attr is set for non-VLAN frame");
			return  -EINVAL;
		}
	}

    //将 key_attrs 中对应的 ovs_key_attr 从 a 中取出来赋值给 match->key
	err = ovs_key_from_nlattrs(match, key_attrs, a, false, log);
	if (err)
		return err;

	if (match->mask) {
		if (!nla_mask) {
			/* Create an exact match mask. We need to set to 0xff
			 * all the 'match->mask' fields that have been touched
			 * in 'match->key'. We cannot simply memset
			 * 'match->mask', because padding bytes and fields not
			 * specified in 'match->key' should be left to 0.
			 * Instead, we use a stream of netlink attributes,
			 * copied from 'key' and set to 0xff.
			 * ovs_key_from_nlattrs() will take care of filling
			 * 'match->mask' appropriately.
			 */
			newmask = kmemdup(nla_key,
					  nla_total_size(nla_len(nla_key)),
					  GFP_KERNEL);
			if (!newmask)
				return -ENOMEM;

			mask_set_nlattr(newmask, 0xff);

			/* The userspace does not send tunnel attributes that
			 * are 0, but we should not wildcard them nonetheless.
			 */
			if (match->key->tun_key.ipv4_dst)
				SW_FLOW_KEY_MEMSET_FIELD(match, tun_key,
							 0xff, true);

			nla_mask = newmask;
		}

        //解析 nla_mask 写入 a, ovs_key_attr 保持在 mask_attrs
		err = parse_flow_mask_nlattrs(nla_mask, a, &mask_attrs, log);
		if (err)
			goto free_newmask;

		/* Always match on tci. */
        //match->mask->key.eth.tci = 0xffff;
		SW_FLOW_KEY_PUT(match, eth.tci, htons(0xffff), true);

		if (mask_attrs & 1ULL << OVS_KEY_ATTR_ENCAP) {
			__be16 eth_type = 0;
			__be16 tci = 0;

			if (!encap_valid) {
				OVS_NLERR(log, "Encap mask attribute is set for non-VLAN frame.");
				err = -EINVAL;
				goto free_newmask;
			}

			mask_attrs &= ~(1ULL << OVS_KEY_ATTR_ENCAP);
			if (a[OVS_KEY_ATTR_ETHERTYPE])
				eth_type = nla_get_be16(a[OVS_KEY_ATTR_ETHERTYPE]);

			if (eth_type == htons(0xffff)) {
				mask_attrs &= ~(1ULL << OVS_KEY_ATTR_ETHERTYPE);
				encap = a[OVS_KEY_ATTR_ENCAP];
				err = parse_flow_mask_nlattrs(encap, a,
							      &mask_attrs, log);
				if (err)
					goto free_newmask;
			} else {
				OVS_NLERR(log, "VLAN frames must have an exact match on the TPID (mask=%x).",
					  ntohs(eth_type));
				err = -EINVAL;
				goto free_newmask;
			}

			if (a[OVS_KEY_ATTR_VLAN])
				tci = nla_get_be16(a[OVS_KEY_ATTR_VLAN]);

			if (!(tci & htons(VLAN_TAG_PRESENT))) {
				OVS_NLERR(log, "VLAN tag present bit must have an exact match (tci_mask=%x).",
					  ntohs(tci));
				err = -EINVAL;
				goto free_newmask;
			}
		}

        //将 mask_attrs 中对应的 ovs_key_attr  从 a 中取出来赋值给 match
		err = ovs_key_from_nlattrs(match, mask_attrs, a, true, log);
		if (err)
			goto free_newmask;
	}

    //对 match 进行有效性检查
	if (!match_validate(match, key_attrs, mask_attrs, log))
		err = -EINVAL;

free_newmask:
	kfree(newmask);
	return err;
}

static size_t get_ufid_len(const struct nlattr *attr, bool log)
{
	size_t len;

	if (!attr)
		return 0;

	len = nla_len(attr);
	if (len < 1 || len > MAX_UFID_LENGTH) {
		OVS_NLERR(log, "ufid size %u bytes exceeds the range (1, %d)",
			  nla_len(attr), MAX_UFID_LENGTH);
		return 0;
	}

	return len;
}

/* Initializes 'flow->ufid', returning true if 'attr' contains a valid UFID,
 * or false otherwise.
 */
/*
 * 用 attr 初始化 sfid,　并返回 sfid_len
 *
 * sfid->ufid_len = nla_len(ufid)
 * sfid->ufid = nla_data(ufid)
 */
bool ovs_nla_get_ufid(struct sw_flow_id *sfid, const struct nlattr *attr,
		      bool log)
{
	sfid->ufid_len = get_ufid_len(attr, log);
	if (sfid->ufid_len)
		memcpy(sfid->ufid, nla_data(attr), sfid->ufid_len);

	return sfid->ufid_len;
}

//计算 flow key 的 id 即 sfid
//如果 a[OVS_FLOW_ATTR_UFID] = NULL, new_flow->unmasked_key = key
//否则
//      new_flow->id->ufid_len = nla_len(a[OVS_FLOW_ATTR_UFID])
//      new_flow->id->ufid = nla_data([OVS_FLOW_ATTR_UFID])
int ovs_nla_get_identifier(struct sw_flow_id *sfid, const struct nlattr *ufid,
			   const struct sw_flow_key *key, bool log)
{
	struct sw_flow_key *new_key;

    /*
     * sfid->ufid_len = nla_len(ufid)
     * sfid->ufid = nla_data(ufid)
     */
	if (ovs_nla_get_ufid(sfid, ufid, log))
		return 0;

	/* If UFID was not provided, use unmasked key. */
	new_key = kmalloc(sizeof(*new_key), GFP_KERNEL);
	if (!new_key)
		return -ENOMEM;
	memcpy(new_key, key, sizeof(*key));
	sfid->unmasked_key = new_key;

	return 0;
}

u32 ovs_nla_get_ufid_flags(const struct nlattr *attr)
{
	return attr ? nla_get_u32(attr) : 0;
}

/**
 * ovs_nla_get_flow_metadata - parses Netlink attributes into a flow key.
 * @key: Receives extracted in_port, priority, tun_key and skb_mark.
 * @attr: Netlink attribute holding nested %OVS_KEY_ATTR_* Netlink attribute
 * sequence.
 * @log: Boolean to allow kernel error logging.  Normally true, but when
 * probing for feature compatibility this should be passed in as false to
 * suppress unnecessary error logging.
 *
 * This parses a series of Netlink attributes that form a flow key, which must
 * take the same form accepted by flow_from_nlattrs(), but only enough of it to
 * get the metadata, that is, the parts of the flow key that cannot be
 * extracted from the packet itself.
 */

/*
 *  1. 解析 attr 保持在 a 中
 *  2. key 初始化 match.key
 *  3. 用 a 根据 attrs 中指定的类型初始化 match
 */
int ovs_nla_get_flow_metadata(const struct nlattr *attr,
			      struct sw_flow_key *key,
			      bool log)
{
	const struct nlattr *a[OVS_KEY_ATTR_MAX + 1];
	struct sw_flow_match match;
	u64 attrs = 0;
	int err;

    //解析 attr 保持在 a 中
	err = parse_flow_nlattrs(attr, a, &attrs, log);
	if (err)
		return -EINVAL;

	memset(&match, 0, sizeof(match));
	match.key = key;

	memset(key, 0, OVS_SW_FLOW_KEY_METADATA_SIZE);
	key->phy.in_port = DP_MAX_PORTS;

    //用 a 根据 attrs 中指定的类型初始化 match
	return metadata_from_nlattrs(&match, &attrs, a, false, log);
}

static int __ovs_nla_put_key(const struct sw_flow_key *swkey,
			     const struct sw_flow_key *output, bool is_mask,
			     struct sk_buff *skb)
{
	struct ovs_key_ethernet *eth_key;
	struct nlattr *nla, *encap;

	if (nla_put_u32(skb, OVS_KEY_ATTR_RECIRC_ID, output->recirc_id))
		goto nla_put_failure;

	if (nla_put_u32(skb, OVS_KEY_ATTR_DP_HASH, output->ovs_flow_hash))
		goto nla_put_failure;

	if (nla_put_u32(skb, OVS_KEY_ATTR_PRIORITY, output->phy.priority))
		goto nla_put_failure;

	if ((swkey->tun_key.ipv4_dst || is_mask)) {
		const void *opts = NULL;

		if (output->tun_key.tun_flags & TUNNEL_OPTIONS_PRESENT)
			opts = TUN_METADATA_OPTS(output, swkey->tun_opts_len);

		if (ipv4_tun_to_nlattr(skb, &output->tun_key, opts,
				       swkey->tun_opts_len))
			goto nla_put_failure;
	}

	if (swkey->phy.in_port == DP_MAX_PORTS) {
		if (is_mask && (output->phy.in_port == 0xffff))
			if (nla_put_u32(skb, OVS_KEY_ATTR_IN_PORT, 0xffffffff))
				goto nla_put_failure;
	} else {
		u16 upper_u16;
		upper_u16 = !is_mask ? 0 : 0xffff;

		if (nla_put_u32(skb, OVS_KEY_ATTR_IN_PORT,
				(upper_u16 << 16) | output->phy.in_port))
			goto nla_put_failure;
	}

	if (nla_put_u32(skb, OVS_KEY_ATTR_SKB_MARK, output->phy.skb_mark))
		goto nla_put_failure;

	nla = nla_reserve(skb, OVS_KEY_ATTR_ETHERNET, sizeof(*eth_key));
	if (!nla)
		goto nla_put_failure;

	eth_key = nla_data(nla);
	ether_addr_copy(eth_key->eth_src, output->eth.src);
	ether_addr_copy(eth_key->eth_dst, output->eth.dst);

	if (swkey->eth.tci || swkey->eth.type == htons(ETH_P_8021Q)) {
		__be16 eth_type;
		eth_type = !is_mask ? htons(ETH_P_8021Q) : htons(0xffff);
		if (nla_put_be16(skb, OVS_KEY_ATTR_ETHERTYPE, eth_type) ||
		    nla_put_be16(skb, OVS_KEY_ATTR_VLAN, output->eth.tci))
			goto nla_put_failure;
		encap = nla_nest_start(skb, OVS_KEY_ATTR_ENCAP);
		if (!swkey->eth.tci)
			goto unencap;
	} else
		encap = NULL;

	if (swkey->eth.type == htons(ETH_P_802_2)) {
		/*
		 * Ethertype 802.2 is represented in the netlink with omitted
		 * OVS_KEY_ATTR_ETHERTYPE in the flow key attribute, and
		 * 0xffff in the mask attribute.  Ethertype can also
		 * be wildcarded.
		 */
		if (is_mask && output->eth.type)
			if (nla_put_be16(skb, OVS_KEY_ATTR_ETHERTYPE,
						output->eth.type))
				goto nla_put_failure;
		goto unencap;
	}

	if (nla_put_be16(skb, OVS_KEY_ATTR_ETHERTYPE, output->eth.type))
		goto nla_put_failure;

	if (swkey->eth.type == htons(ETH_P_IP)) {
		struct ovs_key_ipv4 *ipv4_key;

		nla = nla_reserve(skb, OVS_KEY_ATTR_IPV4, sizeof(*ipv4_key));
		if (!nla)
			goto nla_put_failure;
		ipv4_key = nla_data(nla);
		ipv4_key->ipv4_src = output->ipv4.addr.src;
		ipv4_key->ipv4_dst = output->ipv4.addr.dst;
		ipv4_key->ipv4_proto = output->ip.proto;
		ipv4_key->ipv4_tos = output->ip.tos;
		ipv4_key->ipv4_ttl = output->ip.ttl;
		ipv4_key->ipv4_frag = output->ip.frag;
	} else if (swkey->eth.type == htons(ETH_P_IPV6)) {
		struct ovs_key_ipv6 *ipv6_key;

		nla = nla_reserve(skb, OVS_KEY_ATTR_IPV6, sizeof(*ipv6_key));
		if (!nla)
			goto nla_put_failure;
		ipv6_key = nla_data(nla);
		memcpy(ipv6_key->ipv6_src, &output->ipv6.addr.src,
				sizeof(ipv6_key->ipv6_src));
		memcpy(ipv6_key->ipv6_dst, &output->ipv6.addr.dst,
				sizeof(ipv6_key->ipv6_dst));
		ipv6_key->ipv6_label = output->ipv6.label;
		ipv6_key->ipv6_proto = output->ip.proto;
		ipv6_key->ipv6_tclass = output->ip.tos;
		ipv6_key->ipv6_hlimit = output->ip.ttl;
		ipv6_key->ipv6_frag = output->ip.frag;
	} else if (swkey->eth.type == htons(ETH_P_ARP) ||
		   swkey->eth.type == htons(ETH_P_RARP)) {
		struct ovs_key_arp *arp_key;

		nla = nla_reserve(skb, OVS_KEY_ATTR_ARP, sizeof(*arp_key));
		if (!nla)
			goto nla_put_failure;
		arp_key = nla_data(nla);
		memset(arp_key, 0, sizeof(struct ovs_key_arp));
		arp_key->arp_sip = output->ipv4.addr.src;
		arp_key->arp_tip = output->ipv4.addr.dst;
		arp_key->arp_op = htons(output->ip.proto);
		ether_addr_copy(arp_key->arp_sha, output->ipv4.arp.sha);
		ether_addr_copy(arp_key->arp_tha, output->ipv4.arp.tha);
	} else if (eth_p_mpls(swkey->eth.type)) {
		struct ovs_key_mpls *mpls_key;

		nla = nla_reserve(skb, OVS_KEY_ATTR_MPLS, sizeof(*mpls_key));
		if (!nla)
			goto nla_put_failure;
		mpls_key = nla_data(nla);
		mpls_key->mpls_lse = output->mpls.top_lse;
	}

	if ((swkey->eth.type == htons(ETH_P_IP) ||
	     swkey->eth.type == htons(ETH_P_IPV6)) &&
	     swkey->ip.frag != OVS_FRAG_TYPE_LATER) {

		if (swkey->ip.proto == IPPROTO_TCP) {
			struct ovs_key_tcp *tcp_key;

			nla = nla_reserve(skb, OVS_KEY_ATTR_TCP, sizeof(*tcp_key));
			if (!nla)
				goto nla_put_failure;
			tcp_key = nla_data(nla);
			tcp_key->tcp_src = output->tp.src;
			tcp_key->tcp_dst = output->tp.dst;
			if (nla_put_be16(skb, OVS_KEY_ATTR_TCP_FLAGS,
					 output->tp.flags))
				goto nla_put_failure;
		} else if (swkey->ip.proto == IPPROTO_UDP) {
			struct ovs_key_udp *udp_key;

			nla = nla_reserve(skb, OVS_KEY_ATTR_UDP, sizeof(*udp_key));
			if (!nla)
				goto nla_put_failure;
			udp_key = nla_data(nla);
			udp_key->udp_src = output->tp.src;
			udp_key->udp_dst = output->tp.dst;
		} else if (swkey->ip.proto == IPPROTO_SCTP) {
			struct ovs_key_sctp *sctp_key;

			nla = nla_reserve(skb, OVS_KEY_ATTR_SCTP, sizeof(*sctp_key));
			if (!nla)
				goto nla_put_failure;
			sctp_key = nla_data(nla);
			sctp_key->sctp_src = output->tp.src;
			sctp_key->sctp_dst = output->tp.dst;
		} else if (swkey->eth.type == htons(ETH_P_IP) &&
			   swkey->ip.proto == IPPROTO_ICMP) {
			struct ovs_key_icmp *icmp_key;

			nla = nla_reserve(skb, OVS_KEY_ATTR_ICMP, sizeof(*icmp_key));
			if (!nla)
				goto nla_put_failure;
			icmp_key = nla_data(nla);
			icmp_key->icmp_type = ntohs(output->tp.src);
			icmp_key->icmp_code = ntohs(output->tp.dst);
		} else if (swkey->eth.type == htons(ETH_P_IPV6) &&
			   swkey->ip.proto == IPPROTO_ICMPV6) {
			struct ovs_key_icmpv6 *icmpv6_key;

			nla = nla_reserve(skb, OVS_KEY_ATTR_ICMPV6,
						sizeof(*icmpv6_key));
			if (!nla)
				goto nla_put_failure;
			icmpv6_key = nla_data(nla);
			icmpv6_key->icmpv6_type = ntohs(output->tp.src);
			icmpv6_key->icmpv6_code = ntohs(output->tp.dst);

			if (icmpv6_key->icmpv6_type == NDISC_NEIGHBOUR_SOLICITATION ||
			    icmpv6_key->icmpv6_type == NDISC_NEIGHBOUR_ADVERTISEMENT) {
				struct ovs_key_nd *nd_key;

				nla = nla_reserve(skb, OVS_KEY_ATTR_ND, sizeof(*nd_key));
				if (!nla)
					goto nla_put_failure;
				nd_key = nla_data(nla);
				memcpy(nd_key->nd_target, &output->ipv6.nd.target,
							sizeof(nd_key->nd_target));
				ether_addr_copy(nd_key->nd_sll, output->ipv6.nd.sll);
				ether_addr_copy(nd_key->nd_tll, output->ipv6.nd.tll);
			}
		}
	}

unencap:
	if (encap)
		nla_nest_end(skb, encap);

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

int ovs_nla_put_key(const struct sw_flow_key *swkey,
		    const struct sw_flow_key *output, int attr, bool is_mask,
		    struct sk_buff *skb)
{
	int err;
	struct nlattr *nla;

	nla = nla_nest_start(skb, attr);
	if (!nla)
		return -EMSGSIZE;
	err = __ovs_nla_put_key(swkey, output, is_mask, skb);
	if (err)
		return err;
	nla_nest_end(skb, nla);

	return 0;
}

/* Called with ovs_mutex or RCU read lock. */
int ovs_nla_put_identifier(const struct sw_flow *flow, struct sk_buff *skb)
{
	if (ovs_identifier_is_ufid(&flow->id))
		return nla_put(skb, OVS_FLOW_ATTR_UFID, flow->id.ufid_len,
			       flow->id.ufid);

	return ovs_nla_put_key(flow->id.unmasked_key, flow->id.unmasked_key,
			       OVS_FLOW_ATTR_KEY, false, skb);
}

/* Called with ovs_mutex or RCU read lock. */
int ovs_nla_put_masked_key(const struct sw_flow *flow, struct sk_buff *skb)
{
	return ovs_nla_put_key(&flow->key, &flow->key,
				OVS_FLOW_ATTR_KEY, false, skb);
}

/* Called with ovs_mutex or RCU read lock. */
int ovs_nla_put_mask(const struct sw_flow *flow, struct sk_buff *skb)
{
	return ovs_nla_put_key(&flow->key, &flow->mask->key,
				OVS_FLOW_ATTR_MASK, true, skb);
}

#define MAX_ACTIONS_BUFSIZE	(32 * 1024)

//分配 sw_flow_actions 空间
static struct sw_flow_actions *nla_alloc_flow_actions(int size, bool log)
{
	struct sw_flow_actions *sfa;

	if (size > MAX_ACTIONS_BUFSIZE) {
		OVS_NLERR(log, "Flow action size %u bytes exceeds max", size);
		return ERR_PTR(-EINVAL);
	}

	sfa = kmalloc(sizeof(*sfa) + size, GFP_KERNEL);
	if (!sfa)
		return ERR_PTR(-ENOMEM);

	sfa->actions_len = 0;
	return sfa;
}

/* RCU callback used by ovs_nla_free_flow_actions. */
static void rcu_free_acts_callback(struct rcu_head *rcu)
{
	struct sw_flow_actions *sf_acts = container_of(rcu,
			struct sw_flow_actions, rcu);
	kfree(sf_acts);
}

/* Schedules 'sf_acts' to be freed after the next RCU grace period.
 * The caller must hold rcu_read_lock for this to be sensible.
 */
void ovs_nla_free_flow_actions(struct sw_flow_actions *sf_acts)
{
	call_rcu(&sf_acts->rcu, rcu_free_acts_callback);
}

/*
 * 为 sfa 扩展 attr_len 长度的空间, 返回扩展空间的首地址
 *
 * 在 sfs 现有长度基础上增加 attr_len 长度:
 * 如果空间不够, 就将原来空间扩大 2 倍, 如果扩大 2 被超出了 action 的阈值, 检查 action 的阈值长度
 * 是否能满足要求
 * 如果空间足够返回 sfs 扩展首地址
 */
static struct nlattr *reserve_sfa_size(struct sw_flow_actions **sfa,
				       int attr_len, bool log)
{

	struct sw_flow_actions *acts;
	int new_acts_size;
	int req_size = NLA_ALIGN(attr_len);
	int next_offset = offsetof(struct sw_flow_actions, actions) +
					(*sfa)->actions_len;

	if (req_size <= (ksize(*sfa) - next_offset))
		goto out;

	new_acts_size = ksize(*sfa) * 2;

    //新增加的长度大于 action 的阈值
	if (new_acts_size > MAX_ACTIONS_BUFSIZE) {
		if ((MAX_ACTIONS_BUFSIZE - next_offset) < req_size)
			return ERR_PTR(-EMSGSIZE);
		new_acts_size = MAX_ACTIONS_BUFSIZE;
	}

	acts = nla_alloc_flow_actions(new_acts_size, log);
	if (IS_ERR(acts))
		return (void *)acts;

	memcpy(acts->actions, (*sfa)->actions, (*sfa)->actions_len);
	acts->actions_len = (*sfa)->actions_len;
	kfree(*sfa);
	*sfa = acts;

out:
	(*sfa)->actions_len += req_size;
	return  (struct nlattr *) ((unsigned char *)(*sfa) + next_offset);
}

static struct nlattr *__add_action(struct sw_flow_actions **sfa,
				   int attrtype, void *data, int len, bool log)
{
	struct nlattr *a;

	a = reserve_sfa_size(sfa, nla_attr_size(len), log);
	if (IS_ERR(a))
		return a;

	a->nla_type = attrtype;
	a->nla_len = nla_attr_size(len);

	if (data)
		memcpy(nla_data(a), data, len);
	memset((unsigned char *) a + a->nla_len, 0, nla_padlen(len));

	return a;
}

static int add_action(struct sw_flow_actions **sfa, int attrtype,
		      void *data, int len, bool log)
{
	struct nlattr *a;

	a = __add_action(sfa, attrtype, data, len, log);
	if (IS_ERR(a))
		return PTR_ERR(a);

	return 0;
}

static inline int add_nested_action_start(struct sw_flow_actions **sfa,
					  int attrtype, bool log)
{
	int used = (*sfa)->actions_len;
	int err;

	err = add_action(sfa, attrtype, NULL, 0, log);
	if (err)
		return err;

	return used;
}

static inline void add_nested_action_end(struct sw_flow_actions *sfa,
					 int st_offset)
{
	struct nlattr *a = (struct nlattr *) ((unsigned char *)sfa->actions +
							       st_offset);

	a->nla_len = sfa->actions_len - st_offset;
}

static int __ovs_nla_copy_actions(const struct nlattr *attr,
				  const struct sw_flow_key *key,
				  int depth, struct sw_flow_actions **sfa,
				  __be16 eth_type, __be16 vlan_tci, bool log);

//TODO
static int validate_and_copy_sample(const struct nlattr *attr,
				    const struct sw_flow_key *key, int depth,
				    struct sw_flow_actions **sfa,
				    __be16 eth_type, __be16 vlan_tci, bool log)
{
	const struct nlattr *attrs[OVS_SAMPLE_ATTR_MAX + 1];
	const struct nlattr *probability, *actions;
	const struct nlattr *a;
	int rem, start, err, st_acts;

	memset(attrs, 0, sizeof(attrs));
	nla_for_each_nested(a, attr, rem) {
		int type = nla_type(a);
		if (!type || type > OVS_SAMPLE_ATTR_MAX || attrs[type])
			return -EINVAL;
		attrs[type] = a;
	}
	if (rem)
		return -EINVAL;

	probability = attrs[OVS_SAMPLE_ATTR_PROBABILITY];
	if (!probability || nla_len(probability) != sizeof(u32))
		return -EINVAL;

	actions = attrs[OVS_SAMPLE_ATTR_ACTIONS];
	if (!actions || (nla_len(actions) && nla_len(actions) < NLA_HDRLEN))
		return -EINVAL;

	/* validation done, copy sample action. */
	start = add_nested_action_start(sfa, OVS_ACTION_ATTR_SAMPLE, log);
	if (start < 0)
		return start;
	err = add_action(sfa, OVS_SAMPLE_ATTR_PROBABILITY,
			 nla_data(probability), sizeof(u32), log);
	if (err)
		return err;
	st_acts = add_nested_action_start(sfa, OVS_SAMPLE_ATTR_ACTIONS, log);
	if (st_acts < 0)
		return st_acts;

	err = __ovs_nla_copy_actions(actions, key, depth + 1, sfa,
				     eth_type, vlan_tci, log);
	if (err)
		return err;

	add_nested_action_end(*sfa, st_acts);
	add_nested_action_end(*sfa, start);

	return 0;
}

void ovs_match_init(struct sw_flow_match *match,
		    struct sw_flow_key *key,
		    struct sw_flow_mask *mask)
{
	memset(match, 0, sizeof(*match));
	match->key = key;
	match->mask = mask;

	memset(key, 0, sizeof(*key));

	if (mask) {
		memset(&mask->key, 0, sizeof(mask->key));
		mask->range.start = mask->range.end = 0;
	}
}

static int validate_geneve_opts(struct sw_flow_key *key)
{
	struct geneve_opt *option;
	int opts_len = key->tun_opts_len;
	bool crit_opt = false;

	option = (struct geneve_opt *)TUN_METADATA_OPTS(key, key->tun_opts_len);
	while (opts_len > 0) {
		int len;

		if (opts_len < sizeof(*option))
			return -EINVAL;

		len = sizeof(*option) + option->length * 4;
		if (len > opts_len)
			return -EINVAL;

		crit_opt |= !!(option->type & GENEVE_CRIT_OPT_TYPE);

		option = (struct geneve_opt *)((u8 *)option + len);
		opts_len -= len;
	};

	key->tun_key.tun_flags |= crit_opt ? TUNNEL_CRIT_OPT : 0;

	return 0;
}

static int validate_and_copy_set_tun(const struct nlattr *attr,
				     struct sw_flow_actions **sfa, bool log)
{
	struct sw_flow_match match;
	struct sw_flow_key key;
	struct ovs_tunnel_info *tun_info;
	struct nlattr *a;
	int start, opts_type;
	int err = 0;

	ovs_match_init(&match, &key, NULL);
	opts_type = ipv4_tun_from_nlattr(nla_data(attr), &match, false, log);
	if (opts_type < 0)
		return opts_type;

	if (key.tun_opts_len) {
		switch (opts_type) {
		case OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS:
			err = validate_geneve_opts(&key);
			if (err < 0)
				return err;
			break;
		case OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS:
			break;
		}
	};

	start = add_nested_action_start(sfa, OVS_ACTION_ATTR_SET, log);
	if (start < 0)
		return start;

	a = __add_action(sfa, OVS_KEY_ATTR_TUNNEL_INFO, NULL,
			 sizeof(*tun_info) + key.tun_opts_len, log);
	if (IS_ERR(a))
		return PTR_ERR(a);

	tun_info = nla_data(a);
	tun_info->tunnel = key.tun_key;
	tun_info->options_len = key.tun_opts_len;

	if (tun_info->options_len) {
		/* We need to store the options in the action itself since
		 * everything else will go away after flow setup. We can append
		 * it to tun_info and then point there.
		 */
		memcpy((tun_info + 1),
		       TUN_METADATA_OPTS(&key, key.tun_opts_len), key.tun_opts_len);
		tun_info->options = (tun_info + 1);
	} else {
		tun_info->options = NULL;
	}

	add_nested_action_end(*sfa, start);

	return err;
}

/* Return false if there are any non-masked bits set.
 * Mask follows data immediately, before any netlink padding.
 */
static bool validate_masked(u8 *data, int len)
{
	u8 *mask = data + len;

	while (len--)
		if (*data++ & ~*mask++)
			return false;

	return true;
}

//
static int validate_set(const struct nlattr *a,
			const struct sw_flow_key *flow_key,
			struct sw_flow_actions **sfa,
			bool *skip_copy, __be16 eth_type, bool masked, bool log)
{
	const struct nlattr *ovs_key = nla_data(a);
	int key_type = nla_type(ovs_key);
	size_t key_len;

	/* There can be only one key in a action */
	if (nla_total_size(nla_len(ovs_key)) != nla_len(a))
		return -EINVAL;

	key_len = nla_len(ovs_key);
	if (masked)
		key_len /= 2;

	if (key_type > OVS_KEY_ATTR_MAX ||
	    (ovs_key_lens[key_type].len != key_len &&
	     ovs_key_lens[key_type].len != OVS_ATTR_NESTED))
		return -EINVAL;

	if (masked && !validate_masked(nla_data(ovs_key), key_len))
		return -EINVAL;

	switch (key_type) {
	const struct ovs_key_ipv4 *ipv4_key;
	const struct ovs_key_ipv6 *ipv6_key;
	int err;

	case OVS_KEY_ATTR_PRIORITY:
	case OVS_KEY_ATTR_SKB_MARK:
	case OVS_KEY_ATTR_ETHERNET:
		break;

	case OVS_KEY_ATTR_TUNNEL:
		if (eth_p_mpls(eth_type))
			return -EINVAL;

		if (masked)
			return -EINVAL; /* Masked tunnel set not supported. */

		*skip_copy = true;
		err = validate_and_copy_set_tun(a, sfa, log);
		if (err)
			return err;
		break;

	case OVS_KEY_ATTR_IPV4:
		if (eth_type != htons(ETH_P_IP))
			return -EINVAL;

		ipv4_key = nla_data(ovs_key);

		if (masked) {
			const struct ovs_key_ipv4 *mask = ipv4_key + 1;

			/* Non-writeable fields. */
			if (mask->ipv4_proto || mask->ipv4_frag)
				return -EINVAL;
		} else {
			if (ipv4_key->ipv4_proto != flow_key->ip.proto)
				return -EINVAL;

			if (ipv4_key->ipv4_frag != flow_key->ip.frag)
				return -EINVAL;
		}
		break;

	case OVS_KEY_ATTR_IPV6:
		if (eth_type != htons(ETH_P_IPV6))
			return -EINVAL;

		ipv6_key = nla_data(ovs_key);

		if (masked) {
			const struct ovs_key_ipv6 *mask = ipv6_key + 1;

			/* Non-writeable fields. */
			if (mask->ipv6_proto || mask->ipv6_frag)
				return -EINVAL;

			/* Invalid bits in the flow label mask? */
			if (ntohl(mask->ipv6_label) & 0xFFF00000)
				return -EINVAL;
		} else {
			if (ipv6_key->ipv6_proto != flow_key->ip.proto)
				return -EINVAL;

			if (ipv6_key->ipv6_frag != flow_key->ip.frag)
				return -EINVAL;
		}
		if (ntohl(ipv6_key->ipv6_label) & 0xFFF00000)
			return -EINVAL;

		break;

	case OVS_KEY_ATTR_TCP:
		if ((eth_type != htons(ETH_P_IP) &&
		     eth_type != htons(ETH_P_IPV6)) ||
		    flow_key->ip.proto != IPPROTO_TCP)
			return -EINVAL;

		break;

	case OVS_KEY_ATTR_UDP:
		if ((eth_type != htons(ETH_P_IP) &&
		     eth_type != htons(ETH_P_IPV6)) ||
		    flow_key->ip.proto != IPPROTO_UDP)
			return -EINVAL;

		break;

	case OVS_KEY_ATTR_MPLS:
		if (!eth_p_mpls(eth_type))
			return -EINVAL;
		break;

	case OVS_KEY_ATTR_SCTP:
		if ((eth_type != htons(ETH_P_IP) &&
		     eth_type != htons(ETH_P_IPV6)) ||
		    flow_key->ip.proto != IPPROTO_SCTP)
			return -EINVAL;

		break;

	default:
		return -EINVAL;
	}

	/* Convert non-masked non-tunnel set actions to masked set actions. */
	if (!masked && key_type != OVS_KEY_ATTR_TUNNEL) {
		int start, len = key_len * 2;
		struct nlattr *at;

		*skip_copy = true;

		start = add_nested_action_start(sfa,
						OVS_ACTION_ATTR_SET_TO_MASKED,
						log);
		if (start < 0)
			return start;

		at = __add_action(sfa, key_type, NULL, len, log);
		if (IS_ERR(at))
			return PTR_ERR(at);

		memcpy(nla_data(at), nla_data(ovs_key), key_len); /* Key. */
		memset(nla_data(at) + key_len, 0xff, key_len);    /* Mask. */
		/* Clear non-writeable bits from otherwise writeable fields. */
		if (key_type == OVS_KEY_ATTR_IPV6) {
			struct ovs_key_ipv6 *mask = nla_data(at) + key_len;

			mask->ipv6_label &= htonl(0x000FFFFF);
		}
		add_nested_action_end(*sfa, start);
	}

	return 0;
}

//遍历 attr 所有元素, 加入 a, a[OVS_USERSPACE_ATTR_PID] 不能为 NULL 或 0
static int validate_userspace(const struct nlattr *attr)
{
	static const struct nla_policy userspace_policy[OVS_USERSPACE_ATTR_MAX + 1] = {
		[OVS_USERSPACE_ATTR_PID] = {.type = NLA_U32 },
		[OVS_USERSPACE_ATTR_USERDATA] = {.type = NLA_UNSPEC },
		[OVS_USERSPACE_ATTR_EGRESS_TUN_PORT] = {.type = NLA_U32 },
	};
	struct nlattr *a[OVS_USERSPACE_ATTR_MAX + 1];
	int error;

    //遍历 attr 所有元素, 加入 a
	error = nla_parse_nested(a, OVS_USERSPACE_ATTR_MAX,
				 attr, userspace_policy);
	if (error)
		return error;

	if (!a[OVS_USERSPACE_ATTR_PID] ||
	    !nla_get_u32(a[OVS_USERSPACE_ATTR_PID]))
		return -EINVAL;

	return 0;
}

//将 from 附加到 sfa 的尾部
static int copy_action(const struct nlattr *from,
		       struct sw_flow_actions **sfa, bool log)
{
	int totlen = NLA_ALIGN(from->nla_len);
	struct nlattr *to;

    //为 sfa 扩展 attr_len 长度的空间, 返回扩展空间的首地址
	to = reserve_sfa_size(sfa, from->nla_len, log);
	if (IS_ERR(to))
		return PTR_ERR(to);

	memcpy(to, from, totlen);
	return 0;
}

//遍历 attr 每个元素, 验证每个元素的有效性, 并初始化 eth_type, vlan_tci
static int __ovs_nla_copy_actions(const struct nlattr *attr,
				  const struct sw_flow_key *key,
				  int depth, struct sw_flow_actions **sfa,
				  __be16 eth_type, __be16 vlan_tci, bool log)
{
	const struct nlattr *a;
	int rem, err;

	if (depth >= SAMPLE_ACTION_DEPTH)
		return -EOVERFLOW;

	nla_for_each_nested(a, attr, rem) {
		/* Expected argument lengths, (u32)-1 for variable length. */
		static const u32 action_lens[OVS_ACTION_ATTR_MAX + 1] = {
			[OVS_ACTION_ATTR_OUTPUT] = sizeof(u32),
			[OVS_ACTION_ATTR_RECIRC] = sizeof(u32),
			[OVS_ACTION_ATTR_USERSPACE] = (u32)-1,
			[OVS_ACTION_ATTR_PUSH_MPLS] = sizeof(struct ovs_action_push_mpls),
			[OVS_ACTION_ATTR_POP_MPLS] = sizeof(__be16),
			[OVS_ACTION_ATTR_PUSH_VLAN] = sizeof(struct ovs_action_push_vlan),
			[OVS_ACTION_ATTR_POP_VLAN] = 0,
			[OVS_ACTION_ATTR_SET] = (u32)-1,
			[OVS_ACTION_ATTR_SET_MASKED] = (u32)-1,
			[OVS_ACTION_ATTR_SAMPLE] = (u32)-1,
			[OVS_ACTION_ATTR_HASH] = sizeof(struct ovs_action_hash)
		};
		const struct ovs_action_push_vlan *vlan;
		int type = nla_type(a);
		bool skip_copy;

		if (type > OVS_ACTION_ATTR_MAX ||
		    (action_lens[type] != nla_len(a) &&
		     action_lens[type] != (u32)-1))
			return -EINVAL;

		skip_copy = false;
		switch (type) {
		case OVS_ACTION_ATTR_UNSPEC:
			return -EINVAL;

		case OVS_ACTION_ATTR_USERSPACE:
            //遍历 a 所有元素, 确保 a[OVS_USERSPACE_ATTR_PID] 不能为 NULL 或 0
			err = validate_userspace(a);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_OUTPUT:
			if (nla_get_u32(a) >= DP_MAX_PORTS)
				return -EINVAL;
			break;

		case OVS_ACTION_ATTR_HASH: {
			const struct ovs_action_hash *act_hash = nla_data(a);

			switch (act_hash->hash_alg) {
			case OVS_HASH_ALG_L4:
				break;
			default:
				return  -EINVAL;
			}

			break;
		}

		case OVS_ACTION_ATTR_POP_VLAN:
			vlan_tci = htons(0);
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			vlan = nla_data(a);
			if (vlan->vlan_tpid != htons(ETH_P_8021Q))
				return -EINVAL;
			if (!(vlan->vlan_tci & htons(VLAN_TAG_PRESENT)))
				return -EINVAL;
			vlan_tci = vlan->vlan_tci;
			break;

		case OVS_ACTION_ATTR_RECIRC:
			break;

		case OVS_ACTION_ATTR_PUSH_MPLS: {
			const struct ovs_action_push_mpls *mpls = nla_data(a);

			if (!eth_p_mpls(mpls->mpls_ethertype))
				return -EINVAL;
			/* Prohibit push MPLS other than to a white list
			 * for packets that have a known tag order.
			 */
			if (vlan_tci & htons(VLAN_TAG_PRESENT) ||
			    (eth_type != htons(ETH_P_IP) &&
			     eth_type != htons(ETH_P_IPV6) &&
			     eth_type != htons(ETH_P_ARP) &&
			     eth_type != htons(ETH_P_RARP) &&
			     !eth_p_mpls(eth_type)))
				return -EINVAL;
			eth_type = mpls->mpls_ethertype;
			break;
		}

		case OVS_ACTION_ATTR_POP_MPLS:
			if (vlan_tci & htons(VLAN_TAG_PRESENT) ||
			    !eth_p_mpls(eth_type))
				return -EINVAL;

			/* Disallow subsequent L2.5+ set and mpls_pop actions
			 * as there is no check here to ensure that the new
			 * eth_type is valid and thus set actions could
			 * write off the end of the packet or otherwise
			 * corrupt it.
			 *
			 * Support for these actions is planned using packet
			 * recirculation.
			 */
			eth_type = htons(0);
			break;

		case OVS_ACTION_ATTR_SET:
            //
			err = validate_set(a, key, sfa,
					   &skip_copy, eth_type, false, log);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_SET_MASKED:
            //
			err = validate_set(a, key, sfa,
					   &skip_copy, eth_type, true, log);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			err = validate_and_copy_sample(a, key, depth, sfa,
						       eth_type, vlan_tci, log);
			if (err)
				return err;
			skip_copy = true;
			break;

		default:
			OVS_NLERR(log, "Unknown Action type %d", type);
			return -EINVAL;
		}
		if (!skip_copy) {
            //将 a 附加到 sfa 的尾部, 如果空间不够返回错误
			err = copy_action(a, sfa, log);
			if (err)
				return err;
		}
	}

	if (rem > 0)
		return -EINVAL;

	return 0;
}

/* 'key' must be the masked key. */
int ovs_nla_copy_actions(const struct nlattr *attr,
			 const struct sw_flow_key *key,
			 struct sw_flow_actions **sfa, bool log)
{
	int err;

	*sfa = nla_alloc_flow_actions(nla_len(attr), log);
	if (IS_ERR(*sfa))
		return PTR_ERR(*sfa);

    //
	err = __ovs_nla_copy_actions(attr, key, 0, sfa, key->eth.type,
				     key->eth.tci, log);
	if (err)
		kfree(*sfa);

	return err;
}

static int sample_action_to_attr(const struct nlattr *attr, struct sk_buff *skb)
{
	const struct nlattr *a;
	struct nlattr *start;
	int err = 0, rem;

	start = nla_nest_start(skb, OVS_ACTION_ATTR_SAMPLE);
	if (!start)
		return -EMSGSIZE;

	nla_for_each_nested(a, attr, rem) {
		int type = nla_type(a);
		struct nlattr *st_sample;

		switch (type) {
		case OVS_SAMPLE_ATTR_PROBABILITY:
			if (nla_put(skb, OVS_SAMPLE_ATTR_PROBABILITY,
				    sizeof(u32), nla_data(a)))
				return -EMSGSIZE;
			break;
		case OVS_SAMPLE_ATTR_ACTIONS:
			st_sample = nla_nest_start(skb, OVS_SAMPLE_ATTR_ACTIONS);
			if (!st_sample)
				return -EMSGSIZE;
			err = ovs_nla_put_actions(nla_data(a), nla_len(a), skb);
			if (err)
				return err;
			nla_nest_end(skb, st_sample);
			break;
		}
	}

	nla_nest_end(skb, start);
	return err;
}

static int set_action_to_attr(const struct nlattr *a, struct sk_buff *skb)
{
	const struct nlattr *ovs_key = nla_data(a);
	int key_type = nla_type(ovs_key);
	struct nlattr *start;
	int err;

	switch (key_type) {
	case OVS_KEY_ATTR_TUNNEL_INFO: {
		struct ovs_tunnel_info *tun_info = nla_data(ovs_key);

		start = nla_nest_start(skb, OVS_ACTION_ATTR_SET);
		if (!start)
			return -EMSGSIZE;

		err = ipv4_tun_to_nlattr(skb, &tun_info->tunnel,
					 tun_info->options_len ?
						tun_info->options : NULL,
					 tun_info->options_len);
		if (err)
			return err;
		nla_nest_end(skb, start);
		break;
	}
	default:
		if (nla_put(skb, OVS_ACTION_ATTR_SET, nla_len(a), ovs_key))
			return -EMSGSIZE;
		break;
	}

	return 0;
}

static int masked_set_action_to_set_action_attr(const struct nlattr *a,
						struct sk_buff *skb)
{
	const struct nlattr *ovs_key = nla_data(a);
	size_t key_len = nla_len(ovs_key) / 2;

	/* Revert the conversion we did from a non-masked set action to
	 * masked set action.
	 */
	if (nla_put(skb, OVS_ACTION_ATTR_SET, nla_len(a) - key_len, ovs_key))
		return -EMSGSIZE;

	return 0;
}

int ovs_nla_put_actions(const struct nlattr *attr, int len, struct sk_buff *skb)
{
	const struct nlattr *a;
	int rem, err;

	nla_for_each_attr(a, attr, len, rem) {
		int type = nla_type(a);

		switch (type) {
		case OVS_ACTION_ATTR_SET:
			err = set_action_to_attr(a, skb);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_SET_TO_MASKED:
			err = masked_set_action_to_set_action_attr(a, skb);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			err = sample_action_to_attr(a, skb);
			if (err)
				return err;
			break;
		default:
			if (nla_put(skb, type, nla_len(a), nla_data(a)))
				return -EMSGSIZE;
			break;
		}
	}

	return 0;
}
