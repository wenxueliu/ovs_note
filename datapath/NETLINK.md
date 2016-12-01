
nlmsg : netlink message 的简称

nla : netlink attribute 的简称

netlink 消息格式:

    +----------+- - -+----------------------+- - -+----------+- - -+- - - - - - - - - +- - -+-------- - +- - -+- - - - - - - - - +- - -+- - -+-------- - -
    | nlmsghdr | Pad |     Family Header    | Pad |  Header  | Pad |     Payload      | Pad |  Header   | Pad |     Payload      | Pad | Pad | nlmsghdr
    +----------+- - -+----------------------+- - -+----------+- - -+- - - - - - - - - +- - -+-------- - +- - -+- - - - - - - - - +- - -+- - -+-------- - -
    |   header       |                                      Payload                                                                    |
    |   header       |       Payload header       |                 Payload body                                                       |
    |   header       |       Payload header       |                                     Attributes                                     |
    |   header       |       Payload header       |              Attribute1                 |               Attribute2                 |


因此, 构造一个 netlink 消息, 就需要先增加 netlink 头, 之后 Family Header, 之后
Attributes。


/* ========================================================================
 *         Netlink Messages and Attributes Interface (As Seen On TV)
 * ------------------------------------------------------------------------
 *                          Messages Interface
 * ------------------------------------------------------------------------
 *
 * Message Format:
 *    <--- nlmsg_total_size(payload)  --->
 *    <-- nlmsg_msg_size(payload) ->
 *   +----------+- - -+-------------+- - -+-------- - -
 *   | nlmsghdr | Pad |   Payload   | Pad | nlmsghdr
 *   +----------+- - -+-------------+- - -+-------- - -
 *   nlmsg_data(nlh)---^                   ^
 *   nlmsg_next(nlh)-----------------------+
 *
 * Payload Format:
 *    <---------------------- nlmsg_len(nlh) --------------------->
 *    <------ hdrlen ------>       <- nlmsg_attrlen(nlh, hdrlen) ->
 *   +----------------------+- - -+--------------------------------+
 *   |     Family Header    | Pad |           Attributes           |
 *   +----------------------+- - -+--------------------------------+
 *   nlmsg_attrdata(nlh, hdrlen)---^
 *
 * Data Structures:
 *   struct nlmsghdr                    netlink message header
 *
 * Message Construction:
 *   nlmsg_new()                        create a new netlink message
 *   nlmsg_put()                        add a netlink message to an skb
 *   nlmsg_put_answer()                 callback based nlmsg_put()
 *   nlmsg_end()                        finalize netlink message
 *   nlmsg_get_pos()                    return current position in message
 *   nlmsg_trim()                       trim part of message
 *   nlmsg_cancel()                     cancel message construction
 *   nlmsg_free()                       free a netlink message
 *
 * Message Sending:
 *   nlmsg_multicast()                  multicast message to several groups
 *   nlmsg_unicast()                    unicast a message to a single socket
 *   nlmsg_notify()                     send notification message
 *
 * Message Length Calculations:
 *   nlmsg_msg_size(payload)            length of message w/o padding
 *   nlmsg_total_size(payload)          length of message w/ padding
 *   nlmsg_padlen(payload)              length of padding at tail
 *
 * Message Payload Access:
 *   nlmsg_data(nlh)                    head of message payload
 *   nlmsg_len(nlh)                     length of message payload
 *   nlmsg_attrdata(nlh, hdrlen)        head of attributes data
 *   nlmsg_attrlen(nlh, hdrlen)         length of attributes data
 *
 * Message Parsing:
 *   nlmsg_ok(nlh, remaining)           does nlh fit into remaining bytes?
 *   nlmsg_next(nlh, remaining)         get next netlink message
 *   nlmsg_parse()                      parse attributes of a message
 *   nlmsg_find_attr()                  find an attribute in a message
 *   nlmsg_for_each_msg()               loop over all messages
 *   nlmsg_validate()                   validate netlink message incl. attrs
 *   nlmsg_for_each_attr()              loop over all attributes
 *
 * Misc:
 *   nlmsg_report()                     report back to application?
 *
 * ------------------------------------------------------------------------
 *                          Attributes Interface
 * ------------------------------------------------------------------------
 *
 * Attribute Format:
 *    <------- nla_total_size(payload) ------->
 *    <---- nla_attr_size(payload) ----->
 *   +----------+- - -+- - - - - - - - - +- - -+-------- - -
 *   |  Header  | Pad |     Payload      | Pad |  Header
 *   +----------+- - -+- - - - - - - - - +- - -+-------- - -
 *                     <- nla_len(nla) ->      ^
 *   nla_data(nla)----^                        |
 *   nla_next(nla)-----------------------------'
 *
 *  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 * |        Header       | Pad |     Payload       | Pad |
 * |   (struct nlattr)   | ing |                   | ing |
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 *  <-------------- nlattr->nla_len -------------->
 *
 *
 * Data Structures:
 *   struct nlattr                      netlink attribute header
 *
 * Attribute Construction:
 *   nla_reserve(skb, type, len)        reserve room for an attribute
 *   nla_reserve_nohdr(skb, len)        reserve room for an attribute w/o hdr
 *   nla_put(skb, type, len, data)      add attribute to skb
 *   nla_put_nohdr(skb, len, data)      add attribute w/o hdr
 *   nla_append(skb, len, data)         append data to skb
 *
 * Attribute Construction for Basic Types:
 *   nla_put_u8(skb, type, value)       add u8 attribute to skb
 *   nla_put_u16(skb, type, value)      add u16 attribute to skb
 *   nla_put_u32(skb, type, value)      add u32 attribute to skb
 *   nla_put_u64(skb, type, value)      add u64 attribute to skb
 *   nla_put_s8(skb, type, value)       add s8 attribute to skb
 *   nla_put_s16(skb, type, value)      add s16 attribute to skb
 *   nla_put_s32(skb, type, value)      add s32 attribute to skb
 *   nla_put_s64(skb, type, value)      add s64 attribute to skb
 *   nla_put_string(skb, type, str)     add string attribute to skb
 *   nla_put_flag(skb, type)            add flag attribute to skb
 *   nla_put_msecs(skb, type, jiffies)  add msecs attribute to skb
 *
 * Nested Attributes Construction:
 *   nla_nest_start(skb, type)          start a nested attribute
 *   nla_nest_end(skb, nla)             finalize a nested attribute
 *   nla_nest_cancel(skb, nla)          cancel nested attribute construction
 *
 * Attribute Length Calculations:
 *   nla_attr_size(payload)             length of attribute w/o padding
 *   nla_total_size(payload)            length of attribute w/ padding
 *   nla_padlen(payload)                length of padding
 *
 * Attribute Payload Access:
 *   nla_data(nla)                      head of attribute payload
 *   nla_len(nla)                       length of attribute payload
 *
 * Attribute Payload Access for Basic Types:
 *   nla_get_u8(nla)                    get payload for a u8 attribute
 *   nla_get_u16(nla)                   get payload for a u16 attribute
 *   nla_get_u32(nla)                   get payload for a u32 attribute
 *   nla_get_u64(nla)                   get payload for a u64 attribute
 *   nla_get_s8(nla)                    get payload for a s8 attribute
 *   nla_get_s16(nla)                   get payload for a s16 attribute
 *   nla_get_s32(nla)                   get payload for a s32 attribute
 *   nla_get_s64(nla)                   get payload for a s64 attribute
 *   nla_get_flag(nla)                  return 1 if flag is true
 *   nla_get_msecs(nla)                 get payload for a msecs attribute
 *
 * Attribute Misc:
 *   nla_memcpy(dest, nla, count)       copy attribute into memory
 *   nla_memcmp(nla, data, size)        compare attribute with memory area
 *   nla_strlcpy(dst, nla, size)        copy attribute to a sized string
 *   nla_strcmp(nla, str)               compare attribute with string
 *
 * Attribute Parsing:
 *   nla_ok(nla, remaining)             does nla fit into remaining bytes?
 *   nla_next(nla, remaining)           get next netlink attribute
 *   nla_validate()                     validate a stream of attributes
 *   nla_validate_nested()              validate a stream of nested attributes
 *   nla_find()                         find attribute in stream of attributes
 *   nla_find_nested()                  find attribute in nested attributes
 *   nla_parse()                        parse and validate stream of attrs
 *   nla_parse_nested()                 parse nested attribuets
 *   nla_for_each_attr()                loop over all attributes
 *   nla_for_each_nested()              loop over the nested attributes
 *=========================================================================
 */

 /**
  * Standard attribute types to specify validation policy
  */
enum {
        NLA_UNSPEC,
        NLA_U8,
        NLA_U16,
        NLA_U32,
        NLA_U64,
        NLA_STRING,
        NLA_FLAG,
        NLA_MSECS,
        NLA_NESTED,
        NLA_NESTED_COMPAT,
        NLA_NUL_STRING,
        NLA_BINARY,
        NLA_S8,
        NLA_S16,
        NLA_S32,
        NLA_S64,
        __NLA_TYPE_MAX,
};

### 分配 netlink 消息

/**
 * nlmsg_new - Allocate a new netlink message
 * @payload: size of the message payload
 * @flags: the type of memory to allocate.
 *
 * Use NLMSG_DEFAULT_SIZE if the size of the payload isn't known
 * and a good default is needed.
 */
static inline struct sk_buff *nlmsg_new(size_t payload, gfp_t flags)
{
        return alloc_skb(nlmsg_total_size(payload), flags);
}

### 增加一个通用的 netlink 消息头

/**
 * genlmsg_put - Add generic netlink header to netlink message
 * @skb: socket buffer holding the message
 * @portid: netlink portid the message is addressed to
 * @seq: sequence number (usually the one of the sender)
 * @family: generic netlink family
 * @flags: netlink message flags
 * @cmd: generic netlink command
 *
 * Returns pointer to user specific header
 */
void *genlmsg_put(struct sk_buff *skb, u32 portid, u32 seq,
                                struct genl_family *family, int flags, u8 cmd)
{
        struct nlmsghdr *nlh;
        struct genlmsghdr *hdr;

        nlh = nlmsg_put(skb, portid, seq, family->id, GENL_HDRLEN +
                        family->hdrsize, flags);
        if (nlh == NULL)
                return NULL;

        hdr = nlmsg_data(nlh);
        hdr->cmd = cmd;
        hdr->version = family->version;
        hdr->reserved = 0;

        return (char *) hdr + GENL_HDRLEN;
}
EXPORT_SYMBOL(genlmsg_put);

/**
 * nlmsg_put - Add a new netlink message to an skb
 * @skb: socket buffer to store message in
 * @portid: netlink process id
 * @seq: sequence number of message
 * @type: message type
 * @payload: length of message payload
 * @flags: message flags
 *
 * Returns NULL if the tailroom of the skb is insufficient to store
 * the message header and payload.
 */
static inline struct nlmsghdr *nlmsg_put(struct sk_buff *skb, u32 portid, u32 seq,
                                         int type, int payload, int flags)
{
        if (unlikely(skb_tailroom(skb) < nlmsg_total_size(payload)))
                return NULL;

        return __nlmsg_put(skb, portid, seq, type, payload, flags);
}

struct nlmsghdr * __nlmsg_put(struct sk_buff *skb, u32 portid, u32 seq, int type, int len, int flags)
{
        struct nlmsghdr *nlh;
        int size = nlmsg_msg_size(len);

        nlh = (struct nlmsghdr*)skb_put(skb, NLMSG_ALIGN(size));
        nlh->nlmsg_type = type;
        nlh->nlmsg_len = size;
        nlh->nlmsg_flags = flags;
        nlh->nlmsg_pid = portid;
        nlh->nlmsg_seq = seq;
        if (!__builtin_constant_p(size) || NLMSG_ALIGN(size) - size != 0)
                memset(nlmsg_data(nlh) + len, 0, NLMSG_ALIGN(size) - size);
        return nlh;
}
EXPORT_SYMBOL(__nlmsg_put);

可见, genlmsg_put 增加一个长度为 GENL_HDRLEN + family->hdrsize 的 nlmsghdr 到 skb

### 增加 netlink 属性给 socket buffer

/**
 * nla_put - Add a netlink attribute to a socket buffer
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 *
 * Returns -EMSGSIZE if the tailroom of the skb is insufficient to store
 * the attribute header and payload.
 */
int nla_put(struct sk_buff *skb, int attrtype, int attrlen, const void *data)
{
        if (unlikely(skb_tailroom(skb) < nla_total_size(attrlen)))
                return -EMSGSIZE;

        __nla_put(skb, attrtype, attrlen, data);
        return 0;
}

/**
 * __nla_put - Add a netlink attribute to a socket buffer
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 *
 * The caller is responsible to ensure that the skb provides enough
 * tailroom for the attribute header and payload.
 */
void __nla_put(struct sk_buff *skb, int attrtype, int attrlen,
                             const void *data)
{
        struct nlattr *nla;

        nla = __nla_reserve(skb, attrtype, attrlen);
        memcpy(nla_data(nla), data, attrlen);
}
EXPORT_SYMBOL(__nla_put);

/* __nla_reserve - reserve room for attribute on the skb
 * @skb: socket buffer to reserve room on
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 *
 * Adds a netlink attribute header to a socket buffer and reserves
 * room for the payload but does not copy it.
 *
 * The caller is responsible to ensure that the skb provides enough
 * tailroom for the attribute header and payload.
 */
struct nlattr *__nla_reserve(struct sk_buff *skb, int attrtype, int attrlen)
{
        struct nlattr *nla;

        nla = (struct nlattr *) skb_put(skb, nla_total_size(attrlen));
        nla->nla_type = attrtype;
        nla->nla_len = nla_attr_size(attrlen);

        memset((unsigned char *) nla + nla->nla_len, 0, nla_padlen(attrlen));

        return nla;
}
EXPORT_SYMBOL(__nla_reserve);

由上可知, 增加一个属性过程如下:

1. skb 上开辟一块长度为 NLA_ALIGN(NLA_HDRLEN + attrlen) 空间
2. 初始化 nla->nla_type 为 attrtype, nla->nla_len 为 attrlen
2. 将长度为 attrlen 的数据 data 拷贝给 (char *) nla + NLA_HDRLEN 开头的 attrlen 空间

### 发送多播消息给指定命名空间

/**
 * genlmsg_multicast_netns - multicast a netlink message to a specific netns
 * @family: the generic netlink family
 * @net: the net namespace
 * @skb: netlink message as socket buffer
 * @portid: own netlink portid to avoid sending to yourself
 * @group: offset of multicast group in groups array
 * @flags: allocation flags
 */
static inline int genlmsg_multicast_netns(struct genl_family *family,
                                          struct net *net, struct sk_buff *skb,
                                          u32 portid, unsigned int group, gfp_t flags)
{
        if (WARN_ON_ONCE(group >= family->n_mcgrps))
                return -EINVAL;
        group = family->mcgrp_offset + group;
        return nlmsg_multicast(net->genl_sock, skb, portid, group, flags);
}

比如

	genlmsg_multicast_netns(&dp_vport_genl_family,
				ovs_dp_get_net(dp), notify, 0,
				GROUP_ID(&ovs_dp_vport_multicast_group),
				GFP_KERNEL);

其中:

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

    struct genl_multicast_group ovs_dp_vport_multicast_group = {
    	.name = OVS_VPORT_MCGROUP
    };

    #ifdef HAVE_GENL_MULTICAST_GROUP_WITH_ID
    #define GROUP_ID(grp)	((grp)->id)
    #else
    #define GROUP_ID(grp)	0
    #endif


## ovs 内核与用户交互设计

### datapath



### vport


### flow

enum ovs_key_attr {
	OVS_KEY_ATTR_UNSPEC,
	OVS_KEY_ATTR_ENCAP,	/* Nested set of encapsulated attributes. */
	OVS_KEY_ATTR_PRIORITY,  /* u32 skb->priority */
	OVS_KEY_ATTR_IN_PORT,   /* u32 OVS dp port number */
	OVS_KEY_ATTR_ETHERNET,  /* struct ovs_key_ethernet */
	OVS_KEY_ATTR_VLAN,	/* be16 VLAN TCI */
	OVS_KEY_ATTR_ETHERTYPE,	/* be16 Ethernet type */
	OVS_KEY_ATTR_IPV4,      /* struct ovs_key_ipv4 */
	OVS_KEY_ATTR_IPV6,      /* struct ovs_key_ipv6 */
	OVS_KEY_ATTR_TCP,       /* struct ovs_key_tcp */
	OVS_KEY_ATTR_UDP,       /* struct ovs_key_udp */
	OVS_KEY_ATTR_ICMP,      /* struct ovs_key_icmp */
	OVS_KEY_ATTR_ICMPV6,    /* struct ovs_key_icmpv6 */
	OVS_KEY_ATTR_ARP,       /* struct ovs_key_arp */
	OVS_KEY_ATTR_ND,        /* struct ovs_key_nd */
	OVS_KEY_ATTR_SKB_MARK,  /* u32 skb mark */
	OVS_KEY_ATTR_TUNNEL,	/* Nested set of ovs_tunnel attributes */
	OVS_KEY_ATTR_SCTP,      /* struct ovs_key_sctp */
	OVS_KEY_ATTR_TCP_FLAGS,	/* be16 TCP flags. */
	OVS_KEY_ATTR_DP_HASH,	/* u32 hash value. Value 0 indicates the hash
				   is not computed by the datapath. */
	OVS_KEY_ATTR_RECIRC_ID, /* u32 recirc id */
#ifdef __KERNEL__
	/* Only used within kernel data path. */
	OVS_KEY_ATTR_IPV4_TUNNEL,  /* struct ovs_key_ipv4_tunnel */
#endif
	/* Experimental */

	OVS_KEY_ATTR_MPLS = 62, /* array of struct ovs_key_mpls.
				 * The implementation may restrict
				 * the accepted length of the array. */
	__OVS_KEY_ATTR_MAX
};

#define OVS_KEY_ATTR_MAX (__OVS_KEY_ATTR_MAX - 1)

enum ovs_tunnel_key_attr {
	OVS_TUNNEL_KEY_ATTR_ID,			/* be64 Tunnel ID */
	OVS_TUNNEL_KEY_ATTR_IPV4_SRC,		/* be32 src IP address. */
	OVS_TUNNEL_KEY_ATTR_IPV4_DST,		/* be32 dst IP address. */
	OVS_TUNNEL_KEY_ATTR_TOS,		/* u8 Tunnel IP ToS. */
	OVS_TUNNEL_KEY_ATTR_TTL,		/* u8 Tunnel IP TTL. */
	OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT,	/* No argument, set DF. */
	OVS_TUNNEL_KEY_ATTR_CSUM,		/* No argument. CSUM packet. */
	__OVS_TUNNEL_KEY_ATTR_MAX
};

#define OVS_TUNNEL_KEY_ATTR_MAX (__OVS_TUNNEL_KEY_ATTR_MAX - 1)


/**
 * enum ovs_sample_attr - Attributes for %OVS_ACTION_ATTR_SAMPLE action.
 * @OVS_SAMPLE_ATTR_PROBABILITY: 32-bit fraction of packets to sample with
 * @OVS_ACTION_ATTR_SAMPLE.  A value of 0 samples no packets, a value of
 * %UINT32_MAX samples all packets and intermediate values sample intermediate
 * fractions of packets.
 * @OVS_SAMPLE_ATTR_ACTIONS: Set of actions to execute in sampling event.
 * Actions are passed as nested attributes.
 *
 * Executes the specified actions with the given probability on a per-packet
 * basis.
 */
enum ovs_sample_attr {
	OVS_SAMPLE_ATTR_UNSPEC,
	OVS_SAMPLE_ATTR_PROBABILITY, /* u32 number */
	OVS_SAMPLE_ATTR_ACTIONS,     /* Nested OVS_ACTION_ATTR_* attributes. */
	__OVS_SAMPLE_ATTR_MAX,
};






/* The size of the argument for each %OVS_KEY_ATTR_* Netlink attribute.  */
static const int ovs_key_lens[OVS_KEY_ATTR_MAX + 1] = {
	[OVS_KEY_ATTR_ENCAP] = -1,
	[OVS_KEY_ATTR_PRIORITY] = sizeof(u32),
	[OVS_KEY_ATTR_IN_PORT] = sizeof(u32),
	[OVS_KEY_ATTR_SKB_MARK] = sizeof(u32),
	[OVS_KEY_ATTR_ETHERNET] = sizeof(struct ovs_key_ethernet),
	[OVS_KEY_ATTR_VLAN] = sizeof(__be16),
	[OVS_KEY_ATTR_ETHERTYPE] = sizeof(__be16),
	[OVS_KEY_ATTR_IPV4] = sizeof(struct ovs_key_ipv4),
	[OVS_KEY_ATTR_IPV6] = sizeof(struct ovs_key_ipv6),
	[OVS_KEY_ATTR_TCP] = sizeof(struct ovs_key_tcp),
	[OVS_KEY_ATTR_TCP_FLAGS] = sizeof(__be16),
	[OVS_KEY_ATTR_UDP] = sizeof(struct ovs_key_udp),
	[OVS_KEY_ATTR_SCTP] = sizeof(struct ovs_key_sctp),
	[OVS_KEY_ATTR_ICMP] = sizeof(struct ovs_key_icmp),
	[OVS_KEY_ATTR_ICMPV6] = sizeof(struct ovs_key_icmpv6),
	[OVS_KEY_ATTR_ARP] = sizeof(struct ovs_key_arp),
	[OVS_KEY_ATTR_ND] = sizeof(struct ovs_key_nd),
	[OVS_KEY_ATTR_DP_HASH] = sizeof(u32),
	[OVS_KEY_ATTR_RECIRC_ID] = sizeof(u32),
	[OVS_KEY_ATTR_TUNNEL] = -1,
};



## 参考

include/net/netlink.h
