
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

    nla_type (16 bits)
     +---+---+-------------------------------+
     | N | O | Attribute Type                |
     +---+---+-------------------------------+
     N := Carries nested attributes
     O := Payload stored in network byte order

     Note: The N and O flag are mutually exclusive.

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


### upcall

数据大小

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

数据组织形式

    参考 queue_userspace_packet


### 注册到内核空间

static void dp_unregister_genl(int n_families)

	for (i = 0; i < n_families; i++)
		genl_unregister_family(dp_genl_families[i]);

static int dp_register_genl(void)

	for (i = 0; i < ARRAY_SIZE(dp_genl_families); i++)
		genl_register_family(dp_genl_families[i]);

### datapath

#define OVS_DATAPATH_FAMILY  "ovs_datapath"
#define OVS_DATAPATH_VERSION 2
#define OVS_DP_ATTR_MAX (__OVS_DP_ATTR_MAX - 1)

#define OVS_DP_ATTR_MAX (__OVS_DP_ATTR_MAX - 1)

static const struct nla_policy datapath_policy[OVS_DP_ATTR_MAX + 1] = {
	[OVS_DP_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[OVS_DP_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_DP_ATTR_USER_FEATURES] = { .type = NLA_U32 },
};

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

enum ovs_datapath_cmd {
	OVS_DP_CMD_UNSPEC,
	OVS_DP_CMD_NEW,
	OVS_DP_CMD_DEL,
	OVS_DP_CMD_GET,
	OVS_DP_CMD_SET
};

static const struct genl_multicast_group ovs_dp_datapath_multicast_group = {
	.name = OVS_DATAPATH_MCGROUP,
};


enum ovs_datapath_attr {
	OVS_DP_ATTR_UNSPEC,
	OVS_DP_ATTR_NAME,		/* name of dp_ifindex netdev */
	OVS_DP_ATTR_UPCALL_PID,		/* Netlink PID to receive upcalls */
	OVS_DP_ATTR_STATS,		/* struct ovs_dp_stats */
	OVS_DP_ATTR_MEGAFLOW_STATS,	/* struct ovs_dp_megaflow_stats */
	OVS_DP_ATTR_USER_FEATURES,	/* OVS_DP_F_*  */
	__OVS_DP_ATTR_MAX
};

static struct genl_family * const dp_genl_families[] = {
	&dp_datapath_genl_family,
	&dp_vport_genl_family,
	&dp_flow_genl_family,
	&dp_packet_genl_family,
};

### vport

#define OVS_VPORT_FAMILY  "ovs_vport"
#define OVS_VPORT_MCGROUP "ovs_vport"

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
}

const struct genl_multicast_group ovs_dp_vport_multicast_group = {
	.name = OVS_VPORT_MCGROUP,
};

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

### 消息格式

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	ovs_header = genlmsg_put(skb, portid, seq, &dp_vport_genl_family, flags, cmd);
	ovs_header->dp_ifindex = get_dpifindex(vport->dp);
    nla_put_u32(skb, OVS_VPORT_ATTR_PORT_NO, vport->port_no)
	nla_put_u32(skb, OVS_VPORT_ATTR_TYPE, vport->ops->type)
	nla_put_string(skb, OVS_VPORT_ATTR_NAME, vport->ops->get_name(vport))
	ovs_vport_get_stats(vport, &vport_stats);
    nla_put(skb, OVS_VPORT_ATTR_STATS, sizeof(struct ovs_vport_stats), &vport_stats))
    ovs_vport_get_upcall_portids(vport, skb))
    ovs_vport_get_options(vport, skb);
	genlmsg_end(skb, ovs_header);


### flow

#define OVS_FLOW_FAMILY  "ovs_flow"
#define OVS_FLOW_VERSION 0x1

#define OVS_FLOW_ATTR_MAX (__OVS_FLOW_ATTR_MAX - 1)

#define OVS_FLOW_MCGROUP "ovs_flow"

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

enum ovs_flow_attr {
	OVS_FLOW_ATTR_UNSPEC,
	OVS_FLOW_ATTR_KEY,       /* Sequence of OVS_KEY_ATTR_* attributes. */
	OVS_FLOW_ATTR_ACTIONS,   /* Nested OVS_ACTION_ATTR_* attributes. */
	OVS_FLOW_ATTR_STATS,     /* struct ovs_flow_stats. */
	OVS_FLOW_ATTR_TCP_FLAGS, /* 8-bit OR'd TCP flags. */
	OVS_FLOW_ATTR_USED,      /* u64 msecs last used in monotonic time. */
	OVS_FLOW_ATTR_CLEAR,     /* Flag to clear stats, tcp_flags, used. */
	OVS_FLOW_ATTR_MASK,      /* Sequence of OVS_KEY_ATTR_* attributes. */
	OVS_FLOW_ATTR_PROBE,     /* Flow operation is a feature probe, error
				  * logging should be suppressed. */
	OVS_FLOW_ATTR_UFID,      /* Variable length unique flow identifier. */
	OVS_FLOW_ATTR_UFID_FLAGS,/* u32 of OVS_UFID_F_*. */
	__OVS_FLOW_ATTR_MAX
};

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

static const struct genl_multicast_group ovs_dp_flow_multicast_group = {
	.name = OVS_FLOW_MCGROUP,
};

#### 构造 flow 的 netlink 消息过程

2.3.5 较 2.3.2 增加了 ufid

static struct sk_buff *ovs_flow_cmd_build_info(const struct sw_flow *flow, int dp_ifindex, struct genl_info *info, u8 cmd, bool always, u32 ufid_flags)

	len = ovs_flow_cmd_msg_size(acts, sfid, ufid_flags);
	skb = genlmsg_new_unicast(len, info, GFP_KERNEL);
	ovs_header = genlmsg_put(skb, portid, seq, &dp_flow_genl_family, flags, cmd);
	ovs_header->dp_ifindex = dp_ifindex;
    ovs_nla_put_identifier(flow, skb);
    ovs_nla_put_masked_key(flow, skb);
    ovs_nla_put_mask(flow, skb);
    ovs_flow_cmd_fill_stats(flow, skb);
    ovs_flow_cmd_fill_actions(flow, skb, skb_orig_len);
	genlmsg_end(skb, ovs_header);
	return skb;






### packet

#define OVS_PACKET_FAMILY "ovs_packet"
#define OVS_PACKET_VERSION 0x1

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

#define OVS_PACKET_ATTR_MAX (__OVS_PACKET_ATTR_MAX - 1)

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

enum ovs_packet_attr {
	OVS_PACKET_ATTR_UNSPEC,
	OVS_PACKET_ATTR_PACKET,      /* Packet data. */
	OVS_PACKET_ATTR_KEY,         /* Nested OVS_KEY_ATTR_* attributes. */
	OVS_PACKET_ATTR_ACTIONS,     /* Nested OVS_ACTION_ATTR_* attributes. */
	OVS_PACKET_ATTR_USERDATA,    /* OVS_ACTION_ATTR_USERSPACE arg. */
	OVS_PACKET_ATTR_EGRESS_TUN_KEY,  /* Nested OVS_TUNNEL_KEY_ATTR_*
					    attributes. */
	OVS_PACKET_ATTR_UNUSED1,
	OVS_PACKET_ATTR_UNUSED2,
	OVS_PACKET_ATTR_PROBE,      /* Packet operation is a feature probe,
				       error logging should be suppressed. */
	__OVS_PACKET_ATTR_MAX
};

---------------------------------------------------

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


size_t ovs_key_attr_size(void)
	/* Whenever adding new OVS_KEY_ FIELDS, we should consider
	 * updating this function.
	 */
	BUILD_BUG_ON(OVS_KEY_ATTR_TUNNEL_INFO != 22);

	return    nla_total_size(4)   /* OVS_KEY_ATTR_PRIORITY */
		+ nla_total_size(0)   /* OVS_KEY_ATTR_TUNNEL */
		//ovs_tun_key_attr_size() begin
	    + nla_total_size(8)    /* OVS_TUNNEL_KEY_ATTR_ID */
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
		//ovs_tun_key_attr_size() end
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


### upcall netlink

    skb_buff->data = nlmsg
                     -> nlmsghdr = struct nlmsghdr *nlh
                     -> family header = struct genlmsghdr *hdr
                     -> attributes
                        -> upcall                           : dp_ifindex
                        -> OVS_PACKET_ATTR_KEY              : key
                        -> OVS_PACKET_ATTR_USERDATA         : upcall_info->userdata
                        -> OVS_PACKET_ATTR_EGRESS_TUN_KEY   : tun_info
                        -> OVS_PACKET_ATTR_ACTIONS          : actions

    genlmsg_unicast(dp->net, skb_buff, upcall_info->portid)

        struct sw_flow_key *key
        struct dp_upcall_info upcall = {
            .cmd    = OVS_PACKET_CMD_MISS
            .portid = ovs_vport_find_upcall_portid(OVS_CB(skb)->input_vport, skb)
        }

        struct genl_info info = {
        #ifdef HAVE_GENLMSG_NEW_UNICAST
            .dst_sk = ovs_dp_get_net(dp)->genl_sock,
        #endif
            .snd_portid = upcall_info->portid,
        };

        family = dp_packet_genl_family
        nlh->nlmsg_type = family->id;
        nlh->nlmsg_len = nlmsg_msg_size(GENL_HDRLEN + family->hdrsize);
        nlh->nlmsg_flags = 0;
        nlh->nlmsg_pid = 0;
        nlh->nlmsg_seq = 0;

        hdr->cmd = upcall_info->cmd
        hdr->version = family->version
        hdr->reserved = 0;

        upcall->dp_ifindex = get_dpifindex(dp);

        nlattr key = {
            OVS_KEY_ATTR_RECIRC_ID : key->recirc_id
            OVS_KEY_ATTR_DP_HASH   : key->ovs_flow_hash
            OVS_KEY_ATTR_PRIORITY  : key->phy.priority
            OVS_KEY_ATTR_IN_PORT   : key->phy.in_port
            OVS_KEY_ATTR_SKB_MARK  : key->phy.skb_mark
            OVS_KEY_ATTR_ETHERNET  : key->eth.src+key->eth.dst
            OVS_KEY_ATTR_ETHERTYPE : key->eth.type
            OVS_KEY_ATTR_IPV4      : key->ipv4.addr.src+key->ipv4.addr.dst ..
            OVS_KEY_ATTR_TCP       : key->tp.src+key->tp.dst+key->tp.flags
        }

        tun_key = upcall_info->tunnel
        nlattr tun_info = {
            OVS_TUNNEL_KEY_ATTR_ID              : tun_key->tun_id
            OVS_TUNNEL_KEY_ATTR_IPV4_SRC        : tun_key->ipv4_src
            OVS_TUNNEL_KEY_ATTR_IPV4_DST        : tun_key->ipv4_dst
            OVS_TUNNEL_KEY_ATTR_TOS             : tun_key->ipv4_tos
            OVS_TUNNEL_KEY_ATTR_TTL             : tun_key->ipv4_ttl
            OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT   : NULL
            OVS_TUNNEL_KEY_ATTR_CSUM            : NULL
            OVS_TUNNEL_KEY_ATTR_TP_SRC          : tun_key->tp_src
            OVS_TUNNEL_KEY_ATTR_TP_DST          : tun_key->tp_dst
            OVS_TUNNEL_KEY_ATTR_IPV4_DST        : NULL
            OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS     : upcall_info->options
            OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS      {
                OVS_VXLAN_EXT_GBP : upcall_info->options->gbp
            }
        }

        actions = upcall_info->actions
        actions = {
            if actions = OVS_ACTION_ATTR_SET:
            OVS_ACTION_ATTR_SET : {
                actions = nla_data(actions)
                OVS_KEY_ATTR_TUNNEL_INFO {
                    actions = nla_data(nla_data(actions))
                    OVS_ACTION_ATTR_SET : {
                        tun_key = actions->tunnel
                        OVS_KEY_ATTR_TUNNEL : {
                            OVS_TUNNEL_KEY_ATTR_ID              : tun_key->tun_id
                            OVS_TUNNEL_KEY_ATTR_IPV4_SRC        : tun_key->ipv4_src
                            OVS_TUNNEL_KEY_ATTR_IPV4_DST        : tun_key->ipv4_dst
                            OVS_TUNNEL_KEY_ATTR_TOS             : tun_key->ipv4_tos
                            OVS_TUNNEL_KEY_ATTR_TTL             : tun_key->ipv4_ttl
                            OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT   : NULL
                            OVS_TUNNEL_KEY_ATTR_CSUM            : NULL
                            OVS_TUNNEL_KEY_ATTR_TP_SRC          : tun_key->tp_src
                            OVS_TUNNEL_KEY_ATTR_TP_DST          : tun_key->tp_dst
                            OVS_TUNNEL_KEY_ATTR_IPV4_DST        : NULL
                            OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS     : upcall_info->options
                            OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS      {
                                OVS_VXLAN_EXT_GBP : upcall_info->options->gbp
                            }
                        }
                    }
                }
                OVS_ACTION_ATTR_SET : nla_data(actions)
            }

            if actions->type = OVS_ACTION_ATTR_SET_TO_MASKED :
            OVS_ACTION_ATTR_SET : nal_data(actions)

            if actions->type = OVS_ACTION_ATTR_SET_TO_MASKED :
            OVS_ACTION_ATTR_SAMPLE {
                OVS_SAMPLE_ATTR_PROBABILITY : nla_data(actions)
                OVS_SAMPLE_ATTR_ACTIONS     : {
                     递归了
                }
            }

            else
            nla_type(actions) : nla_data(actions)
        }


## genlink

#define GENL_ID_GENERATE        0
#define GENL_FAM_TAB_SIZE       16
#define GENL_FAM_TAB_MASK       (GENL_FAM_TAB_SIZE - 1)
static struct list_head family_ht[GENL_FAM_TAB_SIZE]

struct rpl_genl_family {
	struct genl_family	compat_family;
	unsigned int            id;
	unsigned int            hdrsize;
	char                    name[GENL_NAMSIZ];
	unsigned int            version;
	unsigned int            maxattr;
	bool                    netnsok;
	bool                    parallel_ops;
	int                     (*pre_doit)(const struct genl_ops *ops,
					    struct sk_buff *skb,
					    struct genl_info *info);
	void                    (*post_doit)(const struct genl_ops *ops,
					     struct sk_buff *skb,
					     struct genl_info *info);
	struct nlattr **        attrbuf;        /* private */
	const struct genl_ops * ops;            /* private */
	const struct genl_multicast_group *mcgrps; /* private */
	unsigned int            n_ops;          /* private */
	unsigned int            n_mcgrps;       /* private */
	unsigned int            mcgrp_offset;   /* private */
	struct list_head        family_list;    /* private */
	struct module           *module;
};

------------------------------------------------

static inline struct list_head *genl_family_chain(unsigned int id)

    return &family_ht[genl_family_hash(id)];

------------------------------------------------

static inline unsigned int genl_family_hash(unsigned int id)

    return id & GENL_FAM_TAB_MASK;

------------------------------------------------

static inline int genl_register_family(struct genl_family *family)

    family->module = THIS_MODULE;
    return __genl_register_family(family);

------------------------------------------------

/**
 * __genl_register_family - register a generic netlink family
 * @family: generic netlink family
 *
 * Registers the specified family after validating it first. Only one
 * family may be registered with the same family name or identifier.
 * The family id may equal GENL_ID_GENERATE causing an unique id to
 * be automatically generated and assigned.
 *
 * The family's ops array must already be assigned, you can use the
 * genl_register_family_with_ops() helper function.
 *
 * Return 0 on success or a negative error code.
 */
int __genl_register_family(struct genl_family *family)

        genl_family_find_byname(family->name))


## 参考

include/net/netlink.h
