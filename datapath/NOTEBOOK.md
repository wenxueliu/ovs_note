
DP_VPORT_HASH_BUCKETS : 大小是否会影响速率

struct datapath {
	struct rcu_head rcu;
	struct list_head list_node;

	/* Flow table. */
	struct flow_table table;

	/* Switch ports. */
	struct hlist_head *ports;

	/* Stats. */
	struct dp_stats_percpu __percpu *stats_percpu;

#ifdef CONFIG_NET_NS
	/* Network namespace ref. */
	struct net *net;
#endif

	u32 user_features;  // 什么意思待理解
};

struct vport {
	struct rcu_head rcu;
	struct datapath	*dp;
	struct vport_portids __rcu *upcall_portids;
	u16 port_no;

	struct hlist_node hash_node;
	struct hlist_node dp_hash_node;
	const struct vport_ops *ops;

	struct pcpu_sw_netstats __percpu *percpu_stats;

	struct vport_err_stats err_stats;
	struct list_head detach_list;
};

struct vport_ops {
	enum ovs_vport_type type;

	/* Called with ovs_mutex. */
	struct vport *(*create)(const struct vport_parms *);
	void (*destroy)(struct vport *);

	int (*set_options)(struct vport *, struct nlattr *);
	int (*get_options)(const struct vport *, struct sk_buff *);

	/* Called with rcu_read_lock or ovs_mutex. */
	const char *(*get_name)(const struct vport *);

	int (*send)(struct vport *, struct sk_buff *);
	int (*get_egress_tun_info)(struct vport *, struct sk_buff *,
				   struct ovs_tunnel_info *);

	struct module *owner;
	struct list_head list;
};

struct vport_portids {
	struct reciprocal_value rn_ids;
	struct rcu_head rcu;
	u32 n_ids;
	u32 ids[];
};

struct flow_table {
	struct table_instance __rcu *ti;
	struct table_instance __rcu *ufid_ti;
	struct mask_cache_entry __percpu *mask_cache;
	struct mask_array __rcu *mask_array;
	unsigned long last_rehash;
	unsigned int count;
	unsigned int ufid_count;
};

struct table_instance {
	struct flex_array *buckets;
	unsigned int n_buckets;
	struct rcu_head rcu;
	int node_ver;
	u32 hash_seed;
	bool keep_flows;
};

struct flex_array {
	union {
		struct {
			int element_size;
			int total_nr_elements;
			int elems_per_part;
			struct reciprocal_value reciprocal_elems;
			struct flex_array_part *parts[];
		};
		/*
		 * This little trick makes sure that
		 * sizeof(flex_array) == PAGE_SIZE
		 */
		char padding[FLEX_ARRAY_BASE_SIZE]; //#define FLEX_ARRAY_BASE_SIZE PAGE_SIZE
	};
};

struct flex_array_part {
    char elements[FLEX_ARRAY_PART_SIZE];
}

struct sw_flow {
	struct rcu_head rcu;
	struct {
		struct hlist_node node[2];
		u32 hash;
	} flow_table, ufid_table;
	int stats_last_writer;		/* NUMA-node id of the last writer on
					 * 'stats[0]'.
					 */
	struct sw_flow_key key;
	struct sw_flow_id id;
	struct sw_flow_mask *mask;
	struct sw_flow_actions __rcu *sf_acts;
	struct flow_stats __rcu *stats[]; /* One for each NUMA node.  First one
					   * is allocated at flow creation time,
					   * the rest are allocated on demand
					   * while holding the 'stats[0].lock'.
					   */
};

struct sw_flow_key {
	u8 tun_opts[255];
	u8 tun_opts_len;
	struct ovs_key_ipv4_tunnel tun_key;  /* Encapsulating tunnel key. */
	struct {
		u32	priority;	/* Packet QoS priority. */
		u32	skb_mark;	/* SKB mark. */
		u16	in_port;	/* Input switch port (or DP_MAX_PORTS). */
	} __packed phy; /* Safe when right after 'tun_key'. */
	u32 ovs_flow_hash;		/* Datapath computed hash value.  */
	u32 recirc_id;			/* Recirculation ID.  */
	struct {
		u8     src[ETH_ALEN];	/* Ethernet source address. */
		u8     dst[ETH_ALEN];	/* Ethernet destination address. */
		__be16 tci;		/* 0 if no VLAN, VLAN_TAG_PRESENT set otherwise. */
		__be16 type;		/* Ethernet frame type. */
	} eth;
	union {
		struct {
			__be32 top_lse;	/* top label stack entry */
		} mpls;
		struct {
			u8     proto;	/* IP protocol or lower 8 bits of ARP opcode. */
			u8     tos;	    /* IP ToS. */
			u8     ttl;	    /* IP TTL/hop limit. */
			u8     frag;	/* One of OVS_FRAG_TYPE_*. */
		} ip;
	};
	struct {
		__be16 src;		/* TCP/UDP/SCTP source port. */
		__be16 dst;		/* TCP/UDP/SCTP destination port. */
		__be16 flags;		/* TCP flags. */
	} tp;
	union {
		struct {
			struct {
				__be32 src;	/* IP source address. */
				__be32 dst;	/* IP destination address. */
			} addr;
			struct {
				u8 sha[ETH_ALEN];	/* ARP source hardware address. */
				u8 tha[ETH_ALEN];	/* ARP target hardware address. */
			} arp;
		} ipv4;
		struct {
			struct {
				struct in6_addr src;	/* IPv6 source address. */
				struct in6_addr dst;	/* IPv6 destination address. */
			} addr;
			__be32 label;			/* IPv6 flow label. */
			struct {
				struct in6_addr target;	/* ND target address. */
				u8 sll[ETH_ALEN];	/* ND source link layer address. */
				u8 tll[ETH_ALEN];	/* ND target link layer address. */
			} nd;
		} ipv6;
	};
} __aligned(BITS_PER_LONG/8); /* Ensure that we can do comparisons as longs. */

struct sw_flow_actions {
	struct rcu_head rcu;
	u32 actions_len;
	struct nlattr actions[];
};

--------------------------------------------------------

###ovs_dp_cmd_new(struct sk_buff *skb, struct genl_info *info)

ovs_flow_tbl_init(&dp->table)

--------------------------------------------------------

###ovs_flow_tbl_init(struct flow_table *table)

初始化 flow_table 结构体

核心是为 mask_cache, mask_array, ti, ufid_ti 分配内存空间, 这里顺序是否关键?

table_instance_alloc(1024)

--------------------------------------------------------
###table_instance_alloc(new_size)

初始化一个 table_instance 结构体, 返回结构体的指针 ti

ti->buckets = alloc_buckets(new_size)
ti->n_buckets = new_size

--------------------------------------------------------
###alloc_buckets(unsigned int n_buckets)

flex_array_alloc(sizeof(struct hlist_head), n_buckets, GFP_KERNEL) 分配 new_size 个 hlist_head

--------------------------------------------------------
###define flex_array_alloc rpl_flex_array_alloc

--------------------------------------------------------
###struct flex_array *rpl_flex_array_alloc(int element_size, unsigned int
        total,gfp_t flags)

    element_size   : sizeof(struct hlist_head)
    n_buckets      : 1024
    elems_per_part : PAGE_SIZE/element_size  : 每页可以放多少个 hlist_head,
                    elems_per_part 即 part 中元素个数

    FLEX_ARRAY_NR_BASE_PTRS : 一页中除去 element_size, total_nr_elements,
    elems_per_part, reciprocal_value 剩余的空间可以存储多少个 part
    max_size = FLEX_ARRAY_NR_BASE_PTRS * elems_per_part 为

    关系: elems_per_part * element_size = PAGE_SIZE
          element_size * n_buckets =

每个 table 分配了一个 bucket 指针, 每个 bucket 中, element_size 与 hlist_head
大小相同, 总共由 1024 个, elems_per_part 为一页可以存储的 hlist_head 个数

--------------------------------------------------------

u32 ovs_vport_find_upcall_portid(const struct vport *vport, struct sk_buff *skb)

如果 vport->upcall_portids 为只有一个, 且 id 为 0, 返回 0
否则 对 skb hash 后获取索引(细节待考)

--------------------------------------------

static int queue_userspace_packet(struct datapath *dp, struct sk_buff *skb,
				  const struct sw_flow_key *key,
				  const struct dp_upcall_info *upcall_info)

upcall 核心实现

dp = (ovs_skb_cb*)(skb->cb)->input_vport->dp;

upcall_info info = {
    .cmd = OVS_PACKET_CMD_MISS
    .portid = ovs_vport_find_upcall_portid(p, skb)
}

len = upcall_msg_size(upcall_info, hlen); //计算

//调用 skb_alloc() 分配 skb 空间 user_skb
user_skb = genlmsg_new_unicast(len, &info, GFP_ATOMIC);

/*
 * nlms_put 填充 user_skb->data 为 nlmsghdr
 * nlmsghdr->payload 为 genlmsghdr
 * 返回 nlmsghdr->family->attributes 的头指针
 * 具体可以参考 netlink.h 的结构体
 */
upcall = genlmsg_put(user_skb, 0, 0, &dp_packet_genl_family,
			     0, upcall_info->cmd);


//将 key 打包到 nlamsg 属性里面
ovs_nla_put_key(key, key, OVS_PACKET_ATTR_KEY, false, user_skb);

之后将 upcall_info 的 userdata, egress_tun_info, actions 打包到 user_skb

//将 user_skb 发送给 upcall_info->portid 对应的 netlink
genlmsg_unicast(ovs_dp_get_net(dp), user_skb, upcall_info->portid);

--------------------------------------------
static inline struct sk_buff *genlmsg_new_unicast(size_t payload,
						  struct genl_info *info,
						  gfp_t flags)
{
	return genlmsg_new(payload, flags);
}

--------------------------------------------

#define skb_zerocopy_headlen rpl_skb_zerocopy_headlen

unsigned int rpl_skb_zerocopy_headlen(const struct sk_buff *from)

如果 (struct skb_shared_info *)(from->end)->frag_list != null 返回 from->len

如果 from->head_fags = false 或 from->tail - from->tail < L1_CACHE_BYTES 或 (from->end)->nr_frags >= MAX_SKB_FRAGS
返回 from->tail - from->tail

否则 返回 0

-------------------------------------
static size_t upcall_msg_size(const struct dp_upcall_info *upcall_info,
			      unsigned int hdrlen)

返回
    ovs_header + hdrlen + ovs_key_attr_size()
    + upcall_info->userdata->nla_len
    + nla_total_size(upcall_info->actions_len)
    + nla_total_size(ovs_tun_key_attr_size())
-------------------------------------

##Netlink

###数据结构

来源 /datapath/linux/compat/include/linux/openvswitch.h

核心实现 /datapath/datapath.c 中的 queue_userspace_packet()

/**
 * struct dp_upcall - metadata to include with a packet to send to userspace
 * @cmd: One of %OVS_PACKET_CMD_*.
 * @userdata: If nonnull, its variable-length value is passed to userspace as
 * %OVS_PACKET_ATTR_USERDATA.
 * @portid: Netlink portid to which packet should be sent.  If @portid is 0
 * then no packet is sent and the packet is accounted in the datapath's @n_lost
 * counter.
 * @egress_tun_info: If nonnull, becomes %OVS_PACKET_ATTR_EGRESS_TUN_KEY.
 */
struct dp_upcall_info {
	const struct ovs_tunnel_info *egress_tun_info;
	const struct nlattr *userdata;
	const struct nlattr *actions;
	int actions_len;
	u32 portid;
	u8 cmd;
};

struct nlattr {
    uint16_t nla_len;
    uint16_t nla_type;
};

/**
 * struct ovs_header - header for OVS Generic Netlink messages.
 * @dp_ifindex: ifindex of local port for datapath (0 to make a request not
 * specific to a datapath).
 *
 * Attributes following the header are specific to a particular OVS Generic
 * Netlink family, but all of the OVS families use this header.
 */

struct ovs_header {
	int dp_ifindex;
};

enum ovs_datapath_cmd {
	OVS_DP_CMD_UNSPEC,
	OVS_DP_CMD_NEW,
	OVS_DP_CMD_DEL,
	OVS_DP_CMD_GET,
	OVS_DP_CMD_SET
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

enum ovs_packet_cmd {
	OVS_PACKET_CMD_UNSPEC,

	/* Kernel-to-user notifications. */
	OVS_PACKET_CMD_MISS,    /* Flow table miss. */
	OVS_PACKET_CMD_ACTION,  /* OVS_ACTION_ATTR_USERSPACE action. */

	/* Userspace commands. */
	OVS_PACKET_CMD_EXECUTE  /* Apply actions to a packet. */
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


enum ovs_vport_cmd {
	OVS_VPORT_CMD_UNSPEC,
	OVS_VPORT_CMD_NEW,
	OVS_VPORT_CMD_DEL,
	OVS_VPORT_CMD_GET,
	OVS_VPORT_CMD_SET
};

enum ovs_vport_type {
	OVS_VPORT_TYPE_UNSPEC,
	OVS_VPORT_TYPE_NETDEV,   /* network device */
	OVS_VPORT_TYPE_INTERNAL, /* network device implemented by datapath */
	OVS_VPORT_TYPE_GRE,      /* GRE tunnel. */
	OVS_VPORT_TYPE_VXLAN,	 /* VXLAN tunnel. */
	OVS_VPORT_TYPE_GENEVE,	 /* Geneve tunnel. */
	OVS_VPORT_TYPE_GRE64 = 104, /* GRE tunnel with 64-bit keys */
	OVS_VPORT_TYPE_LISP = 105,  /* LISP tunnel */
	OVS_VPORT_TYPE_STT = 106, /* STT tunnel */
	__OVS_VPORT_TYPE_MAX
};

enum ovs_vport_attr {
	OVS_VPORT_ATTR_UNSPEC,
	OVS_VPORT_ATTR_PORT_NO,	/* u32 port number within datapath */
	OVS_VPORT_ATTR_TYPE,	/* u32 OVS_VPORT_TYPE_* constant. */
	OVS_VPORT_ATTR_NAME,	/* string name, up to IFNAMSIZ bytes long */
	OVS_VPORT_ATTR_OPTIONS, /* nested attributes, varies by vport type */
	OVS_VPORT_ATTR_UPCALL_PID, /* array of u32 Netlink socket PIDs for */
				/* receiving upcalls */
	OVS_VPORT_ATTR_STATS,	/* struct ovs_vport_stats */
	__OVS_VPORT_ATTR_MAX
};

enum {
	OVS_VXLAN_EXT_UNSPEC,
	OVS_VXLAN_EXT_GBP,      /* Flag or __u32 */
	__OVS_VXLAN_EXT_MAX,
};

enum {
	OVS_TUNNEL_ATTR_UNSPEC,
	OVS_TUNNEL_ATTR_DST_PORT, /* 16-bit UDP port, used by L4 tunnels. */
	OVS_TUNNEL_ATTR_EXTENSION,
	__OVS_TUNNEL_ATTR_MAX
};

enum ovs_flow_cmd {
	OVS_FLOW_CMD_UNSPEC,
	OVS_FLOW_CMD_NEW,
	OVS_FLOW_CMD_DEL,
	OVS_FLOW_CMD_GET,
	OVS_FLOW_CMD_SET
};

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
	OVS_KEY_ATTR_TUNNEL,    /* Nested set of ovs_tunnel attributes */
	OVS_KEY_ATTR_SCTP,      /* struct ovs_key_sctp */
	OVS_KEY_ATTR_TCP_FLAGS,	/* be16 TCP flags. */
	OVS_KEY_ATTR_DP_HASH,   /* u32 hash value. Value 0 indicates the hash
				   is not computed by the datapath. */
	OVS_KEY_ATTR_RECIRC_ID, /* u32 recirc id */
	OVS_KEY_ATTR_MPLS,      /* array of struct ovs_key_mpls.
				 * The implementation may restrict
				 * the accepted length of the array. */

#ifdef __KERNEL__
	/* Only used within kernel data path. */
	OVS_KEY_ATTR_TUNNEL_INFO,  /* struct ovs_tunnel_info */
#endif
	__OVS_KEY_ATTR_MAX
};

enum ovs_tunnel_key_attr {
	OVS_TUNNEL_KEY_ATTR_ID,                 /* be64 Tunnel ID */
	OVS_TUNNEL_KEY_ATTR_IPV4_SRC,           /* be32 src IP address. */
	OVS_TUNNEL_KEY_ATTR_IPV4_DST,           /* be32 dst IP address. */
	OVS_TUNNEL_KEY_ATTR_TOS,                /* u8 Tunnel IP ToS. */
	OVS_TUNNEL_KEY_ATTR_TTL,                /* u8 Tunnel IP TTL. */
	OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT,      /* No argument, set DF. */
	OVS_TUNNEL_KEY_ATTR_CSUM,               /* No argument. CSUM packet. */
	OVS_TUNNEL_KEY_ATTR_OAM,                /* No argument. OAM frame.  */
	OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS,        /* Array of Geneve options. */
	OVS_TUNNEL_KEY_ATTR_TP_SRC,		/* be16 src Transport Port. */
	OVS_TUNNEL_KEY_ATTR_TP_DST,		/* be16 dst Transport Port. */
	OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS,		/* Nested OVS_VXLAN_EXT_* */
	__OVS_TUNNEL_KEY_ATTR_MAX
};

enum ovs_frag_type {
	OVS_FRAG_TYPE_NONE,
	OVS_FRAG_TYPE_FIRST,
	OVS_FRAG_TYPE_LATER,
	__OVS_FRAG_TYPE_MAX
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

enum ovs_sample_attr {
	OVS_SAMPLE_ATTR_UNSPEC,
	OVS_SAMPLE_ATTR_PROBABILITY, /* u32 number */
	OVS_SAMPLE_ATTR_ACTIONS,     /* Nested OVS_ACTION_ATTR_* attributes. */
	__OVS_SAMPLE_ATTR_MAX,
};

enum ovs_userspace_attr {
	OVS_USERSPACE_ATTR_UNSPEC,
	OVS_USERSPACE_ATTR_PID,	      /* u32 Netlink PID to receive upcalls. */
	OVS_USERSPACE_ATTR_USERDATA,  /* Optional user-specified cookie. */
	OVS_USERSPACE_ATTR_EGRESS_TUN_PORT,  /* Optional, u32 output port
					      * to get tunnel info. */
	OVS_USERSPACE_ATTR_ACTIONS,   /* Optional flag to get actions. */
	__OVS_USERSPACE_ATTR_MAX
};

enum ovs_action_attr {
	OVS_ACTION_ATTR_UNSPEC,
	OVS_ACTION_ATTR_OUTPUT,	      /* u32 port number. */
	OVS_ACTION_ATTR_USERSPACE,    /* Nested OVS_USERSPACE_ATTR_*. */
	OVS_ACTION_ATTR_SET,          /* One nested OVS_KEY_ATTR_*. */
	OVS_ACTION_ATTR_PUSH_VLAN,    /* struct ovs_action_push_vlan. */
	OVS_ACTION_ATTR_POP_VLAN,     /* No argument. */
	OVS_ACTION_ATTR_SAMPLE,       /* Nested OVS_SAMPLE_ATTR_*. */
	OVS_ACTION_ATTR_RECIRC,       /* u32 recirc_id. */
	OVS_ACTION_ATTR_HASH,	      /* struct ovs_action_hash. */
	OVS_ACTION_ATTR_PUSH_MPLS,    /* struct ovs_action_push_mpls. */
	OVS_ACTION_ATTR_POP_MPLS,     /* __be16 ethertype. */
	OVS_ACTION_ATTR_SET_MASKED,   /* One nested OVS_KEY_ATTR_* including
				       * data immediately followed by a mask.
				       * The data must be zero for the unmasked
				       * bits. */

#ifndef __KERNEL__
	OVS_ACTION_ATTR_TUNNEL_PUSH,   /* struct ovs_action_push_tnl*/
	OVS_ACTION_ATTR_TUNNEL_POP,    /* u32 port number. */
#endif
	__OVS_ACTION_ATTR_MAX,	      /* Nothing past this will be accepted
				       * from userspace. */

#ifdef __KERNEL__
	OVS_ACTION_ATTR_SET_TO_MASKED, /* Kernel module internal masked
					* set action converted from
					* OVS_ACTION_ATTR_SET. */
#endif
};

--------------------------------------------------------------
int ovs_nla_put_actions(const struct nlattr *attr, int len, struct sk_buff *skb)

    遍历 attr 的每个属性, 根据属性类型增加对应的 data

--------------------------------------------------------------

int ovs_vport_send(struct vport *vport, struct sk_buff *skb)

调用 vport->pos->send(vport, skb), 发送 skb 到 vport, 返回发送
的字节数

--------------------------------------------------------------
static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			      struct sw_flow_key *key,
			      const struct nlattr *attr, int len)
    遍历 attr = key->sf_acts->actions,  判断每个 nla_type(attr)

    OVS_ACTION_ATTR_OUTPUT          : prev_port = nla_get_u32(a);
    OVS_ACTION_ATTR_USERSPACE       : output_userspace(dp, skb, key, a, attr, len);
    OVS_ACTION_ATTR_HASH            : execute_hash(skb, key, a);
    OVS_ACTION_ATTR_PUSH_MPLS       : push_mpls(skb, key, nla_data(a));
    OVS_ACTION_ATTR_POP_MPLS        : pop_mpls(skb, key, nla_get_be16(a));
    OVS_ACTION_ATTR_PUSH_VLAN       : push_vlan(skb, key, nla_data(a));
    OVS_ACTION_ATTR_POP_VLAN        : pop_vlan(skb, key);
    OVS_ACTION_ATTR_RECIRC          : execute_recirc(dp, skb, key, a, rem);
	OVS_ACTION_ATTR_SET             : execute_set_action(skb, key, nla_data(a));
    OVS_ACTION_ATTR_SET_MASKED      : execute_masked_set_action(skb, key, nla_data(a));
    OVS_ACTION_ATTR_SET_TO_MASKED   : execute_masked_set_action(skb, key, nla_data(a));
    OVS_ACTION_ATTR_SAMPLE:         : sample(dp, skb, key, a, attr, len);

--------------------------------------------------------------

static int output_userspace(struct datapath *dp, struct sk_buff *skb,
			    struct sw_flow_key *key, const struct nlattr *attr,
			    const struct nlattr *actions, int actions_len)

初始化 upcall, 向用户空间发送 upcall 信息, 具体如下:

	struct dp_upcall_info upcall;
    upcall.cmd = OVS_PACKET_CMD_ACTION
    遍历 attr 的每个元素 a(显然这里的 attr 是一个内嵌 nla 属性), 如果 nla_type(a)

    OVS_USERSPACE_ATTR_USERDATA         : upcall.userdata = a;
    OVS_USERSPACE_ATTR_PID              : upcall.portid   = nla_get_u32(a)
	OVS_USERSPACE_ATTR_EGRESS_TUN_PORT  : upcall.egress_tun_info = info
	OVS_USERSPACE_ATTR_ACTIONS          : upcall.actions  = actions
                                          upcall.actions_len = actions_len;
    (info 来源于ovs_vport_get_egress_tun_info(vport, skb, &info))

	return ovs_dp_upcall(dp, skb, key, &upcall);

--------------------------------------------------------------

static void execute_hash(struct sk_buff *skb, struct sw_flow_key *key,
			 const struct nlattr *attr)
    初始化 key->ovs_flow_hash = jhash_1word(skb_get_hash(skb))

--------------------------------------------------------------

static int execute_recirc(struct datapath *dp, struct sk_buff *skb,
			  struct sw_flow_key *key,
			  const struct nlattr *a, int rem)

    待理解
--------------------------------------------------------------

static int execute_set_action(struct sk_buff *skb,
			      struct sw_flow_key *flow_key,
			      const struct nlattr *a)

    skb->cb->egress_tun_info = nal_data(a)

err = execute_masked_set_action(skb, key, nla_data(a));

--------------------------------------------------------------

static int execute_masked_set_action(struct sk_buff *skb,
				     struct sw_flow_key *flow_key,
				     const struct nlattr *a)

    用 a 对应的值赋值给 flow_key
    判断 nla_type(a)

	OVS_KEY_ATTR_PRIORITY   : flow_key->phy.priority = skb->priority;
	OVS_KEY_ATTR_SKB_MARK   : flow_key->phy.skb_mark = skb->mark
	OVS_KEY_ATTR_TUNNEL_INFO: err
	OVS_KEY_ATTR_ETHERNET   : set_eth_addr(skb, flow_key, nla_data(a), get_mask(a, struct ovs_key_ethernet *))
    OVS_KEY_ATTR_IPV4       : set_ipv4(skb, flow_key, nla_data(a), get_mask(a, struct ovs_key_ipv4 *))
    OVS_KEY_ATTR_IPV6       : set_ipv(skb, flow_key, nla_data(a), get_mask(a, struct ovs_key_ipv6 *))
    OVS_KEY_ATTR_TCP        : set_tcp(skb, flow_key, nla_data(a), get_mask(a, struct ovs_key_tcp *));
    OVS_KEY_ATTR_UDP        : set_udp(skb, flow_key, nla_data(a), get_mask(a, struct ovs_key_udp *));
    OVS_KEY_ATTR_SCTP       : set_sctp(skb, flow_key, nla_data(a), get_mask(a, struct ovs_key_sctp *));
    OVS_KEY_ATTR_MPLS       : set_mpls(skb, flow_key, nla_data(a), get_mask(a, __be32 *));




--------------------------------------------------------------

static int set_eth_addr(struct sk_buff *skb, struct sw_flow_key *flow_key,
			const struct ovs_key_ethernet *key,
			const struct ovs_key_ethernet *mask)

    将 key 的 eth_src, eth_dst 拷贝到 flow_key->eth.src, flow_key->eth.dst

--------------------------------------------------------------

static int set_ipv4(struct sk_buff *skb, struct sw_flow_key *flow_key,
		    const struct ovs_key_ipv4 *key,
		    const struct ovs_key_ipv4 *mask)

    #define MASKED(OLD, KEY, MASK) ((KEY) | ((OLD) & ~(MASK)))
	new_addr = MASKED(nh->saddr, key->ipv4_src, mask->ipv4_src);
    flow_key->ipv4.addr.src = new_addr
	new_addr = MASKED(nh->daddr, key->ipv4_dst, mask->ipv4_dst);
	flow_key->ipv4.addr.dst = new_addr;
	flow_key->ip.tos = nh->tos;
	flow_key->ip.ttl = nh->ttl;

--------------------------------------------------------------

static int sample(struct datapath *dp, struct sk_buff *skb,
		  struct sw_flow_key *key, const struct nlattr *attr,
		  const struct nlattr *actions, int actions_len)

    attr 是内嵌的 nalattr

	const struct nlattr *acts_list = NULL;

    遍历 attr 的每个元素 a
    判断 nla_type(a)
    OVS_SAMPLE_ATTR_PROBABILITY :
    OVS_SAMPLE_ATTR_ACTIONS     :  acts_list = a

    判断 nla_type(nla_data(acts_list))
    OVS_ACTION_ATTR_USERSPACE   output_userspace(dp, skb, key, a, actions, actions_len);

--------------------------------------------------------------
##核心处理逻辑


ovs_dp_process_packet()
    flow = ovs_flow_tbl_lookup_stats(&dp->table, key, skb_get_hash(skb), &n_mask_hit)
     -->true:
            ovs_dp_upcall(dp, skb, key, upcall_info)
            --> skb_is_gso(skb)
                --> queue_gso_packets(dp, skb, key, upcall_info)
            --> !skb_is_gso(skb)
                --> queue_userspace_packet(dp, skb, key, upcall_info)
            n_lost++
     -->false:
            ovs_execute_actions(dp, skb, acts, key)
            --> do_execute_actions(dp, skb, key, flow->sf_acts->actions,
                    flow->sf_acts->actions_len)

###流表动作执行

	核心函数: ovs_execute_actions(dp, skb, flow->sf_acts, key);



###vswitchd 通信 -- netlink upcall

    核心函数: ovs_dp_upcall(dp, skb, key, &upcall);

      Message Format:
         <--- nlmsg_total_size(payload)  --->
         <-- nlmsg_msg_size(payload) ->
        +----------+- - -+-------------+- - -+-------- - -
        | nlmsghdr | Pad |   Payload   | Pad | nlmsghdr
        +----------+- - -+-------------+- - -+-------- - -
        nlmsg_data(nlh)---^                   ^
        nlmsg_next(nlh)-----------------------+

      Payload Format:
         <---------------------- nlmsg_len(nlh) --------------------->
         <------ hdrlen ------>       <- nlmsg_attrlen(nlh, hdrlen) ->
        +----------------------+- - -+--------------------------------+
        |     Family Header    | Pad |           Attributes           |
        +----------------------+- - -+--------------------------------+
        nlmsg_attrdata(nlh, hdrlen)---^
     Attribute Format:
        <------- nla_total_size(payload) ------->
        <---- nla_attr_size(payload) ----->
       +----------+- - -+- - - - - - - - - +- - -+-------- - -
       |  Header  | Pad |     Payload      | Pad |  Header
       +----------+- - -+- - - - - - - - - +- - -+-------- - -
                         <- nla_len(nla) ->      ^
       nla_data(nla)----^                        |
       nla_next(nla)-----------------------------'



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



