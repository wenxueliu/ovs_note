##预备知识

基本的 makefile 语法见[跟我一起写 Makefile](http://blog.csdn.net/haoel/article/details/2886/)

##编译

为了区别 Kbuild Makefile 和 Normal Makefile

```
    ifeq ($(KERNELRELEASE),)
    # We're being called directly by running make in this directory.
    include Makefile.main
    else
    # We're being included by the Linux kernel build system
    include Kbuild
    endif
```

首先执行 Makefile.main.in 然后执行 Kbuild.in

###Makefile.main.in

####@var@

    export builddir = @abs_builddir@
    export srcdir = @abs_srcdir@
    export top_srcdir = @abs_top_srcdir@
    export KSRC = @KBUILD@
    export VERSION = @VERSION@

@var@ 首先包含这种变量的文件一般以in 为后缀. 在运行 ./configure 的时候, 文件的
in 后缀被去掉, 该变量被替换为 ./configure 配置指定的变量

###foreach

    $(foreach var,list,text)


这个函数的意思是, 把参数 list 中的单词逐一取出放到参数 var 所指定的变量中, 然后再执行 text 所包含的表达式.
每一次 text 会返回一个字符串, 循环过程中 text 的所返回的每个字符串会以空格分隔, 最后当整个循环结束时,
text 所返回的每个字符串所组成的整个字符串(以空格分隔)将会是 foreach 函数的返回值。

###eval

```
    define module_template
    $(1)-y = $$(notdir $$(patsubst %.c,%.o,$($(1)_sources)))
    endef

    $(foreach module,$(build_multi_modules),$(eval $(call module_template,$(module))))
```
如果 module = openvswitch, 结果

openvswitch-y= *.c //*.c 为 openvswitch_sources 下的所有 *.c 文件

###Kbuild.in

ccflags-y：$(CC)的编译选项添加这里，宏开关也在这里添加





##数据结构

DP_VPORT_HASH_BUCKETS : 大小是否会影响速率

struct datapath {
	struct rcu_head rcu;
	struct list_head list_node;

	/*
     * Flow table.
     * 每个 datapath 有 255 张 table
     */
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

/**
 * enum ovs_datapath_attr - attributes for %OVS_DP_* commands.
 * @OVS_DP_ATTR_NAME: Name of the network device that serves as the "local
 * port".  This is the name of the network device whose dp_ifindex is given in
 * the &struct ovs_header.  Always present in notifications.  Required in
 * %OVS_DP_NEW requests.  May be used as an alternative to specifying
 * dp_ifindex in other requests (with a dp_ifindex of 0).
 * @OVS_DP_ATTR_UPCALL_PID: The Netlink socket in userspace that is initially
 * set on the datapath port (for OVS_ACTION_ATTR_MISS).  Only valid on
 * %OVS_DP_CMD_NEW requests. A value of zero indicates that upcalls should
 * not be sent.
 * @OVS_DP_ATTR_STATS: Statistics about packets that have passed through the
 * datapath.  Always present in notifications.
 * @OVS_DP_ATTR_MEGAFLOW_STATS: Statistics about mega flow masks usage for the
 * datapath. Always present in notifications.
 *
 * These attributes follow the &struct ovs_header within the Generic Netlink
 * payload for %OVS_DP_* commands.
 */
enum ovs_datapath_attr {
	OVS_DP_ATTR_UNSPEC,
	OVS_DP_ATTR_NAME,		/* name of dp_ifindex netdev */
	OVS_DP_ATTR_UPCALL_PID,		/* Netlink PID to receive upcalls */
	OVS_DP_ATTR_STATS,		/* struct ovs_dp_stats */
	OVS_DP_ATTR_MEGAFLOW_STATS,	/* struct ovs_dp_megaflow_stats */
	OVS_DP_ATTR_USER_FEATURES,	/* OVS_DP_F_*  */
	__OVS_DP_ATTR_MAX
};


/**
 * struct vport - one port within a datapath
 * @rcu: RCU callback head for deferred destruction.
 * @dp: Datapath to which this port belongs.
 * @upcall_portids: RCU protected 'struct vport_portids'.
 * @port_no: Index into @dp's @ports array.
 * @hash_node: Element in @dev_table hash table in vport.c.
 * @dp_hash_node: Element in @datapath->ports hash table in datapath.c.
 * @ops: Class structure.
 * @percpu_stats: Points to per-CPU statistics used and maintained by vport
 * @err_stats: Points to error statistics used and maintained by vport
 * @detach_list: list used for detaching vport in net-exit call.
 */
struct vport {
	struct rcu_head rcu;
	struct datapath	*dp;
	struct vport_portids __rcu *upcall_portids;
	u16 port_no;

	struct hlist_node hash_node;
	struct hlist_node dp_hash_node; --> datapath->vport->first
	const struct vport_ops *ops;

	struct pcpu_sw_netstats __percpu *percpu_stats;

	struct vport_err_stats err_stats;
	struct list_head detach_list;
};

/**
 * struct vport_ops - definition of a type of virtual port
 *
 * @type: %OVS_VPORT_TYPE_* value for this type of virtual port.
 * @create: Create a new vport configured as specified.  On success returns
 * a new vport allocated with ovs_vport_alloc(), otherwise an ERR_PTR() value.
 * @destroy: Destroys a vport.  Must call vport_free() on the vport but not
 * before an RCU grace period has elapsed.
 * @set_options: Modify the configuration of an existing vport.  May be %NULL
 * if modification is not supported.
 * @get_options: Appends vport-specific attributes for the configuration of an
 * existing vport to a &struct sk_buff.  May be %NULL for a vport that does not
 * have any configuration.
 * @get_name: Get the device's name.
 * @send: Send a packet on the device.  Returns the length of the packet sent,
 * zero for dropped packets or negative for error.
 * @get_egress_tun_info: Get the egress tunnel 5-tuple and other info for
 * a packet.
 */
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
	struct list_head list; //连接所有的 vport_ops
};

/**
 * struct vport_portids - array of netlink portids of a vport.
 *                        must be protected by rcu.
 * @rn_ids: The reciprocal value of @n_ids.
 * @rcu: RCU callback head for deferred destruction.
 * @n_ids: Size of @ids array.
 * @ids: Array storing the Netlink socket pids to be used for packets received
 * on this port that miss the flow table.
 */
struct vport_portids {
	struct reciprocal_value rn_ids;
	struct rcu_head rcu;
	u32 n_ids;
	u32 ids[];
};

struct flow_table {
	struct table_instance __rcu *ti;
	struct table_instance __rcu *ufid_ti;
    //每个 CPU 都有的流表的缓存, 只有三条, 索引为 skb->hash & 3
	struct mask_cache_entry __percpu *mask_cache;
    //内核流表项缓存
	struct mask_array __rcu *mask_array;
	unsigned long last_rehash;
	unsigned int count;
	unsigned int ufid_count;
};

//table_instance　的每个 buckets 中保存 sw_flow.
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

struct mask_cache_entry {
	u32 skb_hash;
	u32 mask_index;
};

struct mask_array {
	struct rcu_head rcu;
	int count;
    int max; //最大索引
	struct sw_flow_mask __rcu *masks[];
};

struct sw_flow_mask {
	int ref_count;
	struct rcu_head rcu;
	struct sw_flow_key_range range;
	struct sw_flow_key key;
};

//key 匹配的范围
struct sw_flow_key_range {
	unsigned short int start;
	unsigned short int end;
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

/**
 * struct ovs_net - Per net-namespace data for ovs.
 * @dps: List of datapaths to enable dumping them all out.
 * Protected by genl_mutex.
 * @vport_net: Per network namespace data for vport.
 */
struct ovs_net {
	struct list_head dps;
	struct work_struct dp_notify_work;
	struct vport_net vport_net;
};

--------------------------------------------------------

###static int ovs_dp_cmd_new(struct sk_buff *skb, struct genl_info *info)

    1. 为一个 struct sk_buff 对象 reply 分配内存, 并根据 info 初始化该对象
    2. 为一个 struct datapath 对象 dp 分配内存, 并初始化
    3. 将 info 修改 replay 对象属性, 并将消息返回给发消息者

    其中2:
        dp->net = skb->sk->sk_net
        dp->table = ovs_flow_tbl_init(table)
        dp->stats_percpu 初始化
        dp->ports = kmalloc(DP_VPORT_HASH_BUCKETS * sizeof(struct hlist_head),GFP_KERNEL)
        初始化每个 dp->ports[i] (i=0,DP_VPORT_HASH_BUCKETS)
        dp->user_features = nla_get_u32(a[OVS_DP_ATTR_USER_FEATURES]);
        dp->list_node  加入链表 dp->net[ovs_net_id - 1]


int ovs_flow_tbl_init(struct flow_table *table)

    初始化 flow_table 结构体

    具体:
	table->mask_cache = __alloc_percpu(sizeof(struct mask_cache_entry) *
					  MC_HASH_ENTRIES, __alignof__(struct mask_cache_entry));

    //TBL_MIN_BUCKETS=1024
    table->ti = kmalloc(sizeof(*ti), GFP_KERNEL) table_instance_alloc();
    table->ti->buckets = alloc_buckets(TBL_MIN_BUCKETS)
	table->ti->n_buckets = new_size;
	table->ti->node_ver = 0;
	table->ti->keep_flows = false;
	get_random_bytes(&table->ti->hash_seed, sizeof(u32));

    //TBL_MIN_BUCKETS=1024
    table->ufid_ti = kmalloc(sizeof(*ti), GFP_KERNEL) 
	table->ufid_ti->buckets = alloc_buckets(new_size);
	table->ufid_ti->n_buckets = TBL_MIN_BUCKETS;
	table->ufid_ti->node_ver = 0;
	table->ufid_ti->keep_flows = false;
	get_random_bytes(&table->ufid_ti->hash_seed, sizeof(u32));

    //MASK_ARRAY_SIZE_MIN=16
    table->mask_array = new  kzalloc(sizeof(struct mask_array) +
		      sizeof(struct sw_flow_mask *) * MASK_ARRAY_SIZE_MIN, GFP_KERNEL);
	table->mask_array->count = 0
	table->mask_array->max = MASK_ARRAY_SIZE_MIN

    table->last_rehash = jiffies
	table->count = 0;
	table->ufid_count = 0;


static struct table_instance *table_instance_alloc(int new_size)

    初始化一个 table_instance 结构体, 返回结构体的指针 ti

    ti->buckets = alloc_buckets(new_size)
    ti->n_buckets = new_size

    alloc_buckets(unsigned int n_buckets)

    flex_array_alloc(sizeof(struct hlist_head), n_buckets, GFP_KERNEL) 分配 new_size 个 hlist_head


    #define flex_array_alloc rpl_flex_array_alloc

struct flex_array *rpl_flex_array_alloc(int element_size, unsigned int
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


static int ovs_dp_cmd_fill_info(struct datapath *dp, struct sk_buff *skb,
				u32 portid, u32 seq, u32 flags, u8 cmd)

	get_dp_stats(dp, &dp_stats, &dp_megaflow_stats);

	ovs_header = genlmsg_put(skb, portid, seq, &dp_datapath_genl_family,
				   flags, cmd);
	ovs_header->dp_ifindex = get_dpifindex(dp);
	nla_put_string(skb, OVS_DP_ATTR_NAME, ovs_dp_name(dp));
    nla_put(skb, OVS_DP_ATTR_STATS, sizeof(struct ovs_dp_stats),&dp_stats)
    nla_put(skb, OVS_DP_ATTR_MEGAFLOW_STATS, sizeof(struct ovs_dp_megaflow_stats), &dp_megaflow_stats)
    nla_put_u32(skb, OVS_DP_ATTR_USER_FEATURES, dp->user_features)
	genlmsg_end(skb, ovs_header);


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

static void do_output(struct datapath *dp, struct sk_buff *skb, int out_port)

    如果从 dp 中找到 port_no = out_port 的 vport, 调用 ovs_vport_send(vport, skb);
    否则释放 skb

--------------------------------------------------------------

int ovs_vport_send(struct vport *vport, struct sk_buff *skb)

调用 vport->pos->send(vport, skb), 发送 skb 到 vport, 返回发送
的字节数

--------------------------------------------------------------
static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			      struct sw_flow_key *key,
			      const struct nlattr *attr, int len)
    遍历 attr = key->sf_acts->actions,  判断每个 nla_type(attr)

    OVS_ACTION_ATTR_OUTPUT          : do_output(dp, out_skb, nla_get_u32(a));
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


--------------------------------------------------------------

static int execute_masked_set_action(struct sk_buff *skb,
				     struct sw_flow_key *flow_key,
				     const struct nlattr *a)


    用 a 对应的值赋值给 flow_key
    判断 nla_type(a)

    //其中 nla_mask(a) 紧邻 nla_data(a) 之后存放, 而且 nla_mask(a) 与 nla_data(a) 类型完全一致, 因此可以做好掩码
	OVS_KEY_ATTR_PRIORITY
                            skb->priority = (nla_data(a) | skb->priority & nla_mask(a))
                            flow_key->phy.priority = skb->priority;
	OVS_KEY_ATTR_SKB_MARK
                            skb->mask = (nla_data(a) | skb->priority & nla_mask(a))
                            flow_key->phy.skb_mark = skb->mark

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

    //校验和
    skb->csum = csum_sub(skb->csum, csum_partial(start, len, 0));

    eth_hdr(skb)->h_source = key->eth_src & ~mask->eth_src
    eth_hdr(skb)->h_dest = key->eth_dst & ~mask->eth_dst

    //重新计算 skb->csum
    skb->csum = csum_add(skb->csum, csum_partial(start, len, 0))

    flow_key->eth_src = eth_hdr(skb)->h_source
    flow_key->eth_dst = eth_hdr(skb)->h_dest

--------------------------------------------------------------

static int set_ipv4(struct sk_buff *skb, struct sw_flow_key *flow_key,
		    const struct ovs_key_ipv4 *key,
		    const struct ovs_key_ipv4 *mask)

    #define MASKED(OLD, KEY, MASK) ((KEY) | ((OLD) & ~(MASK)))
	nh = ip_hdr(skb);
	new_addr = MASKED(nh->saddr, key->ipv4_src, mask->ipv4_src);

    new_addr = key->ipv4_src | (ip_hdr(skb)->saddr & ~mask->ipv4_src)
    ip_hdr(skb)->saddr = new_addr
    flow_key->ipv4.addr.src = new_addr

    new_addr = key->ipv4_dst | (ip_hdr(skb)->daddr & ~mask->ipv4_dst)
    ip_hdr(skb)->daddr = new_addr
	flow_key->ipv4.addr.dst = new_addr;

    ip_hdr(skb)->tos = key->ipv4_tos | (ip_hdr(skb)->tos & ~mask->ipv4_tos)
	flow_key->ip.tos = ip_hdr(skb)->tos;
	flow_key->ip.ttl = ip_hdr(skb)->ttl;

--------------------------------------------------------------

static int set_tcp(struct sk_buff *skb, struct sw_flow_key *flow_key,
		   const struct ovs_key_tcp *key,
		   const struct ovs_key_tcp *mask)

    tcp_hdr(skb)->source = key->tcp_src | (tcp_hdr(skb)->source & ~mask->tcp_src)
    flow_key->tp.src = tcp_hdr(skb)->source

    tcp_hdr(skb)->dest = key->tcp_dst | (tcp_hdr(skb)->dest & ~mask->tcp_dst)
    flow_key->tp.src = tcp_hdr(skb)->dest

--------------------------------------------------------------
static int sample(struct datapath *dp, struct sk_buff *skb,
		  struct sw_flow_key *key, const struct nlattr *attr,
		  const struct nlattr *actions, int actions_len)

    attr 是内嵌的 actions 内嵌的 nlattr

	const struct nlattr *acts_list = NULL;

    遍历 attr 的每个元素 a
    判断 nla_type(a)
    OVS_SAMPLE_ATTR_PROBABILITY :
    OVS_SAMPLE_ATTR_ACTIONS     :  acts_list = a

    判断 nla_type(nla_data(acts_list))
    OVS_ACTION_ATTR_USERSPACE   output_userspace(dp, skb, key, a, actions, actions_len);

--------------------------------------------------------------

struct ovs_gso_cb {
	struct ovs_skb_cb dp_cb;
	gso_fix_segment_t fix_segment;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
	__be16		inner_protocol;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	unsigned int	inner_mac_header;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
	unsigned int	inner_network_header;
#endif
};
#define OVS_GSO_CB(skb) ((struct ovs_gso_cb *)(skb)->cb)

--------------------------------------------------------------

/**
 * struct ovs_skb_cb - OVS data in skb CB
 * @egress_tun_info: Tunnel information about this packet on egress path.
 * NULL if the packet is not being tunneled.
 * @input_vport: The original vport packet came in on. This value is cached
 * when a packet is received by OVS.
 */
struct ovs_skb_cb {
	struct ovs_tunnel_info  *egress_tun_info;
	struct vport		*input_vport;
};
#define OVS_CB(skb) ((struct ovs_skb_cb *)(skb)->cb)

--------------------------------------------------------------

void ovs_vport_receive(struct vport *vport, struct sk_buff *skb,
		       const struct ovs_tunnel_info *tun_info)

	OVS_CB(skb)->input_vport = vport;
	OVS_CB(skb)->egress_tun_info = NULL;
	ovs_flow_key_extract(tun_info, skb, &key);
	ovs_dp_process_packet(skb, &key);

--------------------------------------------------------------

int ovs_flow_key_extract(const struct ovs_tunnel_info *tun_info,
			 struct sk_buff *skb, struct sw_flow_key *key)

    如果 tun_info 不为 null
        key->tun_key = tun_info->tunnel
        key->tun_opts = tun_info->options
        key->tun_opts_len = tun_info->options_len

    key->tun_key = {0}
	key->tun_opts_len = 0;
	key->phy.priority = skb->priority;
	key->phy.in_port = OVS_CB(skb)->input_vport->port_no;
	key->phy.skb_mark = skb->mark;
	key->ovs_flow_hash = 0;
	key->recirc_id = 0;
    其余见 key_extract()

--------------------------------------------------------------
static int key_extract(struct sk_buff *skb, struct sw_flow_key *key)

    此时 skb->data 必须指向 eth 头

    key->tp.flas = 0;
    eth = ethhdr(skb->head + skb->data)
    key->eth.src = eth->h_source
    key->eth.dst = eth->h_dest

    #define ETH_P_8021Q     0x8100

    key->eth.tci = 0 或 0x1000

    如果是 802.3 #define ETH_P_802_3     0x0001
        key->eth.type = (__be16)skb->data

    如果是 LLC 并且 LLC ethertype 为 802.3
        key->eth.type = (__be16)skb->data
    否则 #define ETH_P_802_2     0x0004
        key->eth.type = 0 或 0x0004

    //IPV4
    key->ipv4.addr.src = nh->saddr
	key->ipv4.addr.dst = nh->daddr;
	key->ip.proto = nh->protocol;
	key->ip.tos = nh->tos;
	key->ip.ttl = nh->ttl;
    key->ip.frag = OVS_FRAG_TYPE_FIRST 或 OVS_FRAG_TYPE_LATER 或 OVS_FRAG_TYPE_NONE
    //TCP
    key->tp.src = tcp->source
    key->tp.dst = tcp->dest
    key->tp.flags = tcp->words[3] & htons(0x0FFF)
    //UDP
    key->tp.src = udp->source
    key->tp.dst = udp->dest
    //SCTP
    key->tp.src = sctp->source
    key->tp.dst = sctp->dest
    //ICMP
    key->tp.src = htons(icmp->type)
    key->tp.dst = htons(icmp->code)

    //ARP RARP
    key->ip.proto = ntohs(arp->ar_op) 或 0
    key->ipv4.addr.src = arp->ar_sip
    key->ipv4.addr.dst = arp->ar_tip
    key->ipv4.arp.sha  = arp->ar_sha
    key->ipv4.arp.tha  = arp->ar_tha


--------------------------------------------------------------

#define VLAN_CFI_MASK           0x1000 /* Canonical Format Indicator */
#define VLAN_TAG_PRESENT        VLAN_CFI_MASK
#define skb_vlan_tag_present(__skb)     ((__skb)->vlan_tci & VLAN_TAG_PRESENT)

如果包含 VLAN, skb_vlan_tag_present 就不会为 0, 也即 skb->vlan_tci = 0x1000

-------------------------------------------------------------
void ovs_dp_process_packet(struct sk_buff *skb, struct sw_flow_key *key)

	flow = ovs_flow_tbl_lookup_stats(&dp->table, key, skb_get_hash(skb),
    if (!flow) --> ovs_dp_upcall(dp, skb, key, &upcall);
                   ovs_execute_actions(dp, skb, sf_acts, key);
    else       --> ovs_execute_actions(dp, skb, sf_acts, key);

-------------------------------------------------------------
struct sw_flow *ovs_flow_tbl_lookup_stats(struct flow_table *tbl,
					  const struct sw_flow_key *key,
					  u32 skb_hash,
					  u32 *n_mask_hit)

     skb_hash 唯一鉴别一条 flow, 不同的 flow 应该有不同的 hash, 相同的 flow 应该有相同的 hash

    如果 skb_hash = 0
	return flow_lookup(tbl, ti, ma, key, n_mask_hit, &mask_index);

    否则 先查 CPU 缓存, 再查内核缓存
        entries = tbl->mask_cache
        取 skb_hash 每个字节的低两位为 index
        如果 entries[index] = skb_hash 这 entries 是每个 CPU 缓存的流表; return flow_lookup(tbl, ti, ma, key, 0,&e->mask_index);
        否则 ce = (e->skb_hash 最小值) flow = flow_lookup(tbl, ti, ma, key, 0, &ce->mask_index);

-------------------------------------------------------------
static struct sw_flow *flow_lookup(struct flow_table *tbl,
				   struct table_instance *ti,
				   const struct mask_array *ma,
				   const struct sw_flow_key *key,
				   u32 *n_mask_hit,
				   u32 *index)

    充分利用 CPU 缓存
    如果 index < ma->max;  返回 masked_flow_lookup(ti, key, ma->mask[*index], n_mask_hit)
    否则 遍历 ma 数组所有元素 i, 如果 ma->masks[i] != 0; 返回 masked_flow_lookup(ti, key, ma->mask[i], n_mask_hit)

-------------------------------------------------------------
static struct sw_flow *masked_flow_lookup(struct table_instance *ti,
					  const struct sw_flow_key *unmasked,
					  const struct sw_flow_mask *mask,
					  u32 *n_mask_hit)

	struct sw_flow *flow;
	struct sw_flow_key masked_key;
	struct hlist_head *head;

    //从 mask unmasked 获取 masked_key
	ovs_flow_mask_key(&masked_key, unmasked, mask);

    //找到 ti 合适的 bucket
    hash = jhash2(masked_key+mask->range->start, (mask->ranger->end - mask->ranger->start)>>2, 0)
	head = flex_array_get(ti->buckets, jhash_1word(hash, ti->hash_seed) & (ti->n_buckets - 1));

    //遍历 ti 的每个 bucket 中的每条 sw_flow 直到找到满足如下条件的 flow
	hlist_for_each_entry_rcu(flow, head, flow_table.node[ti->node_ver])
		if (flow->mask == mask && flow->flow_table.hash == hash &&
		    flow_cmp_masked_key(flow, &masked_key, &mask->range))
			return flow;

-------------------------------------------------------------

void ovs_flow_mask_key(struct sw_flow_key *dst, const struct sw_flow_key *src,
		       const struct sw_flow_mask *mask)
    通过 mask->key 和 src 逻辑运算与, 获取 dst

-------------------------------------------------------------

static u32 flow_hash(const struct sw_flow_key *key,
		     const struct sw_flow_key_range *range)
    通过　jhash2 计算 hash
    jhash2(key+range->start, (ranger->end - ranger->start)>>2, 0)

-------------------------------------------------------------

static struct hlist_head *find_bucket(struct table_instance *ti, u32 hash)

	return flex_array_get(ti->buckets, jhash_1word(hash, ti->hash_seed) & (ti->n_buckets - 1));

-------------------------------------------------------------

##核心处理逻辑

    创建 netdev_create(const struct vport_parms *parms) 的注册的 rx_handler_result_t netdev_frame_hook( pskb)

    rx_handler_result_t netdev_frame_hook( pskb)
    -->netdev_port_receive(vport, skb)
       -->ovs_vport_receive(vport, skb, NULL)
          -->ovs_flow_key_extract()
             -->ovs_dp_process_packet()
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

        <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
        +---------------------+- - -+- - - - - - - - - -+- - -+
        |        Header       | Pad |     Payload       | Pad |
        |   (struct nlattr)   | ing |                   | ing |
        +---------------------+- - -+- - - - - - - - - -+- - -+
        <-------------- nlattr->nla_len -------------->

        nla_type (16 bits)
         +---+---+-------------------------------+
         | N | O | Attribute Type                |
         +---+---+-------------------------------+
         N := Carries nested attributes
         O := Payload stored in network byte order

         Note: The N and O flag are mutually exclusive.



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

## datapath 初始化

1 action_fifos_init();
2 ovs_internal_dev_rtnl_link_register();
3 ovs_flow_init();
4 ovs_vport_init();
5 register_pernet_device(&ovs_net_ops);
6 register_netdevice_notifier(&ovs_dp_device_notifier);
7 ovs_netdev_init();
8 dp_register_genl();

对应于

1 分配一个动态的　percpu 区域初始化 action_fifos
2 将 internal_dev_link_ops 加入 linux/rtnetlink.h 中 link_ops 双向链表中,
  将 ovs_internal_vport_ops 加入 vport.c 中的 vport_ops_list 双向链表中
3 从内核缓存区初始化 sw_flow, sw_flow_stats 两块内存
4 分配 1024 个 hlist_head(hash 桶的大小) 初始化 dev_table
5 将 ovs_net_ops 操作, 注册到所有命名空间
6 将 ovs_dp_device_notifier 注册一个网络通知
7 将 ovs_netdev_vport_ops 注册到所有命名空间
8 将 dp_genl_families  中所有元素注册到 generic netlink family


##action

###action_fifos_init()

分配一个动态的　percpu 区域初始化 action_fifos

static struct action_fifo __percpu *action_fifos;
action_fifos = alloc_percpu(struct action_fifo);

#define DEFERRED_ACTION_FIFO_SIZE 10
struct deferred_action {
	struct sk_buff *skb;
	const struct nlattr *actions;

	/* Store pkt_key clone when creating deferred action. */
	struct sw_flow_key pkt_key;
};

struct action_fifo {
	int head;
	int tail;
	/* Deferred action fifo queue storage. */
	struct deferred_action fifo[DEFERRED_ACTION_FIFO_SIZE];
};


##vport-internal_dev

----------------------------------------------

###int ovs_internal_dev_rtnl_link_register(void)

将 internal_dev_link_ops 加入 linux/rtnetlink.h 中 link_ops 双向链表中
将 ovs_internal_vport_ops 加入 vport.c 中的全局变量 vport_ops_list 双向链表中

实现机制:

    static struct rtnl_link_ops internal_dev_link_ops __read_mostly = {
        .kind = "openvswitch",
    };
    rtnl_link_register(&internal_dev_link_ops);

    static LIST_HEAD(vport_ops_list);
    static struct vport_ops ovs_internal_vport_ops = {
        .type		= OVS_VPORT_TYPE_INTERNAL,
        .create		= internal_dev_create,
        .destroy	= internal_dev_destroy,
        .get_name	= ovs_netdev_get_name,
        .send		= internal_dev_recv,
    };
    ovs_vport_ops_register(&ovs_internal_vport_ops);

int ovs_vport_ops_register(struct vport_ops *ops)

    将 ovs_internal_vport_ops 加入 vport.c 中的全局变量 vport_ops_list 双向链表中

    其中
        static struct vport_ops ovs_internal_vport_ops = {
            .type		= OVS_VPORT_TYPE_INTERNAL,
            .create		= internal_dev_create,
            .destroy	= internal_dev_destroy,
            .get_name	= ovs_netdev_get_name,
            .send		= internal_dev_recv,
        };

----------------------------------------------

###static struct vport *internal_dev_create(const struct vport_parms *parms)

     将 vport 与一个 net_device 关联, 然后注册 net_device

    1. 初始化 vport, 其私有数据为 sizeof(struct netdev_vport)
    2. 初始化 vport 的私有数据为一个 struct net_device 设备 netdev_vport. 启动函数为 do_setup
    3. 初始化 netdev_vport 的私有数据为一个 struct internal_dev 对象 internal_dev. 其 vport 指向 1 初始化的 vport
    4. 如果 vport->port_no = OVSP_LOCAL, netdev_vport->dev 增加特性 NETIF_F_NETNS_LOCAL(具体含义待理解);
    5. 注册 netdev_vport 到网络驱动中, 并设置为混杂模式
    6. 允许上层设备调用netdev_vport 的 hard_start_xmit routine

    其中2 包括:
    netdev_vport->name = params->name
    netdev_vport->net = vport->dp->net

    struct netdev_vport {
        struct rcu_head rcu;
        struct net_device *dev;
    };

struct vport *ovs_vport_alloc(int priv_size, const struct vport_ops *ops,
			      const struct vport_parms *parms)

    初始化　struct vport 指针
    1. 为 vport  分配 sizeof(struct vport) + priv_size 内存, VPORT_ALIGN 对齐
    2. vport->dp = params->dp
    3. vport->port_no = parms->port_no
    4. vport->opst = ops;
    5. 初始化 hash 链表  vport->dp_hash_node
    6. 初始化 vport->upcall_portids
    7. 初始化 vport->percpu_stats

    其中
    vport->upcall_portids->n_ids = nla_len(ids) / sizeof(u32)
    vport->upcall_portids->rn_ids = reciprocal_value(vport->upcall_portids->n_ids)
    vport->upcall_portids->ids = ids

    vport->ops 包括:
        .type		= OVS_VPORT_TYPE_INTERNAL,
        .create		= internal_dev_create,
        .destroy	= internal_dev_destroy,
        .get_name	= ovs_netdev_get_name,
        .send		= internal_dev_recv,

    注:
    1. 对照 vport 数据结构发现: hash_node err_stats detach_list 没有初始化
    2. 对 vport 分配了私有数据, 这内核 net_device 的惯例

static void do_setup(struct net_device *netdev)

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

    //分配随机的 MAC 地址
	eth_hw_addr_random(netdev);

    其中
    internal_dev_netdev_ops = {
        //开启
        .ndo_open = internal_dev_open,
        //关闭
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
        //获取状态如接收,传输的包数, 错误和丢弃的包数
        .ndo_get_stats = internal_dev_sys_stats,
    #endif
    };

    internal_dev_ethtool_ops = {
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

    internal_dev_link_ops __read_mostly = {
        .kind = "openvswitch",
    };

----------------------------------------------

###static void internal_dev_destroy(struct vport *vport)

1 停止 vport 所在网络设备
2 取消混杂模式
3 退出设备驱动

----------------------------------------------

###const char *ovs_netdev_get_name(const struct vport *vport)

获取 vport 所在网络设备的名称

----------------------------------------------

###static int internal_dev_recv(struct vport *vport, struct sk_buff *skb)

	len = skb->len;

    //skb->_refdst = 0
	skb_dst_drop(skb);
    //skb->nfct = NULL
	nf_reset(skb);
    //skb->sp = NULL
	secpath_reset(skb);

	skb->dev = netdev;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, netdev);
	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);

    //将 skb 加入当前 CPU 的 backlog
	netif_rx(skb);
	return len;

----------------------------------------------





##flow_table

----------------------------------------------
int ovs_flow_init(void)

    从内核缓存区初始化 sw_flow sw_flow_stats 两块内存

    static struct kmem_cache *flow_cache;
    struct kmem_cache *flow_stats_cache __read_mostly;
	flow_cache = kmem_cache_create("sw_flow", sizeof(struct sw_flow)
				       + (nr_node_ids
					  * sizeof(struct flow_stats *)),
				       0, 0, NULL);
	flow_stats_cache
		= kmem_cache_create("sw_flow_stats", sizeof(struct flow_stats),
				    0, SLAB_HWCACHE_ALIGN, NULL);

    nr_node_ids = 1
----------------------------------------------

##vport

----------------------------------------------

int ovs_vport_init(void)

    分配 1024 个 hlist_head(hash 桶的大小) 初始化 dev_table

    static struct hlist_head *dev_table;
    #define VPORT_HASH_BUCKETS 1024
	dev_table = kzalloc(VPORT_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);

----------------------------------------------

int ovs_vport_ops_register(struct vport_ops *ops)

    将 ops 加入 vport_ops_list 中(前提是 vport_ops_list 中每个元素的 type 是唯一的)

----------------------------------------------


----------------------------------------------

int ovs_vport_set_upcall_portids(struct vport *vport, const struct nlattr *ids)

    初始化或更新 vport->upcall_portids
    1. 分配 sizeof(struct vport_portids) + nla_len(ids) 内存
    2. vport->upcall_portids->n_ids = nla_len(ids) / sizeof(u32)
    3. vport->upcall_portids->rn_ids = reciprocal_value(vport->upcall_portids->n_ids)
    4. vport->upcall_portids->ids = ids

----------------------------------------------

##net_namespace

----------------------------------------------
static struct pernet_operations ovs_net_ops = {
	.init = ovs_init_net,
	.exit = ovs_exit_net,
	.id   = &ovs_net_id,
	.size = sizeof(struct ovs_net),
};

/**
 *      register_pernet_device - register a network namespace device
 *      @ops:  pernet operations structure for the subsystem
 *
 *      Register a device which has init and exit functions
 *      that are called when network namespaces are created and
 *      destroyed respectively.
 *
 *      When registered all network namespace init functions are
 *      called for every existing network namespace.  Allowing kernel
 *      modules to have a race free view of the set of network spaces.
 *
 *      When a new network namespace is created all of the init
 *      methods are called in the order in which they were registered.
 *
 *      When a network namespace is destroyed all of the exit methods
 *      are called in the reverse of the order with which they were
 *      registered.
 */
int register_pernet_device(struct pernet_operations *ops)

    将 ops->list 加入 linux/net_namespace.h pernet_list 双向链表中
    linux/net_namespace.h 从 net_namespace_list 开始遍历所有的 struct net
    1. 分配 ops->size 内存空间 data 并且 net->gen->ptr[id-1] = data
    2. 调用 ops->init(net)
    3. 将 net->exit_list 加入 net_exit_list 双向链表中

    注册一个 net namespace 设备, 当 net namespace 创建的时候调用
    ops->init 在 net namespace 销毁的时候调用 ops->exit

    NOTE: net_namespace_list, net_exit_list 都是 net_namespace.h 中 head_list 类型的全局变量,


static int __net_init ovs_init_net(struct net *net)

    用 net->gen->ptr[ovs_net_id - 1] 初始化结构体 ovs_net

    1. 定义 ovs_net 指向 net->gen->ptr[ovs_net_id - 1]
    2. 初始化双向链表 ovs_net->dps
    3. 初始化 ovs_net->dp_notify_work

	INIT_WORK(&ovs_net->dp_notify_work, ovs_dp_notify_wq);
    其中 3:
        ovs_net->dp_notify_work->data = WORK_STRUCT_NO_POOL
        初始化双向循环链表 ovs_net->dp_notify_work->entry
        ovs_net->dp_notify_work->func = ovs_dp_notify_wq

    注: 没有初始化 ovs_net-> vport_net

    struct ovs_net {
        struct list_head dps;
        struct work_struct dp_notify_work;
        struct vport_net vport_net;
    };

static void __net_exit ovs_exit_net(struct net *dnet)

    1. 遍历 dnet->gen->ptr[ovs_net_id - 1]->dps, 释放每一个 dps
    2. 遍历系统 net_namespace_list 中所有的命名空间对应的网络 struct net,
    遍历每个网络 net->gen->ptr[ovs_net_id - 1]->dps 中每个 dps 中的每个 vport,
    如果 vport->ops->type = OVS_VPORT_TYPE_INTERNAL && netdev_vport_priv(vport)->dev->net = dnet
    将 vport->deatch_list 增加到一个链表 head 中, 然后遍历 head 链表, 销毁对应的 vport.
    4. 取消 net->gen->ptr[ovs_net_id - 1]->dp_notify_work

    其中 3 包括:
    将 vport->deatch_list 从其对应的链表中删除;
    将 vport->dp_hash_node 从其对应的链表中删除;
    将 vport->hash_node 从其对应的链表中删除;
    递减 vport->ops->owner 的引用计数
    调用 vport->ops->destory(vport) 将其自身销毁

----------------------------------------------

/**
 *      register_netdevice_notifier - register a network notifier
 *      @nb: notifier
 *
 *      Register a notifier to be called when network device events .
 *      The notifier passed is linked into the kernel structures and
 *      not be reused until it has been unregistered. A negative code
 *      is returned on a failure.
 *
 *      When registered all registration and up events are replayed
 *      to the new notifier to allow device to have a race free
 *      view of the network device list.
 */

int register_netdevice_notifier(&ovs_dp_device_notifier);

    struct notifier_block ovs_dp_device_notifier = {
        .notifier_call = dp_device_event
    };


static int dp_device_event(struct notifier_block *unused, unsigned long event,
			   void *ptr)

    如果 ptr->dev->netdev_ops != internal_dev_netdev_ops 直接返回
    如果 event 是 NETDEV_UNREGISTER, 将 ptr->dev->dp_notify_work 加入 system_wq

----------------------------------------------

##vport_netdev

static struct vport_ops ovs_netdev_vport_ops = {
    .type		= OVS_VPORT_TYPE_NETDEV,
    .create		= netdev_create,
    .destroy	= netdev_destroy,
    .get_name	= ovs_netdev_get_name,
    .send		= netdev_send,
};

int __init ovs_netdev_init(void)
{
    return ovs_vport_ops_register(&ovs_netdev_vport_ops);
}

int ovs_vport_ops_register(struct vport_ops *ops)

    将 ovs_netdev_vport_ops 加入 vport.c 中的全局变量 vport_ops_list 双向链表中

    其中
        static struct vport_ops ovs_netdev_vport_ops = {
            .type		= OVS_VPORT_TYPE_NETDEV,
            .create		= netdev_create,
            .destroy	= netdev_destroy,
            .get_name	= ovs_netdev_get_name,
            .send		= netdev_send,
        };

static struct vport *netdev_create(const struct vport_parms *parms)

    为 vport 分配内存, 其私有数据大小为 struct netdev_vport, 并初始化

    1. 初始化 vport, 其私有数据为 sizeof(struct netdev_vport)
    2. 确保 netdev_vport->flags & IFF_LOOPBACK = 0; netdev_vport->dev->type =
    ARPHRD_ETHER, netdev_vport->dev->ops != internal_dev_netdev_ops
    3. 从 vport->dp->ports[0] 找到 端口号为 0 的 vp, 将 netdev_vport->dev 增加到 netdev_vport_priv(vp)->dev
    4. 为 netdev_vport 注册一个接受处理器 netdev_frame_hook
    5. 设置 netdev 为混杂模式
	6. netdev_vport->dev->priv_flags |= IFF_OVS_DATAPATH;

static rx_handler_result_t netdev_frame_hook(struct sk_buff **pskb)

	struct sk_buff *skb = *pskb;
	vport = ovs_netdev_get_vport(skb->dev);
    调用 netdev_port_receive(vport, skb)

static void netdev_destroy(struct vport *vport)

    获取 vport 的私有数据, 当 netdev_vport_priv(vport) 的所有读者都读完后, 销毁 netdev_vport_priv(vport)

------------------------------------------------

##datapath

------------------------------------------------
static struct genl_family * const dp_genl_families[] = {
	&dp_datapath_genl_family,
	&dp_vport_genl_family,
	&dp_flow_genl_family,
	&dp_packet_genl_family,
};


/**
 * enum ovs_datapath_attr - attributes for %OVS_DP_* commands.
 * @OVS_DP_ATTR_NAME: Name of the network device that serves as the "local
 * port".  This is the name of the network device whose dp_ifindex is given in
 * the &struct ovs_header.  Always present in notifications.  Required in
 * %OVS_DP_NEW requests.  May be used as an alternative to specifying
 * dp_ifindex in other requests (with a dp_ifindex of 0).
 * @OVS_DP_ATTR_UPCALL_PID: The Netlink socket in userspace that is initially
 * set on the datapath port (for OVS_ACTION_ATTR_MISS).  Only valid on
 * %OVS_DP_CMD_NEW requests. A value of zero indicates that upcalls should
 * not be sent.
 * @OVS_DP_ATTR_STATS: Statistics about packets that have passed through the
 * datapath.  Always present in notifications.
 * @OVS_DP_ATTR_MEGAFLOW_STATS: Statistics about mega flow masks usage for the
 * datapath. Always present in notifications.
 *
 * These attributes follow the &struct ovs_header within the Generic Netlink
 * payload for %OVS_DP_* commands.
 */
enum ovs_datapath_attr {
	OVS_DP_ATTR_UNSPEC,
	OVS_DP_ATTR_NAME,		/* name of dp_ifindex netdev */
	OVS_DP_ATTR_UPCALL_PID,		/* Netlink PID to receive upcalls */
	OVS_DP_ATTR_STATS,		/* struct ovs_dp_stats */
	OVS_DP_ATTR_MEGAFLOW_STATS,	/* struct ovs_dp_megaflow_stats */
	OVS_DP_ATTR_USER_FEATURES,	/* OVS_DP_F_*  */
	__OVS_DP_ATTR_MAX
};



static const struct genl_multicast_group ovs_dp_datapath_multicast_group = {
	.name = OVS_DATAPATH_MCGROUP,
};

###datapath

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


#define OVS_DATAPATH_FAMILY  "ovs_datapath"
#define OVS_DATAPATH_VERSION 2
#define OVS_DP_ATTR_MAX (__OVS_DP_ATTR_MAX - 1)

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

enum ovs_datapath_cmd {
	OVS_DP_CMD_UNSPEC,
	OVS_DP_CMD_NEW,
	OVS_DP_CMD_DEL,
	OVS_DP_CMD_GET,
	OVS_DP_CMD_SET
};

#define OVS_DP_ATTR_MAX (__OVS_DP_ATTR_MAX - 1)
static const struct nla_policy datapath_policy[OVS_DP_ATTR_MAX + 1] = {
	[OVS_DP_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[OVS_DP_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_DP_ATTR_USER_FEATURES] = { .type = NLA_U32 },
};

-----------------------------------------------

#define OVS_VPORT_FAMILY  "ovs_vport"

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

const struct genl_multicast_group ovs_dp_vport_multicast_group = {
	.name = OVS_VPORT_MCGROUP,
};

#define OVS_VPORT_MCGROUP "ovs_vport"

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

------------------------------------------------

#define OVS_FLOW_FAMILY  "ovs_flow"
#define OVS_FLOW_VERSION 0x1

/**
 * enum ovs_flow_attr - attributes for %OVS_FLOW_* commands.
 * @OVS_FLOW_ATTR_KEY: Nested %OVS_KEY_ATTR_* attributes specifying the flow
 * key.  Always present in notifications.  Required for all requests (except
 * dumps).
 * @OVS_FLOW_ATTR_ACTIONS: Nested %OVS_ACTION_ATTR_* attributes specifying
 * the actions to take for packets that match the key.  Always present in
 * notifications.  Required for %OVS_FLOW_CMD_NEW requests, optional for
 * %OVS_FLOW_CMD_SET requests.  An %OVS_FLOW_CMD_SET without
 * %OVS_FLOW_ATTR_ACTIONS will not modify the actions.  To clear the actions,
 * an %OVS_FLOW_ATTR_ACTIONS without any nested attributes must be given.
 * @OVS_FLOW_ATTR_STATS: &struct ovs_flow_stats giving statistics for this
 * flow.  Present in notifications if the stats would be nonzero.  Ignored in
 * requests.
 * @OVS_FLOW_ATTR_TCP_FLAGS: An 8-bit value giving the OR'd value of all of the
 * TCP flags seen on packets in this flow.  Only present in notifications for
 * TCP flows, and only if it would be nonzero.  Ignored in requests.
 * @OVS_FLOW_ATTR_USED: A 64-bit integer giving the time, in milliseconds on
 * the system monotonic clock, at which a packet was last processed for this
 * flow.  Only present in notifications if a packet has been processed for this
 * flow.  Ignored in requests.
 * @OVS_FLOW_ATTR_CLEAR: If present in a %OVS_FLOW_CMD_SET request, clears the
 * last-used time, accumulated TCP flags, and statistics for this flow.
 * Otherwise ignored in requests.  Never present in notifications.
 * @OVS_FLOW_ATTR_MASK: Nested %OVS_KEY_ATTR_* attributes specifying the
 * mask bits for wildcarded flow match. Mask bit value '1' specifies exact
 * match with corresponding flow key bit, while mask bit value '0' specifies
 * a wildcarded match. Omitting attribute is treated as wildcarding all
 * corresponding fields. Optional for all requests. If not present,
 * all flow key bits are exact match bits.
 * @OVS_FLOW_ATTR_UFID: A value between 1-16 octets specifying a unique
 * identifier for the flow. Causes the flow to be indexed by this value rather
 * than the value of the %OVS_FLOW_ATTR_KEY attribute. Optional for all
 * requests. Present in notifications if the flow was created with this
 * attribute.
 * @OVS_FLOW_ATTR_UFID_FLAGS: A 32-bit value of OR'd %OVS_UFID_F_*
 * flags that provide alternative semantics for flow installation and
 * retrieval. Optional for all requests.
 *
 * These attributes follow the &struct ovs_header within the Generic Netlink
 * payload for %OVS_FLOW_* commands.
 */
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

#define OVS_FLOW_ATTR_MAX (__OVS_FLOW_ATTR_MAX - 1)

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

#define OVS_FLOW_MCGROUP "ovs_flow"

static const struct genl_multicast_group ovs_dp_flow_multicast_group = {
	.name = OVS_FLOW_MCGROUP,
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

----------------------------------------------------

#define OVS_PACKET_FAMILY "ovs_packet"
#define OVS_PACKET_VERSION 0x1

/**
 * enum ovs_packet_attr - attributes for %OVS_PACKET_* commands.
 * @OVS_PACKET_ATTR_PACKET: Present for all notifications.  Contains the entire
 * packet as received, from the start of the Ethernet header onward.  For
 * %OVS_PACKET_CMD_ACTION, %OVS_PACKET_ATTR_PACKET reflects changes made by
 * actions preceding %OVS_ACTION_ATTR_USERSPACE, but %OVS_PACKET_ATTR_KEY is
 * the flow key extracted from the packet as originally received.
 * @OVS_PACKET_ATTR_KEY: Present for all notifications.  Contains the flow key
 * extracted from the packet as nested %OVS_KEY_ATTR_* attributes.  This allows
 * userspace to adapt its flow setup strategy by comparing its notion of the
 * flow key against the kernel's.  When used with %OVS_PACKET_CMD_EXECUTE, only
 * metadata key fields (e.g. priority, skb mark) are honored.  All the packet
 * header fields are parsed from the packet instead.
 * @OVS_PACKET_ATTR_ACTIONS: Contains actions for the packet.  Used
 * for %OVS_PACKET_CMD_EXECUTE.  It has nested %OVS_ACTION_ATTR_* attributes.
 * Also used in upcall when %OVS_ACTION_ATTR_USERSPACE has optional
 * %OVS_USERSPACE_ATTR_ACTIONS attribute.
 * @OVS_PACKET_ATTR_USERDATA: Present for an %OVS_PACKET_CMD_ACTION
 * notification if the %OVS_ACTION_ATTR_USERSPACE action specified an
 * %OVS_USERSPACE_ATTR_USERDATA attribute, with the same length and content
 * specified there.
 * @OVS_PACKET_ATTR_EGRESS_TUN_KEY: Present for an %OVS_PACKET_CMD_ACTION
 * notification if the %OVS_ACTION_ATTR_USERSPACE action specified an
 * %OVS_USERSPACE_ATTR_EGRESS_TUN_PORT attribute, which is sent only if the
 * output port is actually a tunnel port. Contains the output tunnel key
 * extracted from the packet as nested %OVS_TUNNEL_KEY_ATTR_* attributes.
 * These attributes follow the &struct ovs_header within the Generic Netlink
 * payload for %OVS_PACKET_* commands.
 */
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

#define OVS_PACKET_ATTR_MAX (__OVS_PACKET_ATTR_MAX - 1)

static const struct genl_ops dp_packet_genl_ops[] = {
	{ .cmd = OVS_PACKET_CMD_EXECUTE,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = packet_policy,
	  .doit = ovs_packet_cmd_execute
	}
};

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


int dp_register_genl(void)

    遍历 dp_genl_families, 对每个元素调用 genl_register_family(dp_genl_families[i]);
    其中 genl_register_family(dp_genl_families[i])




------------------------------------------------

内核版本为 *** 之前

#define genl_register_family rpl_genl_register_family
static inline int rpl_genl_register_family(struct genl_family *family)
{
	family->module = THIS_MODULE;
	return rpl___genl_register_family(family);
}

------------------------------------------------

##genetlink

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
