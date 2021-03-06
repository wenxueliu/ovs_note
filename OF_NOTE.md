
mlockall 对系统性能的影响?

Core component in the system:
* Communicates with outside world using OpenFlow
* Communicates with ovsdb-server using OVSDB protocol
* Communicates with kernel module over netlink
* Communicates with the system through netdev abstract interface

ovs-appctl 命令支持参数

upcall/show
upcall/disable-megaflows
upcall/ensable-megaflows
upcall/disable-ufid
upcall/enable-ufid
upcall/set-flow-limit
revalidator/wait
revalidator/purge

ofproto/list
ofproto/trace
ofproto/trace-packet-out
fdb/flush
fdb/show
mdb/flush
mdb/show
dpif/dump-dps
dpif/show
dpif/dump-flows
ofproto/tnl-push-pop




##Ofproto

通过修改 N_TABLES 可以改变的数量. 可以增加到编译选项?

OFPP_LOCAL : 如果 ofproto_port->name 与 ofproto->name
//目前只包含 ofproto_dpif_class
/* All registered ofproto classes, in probe order. */
static const struct ofproto_class **ofproto_classes;
static size_t n_ofproto_classes;         //ofproto_classes 实际的元素数量
static size_t allocated_ofproto_classes; //ofproto_classes 的容量

unsigned ofproto_flow_limit = OFPROTO_FLOW_LIMIT_DEFAULT;
unsigned ofproto_max_idle = OFPROTO_MAX_IDLE_DEFAULT;

size_t n_handlers, n_revalidators;
size_t n_dpdk_rxqs;
char *pmd_cpu_mask;

/* Map from datapath name to struct ofproto, for use by unixctl commands. */
static struct hmap all_ofprotos = HMAP_INITIALIZER(&all_ofprotos);

/*
 * 在创建 ofproto_dpif 的时候, 如果 ofproto_dpif->backer->dpif 存在与 init_ofp_ports 中,
 * 从 init_ofp_ports 中删除, 将其加入 ofproto-dpif->ports 成员
 *
 * 初始化完 ofproto, 就将 init_ofp_ports 中属于 ofproto 的端口删除
 */
/* Initial mappings of port to OpenFlow number mappings. */
static struct shash init_ofp_ports = SHASH_INITIALIZER(&init_ofp_ports);

/* The default value of true waits for flow restore. */
static bool flow_restore_wait = true;

/* All existing ofproto_backer instances, indexed by ofproto->up.type. */
static struct shash all_dpif_backers = SHASH_INITIALIZER(&all_dpif_backers);


###核心函数

ofproto_init() :
ofproto_class_register()    : 将 ofproto_class 加入 ofproto_classes 中
ofproto_class_unregister()  : 将 ofproto_class 从 ofproto_classes 中删除
ofproto_enumerate_types()   : ofproto_classes 每个元素的 enumerate_types 方法
ofproto_enumerate_names()   : ofproto_classes 每个元素的 enumerate_names 方法
ofproto_create()            : 

具体实现见 ofproto/ofproto.c ofproto/ofproto-dpif.c

###ofport

ofport->port_by_name 保持了所有端口的名称. 在添加端口时, 基于此来检查端口是否已经添加.

ofproto 与 ofport 通过 ofproto->ports 关联


###revalidator 

enum revalidate_reason {
    REV_RECONFIGURE = 1,       /* Switch configuration changed. */
    REV_STP,                   /* Spanning tree protocol port status change. */
    REV_RSTP,                  /* RSTP port status change. */
    REV_BOND,                  /* Bonding changed. */
    REV_PORT_TOGGLED,          /* Port enabled or disabled by CFM, LACP, ...*/
    REV_FLOW_TABLE,            /* Flow table changed. */
    REV_MAC_LEARNING,          /* Mac learning changed. */
    REV_MCAST_SNOOPING,        /* Multicast snooping changed. */
};


ofproto->backer->need_revalidate = REV_MAC_LEARNING | REV_MCAST_SNOOPING

##设备管理

dpif_netlink_open

向内核发送创建 datapath 的消息, 内核将创建一个 datapath, 返回给用户空间, 用户空间解析内核应答
创建 dpif_netlink_dp 对象. 之后用 dpif_netlink_dp 创建 dpif_netlink 对象及　dpif 对象

vport_create_socksp

创建内核与用户空间的 NETLINK 通信


## 控制器连接管理

* Slave 角色只能得到端口变化状态

###OpenFlow 连接(ofconn)

每个控制器对应一个 ofconn, 可以是多个控制器, 详细的交换机和控制的处理消息都在 handle_openflow 函数中

###稳定连接(ofconn->rconn)

每次待发送的消息保持一份到 该稳定链接的所有 monitor(rconn->monitors), 拷贝一份到一个传输队列(rconn->txq).

###链路监控(ofocnn->ofmonitor)

monitor_seqno: 全局变量, 每次流表的添加和修改 monitor_seqno 加 1
monitor_counter : 每次发送消息都会更新计数, 包括 bytes 和 packets, 当 bytes 到达 128 * 1024, 发送停止消息.

###链路 buffer(ofconn->pktbuf)

buffer_id : 32位, 第 0-7 位为 buffer_ids 即 buffers 中的索引, 用于区别不同的 buffer, 第 9-31 是 cookie id, 用于同一 buffer 的包
每一个 buffer 都有过期时间, 为 OVERWRITE_MSECS (5000 ms)

buffer-id = 0 | (1 << 24 ) - 1 是处于 fail_open 模式下特用的 buffer_id

###PACKET_IN (ofconn->schedulers)

PACKET_IN 默认发送长度是 128 字节, 如果是显示的　ACTION 要求,由具体的 PACKET_IN 包大小决定

如果对 PACKET_IN 进行速率限制, PACKET_IN 都保持在 ofconn->schedulers 中. ofconn->schedulers 包含两个元素, 
0: 表示 PACKET_IN 是 NO_MATCH, 1 表示是其他原因(如果 ACTION 到控制器)

如果没有对 PACKET_IN 进行速率限制, 都是直接发送

ofconn->schedulers[i]->queues (i=0,1) 包含一系列以端口为索引的链表, 每个链表保存同一端口的 PACKET_IN 数据包


##内核通信管理

通过 NETLINK 与内核通信, 用户空间的 socket 对象对应内核的一个 pid, 交换机每增加一个端口 dpif->n_handlers 个 socket
, 并将 socket 对应的 pid 传给内核, 内核当需要发送 PACKET_IN 消息时, 查询端口对应的 pid, 通过 NETLINK 将消息发送该
PID, 用户态对应的 socket 就能收到该消息.

此外, 用户态将端口变化的 fd 加入内核 NETLINK 的广播组, 当端口发生变化时, 内核会将端口改变的消息发送给用户态.


/*
 * 保存 genl_family 对象, 以 genl_family->id 为索引
 * ovs_datapath_family : { .name=OVS_DATAPATH_FAMILY, .id=ovs_datapath_family }
 * ovs_vport_family : { .name=OVS_VPORT_FAMILY, .id=ovs_vport_family }
 * ovs_flow_family : { .name=OVS_FLOW_FAMILY, .id=ovs_flow_family }
 * ovs_packet_family : { .name=OVS_PACKET_FAMILY, .id=ovs_packet_family }
 */
static struct hmap genl_families = HMAP_INITIALIZER(&genl_families);


dpif_netlink_init :

    genl_family:
          id                 name
    OVS_DATAPATH_FAMILY ovs_datapath_family
    OVS_VPORT_FAMILY    ovs_vport_family
    OVS_FLOW_FAMILY     ovs_flow_family
    OVS_PACKET_FAMILY   ovs_packet_family

                      CTRL_ATTR_MCAST_GRP_NAME CTRL_ATTR_MCAST_GRP_ID
    OVS_VPORT_FAMILY     OVS_VPORT_FAMILY         ovs_vport_mcgroup

###交互处理 dpif_netlink->handlers

总共有 dpif->n_handlers 个, 每个 handler 对应一个线程. 每个 handler 又包含 port_num(端口数量) 个 channel
每增加端口, 每个 handler 增加一个 channel

dpif_netlink_open       : 向内核发送创建交换机的消息并在用户空间创建 dpif_netlink 对象
dpif_netlink_close      : 删除用户态交换机
dpif_netlink_destroy    : 向内核发送消息删除 dpif_ 对应的 datapath
dpif_netlink_get_stats  : 向内核获取交换机的统计信息
get_vport_type          : 获取端口类型, 目前支持 internal, system, stt, geneve, gre, gre64, vxlan, lisp.
dpif_netlink_port_add   : 向内核发送消息在一台交换机上增加一个端口, 并且在用户空间增加对应的 channel,
                          监听内核该端口的包发送到用户空间的消息.如 PACKET_IN 消息.
dpif_netlink_port_del   : 向内核发送消息在一台交换机上删除一个端口, 并且在用户空间删除端口号对应的 channel
dpif_netlink_port_query_by_number : 向内核发送消息查询指定端口号对应的端口
dpif_netlink_port_query_by_name   : 向内核发送消息查询指定端口名的端口
dpif_netlink_flow_flush           : 向内核发送消息删除交换机下的所有流表

遍历内核中端口的三段式

dpif_netlink_port_dump_start : 向内核发送获取所有端口的阻塞的请求, 并要求内核应答.
dpif_netlink_port_dump_next  : 无限循环非阻塞地接受内核的应答, 直到遍历完或与遇到错误
dpif_netlink_port_dump_done  : 当遍历完或不想继续接受后续消息


dpif_netlink_port_poll       : 非阻塞地无限循环接受内核广播信息, 直到端口发送变化或发生错误
dpif_netlink_port_poll_wait  : poll 等待内核的广播信息.

dpif_netlink_flow_get        : 向内核发送消息获取交换机下某个 key 或 ufid 对应的流表

遍历内核中流表项的五段式, 支持多线程

dpif_netlink_flow_dump_create  : 向内核发送消息, 请求内核发送所有的流表项
dpif_netlink_flow_dump_thread_create : 初始化遍历流表项的线程

dpif_netlink_flow_dump_next : 无限循环当前线程非阻塞地接受内核发送的流表, 解析后保存, 直到遍历完, 达到期望遍历的流表数或发生错误退出。

dpif_netlink_flow_dump_destroy : 当遍历完或不想继续接受后续消息
dpif_netlink_flow_dump_thread_destroy : 销毁遍历流表项的线程

dpif_netlink_operate  : 对内核的流表执行批量操作, get, put, del, execute
dpif_netlink_recv_set : 是否接受内核数据包
dpif_netlink_handlers_set : 设置内核 handle, 刷新所有端口
dpif_netlink_queue_to_priority : TODO

dpif_netlink_recv : 对其中一个 handler, 如果所有的事件都处理完, 重新等待内核空间发送的消息,
                    否则, 非阻塞遍历所有的可读事件, 接受数据并处理

dpif_netlink_recv_wait : 将 POLLIN 加入 handler 的监听
dpif_netlink_recv_purge :  将 dpif->handlers 中所有的 fd 监听的数据都丢弃
dpif_netlink_get_datapath_version : 获取 datapath 版本
dpif_netdev_port_poll_wait : 监听内核发送的端口改变的广播消息.

##用户空间的 datapath, dpif_netdev ---  DPDK

dp_netdev 由多个 poll_thread 对象, 每个 poll_thread 绑定到一个 numa 节点

将 port 与 numa 节点绑定, 每个 numa 节点的所有 cores 都为该 port 服务. 该 port 的
rxq 均匀地分配给各个 core

查询所有的 numa 节点及每个 numa 节点下的 cpu core. 为每个 cpu core 分配一个 pmd
线程.

因此 pmd 与 port 的 rxq 可以是 1 对 1 或 1 对 n, 关系为 pmd->index = rxq % cores

每个端口接受队列与 pmd 绑定, 包收到后首先在 pmd->flow_cache 中查找,
* 如果找到, 加入 flow_cache->batch
* 如果找不到就在 pmd->cls 中查找
    * 如果找到, 加入 flow_cache, 并加入　flow->batch
    * 如果找不到, 就调用 upcall.

###核心代码

dpif_netdev_open
    create_dp_netdev
        do_add_port
            dp_netdev_set_pmds_on_numa
                pmd_thread_main
                    dp_netdev_input
                        emc_processing
                        fast_path_processing

dpif_netdev_enumerate : 从 dp_netdevs 中找到 class = dpif_class 的 dp_netdev 对象, 将 dp_netdev->name 保存在 all_dps 中
dpif_netdev_port_open_type : 返回 类型
dpif_netdev_open : 创建 dpif_netdev 对象
dpif_netdev_close : 对 dp_netdev 引用计数减一
dpif_netdev_destroy : 如果 dp_netdev 还没有销毁, 引用技术减一
dpif_netdev_get_stats : 获取 dp_netdev 的统计信息, 命中, 没有命中和丢失的包数
dpif_netdev_port_add : 给 dp_netdev 增加端口
dpif_netdev_port_del : 给 dp_netdev 删除端口
dpif_netdev_port_query_by_number : 根据端口号在 dp_netdev 中查找端口
dpif_netdev_port_query_by_name: 根据端口名在 dp_netdev 中查找端口

dpif_netdev_port_dump_start : 创建 dp_netdev_port_state 对象
dpif_netdev_port_dump_next : 由 dp_netdev_port_state 确定下一个 dp_netdev 的端口
dpif_netdev_port_dump_done : 释放 dp_netdev_port_state 对象

dpif_netdev_port_poll : 获取端口更新事件(增加, 删除), 返回 ENOBUFS
dpif_netdev_port_poll_waiti : 等待端口发生变化

dpif_netdev_flow_flush : 删除所有流表

dpif_netdev_flow_dump_create : 初始化 dpif_netdev_flow_dump 对象
dpif_netdev_flow_dump_destroy : 销毁 dpif_netdev_flow_dump 对象
dpif_netdev_flow_dump_thread_create : 初始化 thread 对象
dpif_netdev_flow_dump_thread_destroy : 释放 thread 对象


丢包的可能原因:
1. dp_cls 中没有找到对应的 flow, 并且无法获取 upcall 锁
2. 再次查询　dp_cls 仍然没有对应的 flow, 调用 upcall 失败
3. 如果执行 upcall 成功, 再次查询 dp_cls 仍然没有对应的 flow, 加入 pmd->flow_cache


###问题:

1. 端口如何与 numa 绑定

在端口初始化过程中, netdev_open() 中初始化 port->netdev 所属的 numa(仅 dpdk 实现)

2. pmd 什么时候初始化?

在增加端口的时候, 具体在 dp_netdev_set_pmds_on_numa 中实现

1. pmd 是如何与 cpu core 或 numa 关联的 ?

在 pmd 初始化过程中直接赋值. 参考 dpif_netdev.c 中的 dp_netdev_configure_pmd

2. pmd 是如何与对应的线程关联 ?

在 pmd 所属 datapath 中的所有端口中找到
1. 在 pmd 初始化过程中, 将 numa 节点中没有 pinned 的 core 分配给 pmd
2. 将 pmd 所在线程与 pmd->core 绑定

增加端口的时候, 如果是 dpdk, 对交换机所属端口的 numa 节点扫描:
1. 如果 dp->poll_threads 中存在与 numa 绑定的 pmd, 就什么也不做. (如果 numa 是动态增加的就存在问题)
2. 如果 dp->poll_threads 中不存在与 numa 绑定的 pmd, 就遍历该 numa 找到没有 pinned 的 core, 创建 pmd 并将 pmd 所属的线程与 core 绑定.

3. pmd 是如何与 port 的 rxq 绑定的?

在 pmd_thread_main 中实现, pmd 对应的 rxq % cores = pmd->index 的 rxq

port->rxq 可以通过 dpif_netdev_pmd_set 设置
port->txq 为所有 numa 节点的 core + 1

4. flow_cache, cls, flow_table 之间的关系

   先查询 flow_cache, 找不到再查 cls, 再找不到, 发送 upcall, 之后再查询 cls.

   参考 dp_netdev_flow_add

   增加一条 flow:
   1. flow->cr 加入 cls
   2. flow->node 加入 flow_table

5. 缓存替代算法

 将 key, flow 加入 cache
 1. 从 cache 中找到 key 匹配的 cache, 该 cache->flow = flow, cache->key = key
 2. 如果没有与 key 匹配的, 就替换第一条已经不再有效的 cache entry.
 3. 如果key 没有匹配, 并且所有 entry 都是有效的, 就替换 key.hash 最小的 entry

6. dp 的 upcall 在哪里初始化, dp_netdev 的 upcall 具体实现在哪里?

 通过 dpif_netdev_register_upcall_cb, 也即 dpif_class 的 register_upcall_cb(dpif_netdev.c)
 注册, 对外暴露的接口是 dpif_register_upcall_cb(dpif.c)

 具体实现在 ofproto/ofproto_dpif_upcall.c 中的 upcall_cb


7. 谈谈 batch 的作用

struct packet_batch {
    unsigned int packet_count;
    unsigned int byte_count;
    uint16_t tcp_flags;

    struct dp_netdev_flow *flow;

    struct dp_packet *packets[NETDEV_MAX_BURST];
};

交换机收到包后, 查询每个包, 并不是立即就对 packet 执行动作, 而是将 packet 加入
batch 中, 每个 batch 对应一个 flow, 每个 batch 包含很多 packet, 所有的 packet 都
对应相同的 flow. 具体可以参考 dp_netdev_queue_batches

在经过快路径(flow_cache) 和慢路径(cls) 查询后, 对于存在匹配的对应 flow 的 packet
都保持在 batch 中, 之后对 batch 中的每个 packet 执行其 flow 对应的 actions, 对于
不匹配的包直接丢掉







###数据结构

/* ofproto supports two kinds of OpenFlow connections:
 *
 *   - "Primary" connections to ordinary OpenFlow controllers.  ofproto
 *     maintains persistent connections to these controllers and by default
 *     sends them asynchronous messages such as packet-ins.
 *
 *   - "Service" connections, e.g. from ovs-ofctl.  When these connections
 *     drop, it is the other side's responsibility to reconnect them if
 *     necessary.  ofproto does not send them asynchronous messages by default.
 *
 * Currently, active (tcp, ssl, unix) connections are always "primary"
 * connections and passive (ptcp, pssl, punix) connections are always "service"
 * connections.  There is no inherent reason for this, but it reflects the
 * common case.
 */
enum ofconn_type {
    OFCONN_PRIMARY,             /* An ordinary OpenFlow controller. */
    OFCONN_SERVICE              /* A service connection, e.g. "ovs-ofctl". */
};

enum ofproto_band {
    OFPROTO_IN_BAND,            /* In-band connection to controller. */
    OFPROTO_OUT_OF_BAND         /* Out-of-band connection to controller. */
};

/* Controller roles. */
enum ofp12_controller_role {
    OFPCR12_ROLE_NOCHANGE,    /* Don't change current role. */
    OFPCR12_ROLE_EQUAL,       /* Default role, full access. */
    OFPCR12_ROLE_MASTER,      /* Full access, at most one master. */
    OFPCR12_ROLE_SLAVE,       /* Read-only access. */
};

/* Protocols.
 *
 * A "protocol" is an OpenFlow version plus, for some OpenFlow versions,
 * a bit extra about the flow match format in use.
 *
 * These are arranged from most portable to least portable, or alternatively
 * from least powerful to most powerful.  Protocols earlier on the list are
 * more likely to be understood for the purpose of making requests, but
 * protocol later on the list are more likely to accurately describe a flow
 * within a switch.
 *
 * On any given OpenFlow connection, a single protocol is in effect at any
 * given time.  These values use separate bits only because that makes it easy
 * to test whether a particular protocol is within a given set of protocols and
 * to implement set union and intersection.
 */

enum nx_packet_in_format {
    NXPIF_OPENFLOW10 = 0,       /* Standard OpenFlow 1.0 compatible. */
    NXPIF_NXM = 1               /* Nicira Extended. */
};


struct ofproto_controller {
    char *target;               /* e.g. "tcp:127.0.0.1" */
    int max_backoff;            /* Maximum reconnection backoff, in seconds. */
    //如果不为0, 最少为 5 s
    int probe_interval;         /* Max idle time before probing, in seconds. */
    enum ofproto_band band;     /* In-band or out-of-band? */
    bool enable_async_msgs;     /* Initially enable asynchronous messages? */

    /* OpenFlow packet-in rate-limiting. */
    int rate_limit;             /* Max packet-in rate in packets per second. */
    int burst_limit;            /* Limit on accumulating packet credits. */

    uint8_t dscp;               /* DSCP value for controller connection. */
};

####openflw db services

/* A listener for incoming OpenFlow "service" connections. */
struct ofservice {
    struct hmap_node node;      /* In struct connmgr's "services" hmap. */
    struct pvconn *pvconn;      /* OpenFlow connection listener. */

    /* These are not used by ofservice directly.  They are settings for
     * accepted "struct ofconn"s from the pvconn. */
    int probe_interval;         /* Max idle time before probing, in seconds. */
    int rate_limit;             /* Max packet-in rate in packets per second. */
    int burst_limit;            /* Limit on accumulating packet credits. */
    bool enable_async_msgs;     /* Initially enable async messages? */
    uint8_t dscp;               /* DSCP Value for controller connection */
    uint32_t allowed_versions;  /* OpenFlow protocol versions that may
                                 * be negotiated for a session. */
};

####openflow port

/* A port within an OpenFlow switch.
 *
 * 'name' and 'type' are suitable for passing to netdev_open(). */
struct ofproto_port {
    char *name;                 /* Network device name, e.g. "eth0". */
    char *type;                 /* Network device type, e.g. "system". */
    ofp_port_t ofp_port;        /* OpenFlow port number. */
};

#### vlan mode

/* The behaviour of the port regarding VLAN handling */
enum port_vlan_mode {
    /* This port is an access port.  'vlan' is the VLAN ID.  'trunks' is
     * ignored. */
    PORT_VLAN_ACCESS,

    /* This port is a trunk.  'trunks' is the set of trunks. 'vlan' is
     * ignored. */
    PORT_VLAN_TRUNK,

    /* Untagged incoming packets are part of 'vlan', as are incoming packets
     * tagged with 'vlan'.  Outgoing packets tagged with 'vlan' stay tagged.
     * Other VLANs in 'trunks' are trunked. */
    PORT_VLAN_NATIVE_TAGGED,

    /* Untagged incoming packets are part of 'vlan', as are incoming packets
     * tagged with 'vlan'.  Outgoing packets tagged with 'vlan' are untagged.
     * Other VLANs in 'trunks' are trunked. */
    PORT_VLAN_NATIVE_UNTAGGED
};

#### Bundle ????

/* Registers a "bundle" associated with client data pointer 'aux' in 'ofproto'.
 * A bundle is the same concept as a Port in OVSDB, that is, it consists of one
 * or more "slave" devices (Interfaces, in OVSDB) along with a VLAN
 * configuration plus, if there is more than one slave, a bonding
 * configuration.
 *
 * If 'aux' is already registered then this function updates its configuration
 * to 's'.  Otherwise, this function registers a new bundle.
 *
 * Bundles only affect the NXAST_AUTOPATH action and output to the OFPP_NORMAL
 * port. */

1. vlan
2. lacp
3. bond


/* Configuration of bundles. */
struct ofproto_bundle_settings {
    char *name;                 /* For use in log messages. */

    ofp_port_t *slaves;         /* OpenFlow port numbers for slaves. */
    size_t n_slaves;

    enum port_vlan_mode vlan_mode; /* Selects mode for vlan and trunks */
    int vlan;                   /* VLAN VID, except for PORT_VLAN_TRUNK. */
    unsigned long *trunks;      /* vlan_bitmap, except for PORT_VLAN_ACCESS. */
    bool use_priority_tags;     /* Use 802.1p tag for frames in VLAN 0? */

    struct bond_settings *bond; /* Must be nonnull iff if n_slaves > 1. */

    struct lacp_settings *lacp;              /* Nonnull to enable LACP. */
    struct lacp_slave_settings *lacp_slaves; /* Array of n_slaves elements. */

    /* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
     *
     * This is deprecated.  It is only for compatibility with broken device
     * drivers in old versions of Linux that do not properly support VLANs when
     * VLAN devices are not used.  When broken device drivers are no longer in
     * widespread use, we will delete these interfaces. */
    ofp_port_t realdev_ofp_port;/* OpenFlow port number of real device. */
};

#### flow Table

struct ofproto_table_settings {
    char *name;                 /* Name exported via OpenFlow or NULL. */
    unsigned int max_flows;     /* Maximum number of flows or UINT_MAX. */

    /* These members, together with OpenFlow OFPT_TABLE_MOD, determine the
     * handling of an attempt to add a flow that would cause the table to have
     * more than 'max_flows' flows:
     *
     *    - If 'enable_eviction' is false and OFPT_TABLE_MOD does not enable
     *      eviction, overflows will be rejected with an error.
     *
     *    - If 'enable_eviction' is true or OFPT_TABLE_MOD enables eviction, an
     *      overflow will cause a flow to be removed.  The flow to be removed
     *      is chosen to give fairness among groups distinguished by different
     *      values for the 'n_groups' subfields within 'groups'. */
    bool enable_eviction;
    struct mf_subfield *groups;
    size_t n_groups;

    /*
     * Fields for which prefix trie lookup is maintained.
     */
    unsigned int n_prefix_fields;
    enum mf_field_id prefix_fields[CLS_MAX_TRIES];
};

max_flows   : 由 bridge->cfg->n_flow_limit 配置
groups      : 由 bridge->cfg->n_groups 个

####fail_open 模式

/*
 * Fail-open mode.
 *
 * In fail-open mode, the switch detects when the controller cannot be
 * contacted or when the controller is dropping switch connections because the
 * switch does not pass its admission control policy.  In those situations the
 * switch sets up flows itself using the "normal" action.
 *
 * There is a little subtlety to implementation, to properly handle the case
 * where the controller allows switch connections but drops them a few seconds
 * later for admission control reasons.  Because of this case, we don't want to
 * just stop setting up flows when we connect to the controller: if we did,
 * then new flow setup and existing flows would stop during the duration of
 * connection to the controller, and thus the whole network would go down for
 * that period of time.
 *
 * So, instead, we add some special cases when we are connected to a
 * controller, but not yet sure that it has admitted us:
 *
 *     - We set up flows immediately ourselves, but simultaneously send out an
 *       OFPT_PACKET_IN to the controller.  We put a special bogus buffer-id in
 *       these OFPT_PACKET_IN messages so that duplicate packets don't get sent
 *       out to the network when the controller replies.
 *
 *     - We also send out OFPT_PACKET_IN messages for totally bogus packets
 *       every so often, in case no real new flows are arriving in the network.
 *
 *     - We don't flush the flow table at the time we connect, because this
 *       could cause network stuttering in a switch with lots of flows or very
 *       high-bandwidth flows by suddenly throwing lots of packets down to
 *       userspace.
 */

/* How the switch should act if the controller cannot be contacted. */
enum ofproto_fail_mode {
    OFPROTO_FAIL_SECURE,        /* Preserve flow table. */
    OFPROTO_FAIL_STANDALONE     /* Act as a standalone switch. */
};

###操作

控制器信息 connmgr_get_controller_info 可以获取当前控制器的状态信息

void connmgr_run(struct connmgr *mgr, void ( *handle_openflow)(struct ofconn *, const struct ofpbuf *ofp_msg))

    最主要的就是将包发送出去, 然后调用回调函数处理应答. 此外, connmgr 中其他运行起来

    1. 更新 in_band 对象
    2. 遍历 all_conns 中每一个元素 ofconn, 将 ofconn->schedulers 中的包发送出去, 用 handle_openflow 处理对方应答
    3. 如果该 ofconn 的 monitor 有被设置为停止的, 唤醒.
    4. 如果激活而且有其他控制连接, 断了连接时间超过 next_bogus_packet_in, 发送伪造 PACKET_IN, 否则, 等待 2s; 否则设置不在发送伪造包
    5. 遍历 mgr->services, 如果有请求,　就创建对应的 ofconn 连接, 没有就跳过
    6. 遍历 mgr->n_snoops, 如果收到请求, 加入角色最高的 ofconn 的 monitor

void connmgr_wait(struct connmgr *mgr)

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns)
        ofconn_wait(ofconn);

    ofmonitor_wait(mgr);
    if (mgr->in_band)
        in_band_wait(mgr->in_band);

    if (mgr->fail_open)
        fail_open_wait(mgr->fail_open);

    HMAP_FOR_EACH (ofservice, node, &mgr->services)
        pvconn_wait(ofservice->pvconn);

    for (i = 0; i < mgr->n_snoops; i++)
        pvconn_wait(mgr->snoops[i]);

void connmgr_get_memory_usage(const struct connmgr *mgr, struct simap *usage)

    计算当前 mgr 中的连接数和包数(已经发送, 未发送和在缓冲区(buffer_id)的)

void connmgr_get_controller_info(struct connmgr *mgr, struct shash *info)

    遍历 mgr 的每一个 ofconn, 如果 ofconn->rconn->target 不在 info 中, 将其加入
    info 中.

    其中 info 是一个包含 key->value 存储的 hash 链表. info 主要保持的 是控制器所有连接的统计信息

void connmgr_set_controllers(struct connmgr *mgr, const struct ofproto_controller *controllers, size_t n_controllers, uint32_t allowed_versions)

    遍历 controllers 中每个元素 controller, 加入 mgr 的 controllers 或 ofservice 中, 删除旧的 controller
    以及 ofservice.

static void add_controller(struct connmgr *mgr, const char *target, uint8_t dscp, uint32_t allowed_versions)

    增加一个新的 ofconn 到 mgr->controllers, 建立连接

static void update_fail_open(struct connmgr *mgr)

    如果 mgr 配置 controller 而且 fail_mode = OFPROTO_FAIL_STANDALONE ; 创建 mgr->fail_open.
    否则 删除 mgr->fail_open, mgr->fail_open = NULL
    注: 由上可知 mgr->fail_open 只有在 fail_mode = OFPROTO_FAIL_STANDALONE 才有用

bool connmgr_wants_packet_in_on_miss(struct connmgr *mgr)

    连接管理(mgr)中是否存在 table_miss 的时候发送 PACKET_IN 的 ofconn

    满足发送 PACKET_IN 的条件:
    1. ofconn->controller_id = 0
    2. 没有制定协议版本, 版本小于 1.3

void connmgr_flushed(struct connmgr *mgr)

    TODO
    如果配置了 fail_open, 就调用 fail_open_flushed(mgr->fail_open);　
    如果没有控制连接, 并且 fail_mode 是 OFPROTO_FAIL_STANDALONE

### PACKET_IN 消息

/* A packet_in, with extra members to assist in queuing and routing it. */
struct ofproto_packet_in {
    struct ofputil_packet_in up;
    struct ovs_list list_node;  /* For queuing. */
    uint16_t controller_id;     /* Controller ID to send to. */
    int send_len;               /* Length that the action requested sending. */
    enum ofproto_packet_in_miss_type miss_type;
};

/* Abstract packet-in message. */
struct ofputil_packet_in {
    /* Packet data and metadata.
     *
     * To save bandwidth, in some cases a switch may send only the first
     * several bytes of a packet, indicated by 'packet_len < total_len'.  When
     * the full packet is included, 'packet_len == total_len'. */
    const void *packet;
    size_t packet_len;          /* Number of bytes in 'packet'. */
    size_t total_len;           /* Size of packet, pre-truncation. */
    struct match flow_metadata;

    /* Identifies a buffer in the switch that contains the full packet, to
     * allow the controller to reference it later without having to send the
     * entire packet back to the switch.
     *
     * UINT32_MAX indicates that the packet is not buffered in the switch.  A
     * switch should only use UINT32_MAX when it sends the entire packet. */
    uint32_t buffer_id;

    /* Reason that the packet-in is being sent. */
    enum ofp_packet_in_reason reason;    /* One of OFPR_*. */

    /* Information about the OpenFlow flow that triggered the packet-in.
     *
     * A packet-in triggered by a flow table miss has no associated flow.  In
     * that case, 'cookie' is UINT64_MAX. */
    uint8_t table_id;                    /* OpenFlow table ID. */
    ovs_be64 cookie;                     /* Flow's cookie. */
};

/* Why is this packet being sent to the controller? */
enum ofp_packet_in_reason {
    OFPR_NO_MATCH,          /* No matching flow. */
    OFPR_ACTION,            /* Action explicitly output to controller. */
    OFPR_INVALID_TTL,       /* Packet has invalid TTL. */
    OFPR_ACTION_SET,        /* Output to controller in action set */
    OFPR_GROUP,             /* Output to controller in group bucket */
    OFPR_PACKET_OUT,        /* Output to controller in packet-out */
    OFPR_N_REASONS
};

enum ofproto_packet_in_miss_type {
    /* Not generated by a flow miss or table-miss flow. */
    OFPROTO_PACKET_IN_NO_MISS,

    /* The packet_in was generated directly by a table-miss flow, that is, a
     * flow with priority 0 that wildcards all fields.  See OF1.3.3 section
     * 5.4.
     *
     * (Our interpretation of "directly" is "not via groups".  Packet_ins
     * generated by table-miss flows via groups use
     * OFPROTO_PACKET_IN_NO_MISS.) */
    OFPROTO_PACKET_IN_MISS_FLOW,

    /* The packet-in was generated directly by a table-miss, but not a
     * table-miss flow.  That is, it was generated by the OpenFlow 1.0, 1.1, or
     * 1.2 table-miss behavior. */
    OFPROTO_PACKET_IN_MISS_WITHOUT_FLOW,
};

###Openflow 连接


static struct ofconn * ofconn_create(struct connmgr *mgr, struct rconn *rconn, enum ofconn_type type, bool enable_async_msgs)

    为 ofconn 分配内存, 并全部初始化为 0
    ofconn->connmgr 指向 mgr
    ofconn 加入 mgr->all_conns
    初始化 ofconn->monitors, ofconn->updates, ofconn->bundles

注: ofconn->hmap_node = NULL
    ofconn->band      = 0
    ofconn->monitor_paused = 0
    ofconn->sent_abbrev_update

static void ofconn_destroy(struct ofconn *ofconn)

    释放 ofconn 各个成员的内存

static void ofconn_flush(struct ofconn *ofconn)

    重置 ofconn 部分成员

    ofconn->role : OFPCR12_ROLE_EQUAL;
    ofconn->protocol : OFPUTIL_P_NONE);
    ofconn->packet_in_format = NXPIF_OPENFLOW10;
    ofconn->packet_in_counter = rconn_packet_counter_create();
    ofconn->schedulers[i] = pinsched_create(rate, burst);
    ofconn->pktbuf = pktbuf_create();
    ofconn->miss_send_len = (ofconn->type == OFCONN_PRIMARY ? OFP_DEFAULT_MISS_SEND_LEN : 0);
    ofconn->controller_id = 0;
    ofconn->reply_counter = rconn_packet_counter_create();
    ofconn->n_add = 0
    ofconn->n_delete = 0
    ofconn->n_modify = 0;
    ofconn->first_op = ofconn->last_op = LLONG_MIN;
    ofconn->next_op_report = LLONG_MAX;
    ofconn->op_backoff = LLONG_MIN;
    ofconn->monitor_counter = rconn_packet_counter_create();

static void ofconn_reconfigure(struct ofconn *ofconn, const struct ofproto_controller *c)

    用 c 重新配置 ofconn 的选项

static bool ofconn_may_recv(const struct ofconn *ofconn)

    如果 ofconn->reply_counter->n_packets < OFCONN_REPLY_MAX(100) 返回 true, 否则 false

static void ofconn_run(struct ofconn *ofconn, void ( *handle_openflow)(struct ofconn *, const struct ofpbuf *ofp_msg))

    建立连接, 将 schedulers 中的数据包发送出去, 处理接受的的包

    1. 在满足速率限制的前提下, 从 ofconn->schedulers 每个元素中取 50 个元素加入 ofconn->rconn->txq 中;
    2. ofconn->rconn 中的 vconn 与 monitors 与对端完成连接建立, 并将 ofconn->rconn-txq 中的数据包发送给对端
    3. 接受对端的数据包, 调用 handle_openflow 进行处理. 在等待应答的包大于100 或已经接收到 50 个包返回

static void ofconn_send(const struct ofconn *ofconn, struct ofpbuf *msg,
            struct rconn_packet_counter *counter)

    rconn_send(ofconn->rconn, msg, counter);
    如果 ofconn->rconn 处于连接状态, 将 msg 发送给 ofconn->rconn->monitors 的每一个成员所对应的连接,
    msg->list_node 加入 ofconn->rconn->txq 链表尾, 如果 ofconn->rconn->txq 只有 msg 调用 vconn_send(rc->vconn, msg)

    否则 直接释放 b 的内存

static void ofconn_wait(struct ofconn *ofconn)

    1. 如果 ofconn->schedulers 每个元素 token_bucket 中的 tocken 没有超过 1000 就休眠
    2. 如果待应答的包没有超过 100, poll.event = POLLIN
    3. 休眠指定时间

static bool ofconn_receives_async_msg(const struct ofconn *ofconn, enum ofputil_async_msg_type type, unsigned int reason)

    Returns true if 'ofconn' should receive asynchronous messages of the given
    OAM_* 'type' and 'reason', which should be a OFPR_* value for OAM_PACKET_IN,
    a OFPPR_* value for OAM_PORT_STATUS, or an OFPRR_* value for
    OAM_FLOW_REMOVED.  Returns false if the message should not be sent on
    'ofconn'.

static bool ofconn_wants_packet_in_on_miss(struct ofconn *ofconn, const struct ofproto_packet_in *pin)

    当 table-miss 时, 是否发送 PACKET_IN.

    不发送的条件:
    1. 协议版本 >= 1.3
    2. ofconn->connmgr->ofproto->tables[pin->up.table_id].miss_config = OFPUTIL_TABLE_MISS_DEFAULT


static void ofconn_set_rate_limit(struct ofconn *ofconn, int rate, int burst)

    遍历 ofconn->schedulers,
    如果 ofconn->schedulers[i] 为 NULL, 创建并设置 rate, burst;
    如果已经创建, 直接设置 rate, burst

static void ofconn_send(const struct ofconn *ofconn, struct ofpbuf *msg, struct rconn_packet_counter *counter)

    如果 ofconn->rconn 处于连接状态, 将 msg 拷贝给 ofconn->rconn->monitors 的每一个成员, msg->list_node 加入 ofconn->rconn->txq 链表尾
    否则 直接释放 b 的内存
    注: msg->header = counter


struct ofproto * ofconn_get_ofproto(const struct ofconn *ofconn)

    返回 ofconn->connmgr->ofproto;


void ofconn_send_role_status(struct ofconn *ofconn, uint32_t role, uint8_t reason)

    发送 ofconn 的角色状态

void ofconn_set_role(struct ofconn *ofconn, enum ofp12_controller_role role)

    如果 role 是 MASTER 角色, 覆盖已经存在的 MASTER 角色. 否则直接 ofconn->role = role

void ofconn_set_invalid_ttl_to_controller(struct ofconn *ofconn, bool enable)

    设置 ofconn->master_async_config[OAM_PACKET_IN]

void ofconn_send_reply(const struct ofconn *ofconn, struct ofpbuf *msg)

    ofconn_send(ofconn, msg, ofconn->reply_counter);

void ofconn_send_replies(const struct ofconn *ofconn, struct ovs_list *replies)

    LIST_FOR_EACH_POP (reply, list_node, replies) {
        ofconn_send_reply(ofconn, reply);
    }

enum ofperr ofconn_pktbuf_retrieve(struct ofconn *ofconn, uint32_t id, struct dp_packet **bufferp, ofp_port_t *in_port)

    如果 ofconn->pktbuf->packets[id & PKTBUF_MASK]->cookie = PKTBUF_BITS;
    从 bufferp = ofconn->pktbuf->packet[id & PKTBUF_MASK]->buff , in_port = ofconn->pktbuf->packet[id & PKTBUF_MASK]->in_port



###连接监控

/* Flow monitors (NXST_FLOW_MONITOR). */

/* A counter incremented when something significant happens to an OpenFlow
 * rule.
 *
 *     - When a rule is added, its 'add_seqno' and 'modify_seqno' are set to
 *       the current value (which is then incremented).
 *
 *     - When a rule is modified, its 'modify_seqno' is set to the current
 *       value (which is then incremented).
 *
 * Thus, by comparing an old value of monitor_seqno against a rule's
 * 'add_seqno', one can tell whether the rule was added before or after the old
 * value was read, and similarly for 'modify_seqno'.
 *
 * 32 bits should normally be sufficient (and would be nice, to save space in
 * each rule) but then we'd have to have some special cases for wraparound.
 *
 * We initialize monitor_seqno to 1 to allow 0 to be used as an invalid
 * value. */

/* A flow monitor managed by NXST_FLOW_MONITOR and related requests. */
struct ofmonitor {
    struct ofconn *ofconn;      /* Owning 'ofconn'. */
    struct hmap_node ofconn_node; /* In ofconn's 'monitors' hmap. */
    uint32_t id;                    //唯一标记一个 ofmonitor 对象

    enum nx_flow_monitor_flags flags;

    /* Matching. */
    ofp_port_t out_port;
    uint8_t table_id;
    struct minimatch match;
};

/* 'flags' bits in struct nx_flow_monitor_request. */
enum nx_flow_monitor_flags {
    /* When to send updates. */
    NXFMF_INITIAL = 1 << 0,     /* Initially matching flows. */
    NXFMF_ADD = 1 << 1,         /* New matching flows as they are added. */
    NXFMF_DELETE = 1 << 2,      /* Old matching flows as they are removed. */
    NXFMF_MODIFY = 1 << 3,      /* Matching flows as they are changed. */

    /* What to include in updates. */
    NXFMF_ACTIONS = 1 << 4,     /* If set, actions are included. */
    NXFMF_OWN = 1 << 5,         /* If set, include own changes in full. */
};



/* Abstract nx_flow_monitor_request. */
struct ofputil_flow_monitor_request {
    uint32_t id;
    enum nx_flow_monitor_flags flags;
    ofp_port_t out_port;
    uint8_t table_id;
    struct match match;
};

**ofmonitor 中 id 唯一标记一个 ofmonitor 对象**

enum ofperr ofmonitor_create(const struct ofputil_flow_monitor_request *request,
                 struct ofconn *ofconn, struct ofmonitor **monitorp)

    用 参数初始化 ofmonitor 对象 m
    monitorp 指向初始化后的 ofmonitor 对象 m

void ofmonitor_destroy(struct ofmonitor *m)

    如果 m 不为 NULL, 释放 m->match-flow 所指内存, 将 m 从它所属的 ofconn 中删除, 释放 m 内存

void ofmonitor_report(struct connmgr *mgr, struct rule *rule,
                 enum nx_flow_update_event event,
                 enum ofp_flow_removed_reason reason,
                 const struct ofconn *abbrev_ofconn, ovs_be32 abbrev_xid,
                 const struct rule_actions *old_actions)

    TODO

    如果 event 是 ADD, rule->add_seqno 和 rule->modify_seqno 都加 1
    如果 event 是 MODIFY, rule->modify_seqno 都加 1
    如果 event 是 MODIFY, rule->modify_seqno 都加 1

    遍历 mgr->all_conns 的元素 ofconn,
    如果 event= NXFME_DELETED && rule->add_seqno <= ofconn->monitor_paused

    遍历 mgr 下每一个 ofconn, 对 ofconn->ofmonitor 中的 monitor,
    如果
    1. monitro->flags 包含 NXFMF_DELETE
    2. rule->table_id = monitor->table_id || monitor->table_id = 0xff
    3. monitor->out_port = rule->actions->out_port || monitor->out_port = OFPP_ANY
      或  old_actions != NULL && monitor->out_port = rule->actions->out_port || monitor->out_port = OFPP_ANY
    4. !minimask_has_extra(rule->match.mask, criteria->mask) && miniflow_equal_in_minimask(rule->match.flow =  criteria->flow,criteria->mask)

      flags |= monitor->flags

    如果 flags 不为 0

    应满足这样的 rule, 如果 ofconn->updates 为 null, 先加入简要更新规则, 将 rule 加入 ofconn->updates


static bool ofmonitor_may_resume(const struct ofconn *ofconn)

    ofconn->monitor_paused != 0 && ofconn->monitor_counter->n_packets = 0

static void ofmonitor_run(struct connmgr *mgr)

    遍历 mgr->all_conns 的所有 ofconn, 

    如果该 ofconn 的 monitor 有被设置为停止的, 唤醒.
    否则什么也不做

    其中唤醒操作包括:
    遍历 ofconn->monitors 的每个 monitor, 根据 monitor->table 找到流表, 根据
    monitor->match 找到对应的 rules, 将 rules 加入 ofconn->rconn->txq 中等待发送

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        if (ofmonitor_may_resume(ofconn)) {
            COVERAGE_INC(ofmonitor_resume);
            ofmonitor_resume(ofconn);
        }
    }

static void ofmonitor_resume(struct ofconn *ofconn)

    遍历 ofconn->monitors 的每个 monitor, 根据 monitor->table 找到流表, 根据
    monitor->match 找到对应的 rules, 将 rules 加入 ofconn->rconn->txq 中等待发送
    1. 遍历 ofconn->monitors 中的每一个 ofmonitor m
    2. 在 m->ofconn->connmgr->ofproto 中找到 table_id = m->table_id  的 table
    遍历 table->cls 表的每一条流表项, rule 为对应的流表项在 m->flags 的监控范围, 加入 rules
    3. 遍历 rules 每个元素加入 msgs 中
    4. 遍历 msgs 中的每一个元素 msg, 如果 ofconn 处于连接状态, 将 msg 拷贝给 ofconn->rconn->monitors 的每一个成员, msg->list_node 加入 ofconn->rconn->txq 链表尾, 等待发送


static void ofmonitor_wait(struct connmgr *mgr)

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        if (ofmonitor_may_resume(ofconn)) {
            poll_immediate_wake();
        }
    }

void ofmonitor_flush(struct connmgr *mgr)

    遍历 mgr->all_conns 中的每一个 ofconn, 对每个 ofconn->updates 中的 msg,
    如果 ofconn->rconn 处于连接状态, 将 msg 拷贝给 ofconn->rconn->monitors 的每一个成员, msg->list_node 加入 ofconn->rconn->txq 链表尾, 等待发送
    如果 msg->size 之和大于 128 * 1024 就发送监控停止消息, 停止 monitor_seqno++ 的 monitor


###链路数据包缓存

headroom 保持　struct rconn_packet_counter 统计信息

/* Buffer for holding arbitrary data.  An ofpbuf is automatically reallocated
 * as necessary if it grows too large for the available memory.
 *
 * 'header' and 'msg' conventions:
 *
 * OpenFlow messages: 'header' points to the start of the OpenFlow
 *    header, while 'msg' is the OpenFlow msg bofy.
 *    When parsing, the 'data' will move past these, as data is being
 *    pulled from the OpenFlow message.
 *
 *    Caution: buffer manipulation of 'struct ofpbuf' must always update
 *             the 'header' and 'msg' pointers.
 *
 *
 * Actions: When encoding OVS action lists, the 'header' is used
 *    as a pointer to the beginning of the current action (see ofpact_put()).
 *
 * rconn: Reuses 'header' as a private pointer while queuing.
 *
 * opfbuf 将内核的 skb 数据结构搬到的用户空间.
 */
struct ofpbuf {
    void *base;                 /* First byte of allocated space. */
    void *data;                 /* First byte actually in use. */
    uint32_t size;              /* Number of bytes in use. */
    uint32_t allocated;         /* Number of bytes allocated. */

    void *header;               /* OpenFlow header. */
    void *msg;                  /* message's body */
    struct ovs_list list_node;  /* Private list element for use by owner. */
    enum ofpbuf_source source;  /* Source of memory allocated as 'base'. */
};

enum OVS_PACKED_ENUM ofpbuf_source {
    OFPBUF_MALLOC,              /* Obtained via malloc(). */
    OFPBUF_STACK,               /* Un-movable stack space or static buffer. */
    OFPBUF_STUB,                /* Starts on stack, may expand into heap. */
};

/* Creates and returns a new ofpbuf with an initial capacity of 'size'
 * bytes.
 */
struct ofpbuf * ofpbuf_new(size_t size)

    struct ofpbuf *b = new malloc(sizeof *b)
    void *p = (void *)xmalloc(size)
    b->base = p
    b->data = p
    b->size = 0
    b->allocated = size
    b->header = NULL
    b->msg = NULL
    b->list_node = OVS_LIST_POISON
    b->source = OFPBUF_MALLOC

struct ofpbuf * ofpbuf_new_with_headroom(size_t size, size_t headroom)

    ofpbuf_new(size+headroom)
    b->data = (char*)b->data + size;

static inline void *ofpbuf_end(const struct ofpbuf *b)

    return (char *) b->base + b->allocated;

static inline void *ofpbuf_tail(const struct ofpbuf *b)

    return (char *) b->data + b->size;

static inline size_t ofpbuf_headroom(const struct ofpbuf *b)

    return (char*)b->data - (char*)b->base;

void ofpbuf_reserve(struct ofpbuf *b, size_t size)

    //保证有足够内存的接触上
    b->data = (char*)b->data + size;

void *ofpbuf_put(struct ofpbuf *b, const void *p, size_t size)

    将 p　开始的的　size 数据放在 b->tail 后面

struct ofpbuf *ofpbuf_clone_data_with_headroom(const void *data, size_t size, size_t headroom)

    struct ofpbuf *b = ofpbuf_new(size + headroom);
    p->data = p->data + headroom
    memncpy(p->data, data, size)
    return b

struct ofpbuf *ofpbuf_clone_with_headroom(const struct ofpbuf *buffer, size_t headroom)

    struct ofpbuf *b = ofpbuf_new(size + headroom);
    p->data = p->data + headroom
    memncpy(p->data, data, size)
    b->header = b->header + b->data - p->data
    b->msg = p->msg
    return b

struct ofpbuf *ofpbuf_clone(const struct ofpbuf *buffer)

    ofpbuf_clone_with_headroom(buffer, 0)


###PACKET_IN 消息

每个 pinsched 中的 queues 中包含 N(pinsched->n_queued) 个 pinqueue, 每个 pinqueue
包含很多 ofpbuf 对象(pinqueue->packets), 一个 ofpbuf 就是一个 PACKET_IN 消息

每个 pinqueue->node 被 hash_int(port_no) 后保存在 pinsched->queues 的某一个队列中

token_bucket 中 rate 代表 N packets/msec, 每过 M msec, token + N*M, 但是 token
不能超过 burst, last_fill 代表上次更新时间. 如果 packet_send 每秒调用的频率大于
rate, 后续的包就必须加入队列, 而不是直接发送. packet_send() 每次调用, 检查 ps
如果已经超出速度限制就将包加入 ps 的队列中, 否则直接加入 txq 中, 准备发送, 当
包的数量超出了 burst 的限制, 就丢掉最长队里的第一个包, 经新的包加入 ps->queues 中.

这里的速率限制参数由 ofproto_controller 中 rate_limit, burst_limit 配置,
初始化由 ofservice 中 rate_limit, burst_limit 决定, ofservice 中实际由
ofproto_controller 设置

* pinsched_create() : 创建 pinsched 对象
* pinsched_destroy(): 销毁 pinsched 对象
* packet_send()     : 发送数据包, 如果超过速率, 进行限速处理
* pinsched_wait()   : 等待直到满足速率限制, 退出
* pinsched_run()    : 在满足限速的条件下, 取出　50 个数据包加入待发送队列

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
    unsigned int n_queued;      /* Sum over queues[*].n. default 0*/
    struct pinqueue *next_txq;  /* Next pinqueue check in round-robin. default NULL*/

    /* Statistics reporting. */
    unsigned long long n_normal;        /* # txed w/o rate limit queuing. default 0 */
    unsigned long long n_limited;       /* # queued for rate limiting. default 0 */
    unsigned long long n_queue_dropped; /* # dropped due to queue overflow. default 0 */
};

struct pinsched * pinsched_create(int rate_limit, int burst_limit)

    初始化一个发送 PACKET_IN 消息的 pinsched 对象


static void pinqueue_destroy(struct pinsched *ps, struct pinqueue *q)

    从 ps->qeues 中删除 q->node

static struct pinqueue *pinqueue_get(struct pinsched *ps, ofp_port_t port_no)

    从 ps->queu 中找到端口号为 port_no 的 pingueue:
    如果找到, 直接返回
    如果找不到创建对应的 pinqueue 对象, 并返回

//通过对 packet_in 消息的监控可以发现与控制器的沟通是否正常
void pinsched_get_stats(const struct pinsched *, struct pinsched_stats *);


static void drop_packet(struct pinsched *ps)

    从 ps->queues 中找到一个最长的包 pinqueue, 从 pinqueue 的 packets
    中丢弃一个第一个包.

static struct ofpbuf * dequeue_packet(struct pinsched *ps, struct pinqueue *q)

    删除 q->packets 第一个数据包. 返回被删除的数据包

static void advance_txq(struct pinsched *ps)

    轮询从 ps->queues 中取出一个 pinqueue 对象,  ps->next_txq 指向该对象

static struct ofpbuf *get_tx_packet(struct pinsched *ps)

    通过 ps->next_txq 遍历 ps, 从 ps->next_txq->packets 中删除一个数据包. 返回该数据包

static bool get_token(struct pinsched *ps)

    ps->token_bucket->token 大于 1000, 返回 true, 否则返回 false

void pinsched_send(struct pinsched *ps, ofp_port_t port_no, struct ofpbuf *packet, struct ovs_list *txq)

    如果 ps 为 NULL, 将 packet 加入 txq 中准备发送
    如果 ps 不为 NULL, 但是没有任何被限速的数据包, 并且速率要求范围以内, 将 packet 加入 txq 准备发送
    如果 ps 不为 NULL, 已经超出速度限制就将包加入 ps 的队列中

void pinsched_run(struct pinsched *ps, struct ovs_list *txq)

    在满足限速的条件下, 从 ps 中取出　50 个数据包加入 txq 中

void pinsched_wait(struct pinsched *ps)

    如果 ps !=NULL && ps->n_queued >0 && ps->token_bucket->token 小于 1000, 睡眠直到满足条件的时间, 单位 ms

void pinsched_get_limits(const struct pinsched *ps, int *rate_limit, int *burst_limit)

    获取 pinsched 的限制速率情况, rate_limit 表示每秒发送的 PACKET_IN 的数目.
    burst_limit 长时间不发送 PACKET_IN, 再次发送累计可发送的最大值

void pinsched_set_limits(struct pinsched *ps, int rate_limit, int burst_limit)

    设置 ps->token_bucket->rate = rate_limit, ps->token_bucket->burst = burst_limit
    如果 ps->n_queued 大于 burst_limit, 丢弃一个包

void pinsched_get_stats(const struct pinsched *ps, struct pinsched_stats *stats)

    获取 pinsched 的统计信息


##交换机接口(Datapath Interface)

/* Protects against changes to 'dp_netdevs'. */
static struct ovs_mutex dp_netdev_mutex = OVS_MUTEX_INITIALIZER;

/
* dp_netdevs 下由很多 dp_netdev. 每一个 dp_netdev 下有一个线程池和端口池. 每个端口属于一个 netdev.
* 每个端口所属的 netdev 有一个接受队列, 每个线程有一个流表缓存池
* 由 dpif_netdev_open 创建 dp_netdev 对象, 暴露给外面的是 dpif_open(name, "netdev", dp_netdev) 调用
*/
static struct shash dp_netdevs

//ofproto_dpif_upcall.c
static struct ovs_list all_udpifs  //保存 udpif 对象

/*
 * dpif_class 主要由 dpif_netdev_class 和 dpif_netlink_class 实现
 * 保存 dpif_class->type : registered_dpif_class 类型 hash map
 *
 * dpif_class->type 必须是唯一标记一个 dpif_class
 *
 * 目前保存有
 * system : { .dpif_class = dpif_netlink_class, .refcount=0 }
 * netdev : { .dpif_class = dpif_netdev_class, .refcount=0 }
 */
static struct shash dpif_classes = SHASH_INITIALIZER(&dpif_classes);

//黑名单, 加入的是 dpif_class->type (在 ovs-vswitchd 中可以将 system 加入该黑名单)
static struct sset dpif_blacklist = SSET_INITIALIZER(&dpif_blacklist);

const struct dpif_class dpif_netlink_class = {
    "system",
    NULL,                       /* init */
    dpif_netlink_enumerate,
    NULL,
    dpif_netlink_open,
    dpif_netlink_close,
    dpif_netlink_destroy,
    dpif_netlink_run,
    NULL,                       /* wait */
    dpif_netlink_get_stats,
    dpif_netlink_port_add,
    dpif_netlink_port_del,
    dpif_netlink_port_query_by_number,
    dpif_netlink_port_query_by_name,
    dpif_netlink_port_get_pid,
    dpif_netlink_port_dump_start,
    dpif_netlink_port_dump_next,
    dpif_netlink_port_dump_done,
    dpif_netlink_port_poll,
    dpif_netlink_port_poll_wait,
    dpif_netlink_flow_flush,
    dpif_netlink_flow_dump_create,
    dpif_netlink_flow_dump_destroy,
    dpif_netlink_flow_dump_thread_create,
    dpif_netlink_flow_dump_thread_destroy,
    dpif_netlink_flow_dump_next,
    dpif_netlink_operate,
    dpif_netlink_recv_set,
    dpif_netlink_handlers_set,
    NULL,                       /* poll_thread_set */
    dpif_netlink_queue_to_priority,
    dpif_netlink_recv,
    dpif_netlink_recv_wait,
    dpif_netlink_recv_purge,
    NULL,                       /* register_upcall_cb */
    NULL,                       /* enable_upcall */
    NULL,                       /* disable_upcall */
    dpif_netlink_get_datapath_version, /* get_datapath_version */
};

const struct dpif_class dpif_netdev_class = {
    "netdev",
    dpif_netdev_init,
    dpif_netdev_enumerate,
    dpif_netdev_port_open_type,
    dpif_netdev_open,
    dpif_netdev_close,
    dpif_netdev_destroy,
    dpif_netdev_run,
    dpif_netdev_wait,
    dpif_netdev_get_stats,
    dpif_netdev_port_add,
    dpif_netdev_port_del,
    dpif_netdev_port_query_by_number,
    dpif_netdev_port_query_by_name,
    NULL,                       /* port_get_pid */
    dpif_netdev_port_dump_start,
    dpif_netdev_port_dump_next,
    dpif_netdev_port_dump_done,
    dpif_netdev_port_poll,
    dpif_netdev_port_poll_wait,
    dpif_netdev_flow_flush,
    dpif_netdev_flow_dump_create,
    dpif_netdev_flow_dump_destroy,
    dpif_netdev_flow_dump_thread_create,
    dpif_netdev_flow_dump_thread_destroy,
    dpif_netdev_flow_dump_next,
    dpif_netdev_operate,
    NULL,                       /* recv_set */
    NULL,                       /* handlers_set */
    dpif_netdev_pmd_set,
    dpif_netdev_queue_to_priority,
    NULL,                       /* recv */
    NULL,                       /* recv_wait */
    NULL,                       /* recv_purge */
    dpif_netdev_register_upcall_cb,
    dpif_netdev_enable_upcall,
    dpif_netdev_disable_upcall,
    dpif_netdev_get_datapath_version,
};


##dpif-netlink

###消息格式的转换

在将 request 发送给内核的时候必须先转换为 struct ofpbuf 类型
在接受到应答后, 必须将 bufp 转换为 reply
此外, 在给内核发送数据的时候又将 struct ofpbuf 转换为 struct msghdr.
此外, 收到内核应答数据的时候又将 struct msghdr 转换为 struct ofpbuf.

而为了能够更好地映射发送和应答关系, 通过 struct transaction 数据结构 保持, 待发送的 request 和待接受的 reply
而 struct msghdr 又包含 struct iovecs. 可以包多个 struct transaction 消息放入 iovecs 中, 一次发送多个请求.


##flow 流表操作


ofproto_add_flow
    simple_flow_mod
        handle_flow_mod__
            ofproto_flow_mod_start
                OFPFC_ADD           : add_flow_start(ofproto, ofm);
                OFPFC_MODIFY        : modify_flows_start_loose(ofproto, ofm);
                OFPFC_MODIFY_STRICT : modify_flow_start_strict(ofproto, ofm);
                OFPFC_DELETE        : delete_flows_start_loose(ofproto, ofm);
                OFPFC_DELETE_STRICT : delete_flow_start_strict(ofproto, ofm);
            ofproto_flow_mod_finish

ofproto_delete_flow
    simple_flow_mod
        handle_flow_mod__
            ofproto_flow_mod_start
            ofproto_flow_mod_finish

/* A sparse representation of a "struct flow".
 *
 * A "struct flow" is fairly large and tends to be mostly zeros.  Sparse
 * representation has two advantages.  First, it saves memory and, more
 * importantly, minimizes the number of accessed cache lines.  Second, it saves
 * time when the goal is to iterate over only the nonzero parts of the struct.
 *
 * The map members hold one bit for each uint64_t in a "struct flow".  Each
 * 0-bit indicates that the corresponding uint64_t is zero, each 1-bit that it
 * *may* be nonzero (see below how this applies to minimasks).
 *
 * The values indicated by 'tnl_map' and 'pkt_map' always follow the miniflow
 * in memory.  The user of the miniflow is responsible for always having enough
 * storage after the struct miniflow corresponding to the number of 1-bits in
 * maps.
 *
 * Elements in values array are allowed to be zero.  This is useful for "struct
 * minimatch", for which ensuring that the miniflow and minimask members have
 * same maps allows optimization.  This allowance applies only to a miniflow
 * that is not a mask.  That is, a minimask may NOT have zero elements in its
 * values.
 *
 * A miniflow is always dynamically allocated so that the maps are followed by
 * at least as many elements as there are 1-bits in maps. */
/* miniflow->tnl_map 记录了 flow->flow_tnl 中 uint64_t 的个数, 如果每个 uint64_t
 * 对应的值不为 0, tnl_map 对应的位为 1. 最多支持 64 个 bit. 即 flow->flow_tnl
 * 最长为 64 个 uint64_t.
 * miniflow->pkt_map 记录了 flow->flow_tnl 之后的以 uint64_t 为单位的值是否为 0.
 * miniflow->values 记录了 flow 以 uint64_t 为单位的 uint64_t 的值
 */
struct miniflow {
    uint64_t tnl_map;
    uint64_t pkt_map;
    /* Followed by:
     *     uint64_t values[n];
     * where 'n' is miniflow_n_values(miniflow). */
};

struct minimask {
    struct miniflow masks;
};

struct flow_wildcards {
    struct flow masks;
};

struct match {
    struct flow flow;
    struct flow_wildcards wc;
    struct tun_metadata_allocation tun_md;
};

/* Compressed match. */

/* A sparse representation of a "struct match".
 *
 * 'flows' is used for allocating both 'flow' and 'mask' with one
 * miniflow_alloc() call.
 *
 * There are two invariants:
 *
 *   - The same invariant as "struct match", that is, a 1-bit in the 'flow'
 *     must correspond to a 1-bit in 'mask'.
 *
 *   - 'flow' and 'mask' have the same 'map'.  This implies that 'flow' and
 *     'mask' have the same part of "struct flow" at the same offset into
 *     'values', which makes minimatch_matches_flow() faster.
 */
struct minimatch {
    union {
        struct {
            struct miniflow *flow;
            struct minimask *mask;
        };
        struct miniflow *flows[2];
    };
};

用 match, minimatch 初始化 miniflow, minimask

classifier->subtables_map : cls_subtable
cls_subtable->rules       : cls_match
cls_match->cls_rule       : flow

miniflow 的 tnl_map 保持了 flow->tnl_map 中以 uint64_t 为单位对应的值是否为 1
miniflow 的 pkt_map 保持了 flow->pkt_map 中以 uint64_t 为单位对应的值是否为 1
miniflow 的 values 保持了 flow 中以 uint64_t 为单位的值中非 1 的 bit

比如 minflow->tnl_map = 0x0000000000000005 那么表明 flow->tnl_map 的第一个
uint64_t 和第三个 uint64_t 都是 1. 将 flow 分为 uint64_t 为单位的字节, 
miniflow->values[0] 为 flow->tnl_map 第一个 uint64_t 的值, miniflow->values[1]
为 flow->tnl_map 第三个 uint64_t 的值.

classifier->subtables 保持具有相同 mask 的流表的集合
cls_subtable 的 cls_rule 保持流表

table->eviction_groups_by_size 保存 eviction_group 成员
eviction_group 保存具有相同 eviction_fields 的 rule.
一张 oftable 可以有任意数量 eviction_group, 每个 eviction_group 可以有任意条 rule

eviction_group 基于 oftable->eviction_fields 的 hash. 因此, 两条 rule
可能属于不同 eviction_fields 可能在相同 eviction_group

##附录

struct nl_sock {
    int fd;
    uint32_t next_seq;          /* default 1 */
    uint32_t pid;
    int protocol;
    unsigned int rcvbuf;        /* Receive buffer size (SO_RCVBUF). default 1024 * 1024; */
};

/* Compile-time limit on iovecs, so that we can allocate a maximum-size array
 * of iovecs on the stack. */
#define MAX_IOVS 128

/* Maximum number of iovecs that may be passed to sendmsg, capped at a
 * minimum of _XOPEN_IOV_MAX (16) and a maximum of MAX_IOVS.
 *
 * Initialized by nl_sock_create(). */
static int max_iovs;

int nl_sock_create(int protocol, struct nl_sock **sockp)

    struct nl_sock *sock;
    struct sockaddr_nl local, remote;
    socklen_t local_size;
    int rcvbuf;
    int retval = 0;

    if (ovsthread_once_start(&once)) {
        int save_errno = errno;
        errno = 0;

        max_iovs = sysconf(_SC_UIO_MAXIOV);
        if (max_iovs < _XOPEN_IOV_MAX) {
            if (max_iovs == -1 && errno) {
                VLOG_WARN("sysconf(_SC_UIO_MAXIOV): %s", ovs_strerror(errno));
            }
            max_iovs = _XOPEN_IOV_MAX;
        } else if (max_iovs > MAX_IOVS) {
            max_iovs = MAX_IOVS;
        }

        errno = save_errno;
        ovsthread_once_done(&once);
    }

    *sockp = NULL;
    sock = xmalloc(sizeof *sock);

    sock->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
    if (sock->fd < 0) {
        printf("fcntl: %s", errno);
        goto error;
    }

    sock->protocol = protocol;
    sock->next_seq = 1;

    rcvbuf = 1024 * 1024;

    if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUFFORCE,
                   &rcvbuf, sizeof rcvbuf)) {
        /* Only root can use SO_RCVBUFFORCE.  Everyone else gets EPERM.
         * Warn only if the failure is therefore unexpected. */
        if (errno != EPERM) {
            printf("setting %d-byte socket receive buffer failed "
                         "(%s)", rcvbuf, strer(errno));
        }
    }

    socklen_t len;
    int error;
    len = sizeof value;
    if (getsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, &value, &len)) {
        error = sock_errno();
        printf("getsockopt(%s): %s", optname, sock_strerror(error));
    } else if (len != sizeof value) {
        error = EINVAL;
        printf("getsockopt(%s): value is %u bytes (expected %"PRIuSIZE")",
                    optname, (unsigned int) len, sizeof value);
    } else {
        error = 0;
    }

    int retval = error;
    if (retval < 0) {
        retval = -retval;
        goto error;
    }

    rcvbuf = value;
    sock->rcvbuf = rcvbuf;

    /* Connect to kernel (pid 0) as remote address. */
    memset(&remote, 0, sizeof remote);
    remote.nl_family = AF_NETLINK;
    remote.nl_pid = 0;
    if (connect(sock->fd, (struct sockaddr *) &remote, sizeof remote) < 0) {
        printf("connect(0): %s", ovs_strerror(errno));
        goto error;
    }

    /* Obtain pid assigned by kernel. */
    local_size = sizeof local;
    if (getsockname(sock->fd, (struct sockaddr *) &local, &local_size) < 0) {
        printf("getsockname: %s", ovs_strerror(errno));
        goto error;
    }
    if (local_size < sizeof local || local.nl_family != AF_NETLINK) {
        printf("getsockname returned bad Netlink name");
        retval = EINVAL;
        goto error;
    }
    sock->pid = local.nl_pid;

    *sockp = sock;
    return 0;

error:
    if (retval == 0) {
        retval = errno;
        if (retval == 0) {
            retval = EINVAL;
        }
    }
    if (sock->fd >= 0) {
        close(sock->fd);
    }
    free(sock);
    return retval;
}


//加入多播组

if (setsockopt(sock->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                &multicast_group, sizeof multicast_group) < 0) {
    printf("could not join multicast group %u (%s)",
                multicast_group, strerror(errno));
    return errno;
}

//从多播组中去除
if (setsockopt(sock->fd, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
                &multicast_group, sizeof multicast_group) < 0) {
    printf("could not leave multicast group %u (%s)",
                multicast_group, ovs_strerror(errno));
    return errno;
}


//多播组

unsigned int multicast_group
error = nl_sock_create(NETLINK_GENERIC, &sock);
if (setsockopt(sock->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
               &multicast_group, sizeof multicast_group) < 0) {
    printf("could not join multicast group %u (%s)",
              multicast_group, ovs_strerror(errno));
    return errno;
}



##附录

/*
 * dpif, the DataPath InterFace.
 *
 * In Open vSwitch terminology, a "datapath" is a flow-based software switch.
 * A datapath has no intelligence of its own.  Rather, it relies entirely on
 * its client to set up flows.  The datapath layer is core to the Open vSwitch
 * software switch: one could say, without much exaggeration, that everything
 * in ovs-vswitchd above dpif exists only to make the correct decisions
 * interacting with dpif.
 *
 * Typically, the client of a datapath is the software switch module in
 * "ovs-vswitchd", but other clients can be written.  The "ovs-dpctl" utility
 * is also a (simple) client.
 *
 *
 * Overview
 * ========
 *
 * The terms written in quotes below are defined in later sections.
 *
 * When a datapath "port" receives a packet, it extracts the headers (the
 * "flow").  If the datapath's "flow table" contains a "flow entry" matching
 * the packet, then it executes the "actions" in the flow entry and increments
 * the flow's statistics.  If there is no matching flow entry, the datapath
 * instead appends the packet to an "upcall" queue.
 *
 *
 * Ports
 * =====
 *
 * A datapath has a set of ports that are analogous to the ports on an Ethernet
 * switch.  At the datapath level, each port has the following information
 * associated with it:
 *
 *    - A name, a short string that must be unique within the host.  This is
 *      typically a name that would be familiar to the system administrator,
 *      e.g. "eth0" or "vif1.1", but it is otherwise arbitrary.
 *
 *    - A 32-bit port number that must be unique within the datapath but is
 *      otherwise arbitrary.  The port number is the most important identifier
 *      for a port in the datapath interface.
 *
 *    - A type, a short string that identifies the kind of port.  On a Linux
 *      host, typical types are "system" (for a network device such as eth0),
 *      "internal" (for a simulated port used to connect to the TCP/IP stack),
 *      and "gre" (for a GRE tunnel).
 *
 *    - A Netlink PID for each upcall reading thread (see "Upcall Queuing and
 *      Ordering" below).
 *
 * The dpif interface has functions for adding and deleting ports.  When a
 * datapath implements these (e.g. as the Linux and netdev datapaths do), then
 * Open vSwitch's ovs-vswitchd daemon can directly control what ports are used
 * for switching.  Some datapaths might not implement them, or implement them
 * with restrictions on the types of ports that can be added or removed
 * (e.g. on ESX), on systems where port membership can only be changed by some
 * external entity.
 *
 * Each datapath must have a port, sometimes called the "local port", whose
 * name is the same as the datapath itself, with port number 0.  The local port
 * cannot be deleted.
 *
 * Ports are available as "struct netdev"s.  To obtain a "struct netdev *" for
 * a port named 'name' with type 'port_type', in a datapath of type
 * 'datapath_type', call netdev_open(name, dpif_port_open_type(datapath_type,
 * port_type).  The netdev can be used to get and set important data related to
 * the port, such as:
 *
 *    - MTU (netdev_get_mtu(), netdev_set_mtu()).
 *
 *    - Ethernet address (netdev_get_etheraddr(), netdev_set_etheraddr()).
 *
 *    - Statistics such as the number of packets and bytes transmitted and
 *      received (netdev_get_stats()).
 *
 *    - Carrier status (netdev_get_carrier()).
 *
 *    - Speed (netdev_get_features()).
 *
 *    - QoS queue configuration (netdev_get_queue(), netdev_set_queue() and
 *      related functions.)
 *
 *    - Arbitrary port-specific configuration parameters (netdev_get_config(),
 *      netdev_set_config()).  An example of such a parameter is the IP
 *      endpoint for a GRE tunnel.
 *
 *
 * Flow Table
 * ==========
 *
 * The flow table is a collection of "flow entries".  Each flow entry contains:
 *
 *    - A "flow", that is, a summary of the headers in an Ethernet packet.  The
 *      flow must be unique within the flow table.  Flows are fine-grained
 *      entities that include L2, L3, and L4 headers.  A single TCP connection
 *      consists of two flows, one in each direction.
 *
 *      In Open vSwitch userspace, "struct flow" is the typical way to describe
 *      a flow, but the datapath interface uses a different data format to
 *      allow ABI forward- and backward-compatibility.  datapath/README.md
 *      describes the rationale and design.  Refer to OVS_KEY_ATTR_* and
 *      "struct ovs_key_*" in include/odp-netlink.h for details.
 *      lib/odp-util.h defines several functions for working with these flows.
 *
 *    - A "mask" that, for each bit in the flow, specifies whether the datapath
 *      should consider the corresponding flow bit when deciding whether a
 *      given packet matches the flow entry.  The original datapath design did
 *      not support matching: every flow entry was exact match.  With the
 *      addition of a mask, the interface supports datapaths with a spectrum of
 *      wildcard matching capabilities, from those that only support exact
 *      matches to those that support bitwise wildcarding on the entire flow
 *      key, as well as datapaths with capabilities somewhere in between.
 *
 *      Datapaths do not provide a way to query their wildcarding capabilities,
 *      nor is it expected that the client should attempt to probe for the
 *      details of their support.  Instead, a client installs flows with masks
 *      that wildcard as many bits as acceptable.  The datapath then actually
 *      wildcards as many of those bits as it can and changes the wildcard bits
 *      that it does not support into exact match bits.  A datapath that can
 *      wildcard any bit, for example, would install the supplied mask, an
 *      exact-match only datapath would install an exact-match mask regardless
 *      of what mask the client supplied, and a datapath in the middle of the
 *      spectrum would selectively change some wildcard bits into exact match
 *      bits.
 *
 *      Regardless of the requested or installed mask, the datapath retains the
 *      original flow supplied by the client.  (It does not, for example, "zero
 *      out" the wildcarded bits.)  This allows the client to unambiguously
 *      identify the flow entry in later flow table operations.
 *
 *      The flow table does not have priorities; that is, all flow entries have
 *      equal priority.  Detecting overlapping flow entries is expensive in
 *      general, so the datapath is not required to do it.  It is primarily the
 *      client's responsibility not to install flow entries whose flow and mask
 *      combinations overlap.
 *
 *    - A list of "actions" that tell the datapath what to do with packets
 *      within a flow.  Some examples of actions are OVS_ACTION_ATTR_OUTPUT,
 *      which transmits the packet out a port, and OVS_ACTION_ATTR_SET, which
 *      modifies packet headers.  Refer to OVS_ACTION_ATTR_* and "struct
 *      ovs_action_*" in include/odp-netlink.h for details.  lib/odp-util.h
 *      defines several functions for working with datapath actions.
 *
 *      The actions list may be empty.  This indicates that nothing should be
 *      done to matching packets, that is, they should be dropped.
 *
 *      (In case you are familiar with OpenFlow, datapath actions are analogous
 *      to OpenFlow actions.)
 *
 *    - Statistics: the number of packets and bytes that the flow has
 *      processed, the last time that the flow processed a packet, and the
 *      union of all the TCP flags in packets processed by the flow.  (The
 *      latter is 0 if the flow is not a TCP flow.)
 *
 * The datapath's client manages the flow table, primarily in reaction to
 * "upcalls" (see below).
 *
 *
 * Upcalls
 * =======
 *
 * A datapath sometimes needs to notify its client that a packet was received.
 * The datapath mechanism to do this is called an "upcall".
 *
 * Upcalls are used in two situations:
 *
 *    - When a packet is received, but there is no matching flow entry in its
 *      flow table (a flow table "miss"), this causes an upcall of type
 *      DPIF_UC_MISS.  These are called "miss" upcalls.
 *
 *    - A datapath action of type OVS_ACTION_ATTR_USERSPACE causes an upcall of
 *      type DPIF_UC_ACTION.  These are called "action" upcalls.
 *
 * __ An upcall contains an entire packet __.  There is no attempt to, e.g., copy
 * only as much of the packet as normally needed to make a forwarding decision.
 * Such an optimization is doable, but experimental prototypes showed it to be
 * of little benefit because an upcall typically contains the first packet of a
 * flow, which is usually short (e.g. a TCP SYN).  Also, the entire packet can
 * sometimes really be needed.
 *
 * After a client reads a given upcall, the datapath is finished with it, that
 * is, the datapath doesn't maintain any lingering state past that point.
 *
 * The latency from the time that a packet arrives at a port to the time that
 * it is received from dpif_recv() is critical in some benchmarks.  For
 * example, if this latency is 1 ms, then a netperf TCP_CRR test, which opens
 * and closes TCP connections one at a time as quickly as it can, cannot
 * possibly achieve more than 500 transactions per second, since every
 * connection consists of two flows with 1-ms latency to set up each one.
 *
 * To receive upcalls, a client has to enable them with dpif_recv_set().  A
 * datapath should generally support being opened multiple times (e.g. so that
 * one may run "ovs-dpctl show" or "ovs-dpctl dump-flows" while "ovs-vswitchd"
 * is also running) but need not support more than one of these clients
 * enabling upcalls at once.
 *
 *
 * Upcall Queuing and Ordering
 * ---------------------------
 *
 * The datapath's client reads upcalls one at a time by calling dpif_recv().
 * When more than one upcall is pending, the order in which the datapath
 * presents upcalls to its client is important.  The datapath's client does not
 * directly control this order, so the datapath implementer must take care
 * during design.
 *
 * The minimal behavior, suitable for initial testing of a datapath
 * implementation, is that all upcalls are appended to a single queue, which is
 * delivered to the client in order.
 *
 * The datapath should ensure that a high rate of upcalls from one particular
 * port cannot cause upcalls from other sources to be dropped or unreasonably
 * delayed.  Otherwise, one port conducting a port scan or otherwise initiating
 * high-rate traffic spanning many flows could suppress other traffic.
 * Ideally, the datapath should present upcalls from each port in a "round
 * robin" manner, to ensure fairness.
 *
 * The client has no control over "miss" upcalls and no insight into the
 * datapath's implementation, so the datapath is entirely responsible for
 * queuing and delivering them.  On the other hand, the datapath has
 * considerable freedom of implementation.  One good approach is to maintain a
 * separate queue for each port, to prevent any given port's upcalls from
 * interfering with other ports' upcalls.  If this is impractical, then another
 * reasonable choice is to maintain some fixed number of queues and assign each
 * port to one of them.  Ports assigned to the same queue can then interfere
 * with each other, but not with ports assigned to different queues.  Other
 * approaches are also possible.
 *
 * The client has some control over "action" upcalls: it can specify a 32-bit
 * "Netlink PID" as part of the action.  This terminology comes from the Linux
 * datapath implementation, which uses a protocol called Netlink in which a PID
 * designates a particular socket and the upcall data is delivered to the
 * socket's receive queue.  Generically, though, a Netlink PID identifies a
 * queue for upcalls.  The basic requirements on the datapath are:
 *
 *    - The datapath must provide a Netlink PID associated with each port.  The
 *      client can retrieve the PID with dpif_port_get_pid().
 *
 *    - The datapath must provide a "special" Netlink PID not associated with
 *      any port.  dpif_port_get_pid() also provides this PID.  (ovs-vswitchd
 *      uses this PID to queue special packets that must not be lost even if a
 *      port is otherwise busy, such as packets used for tunnel monitoring.)
 *
 * The minimal behavior of dpif_port_get_pid() and the treatment of the Netlink
 * PID in "action" upcalls is that dpif_port_get_pid() returns a constant value
 * and all upcalls are appended to a single queue.
 *
 * The preferred behavior is:
 *
 *    - Each port has a PID that identifies the queue used for "miss" upcalls
 *      on that port.  (Thus, if each port has its own queue for "miss"
 *      upcalls, then each port has a different Netlink PID.)
 *
 *    - "miss" upcalls for a given port and "action" upcalls that specify that
 *      port's Netlink PID add their upcalls to the same queue.  The upcalls
 *      are delivered to the datapath's client in the order that the packets
 *      were received, regardless of whether the upcalls are "miss" or "action"
 *      upcalls.
 *
 *    - Upcalls that specify the "special" Netlink PID are queued separately.
 *
 * Multiple threads may want to read upcalls simultaneously from a single
 * datapath.  To support multiple threads well, one extends the above preferred
 * behavior:
 *
 *    - Each port has multiple PIDs.  The datapath distributes "miss" upcalls
 *      across the PIDs, ensuring that a given flow is mapped in a stable way
 *      to a single PID.
 *
 *    - For "action" upcalls, the thread can specify its own Netlink PID or
 *      other threads' Netlink PID of the same port for offloading purpose
 *      (e.g. in a "round robin" manner).
 *
 *
 * Packet Format
 * =============
 *
 * The datapath interface works with packets in a particular form.  This is the
 * form taken by packets received via upcalls (i.e. by dpif_recv()).  Packets
 * supplied to the datapath for processing (i.e. to dpif_execute()) also take
 * this form.
 *
 * A VLAN tag is represented by an 802.1Q header.  If the layer below the
 * datapath interface uses another representation, then the datapath interface
 * must perform conversion.
 *
 * __ The datapath interface requires all packets to fit within the MTU.  Some
 * operating systems internally process packets larger than MTU, with features
 * such as TSO and UFO. __ When such a packet passes through the datapath
 * interface, it must be broken into multiple MTU or smaller sized packets for
 * presentation as upcalls.  (This does not happen often, because an upcall
 * typically contains the first packet of a flow, which is usually short.)
 *
 * Some operating system TCP/IP stacks maintain packets in an unchecksummed or
 * partially checksummed state until transmission.  The datapath interface
 * requires all host-generated packets to be fully checksummed (e.g. IP and TCP
 * checksums must be correct).  On such an OS, the datapath interface must fill
 * in these checksums.
 *
 * Packets passed through the datapath interface must be at least 14 bytes
 * long, that is, they must have a complete Ethernet header.  They are not
 * required to be padded to the minimum Ethernet length.
 *
 *
 * Typical Usage
 * =============
 *
 * Typically, the client of a datapath begins by configuring the datapath with
 * a set of ports.  Afterward, the client runs in a loop polling for upcalls to
 * arrive.
 *
 * For each upcall received, the client examines the enclosed packet and
 * figures out what should be done with it.  For example, if the client
 * implements a MAC-learning switch, then it searches the forwarding database
 * for the packet's destination MAC and VLAN and determines the set of ports to
 * which it should be sent.  In any case, the client composes a set of datapath
 * actions to properly dispatch the packet and then directs the datapath to
 * execute those actions on the packet (e.g. with dpif_execute()).
 *
 * Most of the time, the actions that the client executed on the packet apply
 * to every packet with the same flow.  For example, the flow includes both
 * destination MAC and VLAN ID (and much more), so this is true for the
 * MAC-learning switch example above.  In such a case, the client can also
 * direct the datapath to treat any further packets in the flow in the same
 * way, using dpif_flow_put() to add a new flow entry.
 *
 * Other tasks the client might need to perform, in addition to reacting to
 * upcalls, include:
 *
 *    - Periodically polling flow statistics, perhaps to supply to its own
 *      clients.
 *
 *    - Deleting flow entries from the datapath that haven't been used
 *      recently, to save memory.
 *
 *    - Updating flow entries whose actions should change.  For example, if a
 *      MAC learning switch learns that a MAC has moved, then it must update
 *      the actions of flow entries that sent packets to the MAC at its old
 *      location.
 *
 *    - Adding and removing ports to achieve a new configuration.
 *
 *
 * Thread-safety
 * =============
 *
 * Most of the dpif functions are fully thread-safe: they may be called from
 * any number of threads on the same or different dpif objects.  The exceptions
 * are:
 *
 *    - dpif_port_poll() and dpif_port_poll_wait() are conditionally
 *      thread-safe: they may be called from different threads only on
 *      different dpif objects.
 *
 *    - dpif_flow_dump_next() is conditionally thread-safe: It may be called
 *      from different threads with the same 'struct dpif_flow_dump', but all
 *      other parameters must be different for each thread.
 *
 *    - dpif_flow_dump_done() is conditionally thread-safe: All threads that
 *      share the same 'struct dpif_flow_dump' must have finished using it.
 *      This function must then be called exactly once for a particular
 *      dpif_flow_dump to finish the corresponding flow dump operation.
 *
 *    - Functions that operate on 'struct dpif_port_dump' are conditionally
 *      thread-safe with respect to those objects.  That is, one may dump ports
 *      from any number of threads at once, but each thread must use its own
 *      struct dpif_port_dump.
 */

###NUMA 相关

void discover_numa_and_core(void)

在 /sys/devices/system/node/node%n 中查找所有 numa node, 每个 numa node 下的
cpu. 并将 numa node 加入 all_numa_nodes, cpu core 加入 all_cpu_cores

int ovs_numa_get_n_numas(void)
int ovs_numa_get_n_cores(void)
struct numa_node* get_numa_by_numa_id(int numa_id)
bool ovs_numa_core_is_pinned(unsigned core_id)
bool ovs_numa_core_id_is_valid(unsigned core_id)
bool ovs_numa_numa_id_is_valid(int numa_id)

###设计考量

1. 为什么 upcall 要包含整个包?

事实上可以这样优化, 但是这是不必要的, 因为典型的 需要 upcall 都是首包, 包
的大小非常小, 因此是不是必须的. 如果业务场景包含大量 upcall 的包, 那么,
对 upcall 的包的大小限制调是合理的.

    An upcall contains an entire packet.  There is no attempt to, e.g., copy
    only as much of the packet as normally needed to make a forwarding decision.
    Such an optimization is doable, but experimental prototypes showed it to be
    of little benefit because an upcall typically contains the first packet of a
    flow, which is usually short (e.g. a TCP SYN).  Also, the entire packet can
    sometimes really be needed.

2. datapath 调用 upcall 的时机

　1. table_miss
  2. 显示地要求 upcall

3. datapath 调用 upcall 之后是否会将包保留在 datapath, 等待用户态下发流表后, 继续走流表?

   不会

    After a client reads a given upcall, the datapath is finished with it, that
    is, the datapath doesn't maintain any lingering state past that point.

4. upcall 的顺序如何保证 ?

如果将所有端口都加入同一队列, 如果某个端口的数据非常多速率非常大, 不能保证保证各个端口
的其他端口的数据被丢掉或不合理的延迟.

因此, 为每个端口维护一个队列,　如果端口过多就导致队列过多, 更好的方式是维护一个固定数量的队列,
每个端口映射到每个队列.  可以将多个端口绑定到一个队列, 但是不允许将一个端口绑定到多个队列.

miss 和 action 都到同一个队列

miss 可以将一个端口绑定到多个 PID, 但需要确保特定的包始终映射到同一PID.
actions 可以将一个端口绑定到多个 PID, 但需要确保特定的包始终映射到同一PID.

    The minimal behavior, suitable for initial testing of a datapath
    implementation, is that all upcalls are appended to a single queue, which is
    delivered to the client in order.

    The datapath should ensure that a high rate of upcalls from one particular
    port cannot cause upcalls from other sources to be dropped or unreasonably
    delayed.  Otherwise, one port conducting a port scan or otherwise initiating
    high-rate traffic spanning many flows could suppress other traffic.
    Ideally, the datapath should present upcalls from each port in a "round
    robin" manner, to ensure fairness.

    The client has no control over "miss" upcalls and no insight into the
    datapath's implementation, so the datapath is entirely responsible for
    queuing and delivering them.  On the other hand, the datapath has
    considerable freedom of implementation.  One good approach is to maintain a
    separate queue for each port, to prevent any given port's upcalls from
    interfering with other ports' upcalls.  If this is impractical, then another
    reasonable choice is to maintain some fixed number of queues and assign each
    port to one of them.  Ports assigned to the same queue can then interfere
    with each other, but not with ports assigned to different queues.  Other
    approaches are also possible.

    The client has some control over "action" upcalls: it can specify a 32-bit
    "Netlink PID" as part of the action.  This terminology comes from the Linux
    datapath implementation, which uses a protocol called Netlink in which a PID
    designates a particular socket and the upcall data is delivered to the
    socket's receive queue.  Generically, though, a Netlink PID identifies a
    queue for upcalls.  The basic requirements on the datapath are:

       - The datapath must provide a Netlink PID associated with each port.  The
         client can retrieve the PID with dpif_port_get_pid().

       - The datapath must provide a "special" Netlink PID not associated with
         any port.  dpif_port_get_pid() also provides this PID.  (ovs-vswitchd
         uses this PID to queue special packets that must not be lost even if a
         port is otherwise busy, such as packets used for tunnel monitoring.)

    The minimal behavior of dpif_port_get_pid() and the treatment of the Netlink
    PID in "action" upcalls is that dpif_port_get_pid() returns a constant value
    and all upcalls are appended to a single queue.

    The preferred behavior is:

       - Each port has a PID that identifies the queue used for "miss" upcalls
         on that port.  (Thus, if each port has its own queue for "miss"
         upcalls, then each port has a different Netlink PID.)

       - "miss" upcalls for a given port and "action" upcalls that specify that
         port's Netlink PID add their upcalls to the same queue.  The upcalls
         are delivered to the datapath's client in the order that the packets
         were received, regardless of whether the upcalls are "miss" or "action"
         upcalls.

       - Upcalls that specify the "special" Netlink PID are queued separately.

    Multiple threads may want to read upcalls simultaneously from a single
    datapath.  To support multiple threads well, one extends the above preferred
    behavior:

       - Each port has multiple PIDs.  The datapath distributes "miss" upcalls
         across the PIDs, ensuring that a given flow is mapped in a stable way
         to a single PID.

       - For "action" upcalls, the thread can specify its own Netlink PID or
         other threads' Netlink PID of the same port for offloading purpose
         (e.g. in a "round robin" manner).


3. 流表相互覆盖问题?

 The flow table does not have priorities; that is, all flow entries have
 equal priority.  Detecting overlapping flow entries is expensive in
 general, so the datapath is not required to do it.  It is primarily the
 client's responsibility not to install flow entries whose flow and mask
 combinations overlap.

4. vswitchd 收到包就立即查匹配流表么, 立即进行 action ? 具体实现细节
1) 与流表项相关的结构, 查询, 存储
2) 与 action 相关的结构
3) 与 流表过期相关的机制
4) 流表项超出配置, 流表淘汰机制, eviction_groups_by_size, eviction_groups_by_id
5) 流表项版本 remove_version add_version

packet_in

ofproto->pins_seq
ofproto->pins_seqno
ofproto->pins
ofproto->up.connmgr

ofproto->rule_executes

port

ofport
ofproto->port_poll_set
ofproto->change_seq
ofproto->ofp_requests

过期流表
ofproto->dump_seq
ofproto->up.expirable

ofproto->eviction_group_timer

每张表, 流表项多于 100000 会发送警告

ofproto->eviction_group_timer
ofproto->eviction_group

oftable->eviction_group
oftable->eviction
oftable->eviction_groups_by_size

5. flow_restore_wait 的意义?

6. 非核心组件

sflow, netflow, ipfix, bundle(lacp, bond), mac learning, mcast snoop, stp, rstp

7 监控相关
ofproto_get_memory_usage : 获取流表对内存的消耗
ofproto_get_ofproto_controller_info : 获取控制器信息



##多线程概要设计


###原子操作

###线程同步


###线程操作
/* Convenient once-only execution.
 *
 *
 * Problem
 * =======
 *
 * POSIX provides pthread_once_t and pthread_once() as primitives for running a
 * set of code only once per process execution.  They are used like this:
 *
 *     static void run_once(void) { ...initialization... }
 *     static pthread_once_t once = PTHREAD_ONCE_INIT;
 * ...
 *     pthread_once(&once, run_once);
 *
 * pthread_once() does not allow passing any parameters to the initialization
 * function, which is often inconvenient, because it means that the function
 * can only access data declared at file scope.
 *
 *
 * Solution
 * ========
 *
 * Use ovsthread_once, like this, instead:
 *
 *     static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
 *
 *     if (ovsthread_once_start(&once)) {
 *         ...initialization...
 *         ovsthread_once_done(&once);
 *     }
 */


###数据结构

/* A flow table within a "struct ofproto".
 *
 *
 * Thread-safety
 * =============
 *
 * Adding or removing rules requires holding ofproto_mutex.
 *
 * Rules in 'cls' are RCU protected.  For extended access to a rule, try
 * incrementing its ref_count with ofproto_rule_try_ref(), or
 * ofproto_rule_ref(), if the rule is still known to be in 'cls'.  A rule
 * will be freed using ovsrcu_postpone() once its 'ref_count' reaches zero.
 *
 * Modifying a rule requires the rule's own mutex.
 *
 * Freeing a rule requires ofproto_mutex.  After removing the rule from the
 * classifier, release a ref_count from the rule ('cls''s reference to the
 * rule).
 *
 * Refer to the thread-safety notes on struct rule for more information.*/
struct oftable {
    enum oftable_flags flags;
    struct classifier cls;      /* Contains "struct rule"s. */
    char *name;                 /* Table name exposed via OpenFlow, or NULL. */

    /* Maximum number of flows or UINT_MAX if there is no limit besides any
     * limit imposed by resource limitations. */
    unsigned int max_flows;
    /* Current number of flows, not counting temporary duplicates nor deferred
     * deletions. */
    unsigned int n_flows;

    /* These members determine the handling of an attempt to add a flow that
     * would cause the table to have more than 'max_flows' flows.
     *
     * If 'eviction_fields' is NULL, overflows will be rejected with an error.
     *
     * If 'eviction_fields' is nonnull (regardless of whether n_eviction_fields
     * is nonzero), an overflow will cause a flow to be removed.  The flow to
     * be removed is chosen to give fairness among groups distinguished by
     * different values for the subfields within 'groups'. */
    struct mf_subfield *eviction_fields;
    size_t n_eviction_fields;

    /* Eviction groups.
     *
     * When a flow is added that would cause the table to have more than
     * 'max_flows' flows, and 'eviction_fields' is nonnull, these groups are
     * used to decide which rule to evict: the rule is chosen from the eviction
     * group that contains the greatest number of rules.*/
    uint32_t eviction_group_id_basis;
    struct hmap eviction_groups_by_id;
    struct heap eviction_groups_by_size;

    /* Flow table miss handling configuration. */
    ATOMIC(enum ofputil_table_miss) miss_config;

    /* Eviction is enabled if either the client (vswitchd) enables it or an
     * OpenFlow controller enables it; thus, a nonzero value indicates that
     * eviction is enabled.  */
#define EVICTION_CLIENT  (1 << 0)  /* Set to 1 if client enables eviction. */
#define EVICTION_OPENFLOW (1 << 1) /* Set to 1 if OpenFlow enables eviction. */
    unsigned int eviction;

    atomic_ulong n_matched;
    atomic_ulong n_missed;
};

/* Flow classifier.
 *
 *
 * What?
 * =====
 *
 * A flow classifier holds any number of "rules", each of which specifies
 * values to match for some fields or subfields and a priority.  Each OpenFlow
 * table is implemented as a flow classifier.
 *
 * The classifier has two primary design goals.  The first is obvious: given a
 * set of packet headers, as quickly as possible find the highest-priority rule
 * that matches those headers.  The following section describes the second
 * goal.
 *
 *
 * "Un-wildcarding"
 * ================
 *
 * A primary goal of the flow classifier is to produce, as a side effect of a
 * packet lookup, a wildcard mask that indicates which bits of the packet
 * headers were essential to the classification result.  Ideally, a 1-bit in
 * any position of this mask means that, if the corresponding bit in the packet
 * header were flipped, then the classification result might change.  A 0-bit
 * means that changing the packet header bit would have no effect.  Thus, the
 * wildcarded bits are the ones that played no role in the classification
 * decision.
 *
 * Such a wildcard mask is useful with datapaths that support installing flows
 * that wildcard fields or subfields.  If an OpenFlow lookup for a TCP flow
 * does not actually look at the TCP source or destination ports, for example,
 * then the switch may install into the datapath a flow that wildcards the port
 * numbers, which in turn allows the datapath to handle packets that arrive for
 * other TCP source or destination ports without additional help from
 * ovs-vswitchd.  This is useful for the Open vSwitch software and,
 * potentially, for ASIC-based switches as well.
 *
 * Some properties of the wildcard mask:
 *
 *     - "False 1-bits" are acceptable, that is, setting a bit in the wildcard
 *       mask to 1 will never cause a packet to be forwarded the wrong way.
 *       As a corollary, a wildcard mask composed of all 1-bits will always
 *       yield correct (but often needlessly inefficient) behavior.
 *
 *     - "False 0-bits" can cause problems, so they must be avoided.  In the
 *       extreme case, a mask of all 0-bits is only correct if the classifier
 *       contains only a single flow that matches all packets.
 *
 *     - 0-bits are desirable because they allow the datapath to act more
 *       autonomously, relying less on ovs-vswitchd to process flow setups,
 *       thereby improving performance.
 *
 *     - We don't know a good way to generate wildcard masks with the maximum
 *       (correct) number of 0-bits.  We use various approximations, described
 *       in later sections.
 *
 *     - Wildcard masks for lookups in a given classifier yield a
 *       non-overlapping set of rules.  More specifically:
 *
 *       Consider an classifier C1 filled with an arbitrary collection of rules
 *       and an empty classifier C2.  Now take a set of packet headers H and
 *       look it up in C1, yielding a highest-priority matching rule R1 and
 *       wildcard mask M.  Form a new classifier rule R2 out of packet headers
 *       H and mask M, and add R2 to C2 with a fixed priority.  If one were to
 *       do this for every possible set of packet headers H, then this
 *       process would not attempt to add any overlapping rules to C2, that is,
 *       any packet lookup using the rules generated by this process matches at
 *       most one rule in C2.
 *
 * During the lookup process, the classifier starts out with a wildcard mask
 * that is all 0-bits, that is, fully wildcarded.  As lookup proceeds, each
 * step tends to add constraints to the wildcard mask, that is, change
 * wildcarded 0-bits into exact-match 1-bits.  We call this "un-wildcarding".
 * A lookup step that examines a particular field must un-wildcard that field.
 * In general, un-wildcarding is necessary for correctness but undesirable for
 * performance.
 *
 *
 * Basic Classifier Design
 * =======================
 *
 * Suppose that all the rules in a classifier had the same form.  For example,
 * suppose that they all matched on the source and destination Ethernet address
 * and wildcarded all the other fields.  Then the obvious way to implement a
 * classifier would be a hash table on the source and destination Ethernet
 * addresses.  If new classification rules came along with a different form,
 * you could add a second hash table that hashed on the fields matched in those
 * rules.  With two hash tables, you look up a given flow in each hash table.
 * If there are no matches, the classifier didn't contain a match; if you find
 * a match in one of them, that's the result; if you find a match in both of
 * them, then the result is the rule with the higher priority.
 *
 * This is how the classifier works.  In a "struct classifier", each form of
 * "struct cls_rule" present (based on its ->match.mask) goes into a separate
 * "struct cls_subtable".  A lookup does a hash lookup in every "struct
 * cls_subtable" in the classifier and tracks the highest-priority match that
 * it finds.  The subtables are kept in a descending priority order according
 * to the highest priority rule in each subtable, which allows lookup to skip
 * over subtables that can't possibly have a higher-priority match than already
 * found.  Eliminating lookups through priority ordering aids both classifier
 * primary design goals: skipping lookups saves time and avoids un-wildcarding
 * fields that those lookups would have examined.
 *
 * One detail: a classifier can contain multiple rules that are identical other
 * than their priority.  When this happens, only the highest priority rule out
 * of a group of otherwise identical rules is stored directly in the "struct
 * cls_subtable", with the other almost-identical rules chained off a linked
 * list inside that highest-priority rule.
 *
 * The following sub-sections describe various optimizations over this simple
 * approach.
 *
 *
 * Staged Lookup (Wildcard Optimization)
 * -------------------------------------
 *
 * Subtable lookup is performed in ranges defined for struct flow, starting
 * from metadata (registers, in_port, etc.), then L2 header, L3, and finally
 * L4 ports.  Whenever it is found that there are no matches in the current
 * subtable, the rest of the subtable can be skipped.
 *
 * Staged lookup does not reduce lookup time, and it may increase it, because
 * it changes a single hash table lookup into multiple hash table lookups.
 * It reduces un-wildcarding significantly in important use cases.
 *
 *
 * Prefix Tracking (Wildcard Optimization)
 * ---------------------------------------
 *
 * Classifier uses prefix trees ("tries") for tracking the used
 * address space, enabling skipping classifier tables containing
 * longer masks than necessary for the given address.  This reduces
 * un-wildcarding for datapath flows in parts of the address space
 * without host routes, but consulting extra data structures (the
 * tries) may slightly increase lookup time.
 *
 * Trie lookup is interwoven with staged lookup, so that a trie is
 * searched only when the configured trie field becomes relevant for
 * the lookup.  The trie lookup results are retained so that each trie
 * is checked at most once for each classifier lookup.
 *
 * This implementation tracks the number of rules at each address
 * prefix for the whole classifier.  More aggressive table skipping
 * would be possible by maintaining lists of tables that have prefixes
 * at the lengths encountered on tree traversal, or by maintaining
 * separate tries for subsets of rules separated by metadata fields.
 *
 * Prefix tracking is configured via OVSDB "Flow_Table" table,
 * "fieldspec" column.  "fieldspec" is a string map where a "prefix"
 * key tells which fields should be used for prefix tracking.  The
 * value of the "prefix" key is a comma separated list of field names.
 *
 * There is a maximum number of fields that can be enabled for any one
 * flow table.  Currently this limit is 3.
 *
 *
 * Partitioning (Lookup Time and Wildcard Optimization)
 * ----------------------------------------------------
 *
 * Suppose that a given classifier is being used to handle multiple stages in a
 * pipeline using "resubmit", with metadata (that is, the OpenFlow 1.1+ field
 * named "metadata") distinguishing between the different stages.  For example,
 * metadata value 1 might identify ingress rules, metadata value 2 might
 * identify ACLs, and metadata value 3 might identify egress rules.  Such a
 * classifier is essentially partitioned into multiple sub-classifiers on the
 * basis of the metadata value.
 *
 * The classifier has a special optimization to speed up matching in this
 * scenario:
 *
 *     - Each cls_subtable that matches on metadata gets a tag derived from the
 *       subtable's mask, so that it is likely that each subtable has a unique
 *       tag.  (Duplicate tags have a performance cost but do not affect
 *       correctness.)
 *
 *     - For each metadata value matched by any cls_rule, the classifier
 *       constructs a "struct cls_partition" indexed by the metadata value.
 *       The cls_partition has a 'tags' member whose value is the bitwise-OR of
 *       the tags of each cls_subtable that contains any rule that matches on
 *       the cls_partition's metadata value.  In other words, struct
 *       cls_partition associates metadata values with subtables that need to
 *       be checked with flows with that specific metadata value.
 *
 * Thus, a flow lookup can start by looking up the partition associated with
 * the flow's metadata, and then skip over any cls_subtable whose 'tag' does
 * not intersect the partition's 'tags'.  (The flow must also be looked up in
 * any cls_subtable that doesn't match on metadata.  We handle that by giving
 * any such cls_subtable TAG_ALL as its 'tags' so that it matches any tag.)
 *
 * Partitioning saves lookup time by reducing the number of subtable lookups.
 * Each eliminated subtable lookup also reduces the amount of un-wildcarding.
 *
 *
 * Classifier Versioning
 * =====================
 *
 * Classifier lookups are always done in a specific classifier version, where
 * a version is defined to be a natural number.
 *
 * When a new rule is added to a classifier, it is set to become visible in a
 * specific version.  If the version number used at insert time is larger than
 * any version number currently used in lookups, the new rule is said to be
 * invisible to lookups.  This means that lookups won't find the rule, but the
 * rule is immediately available to classifier iterations.
 *
 * Similarly, a rule can be marked as to be deleted in a future version.  To
 * delete a rule in a way to not remove the rule before all ongoing lookups are
 * finished, the rule should be made invisible in a specific version number.
 * Then, when all the lookups use a later version number, the rule can be
 * actually removed from the classifier.
 *
 * Classifiers can hold duplicate rules (rules with the same match criteria and
 * priority) when at most one of these duplicates is visible in any given
 * lookup version.  The caller responsible for classifier modifications must
 * maintain this invariant.
 *
 * The classifier supports versioning for two reasons:
 *
 *     1. Support for versioned modifications makes it possible to perform an
 *        arbitraty series of classifier changes as one atomic transaction,
 *        where intermediate versions of the classifier are not visible to any
 *        lookups.  Also, when a rule is added for a future version, or marked
 *        for removal after the current version, such modifications can be
 *        reverted without any visible effects to any of the current lookups.
 *
 *     2. Performance: Adding (or deleting) a large set of rules can, in
 *        pathological cases, have a cost proportional to the number of rules
 *        already in the classifier.  When multiple rules are being added (or
 *        deleted) in one go, though, this pathological case cost can be
 *        typically avoided, as long as it is OK for any new rules to be
 *        invisible until the batch change is complete.
 *
 * Note that the classifier_replace() function replaces a rule immediately, and
 * is therefore not safe to use with versioning.  It is still available for the
 * users that do not use versioning.
 *
 *
 * Deferred Publication
 * ====================
 *
 * Removing large number of rules from classifier can be costly, as the
 * supporting data structures are teared down, in many cases just to be
 * re-instantiated right after.  In the worst case, as when each rule has a
 * different match pattern (mask), the maintenance of the match patterns can
 * have cost O(N^2), where N is the number of different match patterns.  To
 * alleviate this, the classifier supports a "deferred mode", in which changes
 * in internal data structures needed for future version lookups may not be
 * fully computed yet.  The computation is finalized when the deferred mode is
 * turned off.
 *
 * This feature can be used with versioning such that all changes to future
 * versions are made in the deferred mode.  Then, right before making the new
 * version visible to lookups, the deferred mode is turned off so that all the
 * data structures are ready for lookups with the new version number.
 *
 * To use deferred publication, first call classifier_defer().  Then, modify
 * the classifier via additions (classifier_insert() with a specific, future
 * version number) and deletions (use cls_rule_make_removable_after_version()).
 * Then call classifier_publish(), and after that, announce the new version
 * number to be used in lookups.
 *
 *
 * Thread-safety
 * =============
 *
 * The classifier may safely be accessed by many reader threads concurrently
 * and by a single writer, or by multiple writers when they guarantee mutually
 * exlucive access to classifier modifications.
 *
 * Since the classifier rules are RCU protected, the rule destruction after
 * removal from the classifier must be RCU postponed.  Also, when versioning is
 * used, the rule removal itself needs to be typically RCU postponed.  In this
 * case the rule destruction is doubly RCU postponed, i.e., the second
 * ovsrcu_postpone() call to destruct the rule is called from the first RCU
 * callback that removes the rule.
 *
 * Rules that have never been visible to lookups are an exeption to the above
 * rule.  Such rules can be removed immediately, but their destruction must
 * still be RCU postponed, as the rule's visibility attribute may be examined
 * parallel to the rule's removal. */

struct flow {
    /* Metadata */
    struct flow_tnl tunnel;     /* Encapsulating tunnel parameters. */
    ovs_be64 metadata;          /* OpenFlow Metadata. */
    uint32_t regs[FLOW_N_REGS]; /* Registers. */
    uint32_t skb_priority;      /* Packet priority for QoS. */
    uint32_t pkt_mark;          /* Packet mark. */
    uint32_t dp_hash;           /* Datapath computed hash value. The exact
                                 * computation is opaque to the user space. */
    union flow_in_port in_port; /* Input port.*/
    uint32_t recirc_id;         /* Must be exact match. */
    uint32_t conj_id;           /* Conjunction ID. */
    ofp_port_t actset_output;   /* Output port in action set. */
    uint8_t pad1[6];            /* Pad to 64 bits. */

    /* L2, Order the same as in the Ethernet header! (64-bit aligned) */
    uint8_t dl_dst[ETH_ADDR_LEN]; /* Ethernet destination address. */
    uint8_t dl_src[ETH_ADDR_LEN]; /* Ethernet source address. */
    ovs_be16 dl_type;           /* Ethernet frame type. */
    ovs_be16 vlan_tci;          /* If 802.1Q, TCI | VLAN_CFI; otherwise 0. */
    ovs_be32 mpls_lse[ROUND_UP(FLOW_MAX_MPLS_LABELS, 2)]; /* MPLS label stack
                                                             (with padding). */
    /* L3 (64-bit aligned) */
    ovs_be32 nw_src;            /* IPv4 source address. */
    ovs_be32 nw_dst;            /* IPv4 destination address. */
    struct in6_addr ipv6_src;   /* IPv6 source address. */
    struct in6_addr ipv6_dst;   /* IPv6 destination address. */
    ovs_be32 ipv6_label;        /* IPv6 flow label. */
    uint8_t nw_frag;            /* FLOW_FRAG_* flags. */
    uint8_t nw_tos;             /* IP ToS (including DSCP and ECN). */
    uint8_t nw_ttl;             /* IP TTL/Hop Limit. */
    uint8_t nw_proto;           /* IP protocol or low 8 bits of ARP opcode. */
    struct in6_addr nd_target;  /* IPv6 neighbor discovery (ND) target. */
    uint8_t arp_sha[ETH_ADDR_LEN]; /* ARP/ND source hardware address. */
    uint8_t arp_tha[ETH_ADDR_LEN]; /* ARP/ND target hardware address. */
    ovs_be16 tcp_flags;         /* TCP flags. With L3 to avoid matching L4. */
    ovs_be16 pad2;              /* Pad to 64 bits. */

    /* L4 (64-bit aligned) */
    ovs_be16 tp_src;            /* TCP/UDP/SCTP source port. */
    ovs_be16 tp_dst;            /* TCP/UDP/SCTP destination port. */
    ovs_be32 igmp_group_ip4;    /* IGMP group IPv4 address.
                                 * Keep last for BUILD_ASSERT_DECL below. */
};

struct cls_trie {
    const struct mf_field *field; /* Trie field, or NULL. */
    rcu_trie_ptr root;            /* NULL if none. */
};

/* A flow classifier. */
struct classifier {
    int n_rules;                    /* Total number of rules. */
    uint8_t n_flow_segments;
    uint8_t flow_segments[CLS_MAX_INDICES]; /* Flow segment boundaries to use
                                             * for staged lookup. */
    //包含 cls_subtable 元素
    struct cmap subtables_map;      /* Contains "struct cls_subtable"s.  */
    struct pvector subtables;
    struct cmap partitions;         /* Contains "struct cls_partition"s. */
    struct cls_trie tries[CLS_MAX_TRIES]; /* Prefix tries. */
    unsigned int n_tries;
    bool publish;                   /* Make changes visible to lookups? */
};

/* Classifier internal definitions, subject to change at any time. */

/* A set of rules that all have the same fields wildcarded. */
struct cls_subtable {
    struct cmap_node cmap_node;    /* Within classifier's 'subtables_map'. */

    /* These fields are only used by writers. */
    int max_priority;              /* Max priority of any rule in subtable. */
    unsigned int max_count;        /* Count of max_priority rules. */

    /* Accessed by iterators. */
    struct rculist rules_list;              /* Unordered. */

    /* Identical, but lower priority rules are not inserted to any of the
     * following data structures. */

    /* These fields are accessed by readers who care about wildcarding. */
    const tag_type tag;       /* Tag generated from mask for partitioning. */
    const uint8_t n_indices;                   /* How many indices to use. */
    const uint8_t index_ofs[CLS_MAX_INDICES];  /* u64 segment boundaries. */
    unsigned int trie_plen[CLS_MAX_TRIES];  /* Trie prefix length in 'mask'
                                             * (runtime configurable). */
    const int ports_mask_len;
    struct cmap indices[CLS_MAX_INDICES];   /* Staged lookup indices. */
    rcu_trie_ptr ports_trie;                /* NULL if none. */

    /* These fields are accessed by all readers. */
    struct cmap rules;                      /* Contains 'cls_match'es. */
    const struct minimask mask;             /* Wildcards for fields. */
    /* 'mask' must be the last field. */
};

/* Internal representation of a rule in a "struct cls_subtable".
 *
 * The 'next' member is an element in a singly linked, null-terminated list.
 * This list links together identical "cls_match"es in order of decreasing
 * priority.  The classifier code maintains the invariant that at most one rule
 * of a given priority is visible for any given lookup version.
 */
struct cls_match {
    /* Accessed by everybody. */
    OVSRCU_TYPE(struct cls_match *) next; /* Equal, lower-priority matches. */
    OVSRCU_TYPE(struct cls_conjunction_set *) conj_set;

    /* Accessed only by writers. */
    struct cls_partition *partition;

    /* Accessed by readers interested in wildcarding. */
    const int priority;         /* Larger numbers are higher priorities. */
    struct cmap_node index_nodes[CLS_MAX_INDICES]; /* Within subtable's
                                                    * 'indices'. */
    /* Accessed by all readers. */
    struct cmap_node cmap_node; /* Within struct cls_subtable 'rules'. */

    /* Rule versioning.
     *
     * CLS_NOT_REMOVED_VERSION has a special meaning for 'remove_version',
     * meaningthat the rule has been added but not yet removed.
     */
    const cls_version_t add_version;        /* Version rule was added in. */
    ATOMIC(cls_version_t) remove_version;   /* Version rule is removed in. */

    const struct cls_rule *cls_rule;
    const struct miniflow flow; /* Matching rule. Mask is in the subtable. */
    /* 'flow' must be the last field. */
};

struct cls_conjunction {
    uint32_t id;
    uint8_t clause;
    uint8_t n_clauses;
};

/* Doubly linked list head or element. */
struct rculist {
    /* Previous list element. */
    struct rculist *prev OVS_GUARDED_BY(rculist_fake_mutex);

    /* Next list element. */
    OVSRCU_TYPE(struct rculist *) next;
};

/* A rule to be inserted to the classifier. */
struct cls_rule {
    struct rculist node;          /* In struct cls_subtable 'rules_list'. */
    const int priority;           /* Larger numbers are higher priorities. */
    struct cls_match *cls_match;  /* NULL if not in a classifier. */
    const struct minimatch match; /* Matching rule. */
};

/* An OpenFlow flow within a "struct ofproto".
 *
 * With few exceptions, ofproto implementations may look at these fields but
 * should not modify them.
 *
 *
 * Thread-safety
 * =============
 *
 * Except near the beginning or ending of its lifespan, rule 'rule' belongs to
 * the classifier rule->ofproto->tables[rule->table_id].cls.  The text below
 * calls this classifier 'cls'.
 *
 * Motivation
 * ----------
 *
 * The thread safety rules described here for "struct rule" are motivated by
 * two goals:
 *
 *    - Prevent threads that read members of "struct rule" from reading bad
 *      data due to changes by some thread concurrently modifying those
 *      members.
 *
 *    - Prevent two threads making changes to members of a given "struct rule"
 *      from interfering with each other.
 *
 *
 * Rules
 * -----
 *
 * A rule 'rule' may be accessed without a risk of being freed by a thread
 * until the thread quiesces (i.e., rules are RCU protected and destructed
 * using ovsrcu_postpone()).  Code that needs to hold onto a rule for a
 * while should increment 'rule->ref_count' either with ofproto_rule_ref()
 * (if 'ofproto_mutex' is held), or with ofproto_rule_try_ref() (when some
 * other thread might remove the rule from 'cls').  ofproto_rule_try_ref()
 * will fail if the rule has already been scheduled for destruction.
 *
 * 'rule->ref_count' protects 'rule' from being freed.  It doesn't protect the
 * rule from being deleted from 'cls' (that's 'ofproto_mutex') and it doesn't
 * protect members of 'rule' from modification (that's 'rule->mutex').
 *
 * 'rule->mutex' protects the members of 'rule' from modification.  It doesn't
 * protect the rule from being deleted from 'cls' (that's 'ofproto_mutex') and
 * it doesn't prevent the rule from being freed (that's 'rule->ref_count').
 *
 * Regarding thread safety, the members of a rule fall into the following
 * categories:
 *
 *    - Immutable.  These members are marked 'const'.
 *
 *    - Members that may be safely read or written only by code holding
 *      ofproto_mutex.  These are marked OVS_GUARDED_BY(ofproto_mutex).
 *
 *    - Members that may be safely read only by code holding ofproto_mutex or
 *      'rule->mutex', and safely written only by coding holding ofproto_mutex
 *      AND 'rule->mutex'.  These are marked OVS_GUARDED.
 */
struct rule {
    /* Where this rule resides in an OpenFlow switch.
     *
     * These are immutable once the rule is constructed, hence 'const'. */
    struct ofproto *const ofproto; /* The ofproto that contains this rule. */
    const struct cls_rule cr;      /* In owning ofproto's classifier. */
    const uint8_t table_id;        /* Index in ofproto's 'tables' array. */
    bool removed;                  /* Rule has been removed from the ofproto
                                    * data structures. */

    /* Protects members marked OVS_GUARDED.
     * Readers only need to hold this mutex.
     * Writers must hold both this mutex AND ofproto_mutex.
     * By implication writers can read *without* taking this mutex while they
     * hold ofproto_mutex. */
    struct ovs_mutex mutex OVS_ACQ_AFTER(ofproto_mutex);

    /* Number of references.
     * The classifier owns one reference.
     * Any thread trying to keep a rule from being freed should hold its own
     * reference. */
    struct ovs_refcount ref_count;

    /* A "flow cookie" is the OpenFlow name for a 64-bit value associated with
     * a flow.. */
    ovs_be64 flow_cookie OVS_GUARDED;
    struct hindex_node cookie_node OVS_GUARDED_BY(ofproto_mutex);

    enum ofputil_flow_mod_flags flags OVS_GUARDED;

    /* Timeouts. */
    uint16_t hard_timeout OVS_GUARDED; /* In seconds from ->modified. */
    uint16_t idle_timeout OVS_GUARDED; /* In seconds from ->used. */

    /* Eviction precedence. */
    const uint16_t importance;

    /* Removal reason for sending flow removed message.
     * Used only if 'flags' has OFPUTIL_FF_SEND_FLOW_REM set and if the
     * value is not OVS_OFPRR_NONE. */
    uint8_t removed_reason;

    /* Eviction groups (see comment on struct eviction_group for explanation) .
     *
     * 'eviction_group' is this rule's eviction group, or NULL if it is not in
     * any eviction group.  When 'eviction_group' is nonnull, 'evg_node' is in
     * the ->eviction_group->rules hmap. */
    struct eviction_group *eviction_group OVS_GUARDED_BY(ofproto_mutex);
    struct heap_node evg_node OVS_GUARDED_BY(ofproto_mutex);

    /* OpenFlow actions.  See struct rule_actions for more thread-safety
     * notes. */
    const struct rule_actions * const actions;

    /* In owning meter's 'rules' list.  An empty list if there is no meter. */
    struct ovs_list meter_list_node OVS_GUARDED_BY(ofproto_mutex);

    /* Flow monitors (e.g. for NXST_FLOW_MONITOR, related to struct ofmonitor).
     *
     * 'add_seqno' is the sequence number when this rule was created.
     * 'modify_seqno' is the sequence number when this rule was last modified.
     * See 'monitor_seqno' in connmgr.c for more information. */
    enum nx_flow_monitor_flags monitor_flags OVS_GUARDED_BY(ofproto_mutex);
    uint64_t add_seqno OVS_GUARDED_BY(ofproto_mutex);
    uint64_t modify_seqno OVS_GUARDED_BY(ofproto_mutex);

    /* Optimisation for flow expiry.  In ofproto's 'expirable' list if this
     * rule is expirable, otherwise empty. */
    struct ovs_list expirable OVS_GUARDED_BY(ofproto_mutex);

    /* Times.  Last so that they are more likely close to the stats managed
     * by the provider. */
    long long int created OVS_GUARDED; /* Creation time. */

    /* Must hold 'mutex' for both read/write, 'ofproto_mutex' not needed. */
    long long int modified OVS_GUARDED; /* Time of last modification. */
};

/* A set of rules within a single OpenFlow table (oftable) that have the same
 * values for the oftable's eviction_fields.  A rule to be evicted, when one is
 * needed, is taken from the eviction group that contains the greatest number
 * of rules.
 *
 * An oftable owns any number of eviction groups, each of which contains any
 * number of rules.
 *
 * Membership in an eviction group is imprecise, based on the hash of the
 * oftable's eviction_fields (in the eviction_group's id_node.hash member).
 * That is, if two rules have different eviction_fields, but those
 * eviction_fields hash to the same value, then they will belong to the same
 * eviction_group anyway.
 *
 * (When eviction is not enabled on an oftable, we don't track any eviction
 * groups, to save time and space.) */
struct eviction_group {
    struct hmap_node id_node;   /* In oftable's "eviction_groups_by_id". */
    struct heap_node size_node; /* In oftable's "eviction_groups_by_size". */
    struct heap rules;          /* Contains "struct rule"s. */
};
