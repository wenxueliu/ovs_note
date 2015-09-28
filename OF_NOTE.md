
## 控制器连接管理

* PACKET_IN 默认发送长度是 128 字节
* Slave 角色只能得到端口变化状态

###数据结构

/* Connection manager for an OpenFlow switch. */
struct connmgr {
    //交换机
    struct ofproto *ofproto;
    char *name;
    char *local_port_name;

    /* OpenFlow connections. */
    struct hmap controllers;            /* All OFCONN_PRIMARY controllers. */
    struct ovs_list all_conns;          /* All controllers. */
    uint64_t master_election_id;        /* monotonically increasing sequence number
                                            * for master election , default 0 */
    bool master_election_id_defined;    /* default false */

    /* OpenFlow listeners. */
    struct hmap services;               /* Contains "struct ofservice"s. */
    struct pvconn **snoops;
    size_t n_snoops;                    /* the number of snoops */

    /* Fail open. */
    struct fail_open *fail_open;
    enum ofproto_fail_mode fail_mode;   /* default OFPROTO_FAIL_SECURE */

    /* In-band control. */
    struct in_band *in_band;
    struct sockaddr_in *extra_in_band_remotes;
    size_t n_extra_remotes;             /* defautl 0 */
    int in_band_queue;                  /* default -1 */
};

####all_conns

struct ofconn {
/* Configuration that persists from one connection to the next. */

    //list 元素, connmgr->all_conns 的成员
    struct ovs_list node;       /* In struct connmgr's "all_conns" list. */
    struct hmap_node hmap_node; /* In struct connmgr's "controllers" map. */

    struct connmgr *connmgr;    /* Connection's manager. */
    struct rconn *rconn;        /* OpenFlow connection. */
    enum ofconn_type type;      /* Type. */
    enum ofproto_band band;     /* In-band or out-of-band? */
    bool enable_async_msgs;     /* Initially enable async messages? */

/* State that should be cleared from one connection to the next. */

    /* OpenFlow state. */
    enum ofp12_controller_role role;                /* Role.  default OFPCR12_ROLE_EQUAL*/
    enum ofputil_protocol protocol;                 /* Current protocol variant. default OFPUTIL_P_NONE*/
    enum nx_packet_in_format packet_in_format;      /* OFPT_PACKET_IN format. default NXPIF_OPENFLOW10*/

    /* OFPT_PACKET_IN related data. */
    struct rconn_packet_counter *packet_in_counter; /* # queued on 'rconn'. */
#define N_SCHEDULERS 2
    struct pinsched *schedulers[N_SCHEDULERS];
    struct pktbuf *pktbuf;         /* OpenFlow packet buffers. */
    /* 如果 table_miss 发送给 controller 的长度 ofconn->type == OFCONN_PRIMARY ? OFP_DEFAULT_MISS_SEND_LEN : 0*/
    int miss_send_len;             /* Bytes to send of buffered packets. */
    uint16_t controller_id;     /* Connection controller ID. */

    /* Number of OpenFlow messages queued on 'rconn' as replies to OpenFlow
     * requests, and the maximum number before we stop reading OpenFlow
     * requests.  */
#define OFCONN_REPLY_MAX 100
    struct rconn_packet_counter *reply_counter;

    /* Asynchronous message configuration in each possible roles.
     *
     * A 1-bit enables sending an asynchronous message for one possible reason
     * that the message might be generated, a 0-bit disables it. */
    uint32_t master_async_config[OAM_N_TYPES]; /* master, other */
    uint32_t slave_async_config[OAM_N_TYPES];  /* slave */

    /* Flow table operation logging. */
    int n_add, n_delete, n_modify; /* Number of unreported ops of each kind. */
    long long int first_op, last_op; /* Range of times for unreported ops. */
    long long int next_op_report;    /* Time to report ops, default LLONG_MAX. */
    long long int op_backoff;        /* Earliest time to report ops again. */

/* Flow monitors (e.g. NXST_FLOW_MONITOR). */

    /* Configuration.  Contains "struct ofmonitor"s. */
    struct hmap monitors OVS_GUARDED_BY(ofproto_mutex);

    /* Flow control.
     *
     * When too many flow monitor notifications back up in the transmit buffer,
     * we pause the transmission of further notifications.  These members track
     * the flow control state.
     *
     * When notifications are flowing, 'monitor_paused' is 0.  When
     * notifications are paused, 'monitor_paused' is the value of
     * 'monitor_seqno' at the point we paused.
     *
     * 'monitor_counter' counts the OpenFlow messages and bytes currently in
     * flight.  This value growing too large triggers pausing. */
    uint64_t monitor_paused OVS_GUARDED_BY(ofproto_mutex);
    struct rconn_packet_counter *monitor_counter OVS_GUARDED_BY(ofproto_mutex);

    /* State of monitors for a single ongoing flow_mod.
     *
     * 'updates' is a list of "struct ofpbuf"s that contain
     * NXST_FLOW_MONITOR_REPLY messages representing the changes made by the
     * current flow_mod.
     *
     * When 'updates' is nonempty, 'sent_abbrev_update' is true if 'updates'
     * contains an update event of type NXFME_ABBREV and false otherwise.. */
    struct ovs_list updates OVS_GUARDED_BY(ofproto_mutex);
    bool sent_abbrev_update OVS_GUARDED_BY(ofproto_mutex);

    /* Active bundles. Contains "struct ofp_bundle"s. */
    struct hmap bundles;
};

/* A reliable connection to an OpenFlow switch or controller.
 *
 * See the large comment in rconn.h for more information. */
struct rconn {
    struct ovs_mutex mutex;

    enum state state;
    time_t state_entered;

    struct vconn *vconn;
    char *name;                 /* Human-readable descriptive name. */
    char *target;               /* vconn name, passed to vconn_open(). */
    bool reliable;

    struct ovs_list txq;        /* Contains "struct ofpbuf"s. */

    int backoff;
    int max_backoff;
    time_t backoff_deadline;
    time_t last_connected;
    time_t last_disconnected;
    unsigned int seqno;
    int last_error;

    /* In S_ACTIVE and S_IDLE, probably_admitted reports whether we believe
     * that the peer has made a (positive) admission control decision on our
     * connection.  If we have not yet been (probably) admitted, then the
     * connection does not reset the timer used for deciding whether the switch
     * should go into fail-open mode.
     *
     * last_admitted reports the last time we believe such a positive admission
     * control decision was made. */
    bool probably_admitted;
    time_t last_admitted;

    /* These values are simply for statistics reporting, not used directly by
     * anything internal to the rconn (or ofproto for that matter). */
    unsigned int n_attempted_connections, n_successful_connections;
    time_t creation_time;
    unsigned long int total_time_connected;

    /* Throughout this file, "probe" is shorthand for "inactivity probe".  When
     * no activity has been observed from the peer for a while, we send out an
     * echo request as an inactivity probe packet.  We should receive back a
     * response.
     *
     * "Activity" is defined as either receiving an OpenFlow message from the
     * peer or successfully sending a message that had been in 'txq'. */
    int probe_interval;         /* Secs of inactivity before sending probe. */
    time_t last_activity;       /* Last time we saw some activity. */

    uint8_t dscp;

    /* Messages sent or received are copied to the monitor connections. */
#define MAXIMUM_MONITORS 8
    struct vconn *monitors[MAXIMUM_MONITORS];
    size_t n_monitors;

    uint32_t allowed_versions;
};

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
enum ofputil_protocol {
    /* OpenFlow 1.0 protocols.
     *
     * The "STD" protocols use the standard OpenFlow 1.0 flow format.
     * The "NXM" protocols use the Nicira Extensible Match (NXM) flow format.
     *
     * The protocols with "TID" mean that the nx_flow_mod_table_id Nicira
     * extension has been enabled.  The other protocols have it disabled.
     */
#define OFPUTIL_P_NONE 0
    OFPUTIL_P_OF10_STD     = 1 << 0,
    OFPUTIL_P_OF10_STD_TID = 1 << 1,
    OFPUTIL_P_OF10_NXM     = 1 << 2,
    OFPUTIL_P_OF10_NXM_TID = 1 << 3,
#define OFPUTIL_P_OF10_STD_ANY (OFPUTIL_P_OF10_STD | OFPUTIL_P_OF10_STD_TID)
#define OFPUTIL_P_OF10_NXM_ANY (OFPUTIL_P_OF10_NXM | OFPUTIL_P_OF10_NXM_TID)
#define OFPUTIL_P_OF10_ANY (OFPUTIL_P_OF10_STD_ANY | OFPUTIL_P_OF10_NXM_ANY)

    /* OpenFlow 1.1 protocol.
     *
     * We only support the standard OpenFlow 1.1 flow format.
     *
     * OpenFlow 1.1 always operates with an equivalent of the
     * nx_flow_mod_table_id Nicira extension enabled, so there is no "TID"
     * variant. */
    OFPUTIL_P_OF11_STD     = 1 << 4,

    /* OpenFlow 1.2+ protocols (only one variant each).
     *
     * These use the standard OpenFlow Extensible Match (OXM) flow format.
     *
     * OpenFlow 1.2+ always operates with an equivalent of the
     * nx_flow_mod_table_id Nicira extension enabled, so there is no "TID"
     * variant. */
    OFPUTIL_P_OF12_OXM      = 1 << 5,
    OFPUTIL_P_OF13_OXM      = 1 << 6,
    OFPUTIL_P_OF14_OXM      = 1 << 7,
    OFPUTIL_P_OF15_OXM      = 1 << 8,
#define OFPUTIL_P_ANY_OXM (OFPUTIL_P_OF12_OXM | \
                           OFPUTIL_P_OF13_OXM | \
                           OFPUTIL_P_OF14_OXM | \
                           OFPUTIL_P_OF15_OXM)

#define OFPUTIL_P_NXM_OF11_UP (OFPUTIL_P_OF10_NXM_ANY | OFPUTIL_P_OF11_STD | \
                               OFPUTIL_P_ANY_OXM)

#define OFPUTIL_P_NXM_OXM_ANY (OFPUTIL_P_OF10_NXM_ANY | OFPUTIL_P_ANY_OXM)

#define OFPUTIL_P_OF11_UP (OFPUTIL_P_OF11_STD | OFPUTIL_P_ANY_OXM)

#define OFPUTIL_P_OF12_UP (OFPUTIL_P_OF12_OXM | OFPUTIL_P_OF13_UP)
#define OFPUTIL_P_OF13_UP (OFPUTIL_P_OF13_OXM | OFPUTIL_P_OF14_UP)
#define OFPUTIL_P_OF14_UP (OFPUTIL_P_OF14_OXM | OFPUTIL_P_OF15_UP)
#define OFPUTIL_P_OF15_UP OFPUTIL_P_OF15_OXM

    /* All protocols. */
#define OFPUTIL_P_ANY ((1 << 9) - 1)

    /* Protocols in which a specific table may be specified in flow_mods. */
#define OFPUTIL_P_TID (OFPUTIL_P_OF10_STD_TID | \
                       OFPUTIL_P_OF10_NXM_TID | \
                       OFPUTIL_P_OF11_STD |     \
                       OFPUTIL_P_ANY_OXM)
};

enum nx_packet_in_format {
    NXPIF_OPENFLOW10 = 0,       /* Standard OpenFlow 1.0 compatible. */
    NXPIF_NXM = 1               /* Nicira Extended. */
};


/* Counts packets and bytes queued into an rconn by a given source. */
struct rconn_packet_counter {
    struct ovs_mutex mutex;
    unsigned int n_packets OVS_GUARDED; /* Number of packets queued. */
    unsigned int n_bytes OVS_GUARDED;   /* Number of bytes queued. */
    int ref_cnt OVS_GUARDED;            /* Number of owners. */
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


struct pktbuf {
    struct packet packets[PKTBUF_CNT];
    unsigned int buffer_idx;
    unsigned int null_idx;
};

struct packet {
    struct dp_packet *buffer;
    uint32_t cookie;
    long long int timeout;
    ofp_port_t in_port;
};

struct ofproto_controller {
    char *target;               /* e.g. "tcp:127.0.0.1" */
    int max_backoff;            /* Maximum reconnection backoff, in seconds. */
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

static int ofservice_create(struct connmgr *mgr, const char *target, uint32_t allowed_versions, uint8_t dscp)

    根据 target 监听客户端连接, 并初始化 ofservice
    分配 ofservice 对象加入 mgr->services

static void ofservice_destroy(struct connmgr *mgr, struct ofservice *ofservice)

    从 mgr->services 中删除 ofservice
    关闭 ofservice->pvconn

static void ofservice_reconfigure(struct ofservice *ofservice, const struct ofproto_controller *c)

    用 c 重新配置 ofservice

static struct ofservice * ofservice_lookup(struct connmgr *mgr, const char *target)

    遍历 mgr->services 找到 pvconn->name 为 target 的 ofservice

####snoops

/* This structure should be treated as opaque by vconn implementations. */
struct pvconn {
    const struct pvconn_class *pvclass;
    char *name;
    uint32_t allowed_versions;
};

struct pvconn_class {
    /* Prefix for connection names, e.g. "ptcp", "pssl". */
    const char *name;

    /* Attempts to start listening for OpenFlow connections.  'name' is the
     * full connection name provided by the user, e.g. "ptcp:1234".  This name
     * is useful for error messages but must not be modified.
     *
     * 'allowed_versions' is the OpenFlow protocol versions that may * be negotiated for a session.
     *
     * 'suffix' is a copy of 'name' following the colon and may be modified.
     * 'dscp' is the DSCP value that the new connection should use in the IP
     * packets it sends.
     *
     * Returns 0 if successful, otherwise a positive errno value.  If
     * successful, stores a pointer to the new connection in '*pvconnp'.
     *
     * The listen function must not block.  If the connection cannot be
     * completed immediately, it should return EAGAIN (not EINPROGRESS, as
     * returned by the connect system call) and continue the connection in the
     * background. */
    int (*listen)(const char *name, uint32_t allowed_versions,
                  char *suffix, struct pvconn **pvconnp, uint8_t dscp);

    /* Closes 'pvconn' and frees associated memory. */
    void (*close)(struct pvconn *pvconn);

    /* Tries to accept a new connection on 'pvconn'.  If successful, stores the
     * new connection in '*new_vconnp' and returns 0.  Otherwise, returns a
     * positive errno value.
     *
     * The accept function must not block waiting for a connection.  If no
     * connection is ready to be accepted, it should return EAGAIN. */
    int (*accept)(struct pvconn *pvconn, struct vconn **new_vconnp);

    /* Arranges for the poll loop to wake up when a connection is ready to be
     * accepted on 'pvconn'. */
    void (*wait)(struct pvconn *pvconn);
};

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

struct fail_open {
    struct ofproto *ofproto;
    struct connmgr *connmgr;
    int last_disconn_secs;
    long long int next_bogus_packet_in;
    struct rconn_packet_counter *bogus_packet_counter;
    bool fail_open_active;
};

struct rconn_packet_counter {
    struct ovs_mutex mutex;
    unsigned int n_packets OVS_GUARDED; /* Number of packets queued. */
    unsigned int n_bytes OVS_GUARDED;   /* Number of bytes queued. */
    int ref_cnt OVS_GUARDED;            /* Number of owners. */
};

####ofproto_fail_mode

/* How the switch should act if the controller cannot be contacted. */
enum ofproto_fail_mode {
    OFPROTO_FAIL_SECURE,        /* Preserve flow table. */
    OFPROTO_FAIL_STANDALONE     /* Act as a standalone switch. */
};

####in_band

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

/* Track one remote IP and next hop information. */
struct in_band_remote {
    struct sockaddr_in remote_addr; /* IP address, in network byte order. */
    uint8_t remote_mac[ETH_ADDR_LEN]; /* Next-hop MAC, all-zeros if unknown. */
    uint8_t last_remote_mac[ETH_ADDR_LEN]; /* Previous nonzero next-hop MAC. */
    struct netdev *remote_netdev; /* Device to send to next-hop MAC. */
};

/* A rule to add to or delete from ofproto's flow table.  */
struct in_band_rule {
    struct hmap_node hmap_node; /* In struct in_band's "rules" hmap. */
    struct match match;
    int priority;
    enum in_band_op op;
};

####sockaddr_in

struct sockaddr_in {
    sa_family_t sin_family;
    in_port_t sin_port;
    struct in_addr sin_addr;
};

###操作

struct connmgr * connmgr_create(struct ofproto *ofproto, const char *name, const char *local_port_name)

    初始化 connmgr 对象 mgr 并返回 mgr. 指针统一初始化为 NULL, 其他见 struct connmgr 定义


void connmgr_destroy(struct connmgr *mgr)

    如果是 list, hmap 释放每个成员, 如果是指针, 释放指针所指内存, 最后释放 mgr, 除了 mgr->ofproto (不应该被释放)

    遍历 mgr->all_conns 所有成员 ofconn, 调用 ofconn_destroy(ofconn);
    如果 mgr->controllers->buckets != mgr->controllers->one, free(mgr->controllers->buckets)
    遍历 mgr->services 所有成员 ofservice,  ofservice_destroy(mgr, ofservice);
    遍历 mgr->snoops 所有成员, 调用 pvconn_close(mgr->snoops[i])
    调用 fail_open_destroy(mgr->fail_open)


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

void connmgr_free_controller_info(struct shash *info)

    释放 info 中的统计信息

void connmgr_set_controllers(struct connmgr *mgr, const struct ofproto_controller *controllers, size_t n_controllers, uint32_t allowed_versions)

    遍历 controllers 中每个元素 controller, 加入 mgr 的 controllers 或 ofservice 中, 删除旧的 controller
    以及 ofservice.

void connmgr_reconnect(const struct connmgr *mgr)

    强制 mgr 中的所有 mgr->ofconn 进行重连

int connmgr_set_snoops(struct connmgr *mgr, const struct sset *snoops)

    删除 mgr->snoops  中的旧元素, 将 snoops 增加进去

void connmgr_get_snoops(const struct connmgr *mgr, struct sset *snoops)

    将 mgr->snoops 中的 name 加入 snoops 中

static void add_controller(struct connmgr *mgr, const char *target, uint8_t dscp, uint32_t allowed_versions)

    增加一个新的 ofconn 到 mgr->controllers, 建立连接

static struct ofconn * find_controller_by_target(struct connmgr *mgr, const char *target)

    查找 mgr->controllers 中是否存在名字为 target 的 ofconn

static void update_in_band_remotes(struct connmgr *mgr)

    用 mgr->controllers 中 ofconn->type = OFPROTO_IN_BAND 和 mgr->extra_in_band_remotes　中解析出的 sockaddr_in 来初始化 mgr->in_band 对象


static void update_fail_open(struct connmgr *mgr)

    如果 mgr 配置 controller 而且 fail_mode = OFPROTO_FAIL_STANDALONE ; 创建 mgr->fail_open.
    否则 删除 mgr->fail_open, mgr->fail_open = NULL
    注: 由上可知 mgr->fail_open 只有在 fail_mode = OFPROTO_FAIL_STANDALONE 才有用

static int set_pvconns(struct pvconn ***pvconnsp, size_t *n_pvconnsp, const struct sset *sset)

    删除 pvonnsp 中的 n_pvconnsp 个旧元素, 将 sset 增加进去

static int snoop_preference(const struct ofconn *ofconn)

    返回 ofconn->role 的最大值

static void add_snooper(struct connmgr *, struct vconn *);

    从 connmgr->all_conns 的 ofconn 中找到 ofconn->type = OFCONN_PRIMARY 并且
    ofconn->role 最大(即权限越接近MASTER)的 ofconn. 将 vconn 加入 该 ofconn->monitors

bool connmgr_wants_packet_in_on_miss(struct connmgr *mgr)

    连接管理(mgr)中是否存在 table_miss 的时候发送 PACKET_IN 的 ofconn

    满足发送 PACKET_IN 的条件:
    1. ofconn->controller_id = 0
    2. 没有制定协议版本, 版本小于 1.3

static void schedule_packet_in(struct ofconn *, struct ofproto_packet_in, enum ofp_packet_in_reason wire_reason);

    将一个异步 PACKET_IN 消息加入 ofconn->rconn.

void connmgr_send_port_status(struct connmgr *mgr, struct ofconn *source, const struct ofputil_phy_port *pp, uint8_t reason)

    遍历 mgr->all_conns 所有元素 ofconn, 如果 ofconn->rconn->conn->version 版本大于 1.5 或 ofconn != source 发送端口状态消息

void connmgr_send_flow_removed(struct connmgr *mgr, const struct ofputil_flow_removed *fr)

    遍历 mgr->all_conns, 如果满足发送异步消息的条件, 发送流表删除消息

static enum ofp_packet_in_reason wire_reason(struct ofconn *ofconn, const struct ofproto_packet_in *pin)

    返回发送 PACKET_IN 时的 reason

void connmgr_send_packet_in(struct connmgr *mgr, const struct ofproto_packet_in *pin)

    遍历  mgr->all_conns 每个元素 ofconn, 如果 ofconn 满足发送PACKET_IN 条件,
    并且 pin.controller_id = ofconn->controller_id, 发送 PACKET_IN 消息

static void schedule_packet_in(struct ofconn *ofconn, struct ofproto_packet_in pin, enum ofp_packet_in_reason wire_reason)

    1. 计算 buffer_id
    2. 构造 PACKET_IN 消息, 发送

void connmgr_set_fail_mode(struct connmgr *mgr, enum ofproto_fail_mode fail_mode)

    设置 mgr->fail_mode 并更新 mgr->fail_open, 并检查 mgr 是否存在 controller

int connmgr_get_max_probe_interval(const struct connmgr *mgr)

    返回 mgr->controllers 所有 ofconn 中 probe_interval 最大值

int connmgr_failure_duration(const struct connmgr *mgr)

    如果找到控制器和交换机一直连接, 返回 0
    如果 mgr 没有控制连接, 返回 0
    如果控制器和交换机失去连接, mgr->controllers 的  ofconn 中找到上次失去连接到现在的最短时间


static bool any_extras_changed(const struct connmgr *mgr, const struct sockaddr_in *extras, size_t n)

    检查 mgr->extra_in_band_remotes 与即将被修改的 extras 是否相同.
    如果 mgr->n_extra_remotes = n && mgr->extra_in_band_remotes = extras, 返回 false
    否则返回 true

void connmgr_set_extra_in_band_remotes(struct connmgr *mgr, const struct sockaddr_in *extras, size_t n)

    如果mgr->extra_in_band_remotes 与 extras 没有改变, 直接返回
    否则, 删除原来的, 用新的初始化


void connmgr_flushed(struct connmgr *mgr)

    TODO

    如果配置了 fail_open, 就调用 fail_open_flushed(mgr->fail_open);　
    如果没有控制连接, 并且 fail_mode 是 OFPROTO_FAIL_STANDALONE

int connmgr_count_hidden_rules(const struct connmgr *mgr)

    返回 in_band 和 fail_open 中的流表项数量 mgr->in_band->rules + fo->fail_open_active != 0



### in_band

int in_band_create(struct ofproto *, const char *local_name,
                   struct in_band **);
void in_band_destroy(struct in_band *);

void in_band_set_queue(struct in_band *, int queue_id);
void in_band_set_remotes(struct in_band *,
                         const struct sockaddr_in *, size_t n);

bool in_band_run(struct in_band *);
void in_band_wait(struct in_band *);

bool in_band_must_output_to_local_port(const struct flow *);

int in_band_count_rules(const struct in_band *);

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


##连接

与远程建立 OpenFlow 连接.

###名词解释

vconn: virtual connection

pvconn: passive virtual connection

###虚拟连接

####来源

    lib/vconn-provider.c
    lib/vconn-stream.c

####数据结构

struct vconn {
    const struct vconn_class *vclass;
    int state;
    int error;

    /* OpenFlow versions. */
    uint32_t allowed_versions;  /* Bitmap of versions we will accept. */
    uint32_t peer_versions;     /* Peer's bitmap of versions it will accept. */
    enum ofp_version version;   /* Negotiated version (or 0). */
    bool recv_any_version;      /* True to receive a message of any version. */

    char *name;
};

struct vconn_class {
    /* Prefix for connection names, e.g. "nl", "tcp". */
    const char *name;

    /* Attempts to connect to an OpenFlow device.  'name' is the full
     * connection name provided by the user, e.g. "tcp:1.2.3.4".  This name is
     * useful for error messages but must not be modified.
     *
     * 'allowed_versions' is the OpenFlow versions that may be
     * negotiated for a connection.
     *
     * 'suffix' is a copy of 'name' following the colon and may be modified.
     * 'dscp' is the DSCP value that the new connection should use in the IP
     * packets it sends.
     *
     * Returns 0 if successful, otherwise a positive errno value.  If
     * successful, stores a pointer to the new connection in '*vconnp'.
     *
     * The open function must not block waiting for a connection to complete.
     * If the connection cannot be completed immediately, it should return
     * EAGAIN (not EINPROGRESS, as returned by the connect system call) and
     * continue the connection in the background. */
    int (*open)(const char *name, uint32_t allowed_versions,
                char *suffix, struct vconn **vconnp, uint8_t dscp);

    /* Closes 'vconn' and frees associated memory. */
    void (*close)(struct vconn *vconn);

    /* Tries to complete the connection on 'vconn'.  If 'vconn''s connection is
     * complete, returns 0 if the connection was successful or a positive errno
     * value if it failed.  If the connection is still in progress, returns
     * EAGAIN.
     *
     * The connect function must not block waiting for the connection to
     * complete; instead, it should return EAGAIN immediately. */
    int (*connect)(struct vconn *vconn);

    /* Tries to receive an OpenFlow message from 'vconn'.  If successful,
     * stores the received message into '*msgp' and returns 0.  The caller is
     * responsible for destroying the message with ofpbuf_delete().  On
     * failure, returns a positive errno value and stores a null pointer into
     * '*msgp'.
     *
     * If the connection has been closed in the normal fashion, returns EOF.
     *
     * The recv function must not block waiting for a packet to arrive.  If no
     * packets have been received, it should return EAGAIN. */
    int (*recv)(struct vconn *vconn, struct ofpbuf **msgp);

    /* Tries to queue 'msg' for transmission on 'vconn'.  If successful,
     * returns 0, in which case ownership of 'msg' is transferred to the vconn.
     * Success does not guarantee that 'msg' has been or ever will be delivered
     * to the peer, only that it has been queued for transmission.
     *
     * Returns a positive errno value on failure, in which case the caller
     * retains ownership of 'msg'.
     *
     * The send function must not block.  If 'msg' cannot be immediately
     * accepted for transmission, it should return EAGAIN. */
    int (*send)(struct vconn *vconn, struct ofpbuf *msg);

    /* Allows 'vconn' to perform maintenance activities, such as flushing
     * output buffers.
     *
     * May be null if 'vconn' doesn't have anything to do here. */
    void (*run)(struct vconn *vconn);

    /* Arranges for the poll loop to wake up when 'vconn' needs to perform
     * maintenance activities.
     *
     * May be null if 'vconn' doesn't have anything to do here. */
    void (*run_wait)(struct vconn *vconn);

    /* Arranges for the poll loop to wake up when 'vconn' is ready to take an
     * action of the given 'type'. */
    void (*wait)(struct vconn *vconn, enum vconn_wait_type type);
};

struct pvconn {
    const struct pvconn_class *pvclass;
    char *name;
    uint32_t allowed_versions;
};

struct pvconn_class {
    /* Prefix for connection names, e.g. "ptcp", "pssl". */
    const char *name;

    /* Attempts to start listening for OpenFlow connections.  'name' is the
     * full connection name provided by the user, e.g. "ptcp:1234".  This name
     * is useful for error messages but must not be modified.
     *
     * 'allowed_versions' is the OpenFlow protocol versions that may
     * be negotiated for a session.
     *
     * 'suffix' is a copy of 'name' following the colon and may be modified.
     * 'dscp' is the DSCP value that the new connection should use in the IP
     * packets it sends.
     *
     * Returns 0 if successful, otherwise a positive errno value.  If
     * successful, stores a pointer to the new connection in '*pvconnp'.
     *
     * The listen function must not block.  If the connection cannot be
     * completed immediately, it should return EAGAIN (not EINPROGRESS, as
     * returned by the connect system call) and continue the connection in the
     * background. */
    int (*listen)(const char *name, uint32_t allowed_versions,
                  char *suffix, struct pvconn **pvconnp, uint8_t dscp);

    /* Closes 'pvconn' and frees associated memory. */
    void (*close)(struct pvconn *pvconn);

    /* Tries to accept a new connection on 'pvconn'.  If successful, stores the
     * new connection in '*new_vconnp' and returns 0.  Otherwise, returns a
     * positive errno value.
     *
     * The accept function must not block waiting for a connection.  If no
     * connection is ready to be accepted, it should return EAGAIN. */
    int (*accept)(struct pvconn *pvconn, struct vconn **new_vconnp);

    /* Arranges for the poll loop to wake up when a connection is ready to be
     * accepted on 'pvconn'. */
    void (*wait)(struct pvconn *pvconn);
};


struct vconn_stream
{
    struct vconn vconn;
    struct stream *stream;
    struct ofpbuf *rxbuf;
    struct ofpbuf *txbuf;
    int n_packets;
};

struct pvconn_pstream
{
    struct pvconn pvconn;
    struct pstream *pstream;
};

/* Active stream connection.
 *
 * This structure should be treated as opaque by implementation. */
struct stream {
    const struct stream_class *class;
    int state;
    int error;
    char *name;
};

struct stream_class {
    /* Prefix for connection names, e.g. "tcp", "ssl", "unix". */
    const char *name;

    /* True if this stream needs periodic probes to verify connectivity.  For
     * streams which need probes, it can take a long time to notice the
     * connection was dropped. */
    bool needs_probes;

    /* Attempts to connect to a peer.  'name' is the full connection name
     * provided by the user, e.g. "tcp:1.2.3.4".  This name is useful for error
     * messages but must not be modified.
     *
     * 'suffix' is a copy of 'name' following the colon and may be modified.
     * 'dscp' is the DSCP value that the new connection should use in the IP
     * packets it sends.
     *
     * Returns 0 if successful, otherwise a positive errno value.  If
     * successful, stores a pointer to the new connection in '*streamp'.
     *
     * The open function must not block waiting for a connection to complete.
     * If the connection cannot be completed immediately, it should return
     * EAGAIN (not EINPROGRESS, as returned by the connect system call) and
     * continue the connection in the background. */
    int (*open)(const char *name, char *suffix, struct stream **streamp,
                uint8_t dscp);

    /* Closes 'stream' and frees associated memory. */
    void (*close)(struct stream *stream);

    /* Tries to complete the connection on 'stream'.  If 'stream''s connection
     * is complete, returns 0 if the connection was successful or a positive
     * errno value if it failed.  If the connection is still in progress,
     * returns EAGAIN.
     *
     * The connect function must not block waiting for the connection to
     * complete; instead, it should return EAGAIN immediately. */
    int (*connect)(struct stream *stream);

    /* Tries to receive up to 'n' bytes from 'stream' into 'buffer', and
     * returns:
     *
     *     - If successful, the number of bytes received (between 1 and 'n').
     *
     *     - On error, a negative errno value.
     *
     *     - 0, if the connection has been closed in the normal fashion.
     *
     * The recv function will not be passed a zero 'n'.
     *
     * The recv function must not block waiting for data to arrive.  If no data
     * have been received, it should return -EAGAIN immediately. */
    ssize_t (*recv)(struct stream *stream, void *buffer, size_t n);

    /* Tries to send up to 'n' bytes of 'buffer' on 'stream', and returns:
     *
     *     - If successful, the number of bytes sent (between 1 and 'n').
     *
     *     - On error, a negative errno value.
     *
     *     - Never returns 0.
     *
     * The send function will not be passed a zero 'n'.
     *
     * The send function must not block.  If no bytes can be immediately
     * accepted for transmission, it should return -EAGAIN immediately. */
    ssize_t (*send)(struct stream *stream, const void *buffer, size_t n);

    /* Allows 'stream' to perform maintenance activities, such as flushing
     * output buffers.
     *
     * May be null if 'stream' doesn't have anything to do here. */
    void (*run)(struct stream *stream);

    /* Arranges for the poll loop to wake up when 'stream' needs to perform
     * maintenance activities.
     *
     * May be null if 'stream' doesn't have anything to do here. */
    void (*run_wait)(struct stream *stream);

    /* Arranges for the poll loop to wake up when 'stream' is ready to take an
     * action of the given 'type'. */
    void (*wait)(struct stream *stream, enum stream_wait_type type);
};

/* Passive listener for incoming stream connections.
 *
 * This structure should be treated as opaque by stream implementations. */
struct pstream {
    const struct pstream_class *class;
    char *name;
    ovs_be16 bound_port;
};

struct pstream_class {
    /* Prefix for connection names, e.g. "ptcp", "pssl", "punix". */
    const char *name;

    /* True if this pstream needs periodic probes to verify connectivity.  For
     * pstreams which need probes, it can take a long time to notice the
     * connection was dropped. */
    bool needs_probes;

    /* Attempts to start listening for stream connections.  'name' is the full
     * connection name provided by the user, e.g. "ptcp:1234".  This name is
     * useful for error messages but must not be modified.
     *
     * 'suffix' is a copy of 'name' following the colon and may be modified.
     * 'dscp' is the DSCP value that the new connection should use in the IP
     * packets it sends.
     *
     * Returns 0 if successful, otherwise a positive errno value.  If
     * successful, stores a pointer to the new connection in '*pstreamp'.
     *
     * The listen function must not block.  If the connection cannot be
     * completed immediately, it should return EAGAIN (not EINPROGRESS, as
     * returned by the connect system call) and continue the connection in the
     * background. */
    int (*listen)(const char *name, char *suffix, struct pstream **pstreamp,
                  uint8_t dscp);

    /* Closes 'pstream' and frees associated memory. */
    void (*close)(struct pstream *pstream);

    /* Tries to accept a new connection on 'pstream'.  If successful, stores
     * the new connection in '*new_streamp' and returns 0.  Otherwise, returns
     * a positive errno value.
     *
     * The accept function must not block waiting for a connection.  If no
     * connection is ready to be accepted, it should return EAGAIN. */
    int (*accept)(struct pstream *pstream, struct stream **new_streamp);

    /* Arranges for the poll loop to wake up when a connection is ready to be
     * accepted on 'pstream'. */
    void (*wait)(struct pstream *pstream);
};


struct stream_fd
{
    struct stream stream;
    int fd;
    int fd_type;
};


/* State of an active stream.*/
enum stream_state {
    SCS_CONNECTING,             /* Underlying stream is not connected. */
    SCS_CONNECTED,              /* Connection established. */
    SCS_DISCONNECTED            /* Connection failed or connection closed. */
};

enum stream_content_type {
    STREAM_UNKNOWN,
    STREAM_OPENFLOW,
    STREAM_SSL,
    STREAM_JSONRPC
};

enum stream_wait_type {
    STREAM_CONNECT,
    STREAM_RECV,
    STREAM_SEND
};


struct fd_pstream {
    struct pstream pstream;
    int fd;
    int (*accept_cb)(int fd, const struct sockaddr_storage *, size_t ss_len,
                     struct stream **);
    char *unlink_path;
};


####源码实现

static const struct vconn_class *vconn_classes[] = {
    &tcp_vconn_class,
    &unix_vconn_class,
#ifdef HAVE_OPENSSL
    &ssl_vconn_class,
#endif
};

static const struct pvconn_class *pvconn_classes[] = {
    &ptcp_pvconn_class,
    &punix_pvconn_class,
#ifdef HAVE_OPENSSL
    &pssl_pvconn_class,
#endif
};

#define STREAM_INIT(NAME)                           \
    {                                               \
            NAME,                                   \
            vconn_stream_open,                      \
            vconn_stream_close,                     \
            vconn_stream_connect,                   \
            vconn_stream_recv,                      \
            vconn_stream_send,                      \
            vconn_stream_run,                       \
            vconn_stream_run_wait,                  \
            vconn_stream_wait,                      \
    }

#define PSTREAM_INIT(NAME)                          \
    {                                               \
            NAME,                                   \
            pvconn_pstream_listen,                  \
            pvconn_pstream_close,                   \
            pvconn_pstream_accept,                  \
            pvconn_pstream_wait                     \
    }

static const struct vconn_class stream_vconn_class = STREAM_INIT("stream");
static const struct pvconn_class pstream_pvconn_class = PSTREAM_INIT("pstream");

const struct vconn_class tcp_vconn_class = STREAM_INIT("tcp");
const struct pvconn_class ptcp_pvconn_class = PSTREAM_INIT("ptcp");

const struct vconn_class unix_vconn_class = STREAM_INIT("unix");
const struct pvconn_class punix_pvconn_class = PSTREAM_INIT("punix");

const struct vconn_class ssl_vconn_class = STREAM_INIT("ssl");
const struct pvconn_class pssl_pvconn_class = PSTREAM_INIT("pssl");

vconn_init(vconn, class, connect_status, name, allowed_versions) : 用后面参数初始化 vconn
vconn_verify_name(name): 根据 name 找到指定的 class 类型, 确认 name 的参数合法
vconn_open(name, allowed_versions, dscp,vconnp) : 打开与对端 Openflow 连接
vconn_connect(vconn): 从当前状态开始建立连接, 如果连接建立成功, 返回 0, 否则发送错误消息给对端
vconn_run(vconn): vconn_connect(vconn) + (vconn->vclass->run)(vconn)
vconn_run_wait(vconn): vconn_connect_wait(vconn) + (vconn->vclass->run_wait)(vconn)
vconn_open_block() : vconn_open() + vconn_connect_block()
vconn_close(vconn) : vconn->class->class(vconn)
vconn_connect(vconn) : 完成状态的切换
vconn_recv(vconn, msgp) : 从 vconn 非阻塞接受消息
vconn_send(vconn, msg) : 将 msg 加入 vconn 的发送队列
vconn_connect_block(vconn) : 完成从 CONNECTING 到 CONNECT 的切换, 成功或失败
vconn_recv_block(vconn, msgp): 接受直到收到所有的消息
vconn_recv_xid(vconn, xid, replyp) : 接受指定 id 的消息
vconn_transact(vconn, request, replyp) : 发送 request, 直到收到 request 的应答信息
vconn_transact_noreply(vconn, request, replyp): 发送 request, 发送 barrier 消息, 直到收到 barrier 的应答
vconn_transact_multiple_noreply(vconn, requests,replyp) : requests 每条消息都调用 vconn_transact_noreply
vconn_bundle_transact(vconn, requests, flags...): 基于事务将 requests 的多条消息一起发送
vconn_wait(vconn, wait) : 根据 vconn->state 设置 wait, 调用 (vconn->class->wait)(vconn, wati)
vconn_connect_wait(vconn) : vconn_wait(vconn, WAIT_CONNECT);
vconn_recv_wait(vconn): vconn_wait(vconn, WAIT_SEND);

pvconn_init(pvconn, class, name, allowed_versions) : 根据后面的参数初始化 pvconn
pvconn_verify_name(name): 根据 name 找到指定的 class 类型, 确认 name 的参数合法
pvconn_open(name, allowed_versions, dscp, pvconnp) : 根据 name 找到 合适的 class, 调用 class->listen(name, allowed_versions, suffix_copy, &pvconn, dscp)
pvconn_close(pvconn) : (pvconn->pvclass->close)(pvconn)
pvconn_accept(pvconn, new_vconn) : (pvconn->pvclass->accept)(pvconn, new_vconn)
pvconn_wait(pvconn) :  (pvconn->pvclass->wait)(pvconn)


由上可知, vconn_* 客户端都基于 vconn_stream 来实现, 服务端都基于 pvconn_pstream_* 实现,
而 vconn_stream_* 和 pvconn_stream_* 又依赖 stream_* 和 pstream_*;


static const struct stream_class *stream_classes[] = {
    &tcp_stream_class,
#ifndef _WIN32
    &unix_stream_class,
#else
    &windows_stream_class,
#endif
#ifdef HAVE_OPENSSL
    &ssl_stream_class,
#endif
};

const struct stream_class tcp_stream_class = {
    "tcp",                      /* name */
    true,                       /* needs_probes */
    tcp_open,                   /* open */
    NULL,                       /* close */
    NULL,                       /* connect */
    NULL,                       /* recv */
    NULL,                       /* send */
    NULL,                       /* run */
    NULL,                       /* run_wait */
    NULL,                       /* wait */
};

static const struct pstream_class *pstream_classes[] = {
    &ptcp_pstream_class,
#ifndef _WIN32
    &punix_pstream_class,
#else
    &pwindows_pstream_class,
#endif
#ifdef HAVE_OPENSSL
    &pssl_pstream_class,
#endif
};

const struct pstream_class ptcp_pstream_class = {
    "ptcp",
    true,
    ptcp_open,
    NULL,
    NULL,
    NULL,
};

stream_init(stream, class, connect_status, name): 用后面参数初始化 vconn
stream_verify_name(name): 根据 name 找到指定的 class 类型, 确认 name 的参数合法
stream_open(name, streamp, dscp) : class->open() 打开连接
stream_open_block(error, streamp) :
stream_close(struct stream *stream): (stream->class->close)(stream)
stream_connect(stream) : 完成连接
stream_recv(stream, buffer, n): stream_connect(stream) + (stream->class->recv)(stream, buffer, n)
stream_send(stream, buffer, n): stream_connect(stream) + (stream->class->send)(stream, buffer, n)
stream_run(stream) : (stream->class->run)(stream)
stream_run_wait(stream) :  (stream->class->run_wait)(stream)
stream_wait(stream, wait): 根据 stream->state 设置 wait, 调用 (vconn->class->wait)(vconn, wati)
stream_connect_wait(stream) : stream_wait(stream, STREAM_CONNECT);
stream_recv_wait(stream) : stream_wait(stream, STREAM_RECV);
stream_send_wait(stream) : stream_wait(stream, STREAM_SEND);
stream_open_with_default_port(name_, default_port, streamp, dscp): 连接到 default_port

pstream_init(pstream, class, name) : 根据后面的参数初始化 pvconn
pstream_verify_name(name) : 根据 name 找到指定的 class 类型, 确认 name 的参数合法
pstream_open(name, pstreamp, dscp) : 根据 name 找到 合适的 class, 调用 class->listen(name, suffix_copy, &pstream, dscp);
pstream_close(pstream) : (pstream->class->close)(pstream)
pstream_accept(pstream, new_stream) : 非阻塞 (pstream->class->accept)(pstream, new_stream)
pstream_accept_block(pstream, new_stream) : 阻塞直到收到请求, pstream_accept(pstream, new_stream)
pstream_wait(struct pstream *pstream) :  (pstream->class->wait)(pstream)
pstream_open_with_default_port(name_, default_port, pstreamp, dscp) : listen 监听 default_port


由上可知,  stream_* 和 pstream_* 依赖具体的协议如果 tcp_stream_class 和 ptcp_pstream_class 类实现


new_tcp_stream(name, fd, connect_status, streamp)

    new_fd_stream(name, fd, connect_status, AF_INET, streamp), 如果 connect_status = 0, 设置 TCP_NODELAY

tcp_open(name, suffix, streamp, dscp)

    inet_open_active(SOCK_STREAM, suffix, 0, NULL, &fd, dscp)
    new_tcp_stream(name, fd, error, streamp)

new_pstream(suffix, name, pstreamp, dscp, unlink_path, kernel_print_port)

    inet_open_passive(SOCK_STREAM, suffix, -1, &ss, dscp, kernel_print_port);
    new_fd_pstream(conn_name, fd, ptcp_accept, unlink_path, pstreamp);
    pstream_set_bound_port(pstreamp, htons(port));

ptcp_open(name suffix, pstreamp, dscp)

    return new_pstream(suffix, NULL, pstreamp, dscp, NULL, true);

ptcp_accept(fd, ss, ss_len streamp)

    return new_tcp_stream(name, fd, 0, streamp);

new_fd_stream(name, fd, connect_status, fd_type, streamp): 初始化 fd_stream 对象
stream_fd_cast(stream) : 从 stream 获取其所在的 stream_fd
fd_close(stream) : 从 stream 定位其所在的 fd_stream 对象 s. 调用 closesocket(s->fd);
fd_connect(struct stream *stream) : 将 stream 所在的 fd_stream 中的 fd 加入 poll
fd_recv(stream, buffer, n) : 从 stream 所在的 fd_stream 中的 fd, 调用 recv(s->fd, buffer, n, 0)
fd_send(stream, buffer, n) : 从 stream 所在的 fd_stream 中的 fd, 调用 send(s->fd, buffer, n, 0)
fd_wait(stream, wait) :  如果 wait = STREAM_CONNECT | STREAM_SEND 调用 poll_fd_wait(s->fd, POLLOUT); 如果 wait = STREAM_RECV 调用 poll_fd_wait(s->fd, POLLIN);
fd_pstream_cast(pstream) : 从 pstream 定位到其所在 fd_pstream 的 fd.
new_fd_pstream(name, fd, (accept_cb), unlink_path, pstreamp) : 初始化 fd_pstream 对象
pfd_close(pstream) :  closesocket(ps->fd)
pfd_accept(pstream, new_streamp) :  accept(ps->fd, (struct sockaddr *) &ss, &ss_len);  set_nonblocking(new_fd); ps->accept_cb(new_fd, &ss, ss_len, new_streamp)
pfd_wait(pstream) : poll_fd_wait(ps->fd, POLLIN);


static const struct stream_class stream_fd_class = {
    "fd",                       /* name */
    false,                      /* needs_probes */
    NULL,                       /* open */
    fd_close,                   /* close */
    fd_connect,                 /* connect */
    fd_recv,                    /* recv */
    fd_send,                    /* send */
    NULL,                       /* run */
    NULL,                       /* run_wait */
    fd_wait,                    /* wait */
};

static const struct pstream_class fd_pstream_class = {
    "pstream",
    false,
    NULL,
    pfd_close,
    pfd_accept,
    pfd_wait,
};

由上可知, tcp_open() 和 ptcp_open() 依赖 fd_stream 来打开连接, 而 fd_stream 中指定 stream_fd_class 为 class


综上所述, 连接的管理(open, conn, recv, send, close, accept)具体实现是在 fd_stream 中完成的.


###封装后的 vconn

该部分将 tcp, unix, ssl 进行封装, 统一了三者的接口.

####来源

    lib/vconn.c


####核心数据结构

/* State of an active vconn.*/
enum vconn_state {
    /* This is the ordinary progression of states. */
    VCS_CONNECTING,             /* Underlying vconn is not connected. */
    VCS_SEND_HELLO,             /* Waiting to send OFPT_HELLO message. */
    VCS_RECV_HELLO,             /* Waiting to receive OFPT_HELLO message. */
    VCS_CONNECTED,              /* Connection established. */

    /* These states are entered only when something goes wrong. */
    VCS_SEND_ERROR,             /* Sending OFPT_ERROR message. */
    VCS_DISCONNECTED            /* Connection failed or connection closed. */
};

enum vconn_wait_type {
    WAIT_CONNECT,
    WAIT_RECV,
    WAIT_SEND
};

####使用流程

* 建立连接

vconn_open_block() 或 vconn_open() + vconn_connect_block()

* 发送数据

vconn_send(vconn, msg)
vconn_send_block(vconn, msg)

pvconn_open() + pvconn_accept()

* 接受数据

vconn_recv(vconn, msg)
vconn_recv_block(vconn, msgp)
vconn_recv_xid(vconn, xid, replyp)
               struct ofpbuf **replyp)
vconn_transact(vconn, request, replyp)
vconn_transact_noreply(vconn, request, replyp)
vconn_transact_multiple_noreply(vconn, requests,replyp)
vconn_bundle_transact(vconn, requests, flags...)

* 关闭连接

vconn_close(vconn) : 关闭连接
pvconn_close() : 关闭监听

####源码分析

注: 这部分代码非常直观明了, 因此包含了精简后的源码.有时候比文字更好说明问题

static int vconn_lookup_class(const char *name, const struct vconn_class **classp)

    从 vconn_classes 中解析出 name = vconn_classes[i]->name , 初始化 classp.
    其中 name 格式为 "TYPE:ARGS" 如 "tcp:192.168.1.1:6633"

int vconn_verify_name(const char *name)

    等于 vconn_lookup_class

int vconn_open(const char *name, uint32_t allowed_versions, uint8_t dscp, struct vconn **vconnp)

    vconn_lookup_class(name, &class);
    class->open(name, allowed_versions, suffix_copy, &vconn, dscp);

    注: vconn->state 必须是 VCS_CONNECTING 并且 vconn->vclass->connect 不能为 NULL


void vconn_run(struct vconn *vconn)

    正常情况下保证 vconn 已经建立连接或发生错误

    if (vconn->state == VCS_CONNECTING || vconn->state == VCS_SEND_HELLO || vconn->state == VCS_RECV_HELLO)
        vconn_connect(vconn);

    //这里判断为 false, 因此与 vconn_connect 相同
    if (vconn->vclass->run)
        (vconn->vclass->run)(vconn);

void vconn_run_wait(struct vconn *vconn)

    if (vconn->state == VCS_CONNECTING ||
        vconn->state == VCS_SEND_HELLO ||
        vconn->state == VCS_RECV_HELLO) {
        vconn_connect_wait(vconn);
    }

    if (vconn->vclass->run_wait) {
        (vconn->vclass->run_wait)(vconn);
    }

int vconn_get_status(const struct vconn *vconn)

    连接处于正常, 返回 0;
    如果错误, 返回正数;
    如果正常关闭,返回 EOF


int vconn_open_block(const char *name, uint32_t allowed_versions, uint8_t dscp, struct vconn **vconnp)

    error = vconn_open(name, allowed_versions, dscp, &vconn);
    if (!error) error = vconn_connect_block(vconn);
    return error;

void vconn_close(struct vconn *vconn)

    (vconn->vclass->close)(vconn);

void vconn_set_recv_any_version(struct vconn *vconn)

    vconn->recv_any_version = true;

    By default, a vconn accepts only OpenFlow messages whose version matches the
    one negotiated for the connection.  A message received with a different
    version is an error that causes the vconn to drop the connection.

    This functions allows 'vconn' to accept messages with any OpenFlow version.
    This is useful in the special case where 'vconn' is used as an rconn
    "monitor" connection (see rconn_add_monitor()), that is, where 'vconn' is
    used as a target for mirroring OpenFlow messages for debugging and
    troubleshooting.

    This function should be called after a successful vconn_open() or
    pvconn_accept() but before the connection completes, that is, before
    vconn_connect() returns success.  Otherwise, messages that arrive on 'vconn'
    beforehand with an unexpected version will the vconn to drop the
    connection.

static void vcs_connecting(struct vconn *vconn)

    int retval = (vconn->vclass->connect)(vconn);
    if (!retval) {
        vconn->state = VCS_SEND_HELLO;
    } else if (retval != EAGAIN) {
        vconn->state = VCS_DISCONNECTED;
        vconn->error = retval;
    }


static void vcs_send_hello(struct vconn *vconn)

    b = ofputil_encode_hello(vconn->allowed_versions);
    retval = do_send(vconn, b);
    成功:
        vconn->state = VCS_RECV_HELLO;
    失败
        if (retval != EAGAIN)
            vconn->state = VCS_DISCONNECTED;
            vconn->error = retval;

static char *version_bitmap_to_string(uint32_t bitmap)

    从 bitmap  解析 OF 的版本信息, 返回版本信息

static void vcs_recv_hello(struct vconn *vconn)

    接受 OFPT_HELLO 消息, 并确认两端的版本兼容, 最后设置 vconn->version; vconn->state = VCS_CONNECTED

    retval = do_recv(vconn, &b);
    成功:
        error = ofptype_decode(&type, b->data);
        成功:
            ofputil_decode_hello(b->data, &vconn->peer_versions))
            common_versions = vconn->peer_versions & vconn->allowed_versions;
            失败:
                vconn->version = leftmost_1bit_idx(vconn->peer_versions);
                输出错误消息
                vconn->state = VCS_SEND_ERROR;
            成功:
                vconn->version = leftmost_1bit_idx(common_versions);
                vconn->state = VCS_CONNECTED;

        失败:
            输出错误消息
            设置 retval = EPROTO

    失败
        vconn->state = VCS_DISCONNECTED;
        vconn->error = retval == EOF ? ECONNRESET : retval;


static void vcs_send_error(struct vconn *vconn)


    发送版本协商的错误信息

    local_s = version_bitmap_to_string(vconn->allowed_versions);
    peer_s = version_bitmap_to_string(vconn->peer_versions);
    snprintf(s, sizeof s, "We support %s, you support %s, no common versions.",
             local_s, peer_s);
    b = ofperr_encode_hello(OFPERR_OFPHFC_INCOMPATIBLE, vconn->version, s);
    retval = do_send(vconn, b);
    成功:
        ofpbuf_delete(b);
    失败
        if (retval != EAGAIN)
            vconn->state = VCS_DISCONNECTED;
            vconn->error = retval ? retval : EPROTO;


int vconn_connect(struct vconn *vconn)

    从 vconn->state 当前状态开始建立连接直到完成或出错. 至此已经发送 HELLO 请求和收到 HELLO 应答

    do {
        last_state = vconn->state;
        switch (vconn->state) {
        case VCS_CONNECTING:
            vcs_connecting(vconn);
            break;

        case VCS_SEND_HELLO:
            vcs_send_hello(vconn);
            break;

        case VCS_RECV_HELLO:
            vcs_recv_hello(vconn);
            break;

        case VCS_CONNECTED:
            return 0;

        case VCS_SEND_ERROR:
            vcs_send_error(vconn);
            break;

        case VCS_DISCONNECTED:
            return vconn->error;

        default:
            OVS_NOT_REACHED();
        }
    } while (vconn->state != last_state);

    return EAGAIN;

int vconn_recv(struct vconn *vconn, struct ofpbuf **msgp)

    建立连接并接受对端的消息, 将消息保存在 msgp 中

    retval = vconn_connect(vconn);
    成功:
        retval = do_recv(vconn, &msg);
        if (!retval && !vconn->recv_any_version)
        成功:
            const struct ofp_header *oh = msg->data;
            if (oh->version != vconn->version)
            成功:
                if (ofptype_decode(&type, msg->data)
                    || (type != OFPTYPE_HELLO &&
                        type != OFPTYPE_ERROR &&
                        type != OFPTYPE_ECHO_REQUEST &&
                        type != OFPTYPE_ECHO_REPLY))
                失败:
                    发送错误版本信息给对端
    失败:
        *msgp = retval ? NULL : msg;



static int do_recv(struct vconn *vconn, struct ofpbuf **msgp)

    return (vconn->vclass->recv)(vconn, msgp);

int vconn_send(struct vconn *vconn, struct ofpbuf *msg)

    vconn_connect(vconn);
    成功:
        retval do_send(vconn, msg);
        return retval;
    失败
        return retval;

static int do_send(struct vconn *vconn, struct ofpbuf *msg)

    确保 msg->size >= sizeof(struct ofp_header)
    ofpmsg_update_length(msg);
    return (vconn->vclass->send)(vconn, msg);

int vconn_connect_block(struct vconn *vconn)

    while ((error = vconn_connect(vconn)) == EAGAIN) {
        vconn_run(vconn);
        vconn_run_wait(vconn);
        vconn_connect_wait(vconn);
        poll_block();
    }
    ovs_assert(error != EINPROGRESS);
    return error;

int vconn_send_block(struct vconn *vconn, struct ofpbuf *msg)

    while ((retval = vconn_send(vconn, msg)) == EAGAIN) {
        vconn_run(vconn);
        vconn_run_wait(vconn);
        vconn_send_wait(vconn);
        poll_block();
    }
    return retval;

int vconn_recv_block(struct vconn *vconn, struct ofpbuf **msgp)

    while ((retval = vconn_recv(vconn, msgp)) == EAGAIN) {
        vconn_run(vconn);
        vconn_run_wait(vconn);
        vconn_recv_wait(vconn);
        poll_block();
    }
    return retval;

static int vconn_recv_xid__(struct vconn *vconn, ovs_be32 xid, struct ofpbuf **replyp, void (*error_reporter)(const struct ofp_header *))

    一直循环直到收到消息 data->xid = xid, 返回.

    for(;;)
        vconn_recv_block(vconn, &reply);
        成功:
            oh = reply->data;
            recv_xid = oh->xid;
            if (xid == recv_xid)
            成功:
                *replyp = reply;
                return 0;
            error = ofptype_decode(&type, oh);
        失败:
            *replyp = NULL;
            return error;


int vconn_recv_xid(struct vconn *vconn, ovs_be32 xid, struct ofpbuf **replyp)

    return vconn_recv_xid__(vconn, xid, replyp, NULL);

    Waits until a message with a transaction ID matching 'xid' is received on
    'vconn'.  Returns 0 if successful, in which case the reply is stored in
    '*replyp' for the caller to examine and free.  Otherwise returns a positive
    errno value, or EOF, and sets '*replyp' to null.

    'request' is always destroyed, regardless of the return value. */


static int vconn_transact__(struct vconn *vconn, struct ofpbuf *request, struct ofpbuf **replyp,
        void (*error_reporter)(const struct ofp_header *))

    发送一条消息, 阻塞直到收到应答.

    error = vconn_send_block(vconn, request);
    ovs_be32 send_xid = ((struct ofp_header *) request->data)->xid;
    成功:
        return vconn_recv_xid__(vconn, send_xid, replyp, error_reporter);
    失败:
        return error

int vconn_transact(struct vconn *vconn, struct ofpbuf *request,
               struct ofpbuf **replyp)

    发送一条消息, 阻塞直到收到应答.(同 vconn_transact__)


int vconn_transact_noreply(struct vconn *vconn, struct ofpbuf *request, struct ofpbuf **replyp)

    发送一条消息, 并且发送 barrier 消息, 直到收到的消息的 msg_xid 等于发送 barrier_xid

    request_xid = ((struct ofp_header *) request->data)->xid;
    error = vconn_send_block(vconn, request);
    失败: 返回 error

    barrier = ofputil_encode_barrier_request(vconn_get_version(vconn));
    barrier_xid = ((struct ofp_header *) barrier->data)->xid;
    error = vconn_send_block(vconn, barrier);
    失败: 返回 error

    for (;;)
        error = vconn_recv_block(vconn, &msg);
        失败: 退出循环
        直到 msg_xid == barrier_xid

    问题: msg_xid == request_xid 没有出现会有问题么?

int vconn_transact_multiple_noreply(struct vconn *vconn, struct ovs_list *requests, struct ofpbuf **replyp)

    遍历 requests 的每个元素 request, 调用 vconn_transact_noreply(vconn, request, replyp)

static enum ofperr vconn_bundle_reply_validate(struct ofpbuf *reply,
                            struct ofputil_bundle_ctrl_msg *request,
                            void (*error_reporter)(const struct ofp_header *))


    对 bundle 控制消息进行验证

    oh = reply->data;
    error = ofptype_decode(&type, oh);
    if (type == OFPTYPE_ERROR)
        return ofperr_decode_msg(oh, NULL);
    if (type != OFPTYPE_BUNDLE_CONTROL)
        return OFPERR_OFPBRC_BAD_TYPE;

    ofputil_decode_bundle_ctrl(oh, &rbc);
    if (rbc.bundle_id != request->bundle_id)
        return OFPERR_OFPBFC_BAD_ID;
    if (rbc.type != request->type + 1)
        return OFPERR_OFPBFC_BAD_TYPE;
    return 0;


static int vconn_bundle_control_transact(struct vconn *vconn,
                              struct ofputil_bundle_ctrl_msg *bc,
                              uint16_t type,
                              void (*error_reporter)(const struct ofp_header *))

    对 bc 进行编码, 之后发送, 等收到应答后, 对应答 bundle 控制消息进行校验

    bc->type = type;
    request = ofputil_encode_bundle_ctrl_request(vconn->version, bc);
    vconn_transact__(vconn, request, &reply, error_reporter);
    vconn_bundle_reply_validate(reply, bc, error_reporter);


static void vconn_recv_error(struct vconn *vconn, void (*error_reporter)(const struct ofp_header *))

    专门接受消息类型为 OFPTYPE_ERROR 的消息, 直到收消息出错

static int vconn_bundle_add_msg(struct vconn *vconn, struct ofputil_bundle_ctrl_msg *bc, struct ofpbuf *msg,
                     void (*error_reporter)(const struct ofp_header *))


    发送一个 bundle_add 消息, 接受错误类型的消息直到接受错误消息出错.

    bam.bundle_id = bc->bundle_id;
    bam.flags = bc->flags;
    bam.msg = msg->data;
    request = ofputil_encode_bundle_add(vconn->version, &bam);
    error = vconn_send_block(vconn, request);
    成功:
        vconn_recv_error(vconn, error_reporter);
    return error

int vconn_bundle_transact(struct vconn *vconn, struct ovs_list *requests, uint16_t flags,
                      void (*error_reporter)(const struct ofp_header *))

    以事务遍历 requests 每一个元素, 发送 bundle_add 消息

    memset(&bc, 0, sizeof bc);
    bc.flags = flags;
    vconn_bundle_control_transact(vconn, &bc, OFPBCT_OPEN_REQUEST, error_reporter);

    LIST_FOR_EACH (request, list_node, requests)
        error = vconn_bundle_add_msg(vconn, &bc, request, error_reporter);
        失败:
            break;

    成功:
        vconn_bundle_control_transact(vconn, &bc, OFPBCT_COMMIT_REQUEST,  error_reporter);
    失败
        vconn_bundle_control_transact(vconn, &bc, OFPBCT_DISCARD_REQUEST, error_reporter);

void vconn_wait(struct vconn *vconn, enum vconn_wait_type wait)

    switch (vconn->state)
    case VCS_CONNECTING:
        wait = WAIT_CONNECT;
        break;

    case VCS_SEND_HELLO:
    case VCS_SEND_ERROR:
        wait = WAIT_SEND;
        break;

    case VCS_RECV_HELLO:
        wait = WAIT_RECV;
        break;

    case VCS_CONNECTED:
        break;

    case VCS_DISCONNECTED:
        poll_immediate_wake();
        return;

    (vconn->vclass->wait)(vconn, wait);

void vconn_connect_wait(struct vconn *vconn)

    等于 vconn_wait(vconn, WAIT_CONNECT);

void vconn_recv_wait(struct vconn *vconn)

    等于 vconn_wait(vconn, WAIT_RECV);

void vconn_send_wait(struct vconn *vconn)

    等于 vconn_wait(vconn, WAIT_SEND);

static int pvconn_lookup_class(const char *name, const struct pvconn_class **classp)

    根据 name 从 pvconn_classes 中找到合适的 pvconn_class , 其中 name 为 "TYPE:ARGS"

int pvconn_verify_name(const char *name)

    调用 pvconn_lookup_class(name)

int pvconn_open(const char *name, uint32_t allowed_versions, uint8_t dscp, struct pvconn **pvconnp)

    从 name 找到合适的 class, 调用该 class->listen() 方法

    error = pvconn_lookup_class(name, &class);
    error = class->listen(name, allowed_versions, suffix_copy, &pvconn, dscp);

void pvconn_close(struct pvconn *pvconn)

    if pvconn != NULL
        (pvconn->pvclass->close)(pvconn);

int pvconn_accept(struct pvconn *pvconn, struct vconn **new_vconn)

    非阻塞调用 (pvconn->pvclass->accept)(pvconn, new_vconn)
    成功:
        将连接保持在 new_vconn
    失败:
        如果没有新的连接返回 EAGAIN

void pvconn_wait(struct pvconn *pvconn)

    (pvconn->pvclass->wait)(pvconn);

void vconn_init(struct vconn *vconn, const struct vconn_class *class,
           int connect_status, const char *name, uint32_t allowed_versions)

    用后面的参数初始化 vconn

    memset(vconn, 0, sizeof *vconn);
    vconn->vclass = class;
    vconn->state = (connect_status == EAGAIN ? VCS_CONNECTING
                    : !connect_status ? VCS_SEND_HELLO
                    : VCS_DISCONNECTED);
    vconn->error = connect_status;
    vconn->allowed_versions = allowed_versions;
    vconn->name = xstrdup(name);

void pvconn_init(struct pvconn *pvconn, const struct pvconn_class *class, const char *name, uint32_t allowed_versions)

    用后面的参数初始化 pvconn

    pvconn->pvclass = class;
    pvconn->name = xstrdup(name);
    pvconn->allowed_versions = allowed_versions;



##可靠的连接

对 vconn 进行状态维护, 使得具有稳定的连接, 也体现了分层的思想, vconn 专注连接, 而 rconn 进行连接的状态管理和统计

####来源: lib/rconn.c lib/rconn.h


####STATE 的转变条件

S_VOID: 没有开始连接
S_CONNECTING : 正在建立连接, 但还没有完成
S_ACTIVE : 已经建立连接, 距离上次数据交互, 但还没有超过 probe_interval
S_IDLE : 已经建立连接, 距离上次数据交互超过 probe_interval, 而且 ECHO Request 已经发出, 等待回应
S_BACKOFF: 对与非正常断开连接, 如果设置了 reliable, 那么就进入该状态, 该状态进行重连,每次递增 2*backoff, 直到重连成功或达到 max_backoff.
S_DISCONNECTED : 已经端口理解

####使用流程

rconn_create(rc) : 创建并初始化一个可靠连接对象 rc
rconn_connect() : 进行可靠连接, 即如果遇到错误会进入 BACKOFF 状态重连
rconn_add_monitor() : 给 rc->monitors 增加一个元素

####核心函数简介

rconn_create(rc) : 创建并初始化一个可靠连接对象 rc
rconn_destroy(rc) : 销毁可靠连接对象 rc
rconn_connect() : 进行可靠连接, 即如果遇到错误会进入 BACKOFF 状态重连
rconn_connect_unreliably() : 进行不可靠连接, 即如果遇到错误直接断开
rconn_reconnect() : 如果从 ACTIVE 或 IDLE 状态进入 BACKOFF 状态
rconn_disconnect() : 如果从非 S_VOID 进入 S_VOID
rconn_run()  : 对应 rc->vconn, rc->monitors 运行 vconn_run, 之后根据 rc->state 调用其之后的状态
rconn_send() : 将一个数据包加入 rc->txq 队列中
run_ACTIVE() : 从 rc->txq 中取出一条消息发送出去
rconn_recv() : 从 rc->vconn 收消息
rconn_add_monitor() : 给 rc->monitors 增加一个元素
rconn_is_alive() : rc->state 不是 VOID 和 DISCONNECTED
rconn_is_connected(): rc->state 是 IDLE 或 ACTIVE
rconn_is_admitted() : rc->state 首先是 is_connected, 并且 rc->last_admitted > rc->last_connected
rconn_failure_duration() : 如果控制器一直监管交换机　返回 0; 如果当前控制器已经不再接管交换机, 返回上次管理时间到现在的时间
rconn_get_version() : rc->vconn 的版本
elapsed_in_this_state() : 处于当前状态的时间多久了
rconn_reconnect() : 如果是rc->reliable = true, rc->state 进入 BACKOFF 状态
timeout_$STATE : 获取各个状态的超时时间


run_$STATE : 各个状态需要的动作

    rc->state = S_VOID : run_VOID()
    rc->state = S_BACKOFF : run_BACKOFF()
    rc->state = S_CONNECTING: run_CONNECTING()
    rc->state = S_ACTIVE : run_ACTIVE()
    rc->state = S_IDLE : run_IDLE()
    rc->state = S_DISCONNECTED: run_DISCONNECTED()

注:

可靠连接和不可靠连接的主要区别: 可靠连接状态切换 S_VOID -> S_CONNECTING 或 S_VOID -> S_BACKOFF,
而不可靠连接状态切换 S_VOID -> S_ACTIVE. 因此, 可靠连接会在进行连接时进行验证, 而不可靠连接直接认为连接是可用的.

一次成功的连接需要 vconn_open --> vconn_connect

/* A wrapper around vconn that provides queuing and optionally reliability.
 *
 * An rconn maintains a message transmission queue of bounded length specified
 * by the caller.  The rconn does not guarantee reliable delivery of
 * queued messages: all queued messages are dropped when reconnection becomes
 * necessary.
 *
 * An rconn optionally provides reliable communication, in this sense: the
 * rconn will re-connect, with exponential backoff, when the underlying vconn
 * disconnects.
 */

/* The connection states have the following meanings:
 *
 *    - S_VOID: No connection information is configured.
 *
 *    - S_BACKOFF: Waiting for a period of time before reconnecting.
 *
 *    - S_CONNECTING: A connection attempt is in progress and has not yet
 *      succeeded or failed.
 *
 *    - S_ACTIVE: A connection has been established and appears to be healthy.
 *
 *    - S_IDLE: A connection has been established but has been idle for some
 *      time.  An echo request has been sent, but no reply has yet been
 *      received.
 *
 *    - S_DISCONNECTED: An unreliable connection has disconnected and cannot be
 *      automatically retried.
 */

enum state {
    S_VOID = 1 << 0
    S_BACKOFF = 1 << 1
    S_CONNECTING = 1 << 2
    S_ACTIVE = 1 << 3
    S_IDLE = 1 << 4
    S_DISCONNECTED = 1 << 5
}

rconn 是 reliable connect 的缩写

struct rconn * rconn_create(int probe_interval, int max_backoff, uint8_t dscp, uint32_t allowed_versions)

    probe_interval: 如果 probe_interval 没有收到对端的消息发送 echo request, 如果再过 probe_interval 没有收到对端消息, 重连. 最少 5 s
    max_backoff : 从 1 s 没有收到对端请求, 之后 2 s 发送请求, 之后 4 s 发送请求... 直到 max_backoff
    allowed_versions : 允许的版本. 传 0 表示默认版本(1.1,1.2,1.3)

    初始化 rconn 的各个数据成员;

    没有显示初始化:
        struct vconn *monitors[MAXIMUM_MONITORS]; 为 NULL?
        int last_error;

void rconn_set_max_backoff(struct rconn *rc, int max_backoff)

    rc->max_backoff = MAX(1, max_backoff);
    如果 max_backoff 小于 rc->backoff, 那么, 就设置 rc->backoff = max_backoff;
    if (rc->state == S_BACKOFF && rc->backoff > max_backoff) {
        rc->backoff = max_backoff;
        if (rc->backoff_deadline > time_now() + max_backoff) {
            rc->backoff_deadline = time_now() + max_backoff;
        }
    }

void rconn_connect(struct rconn *rc, const char *target, const char *name)

    首先 rc->state 恢复到 S_VOID, 初始化 rc->reliable = true, 然后调用 vconn_open() 进行连接,
    如果成功状态进入 CONNECTING, 失败进入 BACKOFF

    rconn_disconnect__(rc);
    rconn_set_target__(rc, target, name);
    rc->reliable = true;
    reconnect(rc);

void rconn_connect_unreliably(struct rconn *rc, struct vconn *vconn, const char *name)

    首先 rc->state 恢复到 S_VOID, 然后进行初始化 rc->reliable = false, 状态直接转变为 S_ACTIVE

    rconn_disconnect__(rc);
    rconn_set_target__(rc, vconn_get_name(vconn), name);
    rc->reliable = false;
    rc->vconn = vconn;
    rc->last_connected = time_now();
    state_transition(rc, S_ACTIVE);

void rconn_reconnect(struct rconn *rc)

    如果从 ACTIVE 或 IDLE 状态进入 BACKOFF 状态

static void rconn_disconnect__(struct rconn *rc)

    从非 S_VOID 状态恢复为 S_VOID

    rc->vconn = NULL;
    rc->target = "void"
    rc->name = "void"
    rc->reliable = false;
    rc->backoff = 0;
    rc->backoff_deadline = TIME_MIN;
    rc->state = S_VOID
    rc->state_entered = time_now()

void rconn_disconnect(struct rconn *rc)

    加锁版 rconn_disconnect__(rc)

void rconn_destroy(struct rconn *rc)

    销毁 rc

static void reconnect(struct rconn *rc)

    调用 vconn_open(rc->target, rc->allowed_versions, rc->dscp, &rc->vconn) 进行连接
    如果成功, rc->state 进入 CONNECTING
    如果失败, rc->state 进入 BACKOFF

    注: 并没有断开连接后重连, 如果是正常的返回时间很慢是否会得到期望的结果

static void run_BACKOFF(struct rconn *rc)

    处于任何 rc->state 的状态下超时, 都进行重连

    if (timed_out(rc)) reconnect(rc);

static void run_CONNECTING(struct rconn *rc)

    调用 vconn_connect(rc->vconn) 进行连接
    如果成功, rc->state 进入 ACTIVE.
    如果失败, rc->state 进入 BACKOFF 状态

static void do_tx_work(struct rconn *rc)

    从 rc->txq 链表中依次取出数据包, 调用 try_send() 发送数据包之. 每次发送都更新 rc->last_activity
    如果 rc->txq 中的数据发送完了, 立即调用 poll_immediate_wake() 唤醒 poll接受数据包

static int try_send(struct rconn *rc)

    从 rc->txq 中取出一个消息 msg, 调用 vconn_send(rc->vconn, msg) 发送,
    如果发送成功, 从 rc->txq 中删除该消息, 更新 rconn_packet_counter;
    如果失败, 将该消息重新放入 rc->txq 中

static void run_ACTIVE(struct rconn *rc)

    如果 rc->state 超时, 转换到 IDLE, 发送 echo request 请求
    否则, 调用 do_tx_work 从 rc->txq 中取出一个数据包发送

static void run_IDLE(struct rconn *rc)

    如果 rc->state 超时, 对于可靠的连接进入 BACKOFF 状态, 对应不可靠连接, 直接断开
    否则, 调用 do_tx_work 从 rc->txq 中取出一个数据包发送

void rconn_run(struct rconn *rc)

    rc->vconn 与 rc->monitors 都完成与对端的连接建立, 从 rc->txq 依次取出所有数据包发送出去

    如果 rc-vconn 不为 NULL, rc-vconn 与对端建立连接或断开连接;
    遍历每个 rc->monitors　元素 rc->monitors[i], rc->monitors[i] 与对端建立连接或断开连接,
    如果建立连接, 非阻塞收对端消息.
        如果失败, 删除该 monitor;
        否则 删除 msg

    之后运行 rc->state 之后的函数
    rc->state = S_VOID : run_VOID()
    rc->state = S_BACKOFF : run_BACKOFF()
    rc->state = S_CONNECTING: run_CONNECTING()
    rc->state = S_ACTIVE : run_ACTIVE()
    rc->state = S_IDLE : run_IDLE()
    rc->state = S_DISCONNECTED: run_DISCONNECTED()

    注: 正常是在 rconn_connect 之后调用该函数, 之后会自动调用 run_CONNECTING
    完成连接, run_ACTIVE() 发送数据包

    注:正常情况 vconn_run()　保证 rc-vconn 已经建立连接, 并且发送 HELLO 请求和接受到 HELLO 应答

void rconn_run_wait(struct rconn *rc)

    保证连接已经完成, 其他什么也不做

    如果 rc-vconn 不为 NULL, 调用 vconn_run_wait(rc->vconn), 如果发送成功, 调用 vconn_wait(rc->vconn, WAIT_SEND);
    遍历每个 rc->monitors　元素 rc->monitors[i], 调用 vconn_run_wait(rc->monitors[i]);vconn_recv_wait(rc->monitors[i]);

    如果 rc->state 没有超时, 睡眠等待到超时时间.

struct ofpbuf * rconn_recv(struct rconn *rc)

    如果 rc->state 是 S_ACTIVE 或 S_IDLE,  调用 vconn_recv(rc->vconn, &buffer)
    成功: 拷贝 buffer 到所有的 rc->monitors, rc->state 变为 ACTIVE
    否则: 更加是否是可靠地连接, 断开或重连

void rconn_recv_wait(struct rconn *rc)

     如果 rc->vconn 不为 NULL,  vconn_wait(rc->vconn, WAIT_RECV);

static void copy_to_monitor(struct rconn *rc, const struct ofpbuf *b)

    克隆数据包 b 为 clone, 遍历 rc->monitors 每个元素, 调用 vconn_send(rc->monitor[i], clone)

static void close_monitor(struct rconn *rc, size_t idx, int retval)

static int rconn_send__(struct rconn *rc, struct ofpbuf *b, struct rconn_packet_counter *counter)

    如果 rc 处于IDLE, ACTIVE 状态, rc->monitors 的每一个成员调用 vconn_send(rc->monitors[i], b),
        b->list_node 加入 rc->txq 链表尾, 如果　rc->txq 中只有 b, 直接发送
    否则 直接释放 b 的内存


int rconn_send(struct rconn *rc, struct ofpbuf *b, struct rconn_packet_counter *counter)

    加锁版的 rconn_send__()

int rconn_send_with_limit(struct rconn *rc, struct ofpbuf *b, struct rconn_packet_counter *counter, int queue_limit)

    如果 counter->packets < queue_limit, 将 b 加入 rc->txq 等待发送
    否则删除 b

void rconn_add_monitor(struct rconn *rc, struct vconn *vconn)

    如果 rc->n_monitors < ARRAY_SIZE(rc->monitors), 将 vconn 加入 rc->monitors,

static bool timed_out(const struct rconn *rc)

    rc 处于 rc->state 的时间是否超时;

    比如在 S_IDLE 状态, 如果 time_now() >= rc->state_entred + rc->probe_interval, 我们就认为处于 IDLE 的超时了
    再 S_ACTIVE, 如果 time_now() > rc->last_activity - rc->state_entered + rc->probe_interval 我们就认为处于 ACTIVE 超时了.

    return time_now() >= sat_add(rc->state_entered, timeout(rc));

static unsigned int timeout(const struct rconn *rc)

    rc->state = S_VOID : UINT_MAX
    rc->state = S_BACKOFF : rc->backoff
    rc->state = S_CONNECTING: max(1,rc->backoff)
    rc->state = S_ACTIVE : rc->probe_interval ? MAX(rc->last_activity, rc->state_entered) + rc->probe_interval - rc->state_entered : UINT_MAX;
    rc->state = S_IDLE : rc->probe_interval
    rc->state = S_DISCONNECTED: UINT_MAX

static void state_transition(struct rconn *rc, enum state state)

    rc->state = state
    rc->state_entered = time_now()
    根据具体条件修改如下值
    rc->total_time_connected
    rc->probably_admitted
    rc->seqno

static void rconn_set_target__(struct rconn *rc, const char *target, const char *name)

    重置 rc->target, rc->name, 如果 name = NULL, rc->name = rc->target

int rconn_failure_duration(const struct rconn *rconn)

    如果控制器一直监管交换机　返回 0;
    如果当前控制器已经不再接管交换机, 返回上次管理时间到现在的时间

    duration = (rconn_is_admitted__(rconn)
                ? 0
                : time_now() - rconn->last_admitted);

static void disconnect(struct rconn *rc, int error)

    释放 rc->vconn
    如果是稳定链路(rc->reliable=true), 转换 rc->state 到 S_BACKOFF
    否则转换 rc->state 状态到 S_DISCONNECTED

    if (rc->reliable) {
        rc->backoff_deadline = now + rc->backoff;
        state_transition(rc, S_BACKOFF);
    } else {
        rc->last_disconnected = time_now();
        state_transition(rc, S_DISCONNECTED);
    }

static void flush_queue(struct rconn *rc)

    丢掉 rc->txq 中的所有数据包, 调用  poll_immediate_wake();



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
struct miniflow {
    uint64_t tnl_map;
    uint64_t pkt_map;
    /* Followed by:
     *     uint64_t values[n];
     * where 'n' is miniflow_n_values(miniflow). */
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

每个 pinsched 中的 queues 中包含 N 个 pinqueue, 每个 pinqueue
包含很多 ofpbuf 对象, 一个 ofpbuf 就是一个 PACKET_IN 消息

每个 pinqueue->node 被 hash_int(port_no) 后保存在 pinsched->queues 的某一个队列中

token_bucket 中 rate 代表 N packets/msec, 每过 M msec, token + N*M, 但是 token
不能超过 burst, last_fill 代表上次更新时间. 如果 packet_send 每秒调用的频率大于
rate, 后续的包就必须加入队列, 而不是直接发送. packet_send() 每次调用, 检查 ps
如果已经超出速度限制就将包加入 ps 的队列中, 否则直接加入 txq 中, 准备发送, 当
包的数量超出了 burst 的限制, 就丢掉最长队里的第一个包.

* pinsched_create() 创建 pinsched 对象
* pinsched_destroy() 销毁 pinsched 对象
* packet_send() 发送数据包

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

    轮询从 ps->queues 中取出一个 pinqueue 对象

static struct ofpbuf *get_tx_packet(struct pinsched *ps)

    每次调用, 轮询从 ps 取出一个 pinqueue 对象 q, 从 q->packets 中取出第一个数据包, 返回.

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
