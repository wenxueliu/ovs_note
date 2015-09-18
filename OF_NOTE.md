
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

####services

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

####fail_open

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
    int queue_id;

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


void connmgr_run(struct connmgr *mgr, void (*handle_openflow)(struct ofconn *, const struct ofpbuf *ofp_msg))


void connmgr_wait(struct connmgr *mgr)




void connmgr_get_memory_usage(const struct connmgr *mgr, struct simap *usage)

struct ofproto * ofconn_get_ofproto(const struct ofconn *ofconn)

    返回 ofconn->connmgr->ofproto;


static void ofmonitor_run(struct connmgr *mgr)

    LIST_FOR_EACH (ofconn, node, &mgr->all_conns) {
        if (ofmonitor_may_resume(ofconn)) {
            COVERAGE_INC(ofmonitor_resume);
            ofmonitor_resume(ofconn);
        }
    }


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



##重连

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

###Openflow 连接


static struct ofconn * ofconn_create(struct connmgr *mgr, struct rconn *rconn, enum ofconn_type type, bool enable_async_msgs)

    为 ofconn 分配内存, 并全部初始化为 0
    ofconn->connmgr 指向 mgr
    ofconn 加入 mgr->all_conns
    初始化 ofconn->monitors, ofconn->updates, ofconn->bundles

注: ofconn->hmap_node = NULL
    ofconn->band      = 0
    ofconn->pktbuf    = NULL
    ofconn->schedulers 没有初始化, 即 ofconn->schedulers[0] = NULL, ofconn->schedulers[1] = NULL;
    ofconn->pktbuf = NULL 而不是 ofconn->pktbuf = pktbuf_create();
    ofconn->monitor_paused = 0

static void ofconn_send(const struct ofconn *ofconn, struct ofpbuf *msg,
            struct rconn_packet_counter *counter)


    rconn_send(ofconn->rconn, msg, counter);
    如果 ofconn->rconn 处于连接状态, 将 msg 发送给 ofconn->rconn->monitors 的每一个成员, msg->list_node 
        加入 ofconn->rconn->txq 链表尾, 如果ofconn->rconn->txq 只有 msg->list_node 调用 vconn_send(rc->vconn, msg)

    否则 直接释放 b 的内存



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

    如果 event 是 ADD, rule->add_seqno 和 rule->modify_seqno 都加 1
    如果 event 是 MODIFY, rule->modify_seqno 都加 1
    如果 event 是 MODIFY, rule->modify_seqno 都加 1




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
