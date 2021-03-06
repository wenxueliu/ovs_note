



##数据结构

###全局变量

/* All created network devices. */
static struct shash netdev_shash : 保存所有的端口

static struct hmap netdev_classes : 保存所有已经注册的网络设备

其中包括

详细的关系见 netdev.c 中的 netdev_initialize

static const struct vport_class patch_class =
    { NULL,
        { "patch", VPORT_FUNCTIONS(get_patch_config,
                                   set_patch_config,
                                   NULL,
                                   NULL, NULL, NULL, NULL) }};

const struct netdev_class netdev_linux_class =
    NETDEV_LINUX_CLASS(
        "system",
        netdev_linux_construct,
        netdev_linux_get_stats,
        netdev_linux_get_features,
        netdev_linux_get_status);

const struct netdev_class netdev_internal_class =
    NETDEV_LINUX_CLASS(
        "internal",
        netdev_linux_construct,
        netdev_internal_get_stats,
        NULL,                  /* get_features */
        netdev_internal_get_status);

const struct netdev_class netdev_tap_class =
    NETDEV_LINUX_CLASS(
        "tap",
        netdev_linux_construct_tap,
        netdev_tap_get_stats,
        netdev_linux_get_features,
        netdev_linux_get_status);

static const struct vport_class vport_classes[] = {
    TUNNEL_CLASS("geneve", "genev_sys", netdev_geneve_build_header,
                                        push_udp_header,
                                        netdev_geneve_pop_header),
    TUNNEL_CLASS("gre", "gre_sys", netdev_gre_build_header,
                                    netdev_gre_push_header,
                                    netdev_gre_pop_header),
    TUNNEL_CLASS("ipsec_gre", "gre_sys", NULL, NULL, NULL),
    TUNNEL_CLASS("gre64", "gre64_sys", NULL,  NULL, NULL),
    TUNNEL_CLASS("ipsec_gre64", "gre64_sys", NULL, NULL, NULL),
    TUNNEL_CLASS("vxlan", "vxlan_sys", netdev_vxlan_build_header,
                                        push_udp_header,
                                        netdev_vxlan_pop_header),
    TUNNEL_CLASS("lisp", "lisp_sys", NULL, NULL, NULL),
    TUNNEL_CLASS("stt", "stt_sys", NULL, NULL, NULL),
};

static const struct netdev_class dpdk_class =
    NETDEV_DPDK_CLASS(
        "dpdk",
        NULL,
        netdev_dpdk_construct,
        netdev_dpdk_destruct,
        netdev_dpdk_set_multiq,
        netdev_dpdk_eth_send,
        netdev_dpdk_get_carrier,
        netdev_dpdk_get_stats,
        netdev_dpdk_get_features,
        netdev_dpdk_get_status,
        netdev_dpdk_rxq_recv);

static const struct netdev_class dpdk_ring_class =
    NETDEV_DPDK_CLASS(
        "dpdkr",
        NULL,
        netdev_dpdk_ring_construct,
        netdev_dpdk_destruct,
        netdev_dpdk_set_multiq,
        netdev_dpdk_ring_send,
        netdev_dpdk_get_carrier,
        netdev_dpdk_get_stats,
        netdev_dpdk_get_features,
        netdev_dpdk_get_status,
        netdev_dpdk_rxq_recv);

static const struct netdev_class OVS_UNUSED dpdk_vhost_cuse_class =
    NETDEV_DPDK_CLASS(
        "dpdkvhostcuse",
        dpdk_vhost_cuse_class_init,
        netdev_dpdk_vhost_cuse_construct,
        netdev_dpdk_vhost_destruct,
        netdev_dpdk_vhost_set_multiq,
        netdev_dpdk_vhost_send,
        netdev_dpdk_vhost_get_carrier,
        netdev_dpdk_vhost_get_stats,
        NULL,
        NULL,
        netdev_dpdk_vhost_rxq_recv);

static const struct netdev_class OVS_UNUSED dpdk_vhost_user_class =
    NETDEV_DPDK_CLASS(
        "dpdkvhostuser",
        dpdk_vhost_user_class_init,
        netdev_dpdk_vhost_user_construct,
        netdev_dpdk_vhost_destruct,
        netdev_dpdk_vhost_set_multiq,
        netdev_dpdk_vhost_send,
        netdev_dpdk_vhost_get_carrier,
        netdev_dpdk_vhost_get_stats,
        NULL,
        NULL,
        netdev_dpdk_vhost_rxq_recv);

###数据结构

/* A network device (e.g. an Ethernet device).
 *
 * Network device implementations may read these members but should not modify
 * them. */
struct netdev {
    /* The following do not change during the lifetime of a struct netdev. */
    char *name;                         /* Name of network device. */
    const struct netdev_class *netdev_class; /* Functions to control
                                                this device. */

    /* A sequence number which indicates changes in one of 'netdev''s
     * properties.   It must be nonzero so that users have a value which
     * they may use as a reset when tracking 'netdev'.
     *
     * Minimally, the sequence number is required to change whenever
     * 'netdev''s flags, features, ethernet address, or carrier changes. */
    uint64_t change_seq;

    /* The following are protected by 'netdev_mutex' (internal to netdev.c). */
    int n_txq;
    int n_rxq;
    int ref_cnt;                        /* Times this devices was opened. */
    struct shash_node *node;            /* Pointer to element in global map. */
    struct ovs_list saved_flags_list; /* Contains "struct netdev_saved_flags". */
};


/* Network device class structure, to be defined by each implementation of a
 * network device.
 *
 * These functions return 0 if successful or a positive errno value on failure,
 * except where otherwise noted.
 *
 *
 * Data Structures
 * ===============
 *
 * These functions work primarily with two different kinds of data structures:
 *
 *   - "struct netdev", which represents a network device.
 *
 *   - "struct netdev_rxq", which represents a handle for capturing packets
 *     received on a network device
 *
 * Each of these data structures contains all of the implementation-independent
 * generic state for the respective concept, called the "base" state.  None of
 * them contains any extra space for implementations to use.  Instead, each
 * implementation is expected to declare its own data structure that contains
 * an instance of the generic data structure plus additional
 * implementation-specific members, called the "derived" state.  The
 * implementation can use casts or (preferably) the CONTAINER_OF macro to
 * obtain access to derived state given only a pointer to the embedded generic
 * data structure.
 *
 *
 * Life Cycle
 * ==========
 *
 * Four stylized functions accompany each of these data structures:
 *
 *            "alloc"          "construct"        "destruct"       "dealloc"
 *            ------------   ----------------  ---------------  --------------
 * netdev      ->alloc        ->construct        ->destruct        ->dealloc
 * netdev_rxq  ->rxq_alloc    ->rxq_construct    ->rxq_destruct    ->rxq_dealloc
 *
 * Any instance of a given data structure goes through the following life
 * cycle:
 *
 *   1. The client calls the "alloc" function to obtain raw memory.  If "alloc"
 *      fails, skip all the other steps.
 *
 *   2. The client initializes all of the data structure's base state.  If this
 *      fails, skip to step 7.
 *
 *   3. The client calls the "construct" function.  The implementation
 *      initializes derived state.  It may refer to the already-initialized
 *      base state.  If "construct" fails, skip to step 6.
 *
 *   4. The data structure is now initialized and in use.
 *
 *   5. When the data structure is no longer needed, the client calls the
 *      "destruct" function.  The implementation uninitializes derived state.
 *      The base state has not been uninitialized yet, so the implementation
 *      may still refer to it.
 *
 *   6. The client uninitializes all of the data structure's base state.
 *
 *   7. The client calls the "dealloc" to free the raw memory.  The
 *      implementation must not refer to base or derived state in the data
 *      structure, because it has already been uninitialized.
 *
 * If netdev support multi-queue IO then netdev->construct should set initialize
 * netdev->n_rxq to number of queues.
 *
 * Each "alloc" function allocates and returns a new instance of the respective
 * data structure.  The "alloc" function is not given any information about the
 * use of the new data structure, so it cannot perform much initialization.
 * Its purpose is just to ensure that the new data structure has enough room
 * for base and derived state.  It may return a null pointer if memory is not
 * available, in which case none of the other functions is called.
 *
 * Each "construct" function initializes derived state in its respective data
 * structure.  When "construct" is called, all of the base state has already
 * been initialized, so the "construct" function may refer to it.  The
 * "construct" function is allowed to fail, in which case the client calls the
 * "dealloc" function (but not the "destruct" function).
 *
 * Each "destruct" function uninitializes and frees derived state in its
 * respective data structure.  When "destruct" is called, the base state has
 * not yet been uninitialized, so the "destruct" function may refer to it.  The
 * "destruct" function is not allowed to fail.
 *
 * Each "dealloc" function frees raw memory that was allocated by the the
 * "alloc" function.  The memory's base and derived members might not have ever
 * been initialized (but if "construct" returned successfully, then it has been
 * "destruct"ed already).  The "dealloc" function is not allowed to fail.
 *
 *
 * Device Change Notification
 * ==========================
 *
 * Minimally, implementations are required to report changes to netdev flags,
 * features, ethernet address or carrier through connectivity_seq. Changes to
 * other properties are allowed to cause notification through this interface,
 * although implementations should try to avoid this. connectivity_seq_get()
 * can be used to acquire a reference to the struct seq. The interface is
 * described in detail in seq.h. */
struct netdev_class {
    /* Type of netdevs in this class, e.g. "system", "tap", "gre", etc.
     *
     * One of the providers should supply a "system" type, since this is
     * the type assumed if no type is specified when opening a netdev.
     * The "system" type corresponds to an existing network device on
     * the system. */
    const char *type;

/* ## ------------------- ## */
/* ## Top-Level Functions ## */
/* ## ------------------- ## */

    /* Called when the netdev provider is registered, typically at program
     * startup.  Returning an error from this function will prevent any network
     * device in this class from being opened.
     *
     * This function may be set to null if a network device class needs no
     * initialization at registration time. */
    int ( *init)(void);

    /* Performs periodic work needed by netdevs of this class.  May be null if
     * no periodic work is necessary. */
    void ( *run)(void);

    /* Arranges for poll_block() to wake up if the "run" member function needs
     * to be called.  Implementations are additionally required to wake
     * whenever something changes in any of its netdevs which would cause their
     * ->change_seq() function to change its result.  May be null if nothing is
     * needed here. */
    void ( *wait)(void);

/* ## ---------------- ## */
/* ## netdev Functions ## */
/* ## ---------------- ## */

    /* Life-cycle functions for a netdev.  See the large comment above on
     * struct netdev_class. */
    struct netdev *( *alloc)(void);
    int ( *construct)(struct netdev *);
    void ( *destruct)(struct netdev *);
    void ( *dealloc)(struct netdev *);

    /* Fetches the device 'netdev''s configuration, storing it in 'args'.
     * The caller owns 'args' and pre-initializes it to an empty smap.
     *
     * If this netdev class does not have any configuration options, this may
     * be a null pointer. */
    int ( *get_config)(const struct netdev *netdev, struct smap *args);

    /* Changes the device 'netdev''s configuration to 'args'.
     *
     * If this netdev class does not support configuration, this may be a null
     * pointer. */
    int ( *set_config)(struct netdev *netdev, const struct smap *args);

    /* Returns the tunnel configuration of 'netdev'.  If 'netdev' is
     * not a tunnel, returns null.
     *
     * If this function would always return null, it may be null instead. */
    const struct netdev_tunnel_config *
        ( *get_tunnel_config)(const struct netdev *netdev);

    /* Build Partial Tunnel header.  Ethernet and ip header is already built,
     * build_header() is suppose build protocol specific part of header. */
    int ( *build_header)(const struct netdev *, struct ovs_action_push_tnl *data,
                        const struct flow *tnl_flow);

    /* build_header() can not build entire header for all packets for given
     * flow.  Push header is called for packet to build header specific to
     * a packet on actual transmit.  It uses partial header build by
     * build_header() which is passed as data. */
    void ( *push_header)(struct dp_packet *packet,
                        const struct ovs_action_push_tnl *data);

    /* Pop tunnel header from packet, build tunnel metadata and resize packet
     * for further processing. */
    int ( *pop_header)(struct dp_packet *packet);

    /* Returns the id of the numa node the 'netdev' is on.  If there is no
     * such info, returns NETDEV_NUMA_UNSPEC. */
    int ( *get_numa_id)(const struct netdev *netdev);

    /* Configures the number of tx queues and rx queues of 'netdev'.
     * Return 0 if successful, otherwise a positive errno value.
     *
     * 'n_rxq' specifies the maximum number of receive queues to create.
     * The netdev provider might choose to create less (e.g. if the hardware
     * supports only a smaller number).  The actual number of queues created
     * is stored in the 'netdev->n_rxq' field.
     *
     * 'n_txq' specifies the exact number of transmission queues to create.
     * The caller will call netdev_send() concurrently from 'n_txq' different
     * threads (with different qid).  The netdev provider is responsible for
     * making sure that these concurrent calls do not create a race condition
     * by using multiple hw queues or locking.
     *
     * On error, the tx queue and rx queue configuration is indeterminant.
     * Caller should make decision on whether to restore the previous or
     * the default configuration.  Also, caller must make sure there is no
     * other thread accessing the queues at the same time. */
    int ( *set_multiq)(struct netdev *netdev, unsigned int n_txq,
                      unsigned int n_rxq);

    /* Sends buffers on 'netdev'.
     * Returns 0 if successful (for every buffer), otherwise a positive errno
     * value.  Returns EAGAIN without blocking if one or more packets cannot be
     * queued immediately. Returns EMSGSIZE if a partial packet was transmitted
     * or if a packet is too big or too small to transmit on the device.
     *
     * If the function returns a non-zero value, some of the packets might have
     * been sent anyway.
     *
     * To retain ownership of 'buffers' caller can set may_steal to false.
     *
     * The network device is expected to maintain one or more packet
     * transmission queues, so that the caller does not ordinarily have to
     * do additional queuing of packets.  'qid' specifies the queue to use
     * and can be ignored if the implementation does not support multiple
     * queues.
     *
     * May return EOPNOTSUPP if a network device does not implement packet
     * transmission through this interface.  This function may be set to null
     * if it would always return EOPNOTSUPP anyhow.  (This will prevent the
     * network device from being usefully used by the netdev-based "userspace
     * datapath".  It will also prevent the OVS implementation of bonding from
     * working properly over 'netdev'.) */
    int ( *send)(struct netdev *netdev, int qid, struct dp_packet **buffers,
                int cnt, bool may_steal);

    /* Registers with the poll loop to wake up from the next call to
     * poll_block() when the packet transmission queue for 'netdev' has
     * sufficient room to transmit a packet with netdev_send().
     *
     * The network device is expected to maintain one or more packet
     * transmission queues, so that the caller does not ordinarily have to
     * do additional queuing of packets.  'qid' specifies the queue to use
     * and can be ignored if the implementation does not support multiple
     * queues.
     *
     * May be null if not needed, such as for a network device that does not
     * implement packet transmission through the 'send' member function. */
    void ( *send_wait)(struct netdev *netdev, int qid);

    /* Sets 'netdev''s Ethernet address to 'mac' */
    int ( *set_etheraddr)(struct netdev *netdev,
                         const uint8_t mac[ETH_ADDR_LEN]);

    /* Retrieves 'netdev''s Ethernet address into 'mac'.
     *
     * This address will be advertised as 'netdev''s MAC address through the
     * OpenFlow protocol, among other uses. */
    int ( *get_etheraddr)(const struct netdev *netdev,
                         uint8_t mac[ETH_ADDR_LEN]);

    /* Retrieves 'netdev''s MTU into '*mtup'.
     *
     * The MTU is the maximum size of transmitted (and received) packets, in
     * bytes, not including the hardware header; thus, this is typically 1500
     * bytes for Ethernet devices.
     *
     * If 'netdev' does not have an MTU (e.g. as some tunnels do not), then
     * this function should return EOPNOTSUPP.  This function may be set to
     * null if it would always return EOPNOTSUPP. */
    int ( *get_mtu)(const struct netdev *netdev, int *mtup);

    /* Sets 'netdev''s MTU to 'mtu'.
     *
     * If 'netdev' does not have an MTU (e.g. as some tunnels do not), then
     * this function should return EOPNOTSUPP.  This function may be set to
     * null if it would always return EOPNOTSUPP. */
    int ( *set_mtu)(const struct netdev *netdev, int mtu);

    /* Returns the ifindex of 'netdev', if successful, as a positive number.
     * On failure, returns a negative errno value.
     *
     * The desired semantics of the ifindex value are a combination of those
     * specified by POSIX for if_nametoindex() and by SNMP for ifIndex.  An
     * ifindex value should be unique within a host and remain stable at least
     * until reboot.  SNMP says an ifindex "ranges between 1 and the value of
     * ifNumber" but many systems do not follow this rule anyhow.
     *
     * This function may be set to null if it would always return -EOPNOTSUPP.
     */
    int ( *get_ifindex)(const struct netdev *netdev);

    /* Sets 'carrier' to true if carrier is active (link light is on) on
     * 'netdev'.
     *
     * May be null if device does not provide carrier status (will be always
     * up as long as device is up).
     */
    int ( *get_carrier)(const struct netdev *netdev, bool *carrier);

    /* Returns the number of times 'netdev''s carrier has changed since being
     * initialized.
     *
     * If null, callers will assume the number of carrier resets is zero. */
    long long int ( *get_carrier_resets)(const struct netdev *netdev);

    /* Forces ->get_carrier() to poll 'netdev''s MII registers for link status
     * instead of checking 'netdev''s carrier.  'netdev''s MII registers will
     * be polled once every 'interval' milliseconds.  If 'netdev' does not
     * support MII, another method may be used as a fallback.  If 'interval' is
     * less than or equal to zero, reverts ->get_carrier() to its normal
     * behavior.
     *
     * Most network devices won't support this feature and will set this
     * function pointer to NULL, which is equivalent to returning EOPNOTSUPP.
     */
    int ( *set_miimon_interval)(struct netdev *netdev, long long int interval);

    /* Retrieves current device stats for 'netdev' into 'stats'.
     *
     * A network device that supports some statistics but not others, it should
     * set the values of the unsupported statistics to all-1-bits
     * (UINT64_MAX). */
    int ( *get_stats)(const struct netdev *netdev, struct netdev_stats *);

    /* Stores the features supported by 'netdev' into each of '*current',
     * '*advertised', '*supported', and '*peer'.  Each value is a bitmap of
     * NETDEV_F_* bits.
     *
     * This function may be set to null if it would always return EOPNOTSUPP.
     */
    int ( *get_features)(const struct netdev *netdev,
                        enum netdev_features *current,
                        enum netdev_features *advertised,
                        enum netdev_features *supported,
                        enum netdev_features *peer);

    /* Set the features advertised by 'netdev' to 'advertise', which is a
     * set of NETDEV_F_* bits.
     *
     * This function may be set to null for a network device that does not
     * support configuring advertisements. */
    int ( *set_advertisements)(struct netdev *netdev,
                              enum netdev_features advertise);

    /* Attempts to set input rate limiting (policing) policy, such that up to
     * 'kbits_rate' kbps of traffic is accepted, with a maximum accumulative
     * burst size of 'kbits' kb.
     *
     * This function may be set to null if policing is not supported. */
    int ( *set_policing)(struct netdev *netdev, unsigned int kbits_rate,
                        unsigned int kbits_burst);

    /* Adds to 'types' all of the forms of QoS supported by 'netdev', or leaves
     * it empty if 'netdev' does not support QoS.  Any names added to 'types'
     * should be documented as valid for the "type" column in the "QoS" table
     * in vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
     *
     * Every network device must support disabling QoS with a type of "", but
     * this function must not add "" to 'types'.
     *
     * The caller is responsible for initializing 'types' (e.g. with
     * sset_init()) before calling this function.  The caller retains ownership
     * of 'types'.
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int ( *get_qos_types)(const struct netdev *netdev, struct sset *types);

    /* Queries 'netdev' for its capabilities regarding the specified 'type' of
     * QoS.  On success, initializes 'caps' with the QoS capabilities.
     *
     * Should return EOPNOTSUPP if 'netdev' does not support 'type'.  May be
     * NULL if 'netdev' does not support QoS at all. */
    int ( *get_qos_capabilities)(const struct netdev *netdev,
                                const char *type,
                                struct netdev_qos_capabilities *caps);

    /* Queries 'netdev' about its currently configured form of QoS.  If
     * successful, stores the name of the current form of QoS into '*typep'
     * and any details of configuration as string key-value pairs in
     * 'details'.
     *
     * A '*typep' of "" indicates that QoS is currently disabled on 'netdev'.
     *
     * The caller initializes 'details' before calling this function.  The
     * caller takes ownership of the string key-values pairs added to
     * 'details'.
     *
     * The netdev retains ownership of '*typep'.
     *
     * '*typep' will be one of the types returned by netdev_get_qos_types() for
     * 'netdev'.  The contents of 'details' should be documented as valid for
     * '*typep' in the "other_config" column in the "QoS" table in
     * vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int ( *get_qos)(const struct netdev *netdev,
                   const char **typep, struct smap *details);

    /* Attempts to reconfigure QoS on 'netdev', changing the form of QoS to
     * 'type' with details of configuration from 'details'.
     *
     * On error, the previous QoS configuration is retained.
     *
     * When this function changes the type of QoS (not just 'details'), this
     * also resets all queue configuration for 'netdev' to their defaults
     * (which depend on the specific type of QoS).  Otherwise, the queue
     * configuration for 'netdev' is unchanged.
     *
     * 'type' should be "" (to disable QoS) or one of the types returned by
     * netdev_get_qos_types() for 'netdev'.  The contents of 'details' should
     * be documented as valid for the given 'type' in the "other_config" column
     * in the "QoS" table in vswitchd/vswitch.xml (which is built as
     * ovs-vswitchd.conf.db(8)).
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int ( *set_qos)(struct netdev *netdev,
                   const char *type, const struct smap *details);

    /* Queries 'netdev' for information about the queue numbered 'queue_id'.
     * If successful, adds that information as string key-value pairs to
     * 'details'.  Returns 0 if successful, otherwise a positive errno value.
     *
     * Should return EINVAL if 'queue_id' is greater than or equal to the
     * number of supported queues (as reported in the 'n_queues' member of
     * struct netdev_qos_capabilities by 'get_qos_capabilities').
     *
     * The caller initializes 'details' before calling this function.  The
     * caller takes ownership of the string key-values pairs added to
     * 'details'.
     *
     * The returned contents of 'details' should be documented as valid for the
     * given 'type' in the "other_config" column in the "Queue" table in
     * vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
     */
    int ( *get_queue)(const struct netdev *netdev,
                     unsigned int queue_id, struct smap *details);

    /* Configures the queue numbered 'queue_id' on 'netdev' with the key-value
     * string pairs in 'details'.  The contents of 'details' should be
     * documented as valid for the given 'type' in the "other_config" column in
     * the "Queue" table in vswitchd/vswitch.xml (which is built as
     * ovs-vswitchd.conf.db(8)).  Returns 0 if successful, otherwise a positive
     * errno value.  On failure, the given queue's configuration should be
     * unmodified.
     *
     * Should return EINVAL if 'queue_id' is greater than or equal to the
     * number of supported queues (as reported in the 'n_queues' member of
     * struct netdev_qos_capabilities by 'get_qos_capabilities'), or if
     * 'details' is invalid for the type of queue.
     *
     * This function does not modify 'details', and the caller retains
     * ownership of it.
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int ( *set_queue)(struct netdev *netdev,
                     unsigned int queue_id, const struct smap *details);

    /* Attempts to delete the queue numbered 'queue_id' from 'netdev'.
     *
     * Should return EINVAL if 'queue_id' is greater than or equal to the
     * number of supported queues (as reported in the 'n_queues' member of
     * struct netdev_qos_capabilities by 'get_qos_capabilities').  Should
     * return EOPNOTSUPP if 'queue_id' is valid but may not be deleted (e.g. if
     * 'netdev' has a fixed set of queues with the current QoS mode).
     *
     * May be NULL if 'netdev' does not support QoS at all, or if all of its
     * QoS modes have fixed sets of queues. */
    int ( *delete_queue)(struct netdev *netdev, unsigned int queue_id);

    /* Obtains statistics about 'queue_id' on 'netdev'.  Fills 'stats' with the
     * queue's statistics.  May set individual members of 'stats' to all-1-bits
     * if the statistic is unavailable.
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int ( *get_queue_stats)(const struct netdev *netdev, unsigned int queue_id,
                           struct netdev_queue_stats *stats);

    /* Attempts to begin dumping the queues in 'netdev'.  On success, returns 0
     * and initializes '*statep' with any data needed for iteration.  On
     * failure, returns a positive errno value.
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int ( *queue_dump_start)(const struct netdev *netdev, void **statep);

    /* Attempts to retrieve another queue from 'netdev' for 'state', which was
     * initialized by a successful call to the 'queue_dump_start' function for
     * 'netdev'.  On success, stores a queue ID into '*queue_id' and fills
     * 'details' with the configuration of the queue with that ID.  Returns EOF
     * if the last queue has been dumped, or a positive errno value on error.
     * This function will not be called again once it returns nonzero once for
     * a given iteration (but the 'queue_dump_done' function will be called
     * afterward).
     *
     * The caller initializes and clears 'details' before calling this
     * function.  The caller takes ownership of the string key-values pairs
     * added to 'details'.
     *
     * The returned contents of 'details' should be documented as valid for the
     * given 'type' in the "other_config" column in the "Queue" table in
     * vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int ( *queue_dump_next)(const struct netdev *netdev, void *state,
                           unsigned int *queue_id, struct smap *details);

    /* Releases resources from 'netdev' for 'state', which was initialized by a
     * successful call to the 'queue_dump_start' function for 'netdev'.
     *
     * May be NULL if 'netdev' does not support QoS at all. */
    int ( *queue_dump_done)(const struct netdev *netdev, void *state);

    /* Iterates over all of 'netdev''s queues, calling 'cb' with the queue's
     * ID, its statistics, and the 'aux' specified by the caller.  The order of
     * iteration is unspecified, but (when successful) each queue must be
     * visited exactly once.
     *
     * 'cb' will not modify or free the statistics passed in. */
    int ( *dump_queue_stats)(const struct netdev *netdev,
                            void ( *cb)(unsigned int queue_id,
                                       struct netdev_queue_stats *,
                                       void *aux),
                            void *aux);

    /* If 'netdev' has an assigned IPv4 address, sets '*address' to that
     * address and '*netmask' to the associated netmask.
     *
     * The following error values have well-defined meanings:
     *
     *   - EADDRNOTAVAIL: 'netdev' has no assigned IPv4 address.
     *
     *   - EOPNOTSUPP: No IPv4 network stack attached to 'netdev'.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int ( *get_in4)(const struct netdev *netdev, struct in_addr *address,
                   struct in_addr *netmask);

    /* Assigns 'addr' as 'netdev''s IPv4 address and 'mask' as its netmask.  If
     * 'addr' is INADDR_ANY, 'netdev''s IPv4 address is cleared.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int ( *set_in4)(struct netdev *netdev, struct in_addr addr,
                   struct in_addr mask);

    /* If 'netdev' has an assigned IPv6 address, sets '*in6' to that address.
     *
     * The following error values have well-defined meanings:
     *
     *   - EADDRNOTAVAIL: 'netdev' has no assigned IPv6 address.
     *
     *   - EOPNOTSUPP: No IPv6 network stack attached to 'netdev'.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int ( *get_in6)(const struct netdev *netdev, struct in6_addr *in6);

    /* Adds 'router' as a default IP gateway for the TCP/IP stack that
     * corresponds to 'netdev'.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int ( *add_router)(struct netdev *netdev, struct in_addr router);

    /* Looks up the next hop for 'host' in the host's routing table.  If
     * successful, stores the next hop gateway's address (0 if 'host' is on a
     * directly connected network) in '*next_hop' and a copy of the name of the
     * device to reach 'host' in '*netdev_name', and returns 0.  The caller is
     * responsible for freeing '*netdev_name' (by calling free()).
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int ( *get_next_hop)(const struct in_addr *host, struct in_addr *next_hop,
                        char **netdev_name);

    /* Retrieves driver information of the device.
     *
     * Populates 'smap' with key-value pairs representing the status of the
     * device.  'smap' is a set of key-value string pairs representing netdev
     * type specific information.  For more information see
     * ovs-vswitchd.conf.db(5).
     *
     * The caller is responsible for destroying 'smap' and its data.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int ( *get_status)(const struct netdev *netdev, struct smap *smap);

    /* Looks up the ARP table entry for 'ip' on 'netdev' and stores the
     * corresponding MAC address in 'mac'.  A return value of ENXIO, in
     * particular, indicates that there is no ARP table entry for 'ip' on
     * 'netdev'.
     *
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int ( *arp_lookup)(const struct netdev *netdev, ovs_be32 ip,
                      uint8_t mac[ETH_ADDR_LEN]);

    /* Retrieves the current set of flags on 'netdev' into '*old_flags'.  Then,
     * turns off the flags that are set to 1 in 'off' and turns on the flags
     * that are set to 1 in 'on'.  (No bit will be set to 1 in both 'off' and
     * 'on'; that is, off & on == 0.)
     *
     * This function may be invoked from a signal handler.  Therefore, it
     * should not do anything that is not signal-safe (such as logging). */
    int ( *update_flags)(struct netdev *netdev, enum netdev_flags off,
                        enum netdev_flags on, enum netdev_flags *old_flags);

/* ## -------------------- ## */
/* ## netdev_rxq Functions ## */
/* ## -------------------- ## */

/* If a particular netdev class does not support receiving packets, all these
 * function pointers must be NULL. */

    /* Life-cycle functions for a netdev_rxq.  See the large comment above on
     * struct netdev_class. */
    struct netdev_rxq *( *rxq_alloc)(void);
    int ( *rxq_construct)(struct netdev_rxq *);
    void ( *rxq_destruct)(struct netdev_rxq *);
    void ( *rxq_dealloc)(struct netdev_rxq *);

    /* Attempts to receive batch of packets from 'rx' and place array of
     * pointers into '*pkts'. netdev is responsible for allocating buffers.
     * '*cnt' points to packet count for given batch. Once packets are returned
     * to caller, netdev should give up ownership of ofpbuf data.
     *
     * Implementations should allocate buffer with DP_NETDEV_HEADROOM headroom
     * and add a VLAN header which is obtained out-of-band to the packet.
     *
     * Caller is expected to pass array of size MAX_RX_BATCH.
     * This function may be set to null if it would always return EOPNOTSUPP
     * anyhow. */
    int ( *rxq_recv)(struct netdev_rxq *rx, struct dp_packet **pkts,
                    int *cnt);

    /* Registers with the poll loop to wake up from the next call to
     * poll_block() when a packet is ready to be received with netdev_rxq_recv()
     * on 'rx'. */
    void ( *rxq_wait)(struct netdev_rxq *rx);

    /* Discards all packets waiting to be received from 'rx'. */
    int ( *rxq_drain)(struct netdev_rxq *rx);
};


##具体实现

int netdev_register_provider(const struct netdev_class *new_class)

    将 new_class 初始化并加入　netdev_classes
    1. 如果 new_class->type 已经存在于 netdev_classes 返回警告信息
    2. 如果 new_class->type 不存在, 调用 new_class 的 init() 方法后, 将其加入 * netdev_classes

static void netdev_initialize(void)

    将 type 为 patch, system, internal, tap, geneve, gre, ipsec, gre64, vxlan, list,stt,
    dpdk, dpdkr, dpdkvhostcuse, dpdkvhostuser 加入到 netdev_classes 中, 并调用对应的初始化方法

void netdev_enumerate_types(struct sset *types)

    将 netdev_classes 中的 netdev_class->type 加入 types 中

struct netdev * netdev_from_name(const char *name)

    根据 name 从 netdev_shash 中找到 netdev, 并将该 netdev 的引用计数加 1

void netdev_get_devices(const struct netdev_class *netdev_class, struct shash *device_list)

    从 netdev_shash 中找到与 netdev_class 同一类型的　netdev 加入 device_list 中. 并更新 netdev 的引用计数

struct netdev ** netdev_get_vports(size_t *size)

    从 netdev_shash 中找到 netdev->netdev_class 为 vport_class 类型的所有 netdev, 加入 vports, 并返回该 vports 对象.
    其中 size 表明匹配的个数

int netdev_open(const char *name, const char *type, struct netdev **netdevp)


    从 netdev_classes 中找到 type 对应的 netdev_registered_class 对象 rc, 调用
    rc->class->alloc() 创建一个 netdev 对象 dev 并初始化, 并将 name, dev 加入
    netdev_shash, 增加 rc 的引用计数

    1. 将 type 为 patch, system, internal, tap, geneve, gre, ipsec, gre64, vxlan, list,stt,
    k, dpdkr, dpdkvhostcuse, dpdkvhostuser 加入到 netdev_classes 中, 并调用对应的初始化方法
    2. 如果 name 对应的 netdev 在 netdev_shash 中, 将 netdev 的引用计数加 1.
    如果 name 对应的 netdev 不在 netdev_shash 中, 继续
    3. 如果 type 在 netdev_classes 中, 调用 alloc 分配一个 netdev * 对象,初始化,加入 netdev_shash.
    如果  type 不在 netdev_classes 中, 返回错误消息

    这里加 1 的意义?
