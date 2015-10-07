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

/*
 * 保持 dpif_class->type : registered_dpif_class 类型 hash map
 * 目前保持有
 * system : { .dpif_class = dpif_netlink_class, .refcount=0 }
 * netdev : { .dpif_class = dpif_netdev_class, .refcount=0 }
 */
static struct shash dpif_classes = SHASH_INITIALIZER(&dpif_classes);

//黑名单, 在 ovs-vswitchd 中可以将 system 加入该黑名单
static struct sset dpif_blacklist = SSET_INITIALIZER(&dpif_blacklist); 

/* Open vSwitch datapath interface.
 *
 * This structure should be treated as opaque by dpif implementations. */
struct dpif {
    const struct dpif_class *dpif_class;
    char *base_name;
    char *full_name;
    uint8_t netflow_engine_type;
    uint8_t netflow_engine_id;
};

/* Datapath interface class structure, to be defined by each implementation of
 * a datapath interface.
 *
 * These functions return 0 if successful or a positive errno value on failure,
 * except where otherwise noted.
 *
 * These functions are expected to execute synchronously, that is, to block as
 * necessary to obtain a result.  Thus, they may not return EAGAIN or
 * EWOULDBLOCK or EINPROGRESS.  We may relax this requirement in the future if
 * and when we encounter performance problems. */
struct dpif_class {
    /* Type of dpif in this class, e.g. "system", "netdev", etc.
     *
     * One of the providers should supply a "system" type, since this is
     * the type assumed if no type is specified when opening a dpif. */
    const char *type;

    /* Called when the dpif provider is registered, typically at program
     * startup.  Returning an error from this function will prevent any
     * datapath with this class from being created.
     *
     * This function may be set to null if a datapath class needs no
     * initialization at registration time. */
    int (*init)(void);

    /* Enumerates the names of all known created datapaths (of class
     * 'dpif_class'), if possible, into 'all_dps'.  The caller has already
     * initialized 'all_dps' and other dpif classes might already have added
     * names to it.
     *
     * This is used by the vswitch at startup, so that it can delete any
     * datapaths that are not configured.
     *
     * Some kinds of datapaths might not be practically enumerable, in which
     * case this function may be a null pointer. */
    int (*enumerate)(struct sset *all_dps, const struct dpif_class *dpif_class);

    /* Returns the type to pass to netdev_open() when a dpif of class
     * 'dpif_class' has a port of type 'type', for a few special cases
     * when a netdev type differs from a port type.  For example, when
     * using the userspace datapath, a port of type "internal" needs to
     * be opened as "tap".
     *
     * Returns either 'type' itself or a string literal, which must not
     * be freed. */
    const char *(*port_open_type)(const struct dpif_class *dpif_class,
                                  const char *type);

    /* Attempts to open an existing dpif called 'name', if 'create' is false,
     * or to open an existing dpif or create a new one, if 'create' is true.
     *
     * 'dpif_class' is the class of dpif to open.
     *
     * If successful, stores a pointer to the new dpif in '*dpifp', which must
     * have class 'dpif_class'.  On failure there are no requirements on what
     * is stored in '*dpifp'. */
    int (*open)(const struct dpif_class *dpif_class,
                const char *name, bool create, struct dpif **dpifp);

    /* Closes 'dpif' and frees associated memory. */
    void (*close)(struct dpif *dpif);

    /* Attempts to destroy the dpif underlying 'dpif'.
     *
     * If successful, 'dpif' will not be used again except as an argument for
     * the 'close' member function. */
    int (*destroy)(struct dpif *dpif);

    /* Performs periodic work needed by 'dpif', if any is necessary.
     * Returns true if need to revalidate. */
    bool (*run)(struct dpif *dpif);

    /* Arranges for poll_block() to wake up if the "run" member function needs
     * to be called for 'dpif'. */
    void (*wait)(struct dpif *dpif);

    /* Retrieves statistics for 'dpif' into 'stats'. */
    int (*get_stats)(const struct dpif *dpif, struct dpif_dp_stats *stats);

    /* Adds 'netdev' as a new port in 'dpif'.  If '*port_no' is not
     * UINT32_MAX, attempts to use that as the port's port number.
     *
     * If port is successfully added, sets '*port_no' to the new port's
     * port number.  Returns EBUSY if caller attempted to choose a port
     * number, and it was in use. */
    int (*port_add)(struct dpif *dpif, struct netdev *netdev,
                    odp_port_t *port_no);

    /* Removes port numbered 'port_no' from 'dpif'. */
    int (*port_del)(struct dpif *dpif, odp_port_t port_no);

    /* Queries 'dpif' for a port with the given 'port_no' or 'devname'.
     * If 'port' is not null, stores information about the port into
     * '*port' if successful.
     *
     * If 'port' is not null, the caller takes ownership of data in
     * 'port' and must free it with dpif_port_destroy() when it is no
     * longer needed. */
    int (*port_query_by_number)(const struct dpif *dpif, odp_port_t port_no,
                                struct dpif_port *port);
    int (*port_query_by_name)(const struct dpif *dpif, const char *devname,
                              struct dpif_port *port);

    /* Returns the Netlink PID value to supply in OVS_ACTION_ATTR_USERSPACE
     * actions as the OVS_USERSPACE_ATTR_PID attribute's value, for use in
     * flows whose packets arrived on port 'port_no'.  In the case where the
     * provider allocates multiple Netlink PIDs to a single port, it may use
     * 'hash' to spread load among them.  The caller need not use a particular
     * hash function; a 5-tuple hash is suitable.
     *
     * (The datapath implementation might use some different hash function for
     * distributing packets received via flow misses among PIDs.  This means
     * that packets received via flow misses might be reordered relative to
     * packets received via userspace actions.  This is not ordinarily a
     * problem.)
     *
     * A 'port_no' of UINT32_MAX should be treated as a special case.  The
     * implementation should return a reserved PID, not allocated to any port,
     * that the client may use for special purposes.
     *
     * The return value only needs to be meaningful when DPIF_UC_ACTION has
     * been enabled in the 'dpif''s listen mask, and it is allowed to change
     * when DPIF_UC_ACTION is disabled and then re-enabled.
     *
     * A dpif provider that doesn't have meaningful Netlink PIDs can use NULL
     * for this function.  This is equivalent to always returning 0. */
    uint32_t (*port_get_pid)(const struct dpif *dpif, odp_port_t port_no,
                             uint32_t hash);

    /* Attempts to begin dumping the ports in a dpif.  On success, returns 0
     * and initializes '*statep' with any data needed for iteration.  On
     * failure, returns a positive errno value. */
    int (*port_dump_start)(const struct dpif *dpif, void **statep);

    /* Attempts to retrieve another port from 'dpif' for 'state', which was
     * initialized by a successful call to the 'port_dump_start' function for
     * 'dpif'.  On success, stores a new dpif_port into 'port' and returns 0.
     * Returns EOF if the end of the port table has been reached, or a positive
     * errno value on error.  This function will not be called again once it
     * returns nonzero once for a given iteration (but the 'port_dump_done'
     * function will be called afterward).
     *
     * The dpif provider retains ownership of the data stored in 'port'.  It
     * must remain valid until at least the next call to 'port_dump_next' or
     * 'port_dump_done' for 'state'. */
    int (*port_dump_next)(const struct dpif *dpif, void *state,
                          struct dpif_port *port);

    /* Releases resources from 'dpif' for 'state', which was initialized by a
     * successful call to the 'port_dump_start' function for 'dpif'.  */
    int (*port_dump_done)(const struct dpif *dpif, void *state);

    /* Polls for changes in the set of ports in 'dpif'.  If the set of ports in
     * 'dpif' has changed, then this function should do one of the
     * following:
     *
     * - Preferably: store the name of the device that was added to or deleted
     *   from 'dpif' in '*devnamep' and return 0.  The caller is responsible
     *   for freeing '*devnamep' (with free()) when it no longer needs it.
     *
     * - Alternatively: return ENOBUFS, without indicating the device that was
     *   added or deleted.
     *
     * Occasional 'false positives', in which the function returns 0 while
     * indicating a device that was not actually added or deleted or returns
     * ENOBUFS without any change, are acceptable.
     *
     * If the set of ports in 'dpif' has not changed, returns EAGAIN.  May also
     * return other positive errno values to indicate that something has gone
     * wrong. */
    int (*port_poll)(const struct dpif *dpif, char **devnamep);

    /* Arranges for the poll loop to wake up when 'port_poll' will return a
     * value other than EAGAIN. */
    void (*port_poll_wait)(const struct dpif *dpif);

    /* Deletes all flows from 'dpif' and clears all of its queues of received
     * packets. */
    int (*flow_flush)(struct dpif *dpif);

    /* Flow dumping interface.
     *
     * This is the back-end for the flow dumping interface described in
     * dpif.h.  Please read the comments there first, because this code
     * closely follows it.
     *
     * 'flow_dump_create' and 'flow_dump_thread_create' must always return an
     * initialized and usable data structure and defer error return until
     * flow_dump_destroy().  This hasn't been a problem for the dpifs that
     * exist so far.
     *
     * 'flow_dump_create' and 'flow_dump_thread_create' must initialize the
     * structures that they return with dpif_flow_dump_init() and
     * dpif_flow_dump_thread_init(), respectively.
     *
     * If 'terse' is true, then only UID and statistics will
     * be returned in the dump. Otherwise, all fields will be returned. */
    struct dpif_flow_dump *(*flow_dump_create)(const struct dpif *dpif,
                                               bool terse);
    int (*flow_dump_destroy)(struct dpif_flow_dump *dump);

    struct dpif_flow_dump_thread *(*flow_dump_thread_create)(
        struct dpif_flow_dump *dump);
    void (*flow_dump_thread_destroy)(struct dpif_flow_dump_thread *thread);

    int (*flow_dump_next)(struct dpif_flow_dump_thread *thread,
                          struct dpif_flow *flows, int max_flows);

    /* Executes each of the 'n_ops' operations in 'ops' on 'dpif', in the order
     * in which they are specified, placing each operation's results in the
     * "output" members documented in comments and the 'error' member of each
     * dpif_op. */
    void (*operate)(struct dpif *dpif, struct dpif_op **ops, size_t n_ops);

    /* Enables or disables receiving packets with dpif_recv() for 'dpif'.
     * Turning packet receive off and then back on is allowed to change Netlink
     * PID assignments (see ->port_get_pid()).  The client is responsible for
     * updating flows as necessary if it does this. */
    int (*recv_set)(struct dpif *dpif, bool enable);

    /* Refreshes the poll loops and Netlink sockets associated to each port,
     * when the number of upcall handlers (upcall receiving thread) is changed
     * to 'n_handlers' and receiving packets for 'dpif' is enabled by
     * recv_set().
     *
     * Since multiple upcall handlers can read upcalls simultaneously from
     * 'dpif', each port can have multiple Netlink sockets, one per upcall
     * handler.  So, handlers_set() is responsible for the following tasks:
     *
     *    When receiving upcall is enabled, extends or creates the
     *    configuration to support:
     *
     *        - 'n_handlers' Netlink sockets for each port.
     *
     *        - 'n_handlers' poll loops, one for each upcall handler.
     *
     *        - registering the Netlink sockets for the same upcall handler to
     *          the corresponding poll loop.
     * */
    int (*handlers_set)(struct dpif *dpif, uint32_t n_handlers);

    /* If 'dpif' creates its own I/O polling threads, refreshes poll threads
     * configuration.  'n_rxqs' configures the number of rx_queues, which
     * are distributed among threads.  'cmask' configures the cpu mask
     * for setting the polling threads' cpu affinity. */
    int (*poll_threads_set)(struct dpif *dpif, unsigned int n_rxqs,
                            const char *cmask);

    /* Translates OpenFlow queue ID 'queue_id' (in host byte order) into a
     * priority value used for setting packet priority. */
    int (*queue_to_priority)(const struct dpif *dpif, uint32_t queue_id,
                             uint32_t *priority);

    /* Polls for an upcall from 'dpif' for an upcall handler.  Since there
     * can be multiple poll loops (see ->handlers_set()), 'handler_id' is
     * needed as index to identify the corresponding poll loop.  If
     * successful, stores the upcall into '*upcall', using 'buf' for
     * storage.  Should only be called if 'recv_set' has been used to enable
     * receiving packets from 'dpif'.
     *
     * The implementation should point 'upcall->key' and 'upcall->userdata'
     * (if any) into data in the caller-provided 'buf'.  The implementation may
     * also use 'buf' for storing the data of 'upcall->packet'.  If necessary
     * to make room, the implementation may reallocate the data in 'buf'.
     *
     * The caller owns the data of 'upcall->packet' and may modify it.  If
     * packet's headroom is exhausted as it is manipulated, 'upcall->packet'
     * will be reallocated.  This requires the data of 'upcall->packet' to be
     * released with ofpbuf_uninit() before 'upcall' is destroyed.  However,
     * when an error is returned, the 'upcall->packet' may be uninitialized
     * and should not be released.
     *
     * This function must not block.  If no upcall is pending when it is
     * called, it should return EAGAIN without blocking. */
    int (*recv)(struct dpif *dpif, uint32_t handler_id,
                struct dpif_upcall *upcall, struct ofpbuf *buf);

    /* Arranges for the poll loop for an upcall handler to wake up when 'dpif'
     * has a message queued to be received with the recv member functions.
     * Since there can be multiple poll loops (see ->handlers_set()),
     * 'handler_id' is needed as index to identify the corresponding poll loop.
     * */
    void (*recv_wait)(struct dpif *dpif, uint32_t handler_id);

    /* Throws away any queued upcalls that 'dpif' currently has ready to
     * return. */
    void (*recv_purge)(struct dpif *dpif);

    /* For datapaths that run in userspace (i.e. dpif-netdev), threads polling
     * for incoming packets can directly call upcall functions instead of
     * offloading packet processing to separate handler threads. Datapaths
     * that directly call upcall functions should use the functions below to
     * to register an upcall function and enable / disable upcalls.
     *
     * Registers an upcall callback function with 'dpif'. This is only used if
     * if 'dpif' directly executes upcall functions. 'aux' is passed to the
     * callback on invocation. */
    void (*register_upcall_cb)(struct dpif *, upcall_callback *, void *aux);

    /* Enables upcalls if 'dpif' directly executes upcall functions. */
    void (*enable_upcall)(struct dpif *);

    /* Disables upcalls if 'dpif' directly executes upcall functions. */
    void (*disable_upcall)(struct dpif *);

    /* Get datapath version. Caller is responsible for freeing the string
     * returned.  */
    char *(*get_datapath_version)(void);
};

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


/* PMD: Poll modes drivers.  PMD accesses devices via polling to eliminate
 * the performance overhead of interrupt processing.  Therefore netdev can
 * not implement rx-wait for these devices.  dpif-netdev needs to poll
 * these device to check for recv buffer.  pmd-thread does polling for
 * devices assigned to itself.
 *
 * DPDK used PMD for accessing NIC.
 *
 * Note, instance with cpu core id NON_PMD_CORE_ID will be reserved for
 * I/O of all non-pmd threads.  There will be no actual thread created
 * for the instance.
 *
 * Each struct has its own flow table and classifier.  Packets received
 * from managed ports are looked up in the corresponding pmd thread's
 * flow table, and are executed with the found actions.
 * */
struct dp_netdev_pmd_thread {
    struct dp_netdev *dp;
    struct ovs_refcount ref_cnt;    /* Every reference must be refcount'ed. */
    struct cmap_node node;          /* In 'dp->poll_threads'. */

    pthread_cond_t cond;            /* For synchronizing pmd thread reload. */
    struct ovs_mutex cond_mutex;    /* Mutex for condition variable. */

    /* Per thread exact-match cache.  Note, the instance for cpu core
     * NON_PMD_CORE_ID can be accessed by multiple threads, and thusly
     * need to be protected (e.g. by 'dp_netdev_mutex').  All other
     * instances will only be accessed by its own pmd thread. */
    struct emc_cache flow_cache;

    /* Classifier and Flow-Table.
     *
     * Writers of 'flow_table' must take the 'flow_mutex'.  Corresponding
     * changes to 'cls' must be made while still holding the 'flow_mutex'.
     */
    struct ovs_mutex flow_mutex;
    struct dpcls cls;
    struct cmap flow_table OVS_GUARDED; /* Flow table. */

    /* Statistics. */
    struct dp_netdev_pmd_stats stats;

    /* Cycles counters */
    struct dp_netdev_pmd_cycles cycles;

    /* Used to count cicles. See 'cycles_counter_end()' */
    unsigned long long last_cycles;

    struct latch exit_latch;        /* For terminating the pmd thread. */
    atomic_uint change_seq;         /* For reloading pmd ports. */
    pthread_t thread;
    int index;                      /* Idx of this pmd thread among pmd*/
                                    /* threads on same numa node. */
    unsigned core_id;               /* CPU core id of this pmd thread. */
    int numa_id;                    /* numa node id of this pmd thread. */
    int tx_qid;                     /* Queue id used by this pmd thread to
                                     * send packets on all netdevs */

    /* Only a pmd thread can write on its own 'cycles' and 'stats'.
     * The main thread keeps 'stats_zero' and 'cycles_zero' as base
     * values and subtracts them from 'stats' and 'cycles' before
     * reporting to the user */
    unsigned long long stats_zero[DP_N_STATS];
    uint64_t cycles_zero[PMD_N_CYCLES];
};

/* Contained by struct dp_netdev_pmd_thread's 'cycle' member.  */
struct dp_netdev_pmd_cycles {
    /* Indexed by PMD_CYCLES_*. */
    atomic_ullong n[PMD_N_CYCLES];
};

/* Contained by struct dp_netdev_pmd_thread's 'stats' member.  */
struct dp_netdev_pmd_stats {
    /* Indexed by DP_STAT_*. */
    atomic_ullong n[DP_N_STATS];
};


enum dp_stat_type {
    DP_STAT_EXACT_HIT,          /* Packets that had an exact match (emc). */
    DP_STAT_MASKED_HIT,         /* Packets that matched in the flow table. */
    DP_STAT_MISS,               /* Packets that did not match. */
    DP_STAT_LOST,               /* Packets not passed up to the client. */
    DP_N_STATS
};

enum pmd_cycles_counter_type {
    PMD_CYCLES_POLLING,         /* Cycles spent polling NICs. */
    PMD_CYCLES_PROCESSING,      /* Cycles spent processing packets */
    PMD_N_CYCLES
};











static void dp_initialize(void)

    tnl_conf_seq = seq_create();
    //注册 dpctl 命令
    dpctl_unixctl_register();
    //tunnel port 初始化
    tnl_port_map_init();
    //tunnel arp cache 初始化
    tnl_arp_cache_init();
    route_table_init();

    //static const struct dpif_class *base_dpif_classes[] = {
    //#if defined(__linux__) || defined(_WIN32)
    //    &dpif_netlink_class,
    //#endif
    //    &dpif_netdev_class,
    //};
    for (i = 0; i < ARRAY_SIZE(base_dpif_classes); i++)
        dp_register_provider(base_dpif_classes[i]);

static int dp_register_provider__(const struct dpif_class *new_class)

    0. 检查 new_class 是否已经加入 dpif_classes 和 dpif_blacklist, 如果加入返回, 否则继续步骤 1
    1. 调用 new_class->init() (实际调用 dpif_netlink_class->init() 和 dpif_netdev_class->init())
    1. 将 new_class 加入 dpif_classes(将 dpif_netdev_class 和 dpif_netlink_class 加入 dpif_class)


###struct dpif_class dpif_netdev_class

static struct shash dp_netdevs : 包含所有的 dp_netdev　的 map(key:name, value:dp_netdev)

static int dpif_netdev_init(void)

    将 dpif-netdev/pmd-stats-show, dpif-netdev/pmd-stats-clear 加入 commands 中

static int dpif_netdev_enumerate(struct sset *all_dps, const struct dpif_class *dpif_class)

    从 dp_netdevs 中找到 class = dpif_class 的 dp_netdev 对象, 保存在 all_dps 中

static const char * dpif_netdev_port_open_type(const struct dpif_class *class, const char *type)

    如果 type=internal, class=dpif_netdev_class 返回 dummy
    如果 type=internal, class!=dpif_netdev_class 返回 tap
    如果 type!=internal, 直接返回 type

static int dpif_netdev_open(const struct dpif_class *class, const char *name, bool create, struct dpif **dpifp)

    检查 name, class 对应的 dp_netdev 是否存在, 如果不存在创建, 如果存在, create = false, 返回 0, 否则返回错误值

    如果 name 在 dp_netdevs 并且 dp->class = class && create = true, 返回 EEXIST
    如果 name 在 dp_netdevs 并且 dp->class = class && create = false,  返回 0
    如果 name 在 dp_netdevs 并且 dp->class != class,  返回 EINVAL
    如果 name 不在 dp_netdevs 并且 create = true,  调用 create_dp_netdev(name, class)
    如果 name 不在 dp_netdevs 并且 create = false, 返回 ENODEV

static void dpif_netdev_close(struct dpif *dpif)

    从 dpif 定位到 dp_netdev 对象 dp, 如果 dp->ref_cnt = 0, 从 dp_netdevs 中删除 dp_netdev, 并释放 dp 内存

static int dpif_netdev_destroy(struct dpif *dpif)


static int dpif_netdev_port_add(struct dpif *dpif, struct netdev *netdev, odp_port_t *port_nop)

    如果 port_nop 不为 NULL 并且已经存在, 返回 EBUSY 或 EEXIST
    如果 port_nop 为 NULL, 不存在, 初始化 port 对象并加入 dp->ports. 名称为 dpif_port, 端口号 port_no. type 为 netdev->type


dp_netdevs 下由很多 dp_netdev. 每一个 dp_netdev 下有一个线程池和端口池.
每个端口属于一个 netdev. 每个端口所属的 netdev 有一个接受队列
每个线程有一个流表缓存池
