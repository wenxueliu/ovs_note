
上次到 ofproto_run(br->ofproto);


##全局变量

static const struct ofproto_class **ofproto_classes //实际只包含 ofproto_dpif_class
static size_t n_ofproto_classes; // ofproto_classes 的数量
static size_t allocated_ofproto_classes;

/* All existing ofproto_backer instances, indexed by ofproto->up.type. */
static struct shash all_dpif_backers = SHASH_INITIALIZER(&all_dpif_backers);

//ofproto.c
/* Initial mappings of port to OpenFlow number mappings. */
static struct shash init_ofp_ports = SHASH_INITIALIZER(&init_ofp_ports);

//ofproto-dpif.c
/* Initial mappings of port to bridge mappings. */
static struct shash init_ofp_ports = SHASH_INITIALIZER(&init_ofp_ports);

/* All existing ofproto_backer instances, indexed by ofproto->up.type. */
static struct shash all_dpif_backers = SHASH_INITIALIZER(&all_dpif_backers);


//ofproto-dpif-rid.c
static struct ovs_mutex mutex;
static struct cmap id_map;
static struct cmap metadata_map;
static struct ovs_list expiring OVS_GUARDED_BY(mutex);
static struct ovs_list expired OVS_GUARDED_BY(mutex);
static uint32_t next_id OVS_GUARDED_BY(mutex); /* Possible next free id. */


/* ofproto class structure, to be defined by each ofproto implementation.
 *
 *
 * Data Structures
 * ===============
 *
 * These functions work primarily with four different kinds of data
 * structures:
 *
 *   - "struct ofproto", which represents an OpenFlow switch.
 *
 *   - "struct ofport", which represents a port within an ofproto.
 *
 *   - "struct rule", which represents an OpenFlow flow within an ofproto.
 *
 *   - "struct ofgroup", which represents an OpenFlow 1.1+ group within an
 *     ofproto.
 *
 * Each of these data structures contains all of the implementation-independent
 * generic state for the respective concept, called the "base" state.  None of
 * them contains any extra space for ofproto implementations to use.  Instead,
 * each implementation is expected to declare its own data structure that
 * contains an instance of the generic data structure plus additional
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
 *            "alloc"       "construct"       "destruct"       "dealloc"
 *            ------------  ----------------  ---------------  --------------
 *   ofproto  ->alloc       ->construct       ->destruct       ->dealloc
 *   ofport   ->port_alloc  ->port_construct  ->port_destruct  ->port_dealloc
 *   rule     ->rule_alloc  ->rule_construct  ->rule_destruct  ->rule_dealloc
 *   group    ->group_alloc ->group_construct ->group_destruct ->group_dealloc
 *
 * "ofproto", "ofport", and "group" have this exact life cycle.  The "rule"
 * data structure also follow this life cycle with some additional elaborations
 * described under "Rule Life Cycle" below.
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
 * Conventions
 * ===========
 *
 * Most of these functions return 0 if they are successful or a positive error
 * code on failure.  Depending on the function, valid error codes are either
 * errno values or OFPERR_* OpenFlow error codes.
 *
 * Most of these functions are expected to execute synchronously, that is, to
 * block as necessary to obtain a result.  Thus, these functions may return
 * EAGAIN (or EWOULDBLOCK or EINPROGRESS) only where the function descriptions
 * explicitly say those errors are a possibility.  We may relax this
 * requirement in the future if and when we encounter performance problems. */

struct ofproto_class {
/* ## ----------------- ## */
/* ## Factory Functions ## */
/* ## ----------------- ## */

    /* Initializes provider.  The caller may pass in 'iface_hints',
     * which contains an shash of "struct iface_hint" elements indexed
     * by the interface's name.  The provider may use these hints to
     * describe the startup configuration in order to reinitialize its
     * state.  The caller owns the provided data, so a provider must
     * make copies of anything required.  An ofproto provider must
     * remove any existing state that is not described by the hint, and
     * may choose to remove it all. */
    void (*init)(const struct shash *iface_hints);

    /* Enumerates the types of all supported ofproto types into 'types'.  The
     * caller has already initialized 'types'.  The implementation should add
     * its own types to 'types' but not remove any existing ones, because other
     * ofproto classes might already have added names to it. */
    void (*enumerate_types)(struct sset *types);

    /* Enumerates the names of all existing datapath of the specified 'type'
     * into 'names' 'all_dps'.  The caller has already initialized 'names' as
     * an empty sset.
     *
     * 'type' is one of the types enumerated by ->enumerate_types().
     *
     * Returns 0 if successful, otherwise a positive errno value.
     */
    int (*enumerate_names)(const char *type, struct sset *names);

    /* Deletes the datapath with the specified 'type' and 'name'.  The caller
     * should have closed any open ofproto with this 'type' and 'name'; this
     * function is allowed to fail if that is not the case.
     *
     * 'type' is one of the types enumerated by ->enumerate_types().
     * 'name' is one of the names enumerated by ->enumerate_names() for 'type'.
     *
     * Returns 0 if successful, otherwise a positive errno value.
     */
    int (*del)(const char *type, const char *name);

    /* Returns the type to pass to netdev_open() when a datapath of type
     * 'datapath_type' has a port of type 'port_type', for a few special
     * cases when a netdev type differs from a port type.  For example,
     * when using the userspace datapath, a port of type "internal"
     * needs to be opened as "tap".
     *
     * Returns either 'type' itself or a string literal, which must not
     * be freed. */
    const char *(*port_open_type)(const char *datapath_type,
                                  const char *port_type);

/* ## ------------------------ ## */
/* ## Top-Level type Functions ## */
/* ## ------------------------ ## */

    /* Performs any periodic activity required on ofprotos of type
     * 'type'.
     *
     * An ofproto provider may implement it or not, depending on whether
     * it needs type-level maintenance.
     *
     * Returns 0 if successful, otherwise a positive errno value. */
    int (*type_run)(const char *type);

    /* Causes the poll loop to wake up when a type 'type''s 'run'
     * function needs to be called, e.g. by calling the timer or fd
     * waiting functions in poll-loop.h.
     *
     * An ofproto provider may implement it or not, depending on whether
     * it needs type-level maintenance. */
    void (*type_wait)(const char *type);

/* ## --------------------------- ## */
/* ## Top-Level ofproto Functions ## */
/* ## --------------------------- ## */

    /* Life-cycle functions for an "ofproto" (see "Life Cycle" above).
     *
     *
     * Construction
     * ============
     *
     * ->construct() should not modify any base members of the ofproto.  The
     * client will initialize the ofproto's 'ports' and 'tables' members after
     * construction is complete.
     *
     * When ->construct() is called, the client does not yet know how many flow
     * tables the datapath supports, so ofproto->n_tables will be 0 and
     * ofproto->tables will be NULL.  ->construct() should call
     * ofproto_init_tables() to allocate and initialize ofproto->n_tables and
     * ofproto->tables.  Each flow table will be initially empty, so
     * ->construct() should delete flows from the underlying datapath, if
     * necessary, rather than populating the tables.
     *
     * If the ofproto knows the maximum port number that the datapath can have,
     * then it can call ofproto_init_max_ports().  If it does so, then the
     * client will ensure that the actions it allows to be used through
     * OpenFlow do not refer to ports above that maximum number.
     *
     * Only one ofproto instance needs to be supported for any given datapath.
     * If a datapath is already open as part of one "ofproto", then another
     * attempt to "construct" the same datapath as part of another ofproto is
     * allowed to fail with an error.
     *
     * ->construct() returns 0 if successful, otherwise a positive errno
     * value.
     *
     *
     * Destruction
     * ===========
     *
     * ->destruct() must also destroy all remaining rules in the ofproto's
     * tables, by passing each remaining rule to ofproto_rule_delete(), then
     * destroy all remaining groups by calling ofproto_group_delete_all().
     *
     * The client will destroy the flow tables themselves after ->destruct()
     * returns.
     */
    struct ofproto *(*alloc)(void);
    int (*construct)(struct ofproto *ofproto);
    void (*destruct)(struct ofproto *ofproto);
    void (*dealloc)(struct ofproto *ofproto);

    /* Performs any periodic activity required by 'ofproto'.  It should:
     *
     *   - Call connmgr_send_packet_in() for each received packet that missed
     *     in the OpenFlow flow table or that had a OFPP_CONTROLLER output
     *     action.
     *
     *   - Call ofproto_rule_expire() for each OpenFlow flow that has reached
     *     its hard_timeout or idle_timeout, to expire the flow.
     *
     * Returns 0 if successful, otherwise a positive errno value. */
    int (*run)(struct ofproto *ofproto);

    /* Causes the poll loop to wake up when 'ofproto''s 'run' function needs to
     * be called, e.g. by calling the timer or fd waiting functions in
     * poll-loop.h.  */
    void (*wait)(struct ofproto *ofproto);

    /* Adds some memory usage statistics for the implementation of 'ofproto'
     * into 'usage', for use with memory_report().
     *
     * This function is optional. */
    void (*get_memory_usage)(const struct ofproto *ofproto,
                             struct simap *usage);

    /* Adds some memory usage statistics for the implementation of 'type'
     * into 'usage', for use with memory_report().
     *
     * This function is optional. */
    void (*type_get_memory_usage)(const char *type, struct simap *usage);

    /* Every "struct rule" in 'ofproto' is about to be deleted, one by one.
     * This function may prepare for that, for example by clearing state in
     * advance.  It should *not* actually delete any "struct rule"s from
     * 'ofproto', only prepare for it.
     *
     * This function is optional; it's really just for optimization in case
     * it's cheaper to delete all the flows from your hardware in a single pass
     * than to do it one by one. */
    void (*flush)(struct ofproto *ofproto);

    /* Helper for the OpenFlow OFPT_TABLE_FEATURES request.
     *
     * The 'features' array contains 'ofproto->n_tables' elements.  Each
     * element is initialized as:
     *
     *   - 'table_id' to the array index.
     *
     *   - 'name' to "table#" where # is the table ID.
     *
     *   - 'metadata_match' and 'metadata_write' to OVS_BE64_MAX.
     *
     *   - 'config' to the table miss configuration.
     *
     *   - 'max_entries' to 1,000,000.
     *
     *   - Both 'nonmiss' and 'miss' to:
     *
     *     * 'next' to all 1-bits for all later tables.
     *
     *     * 'instructions' to all instructions.
     *
     *     * 'write' and 'apply' both to:
     *
     *       - 'ofpacts': All actions.
     *
     *       - 'set_fields': All fields.
     *
     *   - 'match', 'mask', and 'wildcard' to all fields.
     *
     * If 'stats' is nonnull, it also contains 'ofproto->n_tables' elements.
     * Each element is initialized as:
     *
     *   - 'table_id' to the array index.
     *
     *   - 'active_count' to the 'n_flows' of struct ofproto for the table.
     *
     *   - 'lookup_count' and 'matched_count' to 0.
     *
     * The implementation should update any members in each element for which
     * it has better values:
     *
     *   - Any member of 'features' to better describe the implementation's
     *     capabilities.
     *
     *   - 'lookup_count' to the number of packets looked up in this flow table
     *     so far.
     *
     *   - 'matched_count' to the number of packets looked up in this flow
     *     table so far that matched one of the flow entries.
     */
    void (*query_tables)(struct ofproto *ofproto,
                         struct ofputil_table_features *features,
                         struct ofputil_table_stats *stats);

    /* Sets the current tables version the provider should use for classifier
     * lookups. */
    void (*set_tables_version)(struct ofproto *ofproto, cls_version_t version);
/* ## ---------------- ## */
/* ## ofport Functions ## */
/* ## ---------------- ## */

    /* Life-cycle functions for a "struct ofport" (see "Life Cycle" above).
     *
     * ->port_construct() should not modify any base members of the ofport.
     * An ofproto implementation should use the 'ofp_port' member of
     * "struct ofport" as the OpenFlow port number.
     *
     * ofports are managed by the base ofproto code.  The ofproto
     * implementation should only create and destroy them in response to calls
     * to these functions.  The base ofproto code will create and destroy
     * ofports in the following situations:
     *
     *   - Just after the ->construct() function is called, the base ofproto
     *     iterates over all of the implementation's ports, using
     *     ->port_dump_start() and related functions, and constructs an ofport
     *     for each dumped port.
     *
     *   - If ->port_poll() reports that a specific port has changed, then the
     *     base ofproto will query that port with ->port_query_by_name() and
     *     construct or destruct ofports as necessary to reflect the updated
     *     set of ports.
     *
     *   - If ->port_poll() returns ENOBUFS to report an unspecified port set
     *     change, then the base ofproto will iterate over all of the
     *     implementation's ports, in the same way as at ofproto
     *     initialization, and construct and destruct ofports to reflect all of
     *     the changes.
     *
     * ->port_construct() returns 0 if successful, otherwise a positive errno
     * value.
     */
    struct ofport *(*port_alloc)(void);
    int (*port_construct)(struct ofport *ofport);
    void (*port_destruct)(struct ofport *ofport);
    void (*port_dealloc)(struct ofport *ofport);

    /* Called after 'ofport->netdev' is replaced by a new netdev object.  If
     * the ofproto implementation uses the ofport's netdev internally, then it
     * should switch to using the new one.  The old one has been closed.
     *
     * An ofproto implementation that doesn't need to do anything in this
     * function may use a null pointer. */
    void (*port_modified)(struct ofport *ofport);

    /* Called after an OpenFlow request changes a port's configuration.
     * 'ofport->pp.config' contains the new configuration.  'old_config'
     * contains the previous configuration.
     *
     * The caller implements OFPUTIL_PC_PORT_DOWN using netdev functions to
     * turn NETDEV_UP on and off, so this function doesn't have to do anything
     * for that bit (and it won't be called if that is the only bit that
     * changes). */
    void (*port_reconfigured)(struct ofport *ofport,
                              enum ofputil_port_config old_config);

    /* Looks up a port named 'devname' in 'ofproto'.  On success, returns 0 and
     * initializes '*port' appropriately. Otherwise, returns a positive errno
     * value.
     *
     * The caller owns the data in 'port' and must free it with
     * ofproto_port_destroy() when it is no longer needed. */
    int (*port_query_by_name)(const struct ofproto *ofproto,
                              const char *devname, struct ofproto_port *port);

    /* Attempts to add 'netdev' as a port on 'ofproto'.  Returns 0 if
     * successful, otherwise a positive errno value.  The caller should
     * inform the implementation of the OpenFlow port through the
     * ->port_construct() method.
     *
     * It doesn't matter whether the new port will be returned by a later call
     * to ->port_poll(); the implementation may do whatever is more
     * convenient. */
    int (*port_add)(struct ofproto *ofproto, struct netdev *netdev);

    /* Deletes port number 'ofp_port' from the datapath for 'ofproto'.  Returns
     * 0 if successful, otherwise a positive errno value.
     *
     * It doesn't matter whether the new port will be returned by a later call
     * to ->port_poll(); the implementation may do whatever is more
     * convenient. */
    int (*port_del)(struct ofproto *ofproto, ofp_port_t ofp_port);

    /* Get port stats */
    int (*port_get_stats)(const struct ofport *port,
                          struct netdev_stats *stats);

    /* Port iteration functions.
     *
     * The client might not be entirely in control of the ports within an
     * ofproto.  Some hardware implementations, for example, might have a fixed
     * set of ports in a datapath.  For this reason, the client needs a way to
     * iterate through all the ports that are actually in a datapath.  These
     * functions provide that functionality.
     *
     * The 'state' pointer provides the implementation a place to
     * keep track of its position.  Its format is opaque to the caller.
     *
     * The ofproto provider retains ownership of the data that it stores into
     * ->port_dump_next()'s 'port' argument.  The data must remain valid until
     * at least the next call to ->port_dump_next() or ->port_dump_done() for
     * 'state'.  The caller will not modify or free it.
     *
     * Details
     * =======
     *
     * ->port_dump_start() attempts to begin dumping the ports in 'ofproto'.
     * On success, it should return 0 and initialize '*statep' with any data
     * needed for iteration.  On failure, returns a positive errno value, and
     * the client will not call ->port_dump_next() or ->port_dump_done().
     *
     * ->port_dump_next() attempts to retrieve another port from 'ofproto' for
     * 'state'.  If there is another port, it should store the port's
     * information into 'port' and return 0.  It should return EOF if all ports
     * have already been iterated.  Otherwise, on error, it should return a
     * positive errno value.  This function will not be called again once it
     * returns nonzero once for a given iteration (but the 'port_dump_done'
     * function will be called afterward).
     *
     * ->port_dump_done() allows the implementation to release resources used
     * for iteration.  The caller might decide to stop iteration in the middle
     * by calling this function before ->port_dump_next() returns nonzero.
     *
     * Usage Example
     * =============
     *
     * int error;
     * void *state;
     *
     * error = ofproto->ofproto_class->port_dump_start(ofproto, &state);
     * if (!error) {
     *     for (;;) {
     *         struct ofproto_port port;
     *
     *         error = ofproto->ofproto_class->port_dump_next(
     *                     ofproto, state, &port);
     *         if (error) {
     *             break;
     *         }
     *         // Do something with 'port' here (without modifying or freeing
     *         // any of its data).
     *     }
     *     ofproto->ofproto_class->port_dump_done(ofproto, state);
     * }
     * // 'error' is now EOF (success) or a positive errno value (failure).
     */
    int (*port_dump_start)(const struct ofproto *ofproto, void **statep);
    int (*port_dump_next)(const struct ofproto *ofproto, void *state,
                          struct ofproto_port *port);
    int (*port_dump_done)(const struct ofproto *ofproto, void *state);

    /* Polls for changes in the set of ports in 'ofproto'.  If the set of ports
     * in 'ofproto' has changed, then this function should do one of the
     * following:
     *
     * - Preferably: store the name of the device that was added to or deleted
     *   from 'ofproto' in '*devnamep' and return 0.  The caller is responsible
     *   for freeing '*devnamep' (with free()) when it no longer needs it.
     *
     * - Alternatively: return ENOBUFS, without indicating the device that was
     *   added or deleted.
     *
     * Occasional 'false positives', in which the function returns 0 while
     * indicating a device that was not actually added or deleted or returns
     * ENOBUFS without any change, are acceptable.
     *
     * The purpose of 'port_poll' is to let 'ofproto' know about changes made
     * externally to the 'ofproto' object, e.g. by a system administrator via
     * ovs-dpctl.  Therefore, it's OK, and even preferable, for port_poll() to
     * not report changes made through calls to 'port_add' or 'port_del' on the
     * same 'ofproto' object.  (But it's OK for it to report them too, just
     * slightly less efficient.)
     *
     * If the set of ports in 'ofproto' has not changed, returns EAGAIN.  May
     * also return other positive errno values to indicate that something has
     * gone wrong.
     *
     * If the set of ports in a datapath is fixed, or if the only way that the
     * set of ports in a datapath can change is through ->port_add() and
     * ->port_del(), then this function may be a null pointer.
     */
    int (*port_poll)(const struct ofproto *ofproto, char **devnamep);

    /* Arranges for the poll loop to wake up when ->port_poll() will return a
     * value other than EAGAIN.
     *
     * If the set of ports in a datapath is fixed, or if the only way that the
     * set of ports in a datapath can change is through ->port_add() and
     * ->port_del(), or if the poll loop will always wake up anyway when
     * ->port_poll() will return a value other than EAGAIN, then this function
     * may be a null pointer.
     */
    void (*port_poll_wait)(const struct ofproto *ofproto);

    /* Checks the status of LACP negotiation for 'port'.  Returns 1 if LACP
     * partner information for 'port' is up-to-date, 0 if LACP partner
     * information is not current (generally indicating a connectivity
     * problem), or -1 if LACP is not enabled on 'port'.
     *
     * This function may be a null pointer if the ofproto implementation does
     * not support LACP.
     */
    int (*port_is_lacp_current)(const struct ofport *port);

    /* Get LACP port stats. Returns -1 if LACP is not enabled on 'port'.
     *
     * This function may be a null pointer if the ofproto implementation does
     * not support LACP.
     */
    int (*port_get_lacp_stats)(const struct ofport *port,
                               struct lacp_slave_stats *stats);

/* ## ----------------------- ## */
/* ## OpenFlow Rule Functions ## */
/* ## ----------------------- ## */

    /* Chooses an appropriate table for 'match' within 'ofproto'.  On
     * success, stores the table ID into '*table_idp' and returns 0.  On
     * failure, returns an OpenFlow error code.
     *
     * The choice of table should be a function of 'match' and 'ofproto''s
     * datapath capabilities.  It should not depend on the flows already in
     * 'ofproto''s flow tables.  Failure implies that an OpenFlow rule with
     * 'match' as its matching condition can never be inserted into 'ofproto',
     * even starting from an empty flow table.
     *
     * If multiple tables are candidates for inserting the flow, the function
     * should choose one arbitrarily (but deterministically).
     *
     * If this function is NULL then table 0 is always chosen. */
    enum ofperr (*rule_choose_table)(const struct ofproto *ofproto,
                                     const struct match *match,
                                     uint8_t *table_idp);

    /* Life-cycle functions for a "struct rule".
     *
     *
     * Rule Life Cycle
     * ===============
     *
     * The life cycle of a struct rule is an elaboration of the basic life
     * cycle described above under "Life Cycle".
     *
     * After a rule is successfully constructed, it is then inserted.  If
     * insertion is successful, then before it is later destructed, it is
     * deleted.
     *
     * You can think of a rule as having the following extra steps inserted
     * between "Life Cycle" steps 4 and 5:
     *
     *   4.1. The client inserts the rule into the flow table, making it
     *        visible in flow table lookups.
     *
     *   4.2. The client calls "rule_insert" to insert the flow.  The
     *        implementation attempts to install the flow in the underlying
     *        hardware and returns an error code indicate success or failure.
     *        On failure, go to step 5.
     *
     *   4.3. The rule is now installed in the flow table.  Eventually it will
     *        be deleted.
     *
     *   4.4. The client removes the rule from the flow table.  It is no longer
     *        visible in flow table lookups.
     *
     *   4.5. The client calls "rule_delete".  The implementation uninstalls
     *        the flow from the underlying hardware.  Deletion is not allowed
     *        to fail.
     *
     *
     * Construction
     * ============
     *
     * When ->rule_construct() is called, 'rule' is a new rule that is not yet
     * inserted into a flow table.  ->rule_construct() should initialize enough
     * of the rule's derived state for 'rule' to be suitable for inserting into
     * a flow table.  ->rule_construct() should not modify any base members of
     * struct rule.
     *
     * If ->rule_construct() fails (as indicated by returning a nonzero
     * OpenFlow error code), the ofproto base code will uninitialize and
     * deallocate 'rule'.  See "Rule Life Cycle" above for more details.
     *
     * ->rule_construct() must also:
     *
     *   - Validate that the datapath supports the matching rule in 'rule->cr'
     *     datapath.  For example, if the rule's table does not support
     *     registers, then it is an error if 'rule->cr' does not wildcard all
     *     registers.
     *
     *   - Validate that the datapath can correctly implement 'rule->ofpacts'.
     *
     * After a successful construction the rest of the rule life cycle calls
     * may not fail, so ->rule_construct() must also make sure that the rule
     * can be inserted in to the datapath.
     *
     *
     * Insertion
     * =========
     *
     * Following successful construction, the ofproto base case inserts 'rule'
     * into its flow table, then it calls ->rule_insert().  ->rule_insert()
     * must add the new rule to the datapath flow table and return only after
     * this is complete.  The 'new_rule' may be a duplicate of an 'old_rule'.
     * In this case the 'old_rule' is non-null, and the implementation should
     * forward rule statistics from the 'old_rule' to the 'new_rule' if
     * 'forward_stats' is 'true'.  This may not fail.
     *
     *
     * Deletion
     * ========
     *
     * The ofproto base code removes 'rule' from its flow table before it calls
     * ->rule_delete().  ->rule_delete() must remove 'rule' from the datapath
     * flow table and return only after this has completed successfully.
     *
     * Rule deletion must not fail.
     *
     *
     * Destruction
     * ===========
     *
     * ->rule_destruct() must uninitialize derived state.
     *
     * Rule destruction must not fail. */
    struct rule *(*rule_alloc)(void);
    enum ofperr (*rule_construct)(struct rule *rule)
        /* OVS_REQUIRES(ofproto_mutex) */;
    void (*rule_insert)(struct rule *rule, struct rule *old_rule,
                        bool forward_stats)
        /* OVS_REQUIRES(ofproto_mutex) */;
    void (*rule_delete)(struct rule *rule) /* OVS_REQUIRES(ofproto_mutex) */;
    void (*rule_destruct)(struct rule *rule);
    void (*rule_dealloc)(struct rule *rule);

    /* Obtains statistics for 'rule', storing the number of packets that have
     * matched it in '*packet_count' and the number of bytes in those packets
     * in '*byte_count'.  UINT64_MAX indicates that the packet count or byte
     * count is unknown. */
    void (*rule_get_stats)(struct rule *rule, uint64_t *packet_count,
                           uint64_t *byte_count, long long int *used)
        /* OVS_EXCLUDED(ofproto_mutex) */;

    /* Applies the actions in 'rule' to 'packet'.  (This implements sending
     * buffered packets for OpenFlow OFPT_FLOW_MOD commands.)
     *
     * Takes ownership of 'packet' (so it should eventually free it, with
     * ofpbuf_delete()).
     *
     * 'flow' reflects the flow information for 'packet'.  All of the
     * information in 'flow' is extracted from 'packet', except for
     * flow->tunnel and flow->in_port, which are assigned the correct values
     * for the incoming packet.  The register values are zeroed.  'packet''s
     * header pointers and offsets (e.g. packet->l3) are appropriately
     * initialized.  packet->l3 is aligned on a 32-bit boundary.
     *
     * The implementation should add the statistics for 'packet' into 'rule'.
     *
     * Returns 0 if successful, otherwise an OpenFlow error code. */
    enum ofperr (*rule_execute)(struct rule *rule, const struct flow *flow,
                                struct dp_packet *packet);

    /* Changes the OpenFlow IP fragment handling policy to 'frag_handling',
     * which takes one of the following values, with the corresponding
     * meanings:
     *
     *  - OFPC_FRAG_NORMAL: The switch should treat IP fragments the same way
     *    as other packets, omitting TCP and UDP port numbers (always setting
     *    them to 0).
     *
     *  - OFPC_FRAG_DROP: The switch should drop all IP fragments without
     *    passing them through the flow table.
     *
     *  - OFPC_FRAG_REASM: The switch should reassemble IP fragments before
     *    passing packets through the flow table.
     *
     *  - OFPC_FRAG_NX_MATCH (a Nicira extension): Similar to OFPC_FRAG_NORMAL,
     *    except that TCP and UDP port numbers should be included in fragments
     *    with offset 0.
     *
     * Implementations are not required to support every mode.
     * OFPC_FRAG_NORMAL is the default mode when an ofproto is created.
     *
     * At the time of the call to ->set_frag_handling(), the current mode is
     * available in 'ofproto->frag_handling'.  ->set_frag_handling() returns
     * true if the requested mode was set, false if it is not supported.
     *
     * Upon successful return, the caller changes 'ofproto->frag_handling' to
     * reflect the new mode.
     */
    bool (*set_frag_handling)(struct ofproto *ofproto,
                              enum ofp_config_flags frag_handling);

    /* Implements the OpenFlow OFPT_PACKET_OUT command.  The datapath should
     * execute the 'ofpacts_len' bytes of "struct ofpacts" in 'ofpacts'.
     *
     * The caller retains ownership of 'packet' and of 'ofpacts', so
     * ->packet_out() should not modify or free them.
     *
     * This function must validate that it can correctly implement 'ofpacts'.
     * If not, then it should return an OpenFlow error code.
     *
     * 'flow' reflects the flow information for 'packet'.  All of the
     * information in 'flow' is extracted from 'packet', except for
     * flow->in_port (see below).  flow->tunnel and its register values are
     * zeroed.
     *
     * flow->in_port comes from the OpenFlow OFPT_PACKET_OUT message.  The
     * implementation should reject invalid flow->in_port values by returning
     * OFPERR_OFPBRC_BAD_PORT.  (If the implementation called
     * ofproto_init_max_ports(), then the client will reject these ports
     * itself.)  For consistency, the implementation should consider valid for
     * flow->in_port any value that could possibly be seen in a packet that it
     * passes to connmgr_send_packet_in().  Ideally, even an implementation
     * that never generates packet-ins (e.g. due to hardware limitations)
     * should still allow flow->in_port values for every possible physical port
     * and OFPP_LOCAL.  The only virtual ports (those above OFPP_MAX) that the
     * caller will ever pass in as flow->in_port, other than OFPP_LOCAL, are
     * OFPP_NONE and OFPP_CONTROLLER.  The implementation should allow both of
     * these, treating each of them as packets generated by the controller as
     * opposed to packets originating from some switch port.
     *
     * (Ordinarily the only effect of flow->in_port is on output actions that
     * involve the input port, such as actions that output to OFPP_IN_PORT,
     * OFPP_FLOOD, or OFPP_ALL.  flow->in_port can also affect Nicira extension
     * "resubmit" actions.)
     *
     * 'packet' is not matched against the OpenFlow flow table, so its
     * statistics should not be included in OpenFlow flow statistics.
     *
     * Returns 0 if successful, otherwise an OpenFlow error code. */
    enum ofperr (*packet_out)(struct ofproto *ofproto, struct dp_packet *packet,
                              const struct flow *flow,
                              const struct ofpact *ofpacts,
                              size_t ofpacts_len);

/* ## ------------------------- ## */
/* ## OFPP_NORMAL configuration ## */
/* ## ------------------------- ## */

    /* Configures NetFlow on 'ofproto' according to the options in
     * 'netflow_options', or turns off NetFlow if 'netflow_options' is NULL.
     *
     * EOPNOTSUPP as a return value indicates that 'ofproto' does not support
     * NetFlow, as does a null pointer. */
    int (*set_netflow)(struct ofproto *ofproto,
                       const struct netflow_options *netflow_options);

    void (*get_netflow_ids)(const struct ofproto *ofproto,
                            uint8_t *engine_type, uint8_t *engine_id);

    /* Configures sFlow on 'ofproto' according to the options in
     * 'sflow_options', or turns off sFlow if 'sflow_options' is NULL.
     *
     * EOPNOTSUPP as a return value indicates that 'ofproto' does not support
     * sFlow, as does a null pointer. */
    int (*set_sflow)(struct ofproto *ofproto,
                     const struct ofproto_sflow_options *sflow_options);

    /* Configures IPFIX on 'ofproto' according to the options in
     * 'bridge_exporter_options' and the 'flow_exporters_options'
     * array, or turns off IPFIX if 'bridge_exporter_options' and
     * 'flow_exporters_options' is NULL.
     *
     * EOPNOTSUPP as a return value indicates that 'ofproto' does not support
     * IPFIX, as does a null pointer. */
    int (*set_ipfix)(
        struct ofproto *ofproto,
        const struct ofproto_ipfix_bridge_exporter_options
            *bridge_exporter_options,
        const struct ofproto_ipfix_flow_exporter_options
            *flow_exporters_options, size_t n_flow_exporters_options);

    /* Configures connectivity fault management on 'ofport'.
     *
     * If 'cfm_settings' is nonnull, configures CFM according to its members.
     *
     * If 'cfm_settings' is null, removes any connectivity fault management
     * configuration from 'ofport'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support CFM, as does a null pointer. */
    int (*set_cfm)(struct ofport *ofport, const struct cfm_settings *s);

    /* Checks the status change of CFM on 'ofport'.  Returns true if
     * there is status change since last call or if CFM is not specified. */
    bool (*cfm_status_changed)(struct ofport *ofport);

    /* Populates 'smap' with the status of CFM on 'ofport'.  Returns 0 on
     * success, or a positive errno.  EOPNOTSUPP as a return value indicates
     * that this ofproto_class does not support CFM, as does a null pointer.
     *
     * The caller must provide and own '*status', and it must free the array
     * returned in 'status->rmps'.  '*status' is indeterminate if the return
     * value is non-zero. */
    int (*get_cfm_status)(const struct ofport *ofport,
                          struct cfm_status *status);

    /* Configures LLDP on 'ofport'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support LLDP, as does a null pointer. */
    int (*set_lldp)(struct ofport *ofport, const struct smap *cfg);

    /* Checks the status of LLDP configured on 'ofport'.  Returns true if the
     * port's LLDP status was successfully stored into '*status'.  Returns
     * false if the port did not have LLDP configured, in which case '*status'
     * is indeterminate.
     *
     * The caller must provide and own '*status'.  '*status' is indeterminate
     * if the return value is non-zero. */
    bool (*get_lldp_status)(const struct ofport *ofport,
                            struct lldp_status *status);

    /* Configures Auto Attach.
     *
     * If 's' is nonnull, configures Auto Attach according to its members.
     *
     * If 's' is null, removes any Auto Attach configuration.
     */
    int (*set_aa)(struct ofproto *ofproto,
                  const struct aa_settings *s);

    /* If 's' is nonnull, this function registers a mapping associated with
     * client data pointer 'aux' in 'ofproto'.  If 'aux' is already registered
     * then this function updates its configuration to 's'.  Otherwise, this
     * function registers a new mapping.
     *
     * An implementation that does not support mapping at all may set
     * it to NULL or return EOPNOTSUPP.  An implementation that supports
     * only a subset of the functionality should implement what it can
     * and return 0.
     */
    int (*aa_mapping_set)(struct ofproto *ofproto, void *aux,
                          const struct aa_mapping_settings *s);

    /* If 's' is nonnull, this function unregisters a mapping associated with
     * client data pointer 'aux' in 'ofproto'.  If 'aux' is already registered
     * then this function updates its configuration to 's'.  Otherwise, this
     * function unregisters a new mapping.
     *
     * An implementation that does not support mapping at all may set
     * it to NULL or return EOPNOTSUPP.  An implementation that supports
     * only a subset of the functionality should implement what it can
     * and return 0.
     */
    int (*aa_mapping_unset)(struct ofproto *ofproto, void *aux);

    /*
     * Returns the a list of AutoAttach VLAN operations.  When Auto Attach is
     * enabled, the VLAN associated with an I-SID/VLAN mapping is first
     * negotiated with an Auto Attach Server.  Once an I-SID VLAN mapping
     * becomes active, the corresponding VLAN needs to be communicated to the
     * bridge in order to add the VLAN to the trunk port linking the Auto
     * Attach Client (in this case openvswitch) and the Auto Attach Server.
     *
     * The list entries are of type "struct bridge_aa_vlan".  Each entry
     * specifies the operation (add or remove), the interface on which to
     * execute the operation and the VLAN.
     */
    int (*aa_vlan_get_queued)(struct ofproto *ofproto, struct ovs_list *list);

    /*
     * Returns the current number of entries in the list of VLAN operations
     * in the Auto Attach Client (see previous function description
     * aa_vlan_get_queued).  Returns 0 if Auto Attach is disabled.
     */
    unsigned int (*aa_vlan_get_queue_size)(struct ofproto *ofproto);

    /* Configures BFD on 'ofport'.
     *
     * If 'cfg' is NULL, or 'cfg' does not contain the key value pair
     * "enable=true", removes BFD from 'ofport'.  Otherwise, configures BFD
     * according to 'cfg'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support BFD, as does a null pointer. */
    int (*set_bfd)(struct ofport *ofport, const struct smap *cfg);

    /* Checks the status change of BFD on 'ofport'.  Returns true if there
     * is status change since last call or if BFD is not specified. */
    bool (*bfd_status_changed)(struct ofport *ofport);

    /* Populates 'smap' with the status of BFD on 'ofport'.  Returns 0 on
     * success, or a positive errno.  EOPNOTSUPP as a return value indicates
     * that this ofproto_class does not support BFD, as does a null pointer. */
    int (*get_bfd_status)(struct ofport *ofport, struct smap *smap);

    /* Configures spanning tree protocol (STP) on 'ofproto' using the
     * settings defined in 's'.
     *
     * If 's' is nonnull, configures STP according to its members.
     *
     * If 's' is null, removes any STP configuration from 'ofproto'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support STP, as does a null pointer. */
    int (*set_stp)(struct ofproto *ofproto,
                   const struct ofproto_stp_settings *s);

    /* Retrieves state of spanning tree protocol (STP) on 'ofproto'.
     *
     * Stores STP state for 'ofproto' in 's'.  If the 'enabled' member
     * is false, the other member values are not meaningful.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support STP, as does a null pointer. */
    int (*get_stp_status)(struct ofproto *ofproto,
                          struct ofproto_stp_status *s);

    /* Configures spanning tree protocol (STP) on 'ofport' using the
     * settings defined in 's'.
     *
     * If 's' is nonnull, configures STP according to its members.  The
     * caller is responsible for assigning STP port numbers (using the
     * 'port_num' member in the range of 1 through 255, inclusive) and
     * ensuring there are no duplicates.
     *
     * If 's' is null, removes any STP configuration from 'ofport'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support STP, as does a null pointer. */
    int (*set_stp_port)(struct ofport *ofport,
                        const struct ofproto_port_stp_settings *s);

    /* Retrieves spanning tree protocol (STP) port status of 'ofport'.
     *
     * Stores STP state for 'ofport' in 's'.  If the 'enabled' member is
     * false, the other member values are not meaningful.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support STP, as does a null pointer. */
    int (*get_stp_port_status)(struct ofport *ofport,
                               struct ofproto_port_stp_status *s);

    /* Retrieves spanning tree protocol (STP) port statistics of 'ofport'.
     *
     * Stores STP state for 'ofport' in 's'.  If the 'enabled' member is
     * false, the other member values are not meaningful.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support STP, as does a null pointer. */
    int (*get_stp_port_stats)(struct ofport *ofport,
                              struct ofproto_port_stp_stats *s);

    /* Configures Rapid Spanning Tree Protocol (RSTP) on 'ofproto' using the
     * settings defined in 's'.
     *
     * If 's' is nonnull, configures RSTP according to its members.
     *
     * If 's' is null, removes any RSTP configuration from 'ofproto'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support RSTP, as does a null pointer. */
    void (*set_rstp)(struct ofproto *ofproto,
                    const struct ofproto_rstp_settings *s);

    /* Retrieves state of Rapid Spanning Tree Protocol (RSTP) on 'ofproto'.
     *
     * Stores RSTP state for 'ofproto' in 's'.  If the 'enabled' member
     * is false, the other member values are not meaningful.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support RSTP, as does a null pointer. */
    void (*get_rstp_status)(struct ofproto *ofproto,
                           struct ofproto_rstp_status *s);

    /* Configures Rapid Spanning Tree Protocol (RSTP) on 'ofport' using the
     * settings defined in 's'.
     *
     * If 's' is nonnull, configures RSTP according to its members.  The
     * caller is responsible for assigning RSTP port numbers (using the
     * 'port_num' member in the range of 1 through 255, inclusive) and
     * ensuring there are no duplicates.
     *
     * If 's' is null, removes any RSTP configuration from 'ofport'.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support STP, as does a null pointer. */
    void (*set_rstp_port)(struct ofport *ofport,
                         const struct ofproto_port_rstp_settings *s);

    /* Retrieves Rapid Spanning Tree Protocol (RSTP) port status of 'ofport'.
     *
     * Stores RSTP state for 'ofport' in 's'.  If the 'enabled' member is
     * false, the other member values are not meaningful.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support RSTP, as does a null pointer. */
    void (*get_rstp_port_status)(struct ofport *ofport,
                                struct ofproto_port_rstp_status *s);

    /* Registers meta-data associated with the 'n_qdscp' Qualities of Service
     * 'queues' attached to 'ofport'.  This data is not intended to be
     * sufficient to implement QoS.  Instead, providers may use this
     * information to implement features which require knowledge of what queues
     * exist on a port, and some basic information about them.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support QoS, as does a null pointer. */
    int (*set_queues)(struct ofport *ofport,
                      const struct ofproto_port_queue *queues, size_t n_qdscp);

    /* If 's' is nonnull, this function registers a "bundle" associated with
     * client data pointer 'aux' in 'ofproto'.  A bundle is the same concept as
     * a Port in OVSDB, that is, it consists of one or more "slave" devices
     * (Interfaces, in OVSDB) along with VLAN and LACP configuration and, if
     * there is more than one slave, a bonding configuration.  If 'aux' is
     * already registered then this function updates its configuration to 's'.
     * Otherwise, this function registers a new bundle.
     *
     * If 's' is NULL, this function unregisters the bundle registered on
     * 'ofproto' associated with client data pointer 'aux'.  If no such bundle
     * has been registered, this has no effect.
     *
     * This function affects only the behavior of the NXAST_AUTOPATH action and
     * output to the OFPP_NORMAL port.  An implementation that does not support
     * it at all may set it to NULL or return EOPNOTSUPP.  An implementation
     * that supports only a subset of the functionality should implement what
     * it can and return 0. */
    int (*bundle_set)(struct ofproto *ofproto, void *aux,
                      const struct ofproto_bundle_settings *s);

    /* If 'port' is part of any bundle, removes it from that bundle.  If the
     * bundle now has no ports, deletes the bundle.  If the bundle now has only
     * one port, deconfigures the bundle's bonding configuration. */
    void (*bundle_remove)(struct ofport *ofport);

    /* If 's' is nonnull, this function registers a mirror associated with
     * client data pointer 'aux' in 'ofproto'.  A mirror is the same concept as
     * a Mirror in OVSDB.  If 'aux' is already registered then this function
     * updates its configuration to 's'.  Otherwise, this function registers a
     * new mirror.
     *
     * If 's' is NULL, this function unregisters the mirror registered on
     * 'ofproto' associated with client data pointer 'aux'.  If no such mirror
     * has been registered, this has no effect.
     *
     * An implementation that does not support mirroring at all may set
     * it to NULL or return EOPNOTSUPP.  An implementation that supports
     * only a subset of the functionality should implement what it can
     * and return 0. */
    int (*mirror_set)(struct ofproto *ofproto, void *aux,
                      const struct ofproto_mirror_settings *s);

    /* Retrieves statistics from mirror associated with client data
     * pointer 'aux' in 'ofproto'.  Stores packet and byte counts in
     * 'packets' and 'bytes', respectively.  If a particular counter is
     * not supported, the appropriate argument is set to UINT64_MAX.
     *
     * EOPNOTSUPP as a return value indicates that this ofproto_class does not
     * support retrieving mirror statistics. */
    int (*mirror_get_stats)(struct ofproto *ofproto, void *aux,
                            uint64_t *packets, uint64_t *bytes);

    /* Configures the VLANs whose bits are set to 1 in 'flood_vlans' as VLANs
     * on which all packets are flooded, instead of using MAC learning.  If
     * 'flood_vlans' is NULL, then MAC learning applies to all VLANs.
     *
     * This function affects only the behavior of the OFPP_NORMAL action.  An
     * implementation that does not support it may set it to NULL or return
     * EOPNOTSUPP. */
    int (*set_flood_vlans)(struct ofproto *ofproto,
                           unsigned long *flood_vlans);

    /* Returns true if 'aux' is a registered bundle that is currently in use as
     * the output for a mirror. */
    bool (*is_mirror_output_bundle)(const struct ofproto *ofproto, void *aux);

    /* When the configuration option of forward_bpdu changes, this function
     * will be invoked. */
    void (*forward_bpdu_changed)(struct ofproto *ofproto);

    /* Sets the MAC aging timeout for the OFPP_NORMAL action to 'idle_time', in
     * seconds, and the maximum number of MAC table entries to
     * 'max_entries'.
     *
     * An implementation that doesn't support configuring these features may
     * set this function to NULL or implement it as a no-op. */
    void (*set_mac_table_config)(struct ofproto *ofproto,
                                 unsigned int idle_time, size_t max_entries);

    /* Configures multicast snooping on 'ofport' using the settings
     * defined in 's'.
     *
     * If 's' is nonnull, this function updates multicast snooping
     * configuration to 's' in 'ofproto'.
     *
     * If 's' is NULL, this function disables multicast snooping
     * on 'ofproto'.
     *
     * An implementation that does not support multicast snooping may set
     * it to NULL or return EOPNOTSUPP. */
    int (*set_mcast_snooping)(struct ofproto *ofproto,
                              const struct ofproto_mcast_snooping_settings *s);

    /* Configures multicast snooping port's flood setting on 'ofproto'.
     *
     * If 's' is nonnull, this function updates multicast snooping
     * configuration to 's' in 'ofproto'.
     *
     * If 's' is NULL, this function doesn't change anything.
     *
     * An implementation that does not support multicast snooping may set
     * it to NULL or return EOPNOTSUPP. */
    int (*set_mcast_snooping_port)(struct ofproto *ofproto_, void *aux,
                          const struct ofproto_mcast_snooping_port_settings *s);

/* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
 *
 * This is deprecated.  It is only for compatibility with broken device drivers
 * in old versions of Linux that do not properly support VLANs when VLAN
 * devices are not used.  When broken device drivers are no longer in
 * widespread use, we will delete these interfaces. */

    /* If 'realdev_ofp_port' is nonzero, then this function configures 'ofport'
     * as a VLAN splinter port for VLAN 'vid', associated with the real device
     * that has OpenFlow port number 'realdev_ofp_port'.
     *
     * If 'realdev_ofp_port' is zero, then this function deconfigures 'ofport'
     * as a VLAN splinter port.
     *
     * This function should be NULL if an implementation does not support it.
     */
    int (*set_realdev)(struct ofport *ofport,
                       ofp_port_t realdev_ofp_port, int vid);

/* ## ------------------------ ## */
/* ## OpenFlow meter functions ## */
/* ## ------------------------ ## */

    /* These functions should be NULL if an implementation does not support
     * them.  They must be all null or all non-null.. */

    /* Initializes 'features' to describe the metering features supported by
     * 'ofproto'. */
    void (*meter_get_features)(const struct ofproto *ofproto,
                               struct ofputil_meter_features *features);

    /* If '*id' is UINT32_MAX, adds a new meter with the given 'config'.  On
     * success the function must store a provider meter ID other than
     * UINT32_MAX in '*id'.  All further references to the meter will be made
     * with the returned provider meter id rather than the OpenFlow meter id.
     * The caller does not try to interpret the provider meter id, giving the
     * implementation the freedom to either use the OpenFlow meter_id value
     * provided in the meter configuration, or any other value suitable for the
     * implementation.
     *
     * If '*id' is a value other than UINT32_MAX, modifies the existing meter
     * with that meter provider ID to have configuration 'config', while
     * leaving '*id' unchanged.  On failure, the existing meter configuration
     * is left intact. */
    enum ofperr (*meter_set)(struct ofproto *ofproto, ofproto_meter_id *id,
                             const struct ofputil_meter_config *config);

    /* Gets the meter and meter band packet and byte counts for maximum of
     * 'stats->n_bands' bands for the meter with provider ID 'id' within
     * 'ofproto'.  The caller fills in the other stats values.  The band stats
     * are copied to memory at 'stats->bands' provided by the caller.  The
     * number of returned band stats is returned in 'stats->n_bands'. */
    enum ofperr (*meter_get)(const struct ofproto *ofproto,
                             ofproto_meter_id id,
                             struct ofputil_meter_stats *stats);

    /* Deletes a meter, making the 'ofproto_meter_id' invalid for any
     * further calls. */
    void (*meter_del)(struct ofproto *, ofproto_meter_id);


/* ## -------------------- ## */
/* ## OpenFlow 1.1+ groups ## */
/* ## -------------------- ## */

    struct ofgroup *(*group_alloc)(void);
    enum ofperr (*group_construct)(struct ofgroup *);
    void (*group_destruct)(struct ofgroup *);
    void (*group_dealloc)(struct ofgroup *);

    enum ofperr (*group_modify)(struct ofgroup *);

    enum ofperr (*group_get_stats)(const struct ofgroup *,
                                   struct ofputil_group_stats *);

/* ## --------------------- ## */
/* ## Datapath information  ## */
/* ## --------------------- ## */
    /* Retrieve the version string of the datapath. The version
     * string can be NULL if it can not be determined.
     *
     * The version retuned is read only. The caller should not
     * free it.
     *
     * This function should be NULL if an implementation does not support it.
     */
    const char *(*get_datapath_version)(const struct ofproto *);
};

//ofproto_class 的一个实例
const struct ofproto_class ofproto_dpif_class = {
    init,
    enumerate_types,
    enumerate_names,
    del,
    port_open_type,
    type_run,
    type_wait,
    alloc,
    construct,
    destruct,
    dealloc,
    run,
    wait,
    NULL,                       /* get_memory_usage. */
    type_get_memory_usage,
    flush,
    query_tables,
    set_tables_version,
    port_alloc,
    port_construct,
    port_destruct,
    port_dealloc,
    port_modified,
    port_reconfigured,
    port_query_by_name,
    port_add,
    port_del,
    port_get_stats,
    port_dump_start,
    port_dump_next,
    port_dump_done,
    port_poll,
    port_poll_wait,
    port_is_lacp_current,
    port_get_lacp_stats,
    NULL,                       /* rule_choose_table */
    rule_alloc,
    rule_construct,
    rule_insert,
    rule_delete,
    rule_destruct,
    rule_dealloc,
    rule_get_stats,
    rule_execute,
    set_frag_handling,
    packet_out,
    set_netflow,
    get_netflow_ids,
    set_sflow,
    set_ipfix,
    set_cfm,
    cfm_status_changed,
    get_cfm_status,
    set_lldp,
    get_lldp_status,
    set_aa,
    aa_mapping_set,
    aa_mapping_unset,
    aa_vlan_get_queued,
    aa_vlan_get_queue_size,
    set_bfd,
    bfd_status_changed,
    get_bfd_status,
    set_stp,
    get_stp_status,
    set_stp_port,
    get_stp_port_status,
    get_stp_port_stats,
    set_rstp,
    get_rstp_status,
    set_rstp_port,
    get_rstp_port_status,
    set_queues,
    bundle_set,
    bundle_remove,
    mirror_set__,
    mirror_get_stats__,
    set_flood_vlans,
    is_mirror_output_bundle,
    forward_bpdu_changed,
    set_mac_table_config,
    set_mcast_snooping,
    set_mcast_snooping_port,
    set_realdev,
    NULL,                       /* meter_get_features */
    NULL,                       /* meter_set */
    NULL,                       /* meter_get */
    NULL,                       /* meter_del */
    group_alloc,                /* group_alloc */
    group_construct,            /* group_construct */
    group_destruct,             /* group_destruct */
    group_dealloc,              /* group_dealloc */
    group_modify,               /* group_modify */
    group_get_stats,            /* group_get_stats */
    get_datapath_version,       /* get_datapath_version */
};

//文件 lib/dpif.c
static const struct dpif_class *base_dpif_classes[] = {
#if defined(__linux__) || defined(_WIN32)
    &dpif_netlink_class,
#endif
    &dpif_netdev_class,
};

//dpif_class
static struct shash dpif_classes = SHASH_INITIALIZER(&dpif_classes);
//dpif_class 黑名单
static struct sset dpif_blacklist = SSET_INITIALIZER(&dpif_blacklist);

//文件 ofproto.c
static const struct ofproto_class **ofproto_classes;
static size_t n_ofproto_classes; ofproto_classes 的数量


//文件 bridge.c
/* All bridges, indexed by name. */
static struct hmap all_bridges = HMAP_INITIALIZER(&all_bridges); 保持 struct bridge 对象, 以 hash_string(bridge->name, 0) 索引

##核心步骤


bridge_init_ofproto(cfg)
    ofproto_init()
        void init() //ofproto-dpif.c 的 ofproto_dpif_class
bridge_run__()
    ofproto_enumerate_types(&types);
        enumerate_types(types);//ofproto-dpif.c 的 ofproto_dpif_class
            dp_enumerate_types(types)
                dp_initialize();
                    dpif_netdev_init(void) // dpif-netdev.c 的 dpif_netdev_class
                    dpif_netlink_init(void) // dpif-netlink.c 的 dpif_netlink_class

    SSET_FOR_EACH (type, &types)
        ofproto_type_run(type);
            dpif_netlink_class->type_run(datapath_type)
            dpif_netdev_class->type_run(datapath_type)

    HMAP_FOR_EACH (br, node, &all_bridges)
        //从这里开始
        ofproto_run(br->ofproto);

##关键实现


static void bridge_init_ofproto(const struct ovsrec_open_vswitch *cfg)

    调用 ofproto_init()


void ofproto_init(const struct shash *iface_hints)

    1. 将 ofproto_dpif_class 加入 ofproto_classes
    2. 拷贝 iface_hints 到 ofproto.c 中的 init_ofp_ports
    3. 遍历 ofproto_classes 每个元素 ofproto_classes[i], 调用对应的 init() 方法. ofproto_classes[i]->init(&init_ofp_ports);
    4. 注册 ofproto/list 到 ovsdb

    其中3:

    1. 将 iface_hints 拷贝给 ofproto-dpif.c 中的 init_ofp_ports
    2. 注册如下命令

    //ofproto_unixctl_init()
    unixctl_command_register(
        "ofproto/trace",
        "{[dp_name] odp_flow | bridge br_flow} [-generate|packet]",
        1, 3, ofproto_unixctl_trace, NULL);
    unixctl_command_register(
        "ofproto/trace-packet-out",
        "[-consistent] {[dp_name] odp_flow | bridge br_flow} [-generate|packet] actions",
        2, 6, ofproto_unixctl_trace_actions, NULL);
    unixctl_command_register("fdb/flush", "[bridge]", 0, 1,
                             ofproto_unixctl_fdb_flush, NULL);
    unixctl_command_register("fdb/show", "bridge", 1, 1,
                             ofproto_unixctl_fdb_show, NULL);
    unixctl_command_register("mdb/flush", "[bridge]", 0, 1,
                             ofproto_unixctl_mcast_snooping_flush, NULL);
    unixctl_command_register("mdb/show", "bridge", 1, 1,
                             ofproto_unixctl_mcast_snooping_show, NULL);
    unixctl_command_register("dpif/dump-dps", "", 0, 0,
                             ofproto_unixctl_dpif_dump_dps, NULL);
    unixctl_command_register("dpif/show", "", 0, 0, ofproto_unixctl_dpif_show,
                             NULL);
    unixctl_command_register("dpif/dump-flows", "[-m] bridge", 1, 2,
                             ofproto_unixctl_dpif_dump_flows, NULL);

    unixctl_command_register("ofproto/tnl-push-pop", "[on]|[off]", 1, 1,
                             disable_tnl_push_pop, NULL);

    //udpif_init()
    unixctl_command_register("upcall/show", "", 0, 0, upcall_unixctl_show,
                                NULL);
    unixctl_command_register("upcall/disable-megaflows", "", 0, 0,
                                upcall_unixctl_disable_megaflows, NULL);
    unixctl_command_register("upcall/enable-megaflows", "", 0, 0,
                                upcall_unixctl_enable_megaflows, NULL);
    unixctl_command_register("upcall/disable-ufid", "", 0, 0,
                                upcall_unixctl_disable_ufid, NULL);
    unixctl_command_register("upcall/enable-ufid", "", 0, 0,
                                upcall_unixctl_enable_ufid, NULL);
    unixctl_command_register("upcall/set-flow-limit", "", 1, 1,
                                upcall_unixctl_set_flow_limit, NULL);
    unixctl_command_register("revalidator/wait", "", 0, 0,
                                upcall_unixctl_dump_wait, NULL);
    unixctl_command_register("revalidator/purge", "", 0, 0,
                                upcall_unixctl_purge, NULL);


int ofproto_class_register(const struct ofproto_class *new_class)

    将 new_class 加入 ofproto_classes(实际将 ofproto_dpif_class 加入 ofproto_classes)
    1. 检查 new_class 是否与 ofproto_classes 中的元素重复
    2. 如果 ofproto_classes 空间不够, 扩容 2 倍
    3. new_class 加入 ofproto_classes

void ofproto_enumerate_types(struct sset *types)

    调用 ofproto-dpif.c 中的 enumerate_types(struct sset *types)

static void enumerate_types(struct sset *types)

    调用 dp_enumerate_types()

void dp_enumerate_types(struct sset *types)

    dp_initialize();
    SHASH_FOR_EACH(node, &dpif_classes) {
        const struct registered_dpif_class *registered_class = node->data;
        sset_add(types, registered_class->dpif_class->type);
    }

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
    for (i = 0; i < ARRAY_SIZE(base_dpif_classes); i++) {
        dp_register_provider(base_dpif_classes[i]);
    }

int dp_register_provider(const struct dpif_class *new_class)

    error = dp_register_provider__(new_class);
    return error

int ofproto_type_run(const char *datapath_type)

    //TODO
    目前 datapath_type 只能为 system, netdev
    调用 ofproto_dpif_class->type_run(datapath_type)


static int open_dpif_backer(const char *type, struct dpif_backer **backerp)

    //TODO





##附录


###dpctl

    //dpctl
    { "add-dp", "add-dp dp [iface...]", 1, INT_MAX, dpctl_add_dp },
    { "del-dp", "del-dp dp", 1, 1, dpctl_del_dp },
    { "add-if", "add-if dp iface...", 2, INT_MAX, dpctl_add_if },
    { "del-if", "del-if dp iface...", 2, INT_MAX, dpctl_del_if },
    { "set-if", "set-if dp iface...", 2, INT_MAX, dpctl_set_if },
    { "dump-dps", "", 0, 0, dpctl_dump_dps },
    { "show", "[dp...]", 0, INT_MAX, dpctl_show },
    { "dump-flows", "[dp]", 0, 2, dpctl_dump_flows },
    { "add-flow", "add-flow [dp] flow actions", 2, 3, dpctl_add_flow },
    { "mod-flow", "mod-flow [dp] flow actions", 2, 3, dpctl_mod_flow },
    { "get-flow", "get-flow [dp] ufid", 1, 2, dpctl_get_flow },
    { "del-flow", "del-flow [dp] flow", 1, 2, dpctl_del_flow },
    { "del-flows", "[dp]", 0, 1, dpctl_del_flows },
    { "help", "", 0, INT_MAX, dpctl_help },
    { "list-commands", "", 0, INT_MAX, dpctl_list_commands },

    /* Undocumented commands for testing. */
    { "parse-actions", "actions", 1, INT_MAX, dpctl_parse_actions },
    { "normalize-actions", "actions", 2, INT_MAX, dpctl_normalize_actions },

    { NULL, NULL, 0, 0, NULL },

    //tnl_arp_cache_init(void)
    unixctl_command_register("tnl/arp/show", "", 0, 0, tnl_arp_cache_show, NULL);
    unixctl_command_register("tnl/arp/flush", "", 0, 0, tnl_arp_cache_flush, NULL);

    //ovs_router_init(void)
    unixctl_command_register("ovs/route/add", "ipv4_addr/prefix_len out_br_name gw", 2, 3, ovs_router_add, NULL);
    unixctl_command_register("ovs/route/show", "", 0, 0, ovs_router_show, NULL);
    unixctl_command_register("ovs/route/del", "ipv4_addr/prefix_len", 1, 1, ovs_router_del, NULL);
    unixctl_command_register("ovs/route/lookup", "ipv4_addr", 1, 1, ovs_router_lookup_cmd, NULL);

    //upcall
    unixctl_command_register("upcall/show", "", 0, 0, upcall_unixctl_show, NULL);
    unixctl_command_register("upcall/disable-megaflows", "", 0, 0, upcall_unixctl_disable_megaflows, NULL);
    unixctl_command_register("upcall/enable-megaflows", "", 0, 0, upcall_unixctl_enable_megaflows, NULL);
    unixctl_command_register("upcall/disable-ufid", "", 0, 0, upcall_unixctl_disable_ufid, NULL);
    unixctl_command_register("upcall/enable-ufid", "", 0, 0, upcall_unixctl_enable_ufid, NULL);
    unixctl_command_register("upcall/set-flow-limit", "", 1, 1, upcall_unixctl_set_flow_limit, NULL);
    unixctl_command_register("revalidator/wait", "", 0, 0, upcall_unixctl_dump_wait, NULL);
    unixctl_command_register("revalidator/purge", "", 0, 0, upcall_unixctl_purge, NULL);



