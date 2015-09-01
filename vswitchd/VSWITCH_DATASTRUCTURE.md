###ovsdb 数据库结构

struct ovsdb_idl {
    const struct ovsdb_idl_class *class;
    struct jsonrpc_session *session;
    struct shash table_by_name;
    struct ovsdb_idl_table *tables; /* Contains "struct ovsdb_idl_table *"s.*/
    unsigned int change_seqno;
    bool verify_write_only;

    /* Session state. */
    unsigned int state_seqno;
    enum ovsdb_idl_state state;
    struct json *request_id;

    /* Database locking. */
    char *lock_name;            /* Name of lock we need, NULL if none. */
    bool has_lock;              /* Has db server told us we have the lock? */
    bool is_lock_contended;     /* Has db server told us we can't get lock? */
    struct json *lock_request_id; /* JSON-RPC ID of in-flight lock request. */

    /* Transaction support. */
    struct ovsdb_idl_txn *txn;
    struct hmap outstanding_txns;
};

struct ovsdb_idl_class {
    const char *database;       /* <db-name> for this database. */
    const struct ovsdb_idl_table_class *tables;
    size_t n_tables;
};

struct ovsdb_idl_table {
    const struct ovsdb_idl_table_class *class;
    unsigned char *modes;    /* OVSDB_IDL_* bitmasks, indexed by column. */
    bool need_table;         /* Monitor table even if no columns? */
    struct shash columns;    /* Contains "const struct ovsdb_idl_column *"s. */
    struct hmap rows;        /* Contains "struct ovsdb_idl_row"s. */
    struct ovsdb_idl *idl;   /* Containing idl. */
};

struct ovsdb_idl_table_class {
    char *name;
    bool is_root;
    const struct ovsdb_idl_column *columns;
    size_t n_columns;
    size_t allocation_size;
    void (*row_init)(struct ovsdb_idl_row *);
};

struct ovsdb_idl_column {
    char *name;
    struct ovsdb_type type;
    bool mutable;
    void (*parse)(struct ovsdb_idl_row *, const struct ovsdb_datum *);
    void (*unparse)(struct ovsdb_idl_row *);
};

/* An OVSDB type.
 *
 * Several rules constrain the valid types.  See ovsdb_type_is_valid() (in
 * ovsdb-types.c) for details.
 *
 * If 'value_type' is OVSDB_TYPE_VOID, 'n_min' is 1, and 'n_max' is 1, then the
 * type is a single atomic 'key_type'.
 *
 * If 'value_type' is OVSDB_TYPE_VOID and 'n_min' or 'n_max' (or both) has a
 * value other than 1, then the type is a set of 'key_type'.  If 'n_min' is 0
 * and 'n_max' is 1, then the type can also be considered an optional
 * 'key_type'.
 *
 * If 'value_type' is not OVSDB_TYPE_VOID, then the type is a map from
 * 'key_type' to 'value_type'.  If 'n_min' is 0 and 'n_max' is 1, then the type
 * can also be considered an optional pair of 'key_type' and 'value_type'.
 */
struct ovsdb_type {
    struct ovsdb_base_type key;
    struct ovsdb_base_type value;
    unsigned int n_min;
    unsigned int n_max;         /* UINT_MAX stands in for "unlimited". */
};


###Json RPC 数据结构

struct jsonrpc_session {
    struct reconnect *reconnect; //链路定时监测
    struct jsonrpc *rpc;
    struct stream *stream;
    struct pstream *pstream;
    int last_error;
    unsigned int seqno;
    uint8_t dscp;
};

struct reconnect {
    /* Configuration. */
    char *name;
    int min_backoff;
    int max_backoff;
    int probe_interval;
    bool passive;               //被动listen 还是主动 connect
    enum vlog_level info;       /* Used for informational messages. */

    /* State. */
    enum state state;
    long long int state_entered;
    int backoff;
    long long int last_activity;
    long long int last_connected;
    long long int last_disconnected;
    unsigned int max_tries;

    /* These values are simply for statistics reporting, not otherwise used
     * directly by anything internal. */
    long long int creation_time;
    unsigned int n_attempted_connections, n_successful_connections;
    unsigned int total_connected_duration;
    unsigned int seqno;
};

struct jsonrpc {
    struct stream *stream;
    char *name;
    int status;

    /* Input. */
    struct byteq input;
    uint8_t input_buffer[512];
    struct json_parser *parser;

    /* Output. */
    struct ovs_list output;     /* Contains "struct ofpbuf"s. */
    size_t output_count;        /* Number of elements in "output". */
    size_t backlog;
};

/* General-purpose circular queue of bytes. */
struct byteq {
    uint8_t *buffer;            /* Circular queue. */
    unsigned int size;          /* Number of bytes allocated for 'buffer'. */
    unsigned int head;          /* Head of queue. */
    unsigned int tail;          /* Chases the head. */
};

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

### Notifier
/*
 * Function called to report that a netdev has changed.  'change' describes the
 * specific change.  It may be null if the buffer of change information
 * overflowed, in which case the function must assume that every device may
 * have changed.  'aux' is as specified in the call to
 * rtbsd_notifier_register().
 */

typedef void rtbsd_notify_func(const struct rtbsd_change *, void *aux);
struct rtbsd_notifier {
    struct ovs_list node;
    rtbsd_notify_func *cb;
    void *aux;
};

struct if_notifier {
    struct rtbsd_notifier notifier;
    if_notify_func *cb;
    void *aux;
};

###unixctl server

/* Server for control connection. */
struct unixctl_server {
    struct pstream *listener;
    struct ovs_list conns;
};


pstream --> jsonrpc_open() --> jsonrpc
