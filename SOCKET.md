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

