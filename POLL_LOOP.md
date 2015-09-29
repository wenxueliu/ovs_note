struct poll_node {
    struct hmap_node hmap_node;
    struct pollfd pollfd;       /* Events to pass to time_poll(). */
    HANDLE wevent;              /* Events for WaitForMultipleObjects(). */
    const char *where;          /* Where poll_node was created. */
};

struct poll_loop {
    /* All active poll waiters. */
    struct hmap poll_nodes;

    /* Time at which to wake up the next call to poll_block(), LLONG_MIN to
     * wake up immediately, or LLONG_MAX to wait forever. */
    long long int timeout_when; /* In msecs as returned by time_msec(). */
    const char *timeout_where;  /* Where 'timeout_when' was set. */
};

static struct poll_node * find_poll_node(struct poll_loop *loop, int fd, HANDLE wevent)

    从 poll_loop->poll_nodes 每个元素 node 中 找到 node->pollfd.fd = fd && node->wevent = wevent 的 node.返回之;

static struct poll_loop * poll_loop(void)

    定义线程局部变量 key, 保证只初始化一次. 初始化 poll_loop 结构变量 loop.
    返回初始化后的 loop

static void free_poll_loop(void *loop_)

    释放 loop_ 变量

static void poll_create_node(int fd, HANDLE wevent, short int events, const char *where)

    对于 fd 所对应的 poll_node 节点, 如果已经存在于 poll_loop()->poll_nodes, 增加 events 事件.  否则加入 poll_loop()->poll_nodes

    注: fd 用于 linux, wevent 用于 windows, 两者不能通知设置. fd=0&&wevent!=0 或 fd!=0&&wevent=0

void poll_fd_wait_at(int fd, short int events, const char *where)

    调用 poll_create_node(fd, 0, events, where)

void poll_timer_wait_at(long long int msec, const char *where)

    如果 msec = 0, 调用 poll_timer_wait_until_at(0, where);
    如果 msec > 0, 调用 poll_timer_wait_until_at(time_now()+msec, where);
    否则 poll_timer_wait_until_at(LLONG_MAX, where);

void poll_timer_wait_until_at(long long int when, const char *where)

    如果 when < poll_loop()->timeout_when; 设置 poll_loop()->timeout_when = when; poll_loop()->timeout_where = where

void poll_immediate_wake_at(const char *where)

    调用 poll_timer_wait_at(0, where);

static void log_wakeup(const char *where, const struct pollfd *pollfd, int timeout)

    如果 pollfd 不为空,　表示由于事件唤醒, 记录唤醒事件.
    否则是由于 timeout 唤醒, 记录 timeout 唤醒事件

static void free_poll_nodes(struct poll_loop *loop)

    从 loop->poll_nodes 删除每一个节点

void poll_block(void)

    遍历 loop->poll_nodes 的每一个节点加入 poll() 的监控中. 超时时间为 loop->timeout_when
