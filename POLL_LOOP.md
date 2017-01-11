
## poll-loop

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

    定义线程局部变量 key, 保证只初始化一次. 初始化每个线程一个变量的 poll_loop 结构变量 loop.
    返回初始化后的 loop

static void free_poll_loop(void *loop_)

    释放 loop_ 变量

static void poll_create_node(int fd, HANDLE wevent, short int events, const char *where)

    将 fd 的 events 加入当前线程的 poll_loop, (如果 poll_loop 不存在就创建)

    注: fd 用于 linux, wevent 用于 windows, 两者不能通知设置. fd=0&&wevent!=0 或 fd!=0&&wevent=0

void poll_fd_wait_at(int fd, short int events, const char *where)

    将 fd 的 events 加入当前线程的 poll_loop, (如果 poll_loop 不存在就创建)

void poll_timer_wait_at(long long int msec, const char *where)

    设置当前线程 poll_loop 的超时时间为 msec(如果 msec 小于 poll_loop->timeout_when, 最多为 LLONG_MAX 最小 LLONG_MIN)

void poll_timer_wait_until_at(long long int when, const char *where)

    设置当前线程 poll_loop 的超时时间为 when(如果 when 小于 poll_loop->timeout_when)

void poll_immediate_wake_at(const char *where)

    设置当前线程 poll_loop 的超时时间为 0, 即该线程 poll 会被立即唤醒

static void log_wakeup(const char *where, const struct pollfd *pollfd, int timeout)

    记录 pollfd 唤醒事件. 如果 cpu 大于 50 为 INFO, 否则为 DEBUG

static void free_poll_nodes(struct poll_loop *loop)

    从 loop->poll_nodes 删除每一个节点

void poll_block(void)

    1. 注册信号 SIGTERM, SIGINT, SIGHUP, SIGALRM 的处理函数, 当触发信号时, 对应的 fd 即可读.
    遍历 loop->poll_nodes 的每一个节点加入 poll() 的监控中. 超时时间为 loop->timeout_when

    2. 如果运行 poll_loop 的当前线程与 monotonic_clock.large_warp.main_thread_id 不同:
       1) 发现 timewarp_seq 没有变化, 监听 timewarp_seq 的给当前线程的写事件(即读管道另一端写, 到当前线程为读).
       2) 发送 timewarp_seq 变化, 立即将当前 poll_loop 的超时设置为 0, 这样后面的 time_poll 会立即返回

    3. 如果运行 poll_loop 的当前线程与 monotonic_clock.large_warp.main_thread_id 相同:
       就等待 monotonic_clock.large_warp 中的 warp 和 large_warp 减为 0. 返回

    4. 等待当前线程的所有 fd 事件发生(可读或可写), 或超时, 之后继续
    5. 删除 poll_loop 所有节点, 重新初始化 poll_loop
    6. 读取当前线程 seq_thread_key 对于的 seq_thread 中所有 seq_waiter 从所属的 seq->waiters 和 seq_thread->waiters 中删除
       这时当前线程没有任何 seq_waiter, 因此, 设置 seq_thread->waiting 为 false. 并清空管道中的消息.

以 timewarp_seq 为例

1. 线程 B, C 调用 poll_block
2. 线程 A 调用 time/warp TOTAL_MSEC(10000) MSEC(1000)

1)刚开始线程 B, C, 各增加一个 seq_waiter, 分别加入当前线程的 seq_thread->waiters 也加入 seq->waiters
并且监听管道一端的 POLLIN 事件, (当 timewarp_seq 的值发生变化时, 会通过管道的另一端发送 "", 这样监听
端就会收到 POLLIN 事件), 该事件构造 poll_node 加入各自线程的 poll_loop, B, C 线程一直阻塞, 直到收到 POLLIN

2)之后线程 A 调用 time/warp TOTAL_MSEC(10000), MSEC(1000). 线程 A 将 monotonic_clock->warp 每次增加
MSEC(1000), TOTAL_MSEC(10000) 减少 MSEC. 之后设置 timewarp_seq->value = seq_next.
给线程 B, C 发送""消息之后, 将 waiter 从 seq 和 seq_thread 中删除, 并释放
waiter.  最后休息 10s

3)在线程 A  发生 "" 之后, 线程 B, C 收到 POLLIN 事件, 两个线程各自从阻塞中返回. 从当前 poll_loop
中删除所有 poll_node 节点. 将当前线程的所有 waiters 从所属的 seq_thread 和 seq
中删除. 读完管道所有消息. thread->waiting 设置为 false

之后重新循环1),2),3). 直到 TOTAL_MSEC 和 MSEC 都减为 0

-----------------------------------------------------------

## 信号机制

#define MAX_HOOKS 32
static struct hook hooks[MAX_HOOKS];
static size_t n_hooks;

static const int fatal_signals[] = { SIGTERM, SIGINT, SIGHUP, SIGALRM };
static int signal_fds[2];

void fatal_signal_init(void)

    如果 fatal_signals 没有初始化, 初始化之
    并初始化管道

void fatal_signal_add_hook(void (*hook_cb)(void *aux), void (*cancel_cb)(void *aux), void *aux, bool run_at_exit)

    注册一个 hook 加入 hooks

void fatal_signal_handler(int sig_nr)

    fatal_signals 中信号的处理函数(在 fatal_signal_init 中注册),
    即将空字符串写入 signal_fds[1], 并保存当前信号

void fatal_signal_run(void)

    一旦收到 fatal_signals 里面的信号, 就调用对应的 hooks 中所有元素注册的 hook 函数, 之后将信号重新抛出去.

void fatal_signal_wait(void)

    为 signal_fds[0] 注册一个 POLLIN 事件, 一旦触发信号, 就可以知道

void fatal_ignore_sigpipe(void)

    忽略 pipe 信号

void fatal_signal_atexit_handler(void)

    调用 hooks 中只响应一次信号(run_at_exit != 0)的 hook

static void call_hooks(int sig_nr)

    遍历 hooks 所有 hook, 调用对于的 hook 函数


static struct sset files = SSET_INITIALIZER(&files);

/* Has a hook function been registered with fatal_signal_add_hook() (and not
 * cleared by fatal_signal_fork())? */
static bool added_hook;

static void unlink_files(void *aux);
static void cancel_files(void *aux);
static void do_unlink_files(void);


void fatal_signal_add_file_to_unlink(const char *file)

    1. 给 hooks 增加一个元素. hook_cb 为 unlink_files, cancel_cb 为 cancel_files
    2. 将 file 加入 files

void fatal_signal_remove_file_to_unlink(const char *file)

    把 file 从 files 中删除

int fatal_signal_unlink_file_now(const char *file)

    将 file 对应的文件删除, 并将 file 从 files 中删除

static void unlink_files(void *aux)

    删除 files 中的所有文件

static void cancel_files(void *aux)

    清空 files 元素, 并重新设置 add_hook 为 false

static void do_unlink_files(void)

    删除 files 中的所有文件

void fatal_signal_fork(void)

    遍历 hooks 调用每个 hook 对应的 cancel_cb.

void fatal_signal_block(sigset_t *prev_mask)

    将 fatal_signals 所有信号屏蔽, 将之前屏蔽的信号加入 prev_mask


-----------------------------------------------------------

时间机制


/* Structure set by unixctl time/warp command. */
struct large_warp {
    struct unixctl_conn *conn; /* Connection waiting for warp response. */
    long long int total_warp; /* Total offset to be added to monotonic time. */
    long long int warp;      /* 'total_warp' offset done in steps of 'warp'. */
    unsigned int main_thread_id; /* Identification for the main thread. */
};

struct clock {
    clockid_t id;               /* CLOCK_MONOTONIC or CLOCK_REALTIME. */

    /* Features for use by unit tests.  Protected by 'mutex'. */
    struct ovs_mutex mutex;
    atomic_bool slow_path;             /* True if warped or stopped. */
    struct timespec warp OVS_GUARDED;  /* Offset added for unit tests. */
    bool stopped OVS_GUARDED;          /* Disable real-time updates if true. */
    struct timespec cache OVS_GUARDED; /* Last time read from kernel. */
    struct large_warp large_warp OVS_GUARDED; /* Connection information waiting
                                                 for warp response. */
};

/* Our clocks. */
static struct clock monotonic_clock; /* CLOCK_MONOTONIC, if available. */
static struct clock wall_clock;      /* CLOCK_REALTIME. */

static void init_clock(struct clock *c, clockid_t id)

    初始化 c 对象

static void do_init_time(void)

    初始化 monotonic_clock, wall_clock

static void time_init(void)

    确保 do_init_time 只调用一次

static void time_timespec__(struct clock *c, struct timespec *ts)

    如果 c->slow_path 为 false, 将当前时间保持在 ts
    否则将 c->warp, c->cache 时间加起来, 保存在 ts

void time_timespec(struct timespec *ts)

    如果 monotonic_clock->slow_path 为 false, 将当前时间保持在 ts
    否则将 monotonic_clock->warp, monotonic_clock->cache 时间加起来, 保存在 ts

void time_wall_timespec(struct timespec *ts)

    如果 wall_clock->slow_path 为 false, 将当前时间保持在 ts
    否则将 wall_clock->warp, wall_clock->cache 时间加起来, 保存在 ts

static time_t time_sec__(struct clock *c)

    如果 c->slow_path 为 false, 返回当前时间的时间, 精度秒
    否则将 c->warp, c->cache 时间加起来, 返回精度秒

time_t time_now(void)

    返回 monotonic_clock 时间, 单位 second

time_t time_wall(void)

    返回 wall_clock 时间, 单位 second

static long long int time_msec__(struct clock *c)

    如果 c->slow_path 为 false, 返回当前时间的时间, 精度毫秒
    否则将 c->warp, c->cache 时间加起来, 返回精度毫秒

long long int time_msec(void)

    返回 monotonic_clock 时间, 单位 millsecond

long long int time_wall_msec(void)

    返回 wall_clock 时间, 单位 millsecond

void time_alarm(unsigned int secs)

    设置 deadline 为 monotonic_clock 时间. 最多 LLONG_MAX

int time_poll(struct pollfd *pollfds, int n_pollfds, HANDLE *handles OVS_UNUSED, long long int timeout_when, int *elapsed)

    1. 用当前时间减 timeout_when 获取剩余等待时间
    2. TODO
    3. 更新 last_wakeup 为函数退出当前时间
    3. 记录当次 time_poll 执行时间保存在 elapsed

long long int timespec_to_msec(const struct timespec *ts)

    ts 转换为 ms

long long int timeval_to_msec(const struct timeval *tv)

    tv 转换为 ms

long long int time_boot_msec(void)

    返回 boot_time

void xgettimeofday(struct timeval *tv)

    返回当前时间保存在 tv

void xclock_gettime(clock_t id, struct timespec *ts)

    返回当前时间保存在 ts

static void msec_to_timespec(long long int ms, struct timespec *ts)

    ms 转换为 ts

static void timewarp_work(void)


    先将 monotonic_clock->large_warp.total_warp 以 monotonic_clock->large_warp.warp 为单位, 依次增加到 monotonic_clock->warp
    如果 monotonic_clock->large_warp.total_warp 为 0, 之后将 monotonic_clock->large_warp.warp 增加到 monotonic_clock->warp
    最后返回


void timewarp_run(void)

    如果当前线程没有调用 time/warp 命令(调用了 poll_block), 当前线程监听 timewarp_seq 的改变
    如果当前线程调用 time/warp 命令, 将 monotonic_clock->large_warp 时间叠加到 monotonic_clock->warp, 并给所有监听 timewarp_seq 的线程发送 timewarp_seq 变化的消息

    监听 timewarp_seq 的线程收到 POLLIN 消息, poll 返回或者再次执行到 timewarp_run 时, 发现 seq 被改变, 于是设置当前线程的 poll_loop 超时为 0.


static long long int timeval_diff_msec(const struct timeval *a, const struct timeval *b)

    a 和 b 的时间差

static void timespec_add(struct timespec *sum, const struct timespec *a, const struct timespec *b)

    将 a 和 b 的时间加起来保存在 sum

static bool is_warped(const struct clock *c)

    monotonic_clock.warp 是否为 0

static void timeval_stop_cb(struct unixctl_conn *conn, int argc OVS_UNUSED, const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)

    停止 monotonic_clock 的时间, 重新初始化, 对应 time/stop 命令

static void timeval_warp_cb(struct unixctl_conn *conn, int argc OVS_UNUSED, const char *argv[], void *aux OVS_UNUSED)

    time/wrap MSECS  : 将 monotonic_clock.warp 增加 MSECS, 给各个 waiters 发送 timewarp_seq 变化的通知
    time/wrap LARGE_MSECS MSECS : 将 monotonic_clock.warp 以单位 MSECS 增加 LARGE_MSECS+MSECS, 每次增加都给各个 waiters 发送 timewarp_seq 变化的通知

size_t strftime_msec(char *s, size_t max, const char *format, const struct tm_msec *tm)

struct tm_msec * localtime_msec(long long int now, struct tm_msec *result)

    用 localtime_r 获取时间, 返回 result

struct tm_msec * gmtime_msec(long long int now, struct tm_msec *result)

    用 gmtime_r 获取时间, 返回 result


----------------------------------------------------------------

### seq

每个线程一个 poll_loop, 与线程局部变量 key 关联,
当调用 latch_wait_at 时, 每个线程的 seq_thread->latch 会通过
poll_fd_wait 加入调用 latch_wait_at 所属线程的 poll_loop 中.
因此, 每个 poll_loop 包含 poll_node 类型包括 seq_thread 的
latch 的一端. signal_fds 的一端, TODO

一个 seq 包含多个 seq_waiter, 每个 seq_waiter 可以属于不同的线程.
某个线程调用 seq_wait 的时候, 如果该线程没有对应的 seq_waiter, 就会
创建一个. seq 与 seq->waiters 中的元素通过管道来通信, 每个 waiter 监听(poll)
管道的读消息, 当调用 seq_change 的时候, seq 就会给管道一端发送消息,
各个 waiter 就通过其所属线程的管道另一端就能收到 seq 的消息.

每个线程通过管道与各个 seq 建立通信. 每个线程都会创建一个管道,
一端被 seq 写, 一旦 waiter 创建, 另一端就会将当前线程所属管道一端加
入 poll, 监听另一端发送的消息. seq 所属管道一端发送消息, 所有 waiter
所在线程的另一端就会触发 POLLIN 消息, 即 seq 与各个 waiter 所属的线程通信.

各个线程都可用直接访问 seq. 每个线程都可用对 seq 进行读(seq_read)和写(seq_change)
每次触发一次消息, seq_waiter 就会从所属的 seq_thread 和 seq 中删除.
但 seq_thread 和 seq 不会删除, 除非显示地调用 seq_thread_exit 来
删除当前线程的 seq_thread, 和调用 seq_destroy 删除 seq.

一个 seq_thread 是每个线程一个, 与线程局部变量 seq_thread_key 关联,
一个 seq_thread 可用包含多个 seq_waiter, 各个 seq_waiter 属于不同的 seq.

因此 seq 和 seq_thread 是对 seq_waiter 不同的分类方法.

一个实际的例子

线程 A

    seq_create(timewarp_seq) //创建一个 seq 对象

线程 B

    *last_seq = seq_read(timewarp_seq);
    seq_wait(timewarp_seq, *last_seq);

    第一次调用会创建每线程对象 seq_waiter, seq_thread.
    seq_thread 所属线程的将管道的一端读事件加入当前
    线程的 poll-loop. seq 对管道的写操作, 会被 poll-loop
    接受到

线程 C

    *last_seq = seq_read(timewarp_seq);
    seq_wait(timewarp_seq, *last_seq);

    第一次调用会创建每线程对象 seq_waiter, seq_thread.
    seq_thread 所属线程的将管道的一端读事件加入当前
    线程的 poll-loop. seq 对管道的写操作, 会被 poll-loop
    接受到

任意线程调用 seq_change(timewarp_seq), 线程 B, C 的 poll-loop 都会收到
POLLIN 事件



/* A sequence number object. */
struct seq {
    uint64_t value;             //seq 当前值, 每次被修改就会通知所有 waiters POLLIN 事件
    struct hmap waiters;        //包含 seq_waiter
};

/* A thread waiting on a particular seq. */
struct seq_waiter {
    struct seq *seq;            //所属的 seq
    struct hmap_node hmap_node; //seq->waiters 的元素
    unsigned int ovsthread_id;  //所属线程 id, seq->waiters 基于该值哈希

    struct seq_thread *thread;  //所属线程的 seq_thread
    struct ovs_list list_node;  //seq_thread->waiters 的元素

    uint64_t value;             //
};

/* A thread that might be waiting on one or more seqs. */
struct seq_thread {
    struct ovs_list waiters;    //该 seq_thread 所属线程的所有 seq_waiter
    struct latch latch;         //与 seq 通信的管道
    bool waiting;               //当该 seq_thread 中 waiters 不为空时, 就设置为 true
};

static struct ovs_mutex seq_mutex = OVS_MUTEX_INITIALIZER;

static uint64_t seq_next = 1; //记录每个 seq 的 value, 每创建一个 seq, 加 1, 每次事件变化, 加 1

static pthread_key_t seq_thread_key; //线程私有变量. 与 seq_thread 关联

struct seq * seq_create(void)

    创建一个 seq

void seq_destroy(struct seq *seq)

    给所有 waiters 发送消息, 并销毁 seq
    问题: 多个线程同时调用是否存在问题

void seq_change(struct seq *seq)

    设置当前 seq->value 为 seq_next++, 给 seq->waiters 的所有 seq_thread
    发送消息, 并清空 seq->waiters

uint64_t seq_read(const struct seq *seq)

    读取 seq->value

static void seq_wait__(struct seq *seq, uint64_t value, const char *where)

    如果 seq->waiters 中 seq_waiter->value 改变, 设置超时时间为 0, 如果没有改变, 什么也不做
    如果 seq->waiters 中不存在当前线程对应的 seq_waiter, 创建 seq_waiter, 并确保 seq_waiter 所属线程加入 poll 中

void seq_wait_at(const struct seq *seq_, uint64_t value, const char *where)

    当 seq->value 或 seq->waiters 每个元素 waiter->value 存在一个与 value 不同立即设置当前线程的 poll 超时时间为 0, 这样 poll 立即被唤醒
    检查 seq->value = value, 但是 seq->waiters 中不存在于当前线程的 seq_waiter, 创建 seq_waiter, 并确保 seq_waiter 所属线程加入 poll 中
    检查 seq->value 或 seq->waiters 每个元素 waiter->value 每个都与 value 相同, 什么也不做;

void seq_woke(void)

    读取当前线程 seq_thread_key 对于的 seq_thread 中所有 seq_waiter 从所属的 seq->waiters 和 seq_thread->waiters 中删除
    这时当前线程没有任何 seq_waiter, 因此, 设置 seq_thread->waiting 为 false. 并清空管道中的消息.

static void seq_init(void)

    保证 seq_thread_key 被每个线程只初始化一次

static struct seq_thread *seq_thread_get(void)

    获取当前线程与 seq_thread_key 关联的 seq_thread, 如果不存在, 就创建一个新的

static void seq_thread_exit(void *thread_)

    将 thread_ 对象销毁

static void seq_thread_woke(struct seq_thread *thread)

    将 thread->waiters 中所有 seq_waiter 从所属的 seq->waiters 和 seq_thread->waiters 中删除
    之后, 读取 thread->latch 中的消息

static void seq_waiter_destroy(struct seq_waiter *waiter)

    waiter 从所属的 seq->waiters 和 seq_thread->waiters 中删除

static void seq_wake_waiters(struct seq *seq)

    给 seq->waiters 所有元素 seq_waiter 发送消息.
    之后将 waiter 从 seq->waiters 和 seq_thread->waiters 中删除




----------------------------------------------------------------

### latch

void latch_init(struct latch *latch)

    创建一个管道, 并设置为非阻塞模式

void latch_destroy(struct latch *latch)

    关闭管道

bool latch_poll(struct latch *latch)

    返回管道一端是否可读

void latch_set(struct latch *latch)

    给管道另外一段发送消息, 表示可读

bool latch_is_set(const struct latch *latch)

    poll 直到 latch->fds[0] 可读, 可读返回 true, 不可读返回 false

void latch_wait_at(const struct latch *latch, const char *where)

    将 latch->fds[0] 加入当前线程, 并注册 POLLIN 事件

如果之前调用过 latch_set(与调用次数无关), 那么 latch_poll 返回 true

用法:

A 端

    latch_init(latch)
    while(true) {
        latch_wait_at(latch, "test")
        while(!latch_is_set(latch)) {
            //do other thing
        }
        //the pipe is readable now add handler
        latch_poll(latch) //read all message of the other side
    }
    latch_destroy(latch)

B 端

    latch_set(latch) //发送消息


----------------------------------------------------------------


设计思想

多读少写的场景
新版本的写要等待所有的旧版的读操作都完成

1. 每个线程私有对象 perthread_key 对应一个 ovsrcu_perthread
2


ovsrcu_quiesce_end() : 获取线程私有对象 ovsrcu_perthread

ovsrcu_quiesced()

    如果当前进程是单线程模式(没有调用过 pthread_create), 重新初始化 flushed_cbsets, 并调用 flushed_cbsets 的所有回调函数
    如果当前进程是多线程模式(调用过 pthread_create), 创建新的线程脱离当前线程, 循环遍历 flushed_cbsets 中的每个元素, 并调用对应的回调函数


ovsrcu_quiesce   : 让当前线程完成旧版操作
ovsrcu_synchronize : 等待所有线程旧版本操作都完成.
ovsrcu_call_postponed : 当前处于 Quiescent 状态, 返回 false, 不处于 Quiescent, 等待直到进入 Quiescent, 返回 true.

问题: 在多线程模式下, ovsrcu_quiesce_start, ovsrcu_quiesce 每次调用都会创建一个新的线程处理
flushed_cbsets, 这是否是期望的?

struct ovsrcu_cb {
    void (*function)(void *aux);
    void *aux;
};

struct ovsrcu_cbset {
    struct ovs_list list_node;
    //16 是线程专有回调函数刷入全局 flushed_cbsets 的阈值
    struct ovsrcu_cb cbs[16]; //为什么是 16 ?
    //实际 cbs 大小
    int n_cbs;
};

//线程私有对象
struct ovsrcu_perthread {
    struct ovs_list list_node;  /* In global list. */

    struct ovs_mutex mutex;
    uint64_t seqno;
    struct ovsrcu_cbset *cbset;
    char name[16];              /* This thread's name. */
};


static struct seq *global_seqno; //标记旧版本操作完成(即线程的局部 cbset 刷新到全局 flushed_cbsets)

static pthread_key_t perthread_key; //线程专有数据

static struct ovs_list ovsrcu_threads; //保存所有线程专有数据 perthread_key 对应的 ovsrcu_perthread

static struct ovs_mutex ovsrcu_threads_mutex; //ovsrcu_threads 的锁

static struct guarded_list flushed_cbsets; 保存各个线程的 ovsrcu_perthread->cbset

static struct seq *flushed_cbsets_seq; 记录每个线程 ovsrcu_perthread->cbset 将数据拷贝到 flushed_cbsets 的事件

用法

ovsrcu_quiesce()

    仅仅在需要调用当前线程的回到函数时调用

    将 perthread->cbset 局部线程操作同步到 flushed_cbsets, 并通知 global_seqno.
    之后创建一个新的线程, 之后创建子线程处理 flushed_cbsets


ovsrcu_quiesce_start
ovsrcu_quiesce_end

    仅仅在需要更新全部调用函数时执行

ovsrcu_synchronize

    确保所有的线程都执行完就的回调函数

ovsrcu_postpone(void (*function)(void *aux), void *aux)

    将函数加入当前线程的 ovsrcu_perthread->cbsets

ovsrcu_quiesced()
    if single_threaded
        ovsrcu_call_postponed
    else
        ovsthread_once : ovs_thread_create("urcu", ovsrcu_postpone_thread, NULL);

ovsrcu_call_postponed
    guarded_list_pop_all(&flushed_cbsets, &cbsets);
    if (list_is_empty(&cbsets)) return false
    ovsrcu_synchronize()
        warning_threshold = 1000;
        target_seqno = seq_read(global_seqno)
        ovsrcu_quiesce_start();
            perthread = pthread_getspecific(perthread_key);
            if perthread:
                ovsrcu_unregister__(perthread)
                    ovsrcu_flush_cbset(perthread)
        start = time_msec();
        for (;;):
            done = true
            cur_seqno = seq_read(global_seqno);
            LIST_FOR_EACH (perthread, list_node, &ovsrcu_threads)
                if (perthread->seqno <= target_seqno)
                    done = false;
                    break;
            if (done)
                break;
            poll_timer_wait_until(start + warning_threshold);
            if (time_msec() - start >= warning_threshold)
                warning_threshold *= 2;
            seq_wait(global_seqno, cur_seqno);
            poll_block();
        ovsrcu_quiesce_end()


ovsrcu_postpone_thread
    for (;;)
        seqno = seq_read(flushed_cbsets_seq);
        ovsrcu_call_postponed
            guarded_list_pop_all(&flushed_cbsets, &cbsets);
            if (list_is_empty(&cbsets)):
                seq_wait(flushed_cbsets_seq, seqno)
                poll_block()
            else
                ovsrcu_synchronize()
                    warning_threshold = 1000;
                    target_seqno = seq_read(global_seqno)
                    ovsrcu_quiesce_start();
                        perthread = pthread_getspecific(perthread_key);
                        if perthread:
                            ovsrcu_unregister__(perthread)
                                ovsrcu_flush_cbset(perthread)
                    start = time_msec();
                    for (;;):
                        done = true
                        cur_seqno = seq_read(global_seqno);
                        LIST_FOR_EACH (perthread, list_node, &ovsrcu_threads)
                            if (perthread->seqno <= target_seqno)
                                done = false;
                                break;
                        if (done)
                            break;
                        poll_timer_wait_until(start + warning_threshold);
                        if (time_msec() - start >= warning_threshold)
                            warning_threshold *= 2;
                        seq_wait(global_seqno, cur_seqno);
                        poll_block();
                    ovsrcu_quiesce_end()
                LIST_FOR_EACH_POP (cbset, list_node, &cbsets):
                    for (cb = cbset->cbs; cb < &cbset->cbs[cbset->n_cbs]; cb++):
                        cb->function(cb->aux)
                    free(cbset)

ovsrcu_synchronize(void)
    if single_threaded
        return
    ovsrcu_quiesce_start();
        perthread = pthread_getspecific(perthread_key);
        if perthread:
            ovsrcu_unregister__(perthread)
                ovsrcu_flush_cbset(perthread)
        ovsrcu_quiesced
            if ovsthread_once_start(&once):
                ovs_thread_create("urcu", ovsrcu_postpone_thread, NULL);
                    ovsrcu_postpone_thread

    start = time_msec();
    for (;;):
        done = true
        cur_seqno = seq_read(global_seqno);
        LIST_FOR_EACH (perthread, list_node, &ovsrcu_threads)
            if (perthread->seqno <= target_seqno)
                done = false;
                break;
        if (done)
            break;
        poll_timer_wait_until(start + warning_threshold);
        if (time_msec() - start >= warning_threshold)
            warning_threshold *= 2;
        seq_wait(global_seqno, cur_seqno);
        poll_block();
    ovsrcu_quiesce_end();

ovsrcu_postpone_thread
    ovsrcu_call_postponed


static struct ovsrcu_perthread * ovsrcu_perthread_get(void)

    初始化线程专有数据 perthread_key 为 ovsrcu_perthread, 并返回 ovsrcu_perthread

    1. 初始化 ovsrcu_perthread 对象
    2. 将 ovsrcu_perthread 加入 ovsrcu_threads
    3. 将 perthread_key 与 ovsrcu_perthread 关联

    注: 在 perthread_key 没有通过 pthread_key_create() 创建, 或已经通
    过 pthread_key_delete() 删除, 调用 pthread_getspecific() 或
    pthread_setspecific() 是未定义的行为.

void ovsrcu_quiesce_end(void)

    创建新的线程私有对象, 并与 perthread_key 绑定

    初始化线程专有数据 perthread_key 为 ovsrcu_perthread, 并返回 ovsrcu_perthread

static void ovsrcu_quiesced(void)

    等待旧版本的所有线程都完成自己操作

    1. 如果是单线程:
        如果 flushed_cbsets 为 null, 直接返回
        否则 调用 flushed_cbsets 的每个元素的回调函数
    2. 否则, 创建新的线程, 并且新的线程脱离主线程, 新线程的任务: TODO

void ovsrcu_quiesce_start(void)

    将当前线程私有数据与 perthread_key 解绑, 销毁 perthread, 并发送对应的消息给订阅者
    等待旧版本的所有线程都完成自己操作

    1. 将当前线程私有数据与 perthread_key 解绑定, 并释放 ovsrcu_perthread 对象. 其中包括
        1) 当前线程私有数据与 perthread_key 解绑定
        2) 将线程私有数据 ovsrcu_perthread->cbset 加入 flushed_cbsets, 发送 flushed_cbsets_seq 改变消息给所有订阅者
        3) 将线程私有数据 ovsrcu_perthread 从 ovsrcu_threads 中删除, 发送 global_seqno 改变消息给所有订阅者

    2. 如果是单线程:
        如果 flushed_cbsets 为 null, 直接返回
        否则 调用 flushed_cbsets 的每个元素的回调函数
    2. 否则, 创建新的线程, 并且新的线程脱离主线程, 新线程的任务: TODO

void ovsrcu_quiesce(void)

    将 perthread->cbset 局部线程操作同步到 flushed_cbsets, 并通知 flushed_cbsets_seq ,global_seqno 变化
    之后创建一个新的线程, 之后创建子线程处理 flushed_cbsets

    1. 将线程局部数据 perthread->cbset 加入全局数据 flushed_cbsets. 并通知其他线程, flushed_cbsets 被更新了
    2. 通知当前线程 global_seqno 改变了
    3. 如果是单线程: 调用 flushed_cbsets 的所有回调函数, 重新初始化 flushed_cbsets
       如果是多线程: 创建新线程, 脱离当前线程, TODO

bool ovsrcu_is_quiescent(void)

    当前线程的是否处于 quiesce 状态(即 perthread_key 是否为 NULL)

void ovsrcu_synchronize(void)

    等待所有线程 perthread_key 都释放, 然后初始化当前线程的 perthread_key


void ovsrcu_postpone__(void (*function)(void *aux), void *aux)

    1. 为当前线程的 cbset 增加回调函数(如果 cbset 不存在就创建)
    2. 如果 perthread->cbset 实际数量多于 cbset->cbs 的大小, 将当前线程的 cbset
    加入全局的 flushed_cbsets. 并发送 flushed_cbsets 被更新的通知

static bool ovsrcu_call_postponed(void)

    1. 将 flushed_cbsets 元素移动到临时链表 cbsets, 重新初始化 flushed_cbsets
    2. 如果 cbsets 没有任何元素, 返回 false, 否则继续
    3. 等待所有线程 perthread_key 都释放, 然后初始化当前线程的 perthread_key
    3. 调用 flushed_cbsets 的每个元素的所有回调函数, 并销毁该对象, 返回 true

static void * ovsrcu_postpone_thread(void *arg)

    1. 脱离父线程
    2. 将 flushed_cbsets 元素移动到临时链表 cbsets, 重新初始化 flushed_cbsets

static void ovsrcu_flush_cbset(struct ovsrcu_perthread *perthread)

    将线程局部数据 perthread->cbset 加入 flushed_cbsets. 清空 perthread->cbset,
    发送 flushed_cbsets_seq 改变消息给所有订阅者

static void ovsrcu_unregister__(struct ovsrcu_perthread *perthread)

    销毁 perthread, 并发送对应的消息给订阅者(并没有与当前 perthread_key 解绑)

    1. 将线程私有数据 ovsrcu_perthread->cbset 加入 flushed_cbsets, 发送 flushed_cbsets_seq 改变消息给所有订阅者
    2. 将线程私有数据 ovsrcu_perthread 从 ovsrcu_threads 中删除, 释放 ovsrcu_perthread 空间, 发送 global_seqno 改变消息给所有订阅者

static void ovsrcu_thread_exit_cb(void *perthread)

    线程专有数据 perthread_key 被删除时的回调函数

static void ovsrcu_cancel_thread_exit_cb(void *aux OVS_UNUSED)

    perthread_key 与当前线程 ovsrcu_perthread 解绑定(当收到信号(参考 fatal_signals.c)时调用.)

static void ovsrcu_init_module(void)

    保证线程专有数据和全局数据只被初始化一次

    global_seqno
    perthread_key
    flushed_cbsets
    flushed_cbsets_seq
