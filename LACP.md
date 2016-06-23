
##LACP

###协议格式


配置 lacp 的两端互发 lacp pdu(protocol data unit) 包. 来通告自己当前的状态.

###数据结构

struct lacp

    struct ovs_list node;         : lacp 是 all_lacp 的一个节点.
    char *name;                   : lacp 的名字, all_lacp 查找 lacp 以该字段为索引
    uint8_t sys_id[ETH_ADDR_LEN]; : System ID.
    uint16_t sys_priority;        : System Priority.
    bool active;                  : 状态, Active 或 Passive.

    struct hmap slaves;           : 保存 lacp 所有 slave 的键值对.
    struct slave *key_slave;      : Slave whose ID will be the aggregation key. */

    bool fast;                    : 是否启用快速探测模式, 快速探测是 3 s, 正常是 90 s
    bool negotiated;              : LACP 协议协商是否成功.
    bool update;                  : 是否需要进行更新.
    bool fallback_ab;             : 当新的配置失效后, 是否返回到 Active-backup 模式

    struct ovs_refcount ref_cnt;  : 当前 lacp 的引用计数(为了合理释放当前对象).

struct slave

    void *aux;                    : 唯一标记当前 slave. 用于 lacp->slaves 中查找 slave 的索引.
    struct hmap_node node;        : 是 lacp->slave 的一个节点.

    struct lacp *lacp;            : 指向 lacp 的指针.
    uint16_t port_id;             /* Port ID. */
    uint16_t port_priority;       /* Port Priority. */
    uint16_t key;                 /* Aggregation Key. 0 if default. */
    char *name;                   /* Name of this slave. */

    enum slave_status status;     /* Slave status. */
    bool attached;                /* Attached. Traffic may flow. */
    struct lacp_info partner;     : lacp_info 中的 partner
    struct lacp_info ntt_actor;   : lacp_info 中的 actor
    struct timer tx;              /* Next message transmission timer. */
    struct timer rx;              /* Expected message receive timer. */

    uint32_t count_rx_pdus;       : 每次接受一个正常的 lacp pdu 加 1
    uint32_t count_rx_pdus_bad;   : 每次接受一个不正常的 lacp pdu 加 1
    uint32_t count_tx_pdus;       : 每次发送一个 lacp_pdu 加 1



链表 all_lacp 包含一系列 lacp, 每个 lacp 包括多个 slave.

包括快速模式和慢速模式:

快速模式 1000 * 3 ms 接受对端一个 lacp pdu.

慢速模式 30000 * 3 ms 接受对端一个 lacp pdu


向对端发送 lacp pdu 的时机:

1. 心跳时间超时, 如果超时, 下次发送心跳就走快模式
2. 配置或状态改变


###LACP 状态机

如果 slave->rx 超时,

1. 处于 LACP_CURRENT 状态进入 LACP_EXPIRED;
2. 处于 LACP_EXPIRED 状态进入 LACP_DEFAULTED

当 slave->state != LACP_DEFAULTED 或 slave->lacp->active, 如果 slave->tx
心跳时间到或配置更新, 就发送 lacp PDU 数据包.


每次向对端发送的 LACP PDU 的 actor 和  partern 为 slave 的 ntt_actor 和 partner ,

void lacp_process_packet(struct lacp *lacp, const void *slave_, const struct dp_packet *packet)

    1. 在 lacp->slaves 中查找 slave_ 对应的 slave.
    2. 从 packet 解析出 pdu.
    3. 用 pdu 配置 1 中找到的 slave 相关属性(status ,ntt_actor, rx, partner 等等).

enum lacp_status lacp_status(const struct lacp *lacp)

    返回 lacp 的状态.
    如果 lacp 不为空, negotiated 不为空, 返回 LACP_NEGOTIATED;
    如果 lacp 不为空, negotiated 为空, 返回 LACP_CONFIGURED;
    否则 返回 LACP_DISABLED

void lacp_slave_register(struct lacp *lacp, void *slave_, const struct lacp_slave_settings *s)

    1. 从 lacp->slaves 中查找 slave_ 对应的 slave, 如果不存在对应的　slave 就创建之.
    2. 用 s 设置 slave 的相关属性(port_id, port_priority, name, key).
    3. 一旦 slave 的配置更改, 就修改 slave 的相关属性. 将 slave 强制下线(超时).

void lacp_slave_unregister(struct lacp *lacp, const void *slave_)

    从 lacp->slaves 中删除 slave_ 对应的 slave.


static bool slave_may_enable__(struct slave *slave)

    两种情况认为 slave 是使能的:
    1. slave->attached 并且 slave->state 包括 LACP_STATE_SYNC
    2. slave->attached 并且 slave->lacp && slave->lacp->fallback_ab && slave->status == LACP_DEFAULTED

bool lacp_slave_may_enable(const struct lacp *lacp, const void *slave_)

    如果 lacp 为 NULL, 返回 true
    如果 lacp 不为 NULL, 返回 slave_ 对应的 slave 是否是使能的.


bool lacp_slave_is_current(const struct lacp *lacp, const void *slave_)

    如果 lacp 存在 slave_对应的 slave. 并且 slave->status 不是 LACP_DEFAULTED, 返回 true;
    否则返回 false;

void lacp_run(struct lacp *lacp, lacp_send_pdu *send_pdu) OVS_EXCLUDED(mutex)

    1. 遍历 lacp 的所有 slaves, 检查 rx 时间是否超时, 如果超时就修改对应的状态.
    2. 遍历 lacp 的所有 slaves, 检查 tx 时间是否超时, 如果超时就修改对应的状态.

    注:

    Slave 有三种状态:
    LACP_CURRENT    : 有 partner, 并且与 partner 连接正常.
    LACP_EXPIRED,   : 有 partner, 但与 partner 连接超时
    LACP_DEFAULTED, : 没有与任何 partner 连接

static void slave_get_actor(struct slave *slave, struct lacp_info *actor)

    根据 slave 和 slave->lacp 设置 actor

static bool info_tx_equal(struct lacp_info *a, struct lacp_info *b)

    比较两个 lacp_info 是否相同

static void compose_lacp_pdu(const struct lacp_info *actor, const struct lacp_info *partner, struct lacp_pdu *pdu)

    用 actor 和 partern 初始化 pdu.

void lacp_wait(struct lacp *lacp)

    初始化发送和接受心跳的时间.

static void lacp_update_attached(struct lacp *lacp)

    从 lacp->slaves 中选出一个 leader. 如果选出了 leader,
    那么 lacp->negotiated = true

    其中 leader 要满足:
    1． 状态 slave->status == LACP_DEFAULTED && slave->lacp->fallback_ab = true 或 slave->status != LACP_DEFAULTED
    2.  leader 是所有 slave->ntt_actor 和 slave->partner 中 sys_priority, sys_id 是最小的.

    如果 leader->status != LACP_DEFAULTED, 那么 leaer->attached = true, 其他的
    slave->attached = false


static void slave_destroy(struct slave *slave)

    释放 slave 对象

static void slave_set_defaulted(struct slave *slave)

    设置 slave 默认状态

static void slave_set_expired(struct slave *slave)

    设置 slave 状态超时

static void slave_get_actor(struct slave *slave, struct lacp_info *actor)

    用 slave 初始化 actor

static void slave_get_priority(struct slave *slave, struct lacp_info *priority)

    优先比较 slave->lacp->sys_priority 和 slave->partner.sys_priority
    如果两只相同, 再比较 slave->lacp->sys_id 和 slave->partner.sys_id
    最后用较小者设置 priority

static bool slave_may_tx(const struct slave *slave)

    当 slave->lacp->active == true 或 slave->state == LACP_DEFAULTED 返回 true

static struct slave * slave_lookup(const struct lacp *lacp, const void *slave_)

    从 lacp->slaves 中查找 slave_ 对应的 slave

static bool info_tx_equal(struct lacp_info *a, struct lacp_info *b)

    比较 lacp_info 的相等性

static struct lacp * lacp_find(const char *name)

    从 all_lacps 中找到 name 对应的 lacp

static void ds_put_lacp_state(struct ds *ds, uint8_t state)

    将 state 转换成字符串

static void lacp_print_details(struct ds *ds, struct lacp *lacp)

    打印 lacp 的信息.

static void lacp_unixctl_show(struct unixctl_conn *conn, int argc, const char *argv[], void *aux OVS_UNUSED)

　　lacp/show 的命令回调函数, 打印 lacp 详细信息

bool lacp_get_slave_stats(const struct lacp *lacp, const void *slave_, struct lacp_slave_stats *stats)

    将 lacp 中 slave_ 对应的 slave 的信息拷贝给 stats
