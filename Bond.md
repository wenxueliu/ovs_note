
##Bond

###数据结构

all_bonds 包含 bond, bond 包含 bond_slave, bond_slave 包含 bond_entry

struct bond

    struct hmap_node hmap_node      : all_bonds 的节点
    char *name                      : 创建 bond 时指定的 name, 来源于 bond_settings
    struct ofproto_dpif *ofproto    : bond 所在的网桥
    struct hmap slaves              : 包含 bond_slave 的键值对

    struct ovs_mutex mutex          : 任何 enable_salves 中的 bond_slave 必须获取锁
    struct ovs_list enabled_slaves  : 保存工作正常的 bond_slave 的链表

    enum bond_mode balance;         : bond 模式, BM_TCP, BM_SLB, BM_AB, 来源于 bond_settings
    struct bond_slave *active_slave : 工作正常的 bond_slave. 选择算法见 bond_choose_slave 函数
    int updelay                     : 来源于 bond_settings
    int downdelay                   : 来源于 bond_settings /* Delay before slave goes up/down, in ms. */
    enum lacp_status lacp_status;   : LACP_NEGOTIATED, LACP_CONFIGURED, LACP_DISABLED
    bool bond_revalidate;           : /* True if flows need revalidation. */
    uint32_t basis;                 : /* Basis for flow hash function. */ 来源于 bond_settings

    struct bond_entry *hash         /* An array of BOND_BUCKETS elements. */
    int rebalance_interval          : 重平衡间隔, 来源于 bond_settings
    long long int next_rebalance;   :/* Next rebalancing time. */
    bool send_learning_packets
    uint32_t recirc_id              : 如果是 BM_AB, 为 0, 否则为 recirc_alloc_id(bond->ofproto)
    struct hmap pr_rule_ops;        /* Helps to maintain post recirculation rules.*/

    /* Store active slave to OVSDB. */
    bool active_slave_changed;      /* Set to true whenever the bond changes
                                   active slave. It will be reset to false
                                   after it is stored into OVSDB */

    uint8_t active_slave_mac[ETH_ADDR_LEN]: active interface 的 MAC 地址, 来源于 bond_settings
    bool lacp_fallback_ab;          : 当 LACP 失败后是否恢复到 active-backup 模式, 来源于 bond_settings
    struct ovs_refcount ref_cnt;    : 当前对象的引用计数


/* A bond slave, that is, one of the links comprising a bond. */
struct bond_slave

    struct hmap_node hmap_node; : bond 中 hmap 的数据节点
    struct ovs_list list_node;  : bond.enabled_slaves 链表元素
    struct bond *bond;          : 指向所属 bond 的指针
    void *aux;                  : /* Client-provided handle for this slave. */

    struct netdev *netdev;      : 当前 bond_slave 所属的 netdev
    unsigned int change_seq;    : 当 netdev 被替换时,  置为 0
    ofp_port_t  ofp_port;       /* OpenFlow port number. */
    char *name;                 /* Name (a copy of netdev_get_name(netdev)). */

    /* Link status. */
    long long delay_expires;    : enable 被改变的时间点.
    bool enabled;               : 当前 bond_slave 是否可工作
    bool may_enable;            : /* Client considers this slave bondable. */

    /* Rebalancing info.  Used only by bond_rebalance(). */
    struct ovs_list bal_node;   /* In bond_rebalance()'s 'bals' list. */
    struct ovs_list entries;    /* 'struct bond_entry's assigned here. */
    uint64_t tx_bytes;          /* Sum across 'tx_bytes' of entries. */

struct bond_entry

    A hash bucket for mapping a flow to a slave.  "struct bond" has an array of BOND_BUCKETS of these.

    struct bond_slave *slave;   /* Assigned slave, NULL if unassigned. */
    uint64_t tx_bytes           : tx_bytes += rule_tx_bytes - pr_tx_bytes
    struct ovs_list list_node;  /* In bond_slave's 'entries' list. */

    /* Recirculation.
     *
     * 'pr_rule' is the post-recirculation rule for this entry.
     * 'pr_tx_bytes' is the most recently seen statistics for 'pr_rule', which
     * is used to determine delta (applied to 'tx_bytes' above.) */
    struct rule *pr_rule;
    uint64_t pr_tx_bytes        : 发送 bytes 的总量. 累计



bool bond_mode_from_string(enum bond_mode *balance, const char *s)

    将 s 中字符串初始化对应的 balance

    balance-tcp     : BM_TCP
    balance-slb     : BM_SLB
    active-backup   : BM_AB

const char * bond_mode_to_string(enum bond_mode balance)

    将 balance 转换为 字符串

struct bond * bond_create(const struct bond_settings *s, struct ofproto_dpif *ofproto)

    用 ofproto 和 s 初始化 bond

struct bond * bond_ref(const struct bond *bond_)

    将 bond_ 转为 非 const 的 bond. 并对 bond_ 引用计数加 1

void bond_unref(struct bond *bond)

    释放 bond

static void add_pr_rule(struct bond *bond, const struct match *match, ofp_port_t out_ofport, struct rule **rule)

    从 bond->pr_rule_ops 中查找与 match 匹配的 bond_pr_rule_op:
    如果找到, 用 out_ofport, rule 初始化之.
    如果没有找到, 创建新的 bond_pr_rule_op, 并用 match, out_ofport, rule 初始化，之后加入 bond->pr_rule_ops

static void update_recirc_rules(struct bond *bond)

    如果 bond 不是 BM_AB 模式, 将 bond->pr_rule_ops 中不是 bond->entry 的元素删除, 并更新对应的流表
    如果 bond 是 BM_AB 模式, 清空 bond->pr_rule_ops 及其对应的流表

    1. 将 bond->pr_rule_ops 每个成员的 op 设置为 DEL
    2. 将 bond->entry 每个成员 entry 加入 bond->pr_rule_ops.
    3. 遍历 bond->pr_rule_ops 的所有成员:
        如果是 ADD, 就增加对应的 internal 流表;
        如果是 DEL, 就删除对应的 internal 流表, 并将成员从 bond->pr_rule_ops 中删除.

bool bond_reconfigure(struct bond *bond, const struct bond_settings *s)

    用 s 配置 bond 的相关成员属性

struct bond_slave * bond_find_slave_by_mac(const struct bond *bond, const uint8_t mac[ETH_ADDR_LEN])

    从 bond->slaves 中查找 MAC 地址与 mac 相同的 bond_slave

void bond_active_slave_changed(struct bond *bond)

    从 bond->active_slave->netdev 获取 mac 初始化 bond->active_slave->mac
    设置 bond->active_slave_changed 为 ture

void bond_slave_register(struct bond *bond, void *slave_, ofp_port_t ofport, struct netdev *netdev)

    如果 bond->slaves 中存在 slave_ 对应的 bond_slave, 用 ofport, netdev 更新
    否则, 创建新的 bond_slave 用 ofport, netdev 初始化对应成员, 如果 netdev 工作正常, 加入 bond->enable_salves

void bond_slave_set_netdev(struct bond *bond, void *slave_, struct netdev *netdev)

    如果 bond->slaves 中存在 slave_ 对应的 bond_slave, 设置 netdev 属性为 netdev

void bond_slave_unregister(struct bond *bond, const void *slave_)

    从 bond->slaves 中找到 slave_ 对应的 bond_slave.
    从 bond->enable_salves, bond->entry, bond->slaves 删除该 bond_slave,
    如果该 slave 正好是 bond->active_slave, 重新选择新的 bond->active_slave, 并设置 bond->send_learning_packets 为 ture

static void bond_choose_active_slave(struct bond *bond)

    基于 bond_choose_slave 原则选择合适的 bond->active_slave.
    如果新的 bond->active_slave 与旧的不一样, 就重置 bond->active_slave_mac 和 bond->active_slave_changed

static struct bond_slave * bond_choose_slave(const struct bond *bond)

    选择 bond->active_slave 原则:
    1. 如果 bond->slaves 中存在与 bond->active_slave_mac 相同的 slave, 就返回该 bond_slave
    2. 遍历 bond->slaves 找到第一个正常的 bond_slave, 返回该 slave
    3. 遍历 bond->slaves 找到 slave delay_expires 最小的 bond_slave, 返回之.

void bond_slave_set_may_enable(struct bond *bond, void *slave_, bool may_enable)

    如果 bond->slaves 中存在 slave_ 对应的 bond_slave, 设置 slave->may_enable 为 may_enable

bool bond_run(struct bond *bond, enum lacp_status lacp_status)

    1. 基于 slave->enable, slave->may_enable 和 slave 网卡指示灯及 slave->delay_expires 设置 slave
    2. 如果 bond->active_slave 改变, 设置新的 bond->active_slave

void bond_wait(struct bond *bond)

    TODO
    如果 bond->bond_revalidate == true, 立即调用 bond_run.

static bool may_send_learning_packets(const struct bond *bond)

    需要发送学习包的条件
    1. bond->lacp_status 为 LACP_DISABLED && bond->balance 为 BM_SLB, BM_T_AB && bond->active_slave != null
    或 bond->fallback_dpid && bond->lacp_status == LACP_CONFIGURED && bond->active_slave != null
    2. bond->send_learning_packets == true

bool bond_should_send_learning_packets(struct bond *bond)

    是否要发送学习包
    1. bond->lacp_status 为 LACP_DISABLED && bond->balance 为 BM_SLB, BM_T_AB && bond->active_slave != null
    或 bond->fallback_dpid && bond->lacp_status == LACP_CONFIGURED && bond->active_slave != null

struct dp_packet * bond_compose_learning_packet(struct bond *bond, const uint8_t eth_src[ETH_ADDR_LEN], uint16_t vlan, void **port_aux)

    以 eth_src,vlan 组合一个 RARP 包, 并返回

enum bond_verdict bond_check_admissibility(struct bond *bond, const void *slave_, const uint8_t eth_dst[ETH_ADDR_LEN])

    从 bond->slaves 找到 slave_ 对应的 bond_slave
    如果协商成功(bond->lacp_status=LACP_NEGOTIATED), 并且 slave 可用(slave->enable=true), 返回 BV_ACCEPT
    如果协商失败, 并且没有配置 lacp_fallback_ab, 返回 BV_DROP
    如果协商失败, 并且配置 lacp_fallback_ab:
        如果收到广播包, 并且 slave != bond->active_slave 返回 BV_DROP:
        如果 bond->balance 为 BM_AB 返回 BV_ACCEPT
        如果 bond->balance 为 BM_TCP 返回 BV_ACCEPT
        如果 bond->balance 为 BM_SLB 返回 BV_DROP_IF_MOVED

struct bond_slave * choose_output_slave(const struct bond *bond, const struct flow *flow, struct flow_wildcards *wc, uint16_t vlan)

    如果 bond 与对端还没有协商成功(bond->lacp_status == LACP_CONFIGURED), 也没有配置协商失败就采用 Active-Backup 的方式, 返回 NULL,
    如果 bond 与对端还没有协商成功(bond->lacp_status == LACP_CONFIGURED), 配置协商失败就采用 Active-Backup 的方式, 设置 bond->balance 为 BM_AB

    如果是 BM_AB: 返回 bond->active_slave
    如果是 BM_TCP 或 BM_SLB: 返回对 (bond,flow,vlan) 哈希, 之后返回 bond->entry 中对应的 bond_slave

void bond_entry_account(struct bond_entry *entry, uint64_t rule_tx_bytes)

    计算 entry 发送 bytes 的数量.

void bond_recirculation_account(struct bond *bond)

    计算 bond->entry 每个元素发送 bytes 的数量.

bool bond_may_recirc(const struct bond *bond, uint32_t *recirc_id, uint32_t *hash_bias)

    如果 bond->balance 是 BM_TCP, bond->recirc_id != 0:
        用 bond->recirc_id 初始化 recirc_id
        用 bond->hash_bias 初始化 hash_bias
        返回 true
    否则 返回 false

static void bond_update_post_recirc_rules__(struct bond* bond, const bool force)

    遍历 bond->entry 每个元素 e, 如果存在 e->slave == null 或 e->slave->enable == false,
    先从 bond->slaves 中选, 如果失败, 设置为 bond->enable_salve 最后, 强制刷新 bond->entry

void bond_update_post_recirc_rules(struct bond* bond, const bool force)

    bond_update_post_recirc_rules__ 加锁版本

static bool bond_is_balanced(const struct bond *bond)

    是否需要重平衡

void bond_account(struct bond *bond, const struct flow *flow, uint16_t vlan, uint64_t n_bytes)

    如果 bond 需要平衡的, 更新 (bond, flow, vlan) 对应 entry 的 tx_bytes 为 n_bytes

struct bond_slave * bond_slave_from_bal_node(struct ovs_list *bal)

    返回 bal 中 bal_node 成员的内存地址

static void log_bals(struct bond *bond, const struct ovs_list *bals)

    将 bals 中每个元素以字符串形式加入日志.




static void bond_link_status_update(struct bond_slave *slave)

    如果满足条件:
    1. slave 对应的设备的指示灯是亮的并且 slave->may_enable == true
    2. slave->enable == true
    3. slave->delay_expires 为 LLONG_MAX
    什么也不做.

    如果
    1. slave 对应的设备的指示灯是亮的并且 slave->may_enable == true
    2. slave->enable == true
    3. slave->delay_expires 不为 LLONG_MAX
    设置 slave->delay_expires 为 LLONG_MAX

    如果
    1. slave 对应的设备的指示灯是亮的并且 slave->may_enable == true
    2. slave->enable == false
    3. slave->delay_expires 不为 LLONG_MAX
    如果 bond->lacp_status 为 LACP_DISABLED, slave->delay_expires = now, 设置 slave->enable 为 false, 并从 bond->enable_salves 删除 slave
    如果 bond->lacp_status 不为 LACP_DISABLED, 设置 slave->delay_expires = now + bond->downdelay

    如果
    1. slave 对应的设备的指示灯是亮的并且 slave->may_enable == true
    2. slave->enable == false
    3. slave->delay_expires 为 LLONG_MAX
    如果 bond->lacp_status 为 LACP_DISABLED, slave->delay_expires = now, 设置 slave->enable 为 false, 并从 bond->enable_salves 删除 slave
    如果 bond->lacp_status 不为 LACP_DISABLED, 设置 slave->delay_expires = now + bond->downdelay

    如果
    1. slave 对应的设备的指示灯是不亮的或 slave->may_enable == false
    2. slave->enable == ture
    3. slave->delay_expires 为 LLONG_MAX
    如果 bond->lacp_status 为 LACP_DISABLED, slave->delay_expires = now, 设置 slave->enable 为 false, 并从 bond->enable_salves 删除 slave
    如果 bond->lacp_status 不为 LACP_DISABLED, 设置 slave->delay_expires = now + bond->downdelay

    如果
    1. slave 对应的设备的指示灯是不亮的或 slave->may_enable == false
    2. slave->enable == ture
    3. slave->delay_expires 不为 LLONG_MAX
    如果 bond->lacp_status 为 LACP_DISABLED, slave->delay_expires = now, 设置 slave->enable 为 false, 并从 bond->enable_salves 删除 slave
    如果 bond->lacp_status 不为 LACP_DISABLED, 设置 slave->delay_expires = now + bond->downdelay

    如果满足条件:
    1. slave 对应的设备的指示灯是不亮的 或 slave->may_enable == false
    2. slave->enable == false
    3. slave->delay_expires 不为 LLONG_MAX
    什么也不做.

    如果
    1. slave 对应的设备的指示灯是不亮的或 slave->may_enable == false
    2. slave->enable == false
    3. slave->delay_expires 为 LLONG_MAX
    如果 bond->lacp_status 为 LACP_DISABLED, slave->delay_expires = now, 设置 slave->enable 为 false, 并从 bond->enable_salves 删除 slave
    如果 bond->lacp_status 不为 LACP_DISABLED, 设置 slave->delay_expires = now + bond->updelay


