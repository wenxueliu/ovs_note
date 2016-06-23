
1. Discriminator 可以动态修改, 但不在 RFC 5880

###命令

ovs-appctl bfd/show [interface]

显示对应接口的 bfd 状态

ovs-appctl bfd/set-forwarding [interface] normal|false|true

修改 interface 的 forwarding_override 标志, 如果 interface 没有给, 就设置所有
bfd 的 forwarding_override. 其中

    normal : forwarding_override = -1
    true   : forwarding_override = 1
    false  : forwarding_override = 0

###实现

可以包含多个 bfd. 所有的 bfd 保存在 K-V 存储 all_bfds 中. 并且以 bfd->disc 为 key

bool bfd_forwarding(struct bfd *bfd)

bfd_forwarding__(struct bfd *bfd)

void bfd_account_rx(struct bfd *bfd, const struct dpif_flow_stats *stats)


void bfd_forwarding_if_rx_update(struct bfd *bfd) OVS_REQUIRES(mutex)


bfd_check_status_change(struct bfd *bfd)

    返回 bfd->status_changed, 重置 bfd->status_changed

bfd_get_status(const struct bfd *bfd, struct smap *smap)

    获取 bfd 的状态信息
    forwarding : true | false
    state : bfd->state
    diagnostic : bfd->state
    flap_count : bfd->flap_count
    remote_state : bfd->rmt_state
    remote_diagnostic : bfd->rmt_diag

bfd_put_details(struct ds *ds, const struct bfd *bfd) OVS_REQUIRES(mutex)

    显示当前 bfd 状态信息
    Forwarding : true | false
    Detect Multiplier : bfd->mult
    Concatenated Path Down : true | false
    TX Interval     : Approx Max(bfd->min_tx, bfd->rmt_min_rx)
    RX Interval     : Approx Max(bfd->min_rx, bfd->rmt_min_tx)
    Detect Time     : now (now-bfd->detect_time) ms
    Next TX Time    : now (now - bfd->next_tx)
    Last TX Time    : now (now - bfd->last_tx)
    Local Flags     : bfd->flags
    Local Session State  : bfd->state
    Local Diagnostic : bfd->diag
    Local Discriminator : bfd->disc
    Local Minimum TX Interval : bfd->min_tx ms
    Local Minimum RX Interval : bfd->min_rx ms

    Remote Flags            : bfd->rmt_flags
    Remote Session State    : bfd->rmt_state
    Remote Diagnostic       : bfd->rmt_diag
    Remote Discriminator    : bfd->rmt_state
    Remote Minimum TX Interval : bfd->rmt_min_tx
    Remote Minimum RX Interval : bfd->rmt_min_rx

void bfd_unixctl_set_forwarding_override(struct unixctl_conn *conn,
        int argc, const char *argv[], void *aux OVS_UNUSED)

修改 interface 的 forwarding_override 标志, 如果 interface 没有给, 就设置所有
bfd 的 forwarding_override. 其中

    normal : forwarding_override = -1
    true   : forwarding_override = 1
    false  : forwarding_override = 0

struct bfd * bfd_configure(struct bfd *bfd, const char *name, const struct smap *cfg, struct netdev *netdev)

    从 cfg 中获取如下参数, 如果与 bfd 中不相等, 就用 cfg 更新 bfd.
    配置选项

    enablse : false | true
    check_tnl_key : false | true
    min_tx  : 100(默认)
    min_rx  : 10000(默认)
    decay_min_rx : 0(默认)
    cpath_down   : false
    bfd_local_src_mac : 本地源 mac 地址
    bfd_local_dst_mac : 本地目的 mac 地址
    bfd_remote_dst_mac : 远程目的 mac 地址
    bfd_src_ip : 默认(169.254.1.1), 这里可以为主机名
    bfd_dst_ip : 默认(169.254.1.0), 这里可以为主机名
    forward_if_rx : false (默认)

bfd_unref(struct bfd *bfd)

    清除 bfd 相关信息

long long int bfd_wait(const struct bfd *bfd)

    返回下次唤醒时间

long long int bfd_wake_time(const struct bfd *bfd) OVS_EXCLUDED(mutex)

    如果 bfd->flags 包括 FLAG_FINAL, 返回 0
    否则 返回 Min(bfd->detect_time, bfd->next_tx)

bfd_poll(struct bfd *bfd)

    如果 bfd 处于 STATE_UP 或 STATE_INIT, 设置 bfd 相关参数:
    bfd->poll_min_tx : bfd->cfg_min_tx
    bfd->poll_min_rx : bfd->in_decay ? bfd->decay_min_rx : bfd->cfg_min_rx
    bfd->flags : FLAG_POLL
    bfd->next_tx : 0;

void bfd_run(struct bfd *bfd)

    如果当前的 state 为 STATE_UP 或 STATE_INIT, 超时没有收到对方的包, 置当前状态为 STATE_DOWN

bfd_min_tx(const struct bfd *bfd)

    返回 bfd->min_tx

long long int bfd_tx_interval(const struct bfd *bfd) OVS_REQUIRES(mutex)

    返回 MAX(interval, bfd->rmt_min_rx);

long long int bfd_rx_interval(const struct bfd *bfd) OVS_REQUIRES(mutex)

    返回 MAX(bfd->min_rx, bfd->rmt_min_tx);

void bfd_set_next_tx(struct bfd *bfd)

    bfd->next_tx = bfd->last_tx + bfd_tx_interval(bfd) * random_range(26) / 100

const char * bfd_flag_str(enum flags flags)

    将 bfd->flsgs 转换为可读性强的 str

const char * bfd_state_str(enum state state)

    将 bfd->state 转换为字符串

const char * bfd_diag_str(enum diag diag)

    将 bfd->diag 转换为字符串

const char * bfd_flag_str(enum flags flags)

bool bfd_should_send_packet(const struct bfd *bfd)

    如果 bfd 的 flags 包含 FLAG_FINAL, 获得当前时间已经超过下次该发送时间, 返回 true.
    否则返回 false;




uint32_t generate_discriminator(void)

    生成一个唯一的 disc 值(即该 disc 与已经存在的 bfd 的 disc 不同).　disc
    主要用于 hashmap 中索引当前 bfd.

void bfd_set_state(struct bfd *bfd, enum state state, enum diag diag)

    如果 bfd->state == state 和 bfd->diag == diag ,什么也不做
    否则, bfd->state = state; bfd->diag = diag
          如果 state == STATE_ADMIN_DOWN | STATE_DOWN, 重置 bfd->rmt_state 相关参数
          如果 state == STATE_UP 并且 bfd->decay_min_rx 不为 0, 更新 bfd decay 相关参数

void bfd_decay_update(struct bfd * bfd)

    更新 bfd->decay 相关参数:
    decay_rx_packets : 当前 bfd 关联的 inteface 收到的包的数量
    decay_rx_ctl    : 0
    decay_detect_time :  now + bfd->decay_min_rx (不会小于 now + 2000) 单位 ms

bfd_rx_packets(const struct bfd *bfd)

    bfd 关联网卡收到的包数

bfd_try_decay(struct bfd *bfd)

    对于 bfd 关联 interface, 如果在上次调用该函数到现在期间, 收的包的数量 x,
    收到的 bfd->decay_rx_packets 为 y. 如果 x <= 2*y,　开启 bfd decay 功能(置位 bfd->in_decay)

void bfd_status_changed(struct bfd *bfd)

    标记 bfd->status_changed 为 true;

struct bfd * bfd_find_by_name(const char *name)

    从 all_bfds 中找到 name 的 bfd

##注

触发 decay 的条件: 配置 decay_min_rx,并且当前时间超过 bfd->decay_detect_time, 并且 decay_rx_ctl
收到的包乘以 2 大于在上次更新 decay_rx_packets.
