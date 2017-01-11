
问题:

1. bridge 的 mac, datapath-id 生成算法
2. 配置 stp 条件. 比如 cost 如何计算



## 数据结构


### bridge 与 mirror

    bridge->mirrors 包含 map (mirror->uuid, mirror)

    mirror->bridge 指向 bridge

### bridge 与 port

    bridge->ports 包含 map (port->name:port)

    port->bridge 指向 bridge

### port 与 iface

    port->ifaces 包含 list (iface)

    iface->port 指向 port

    一个端口可用包含多个 iface, 比如 bond

### bridge 与 iface

    bridge->iface_by_name 包含 map (iface->name:iface)

    bridge->ifaces 包含 map (iface->ofp_port:iface)

    iface->port->bridge 指向 bridge

### bridge 与 ofproto

    bridge 指向 ofproto

### bridge 与 aa_mapping

    bridge->mappings 包含 map (TODO:aa_mapping)

    aa_mapping->bridge 指向 bridge

### iface 与 netdev

    iface->netdev 指向 netdev

所有 bridge 保存在 all_bridges 中


## 函数

static void bridge_init_ofproto(const struct ovsrec_open_vswitch *cfg)

    解析 cfg, 调用 ofproto_init 进行初始化

    该函数只被调用一次. 不是线程安全的.

    TODO: ofproto_init

static void if_change_cb(void *aux OVS_UNUSED)

    设置 ifaces_changed 为 true

void bridge_init(const char *remote)

    1. 初始化 ovsdb 配置
    2. 初始化各个模块

        lacp_init();
        bond_init();
        cfm_init();
        bfd_init();
        ovs_numa_init();
        stp_init();
        lldp_init();
        rstp_init();
        ifnotifier = if_notifier_create(if_change_cb, NULL);

void bridge_exit(void)

    1. 销毁所有 bridge
    2. 与 ovsdb 断开连接

static void collect_in_band_managers(const struct ovsrec_open_vswitch *ovs_cfg, struct sockaddr_in **managersp, size_t *n_managersp)

    解析 ovs_cfg->manager_options, 将解析后的结果保存咋 managersp(管理地址), n_managersp(管理地址数量)

static void bridge_reconfigure(const struct ovsrec_open_vswitch *ovs_cfg)

    TODO

static void bridge_delete_ofprotos(void)

    TODO

static ofp_port_t * add_ofp_port(ofp_port_t port, ofp_port_t *ports, size_t *n, size_t *allocated)

    将 port 加入 ports, 如果 ports 空间不够, 扩展 2 倍

static void bridge_delete_or_reconfigure_ports(struct bridge *br)

    TODO

static void bridge_add_ports__(struct bridge *br, const struct shash *wanted_ports, bool with_requested_port)

    将 wanted_ports 加入 br


static void bridge_add_ports(struct bridge *br, const struct shash *wanted_ports)

    将 wanted_ports 加入 br

static void port_configure(struct port *port)

    解析 port->cfg, TODO
    1. 配置 LACP
    2. 配置 BOND
    3. 配置 bundle

static void bridge_configure_datapath_id(struct bridge *br)

    1. 获取 br 的 mac 地址, 及 mac 对应的 hw_addr_iface. 参考 bridge_pick_local_hw_addr
    2. 从 br->ifaces 中找到 OFPP_LOCAL 对应的 local_iface, 并配置 local_iface 的 mac 为 br 的 mac
    3. 配置 br 的 dpid. 优先以 br->cfg->other_config 中 datapath-id 为准. 否则由 mac 地址映射
    3. 将生成的 dpid 写入 br->cfg

static uint32_t bridge_get_allowed_versions(struct bridge *br)

    由 br->cfg->protocols 每一位依次左移得到(br->cfg->n_protocols)

static void bridge_configure_netflow(struct bridge *br)

    解析 br->cfg->netflow 配置 netflow. TODO

static void bridge_configure_sflow(struct bridge *br, int *sflow_bridge_number)

    解析 br->cfg->sflow 配置 sflow. TODO

static void bridge_configure_ipfix(struct bridge *br)

    解析 br->cfg->ipfix 配置 sflow. TODO

static void port_configure_stp(const struct ofproto *ofproto, struct port *port, struct ofproto_port_stp_settings *port_s, int *port_num_counter, unsigned long *port_num_bitmap)

    解析 port->cfg->other_config 初始化 port_s.(其中 port_num_counter 记录目前配置的端口号, port_num_bitmap 保存全部已经配置端口号)

    1. internal 类型 iface 不参与 stp
    2. mirror 端口不参与 stp
    3. port->ifaces 必须大于 1
    4. 端口数不能超过 254
    5. 如果 stp-port-num 已经配置, 端口号不能在 port_num_bitmap 中

static void port_configure_rstp(const struct ofproto *ofproto, struct port *port, struct ofproto_port_rstp_settings *port_s, int *port_num_counter)

    解析 port->cfg->other_config 初始化 port_s.(其中 port_num_counter 记录目前配置的端口号, port_num_bitmap 保存全部已经配置端口号)

    1. internal 类型 iface 不参与 stp
    2. mirror 端口不参与 stp
    3. port->ifaces 必须大于 1
    4. 端口数不能超过 4094

static void bridge_configure_stp(struct bridge *br, bool enable_stp)

    TODO
    解析 br->cfg->other_config 调用 ofproto_set_stp(br->ofproto, NULL);
    解析 br->ports 每个 port 的 cfg 为 port_s, 调用ofproto_port_set_stp(br->ofproto, iface->ofp_port, &port_s)

static void bridge_configure_rstp(struct bridge *br, bool enable_rstp)

    TODO
    解析 br->cfg->other_config 调用 ofproto_set_stp(br->ofproto, NULL);
    解析 br->ports 每个 port 的 cfg 为 port_s, 调用 ofproto_port_set_rstp(br->ofproto, iface->ofp_port, port_s)

static void bridge_configure_spanning_tree(struct bridge *br)

    配置 stp
    配置 rstp
    注: 禁止通知配置 stp, rstp

static bool bridge_has_bond_fake_iface(const struct bridge *br, const char *name)

    当 br->ports 中 name 对应的 port 只有一个 iface, 并且 port->cfg->bond_fake_iface 不为 NULL.

static void add_del_bridges(const struct ovsrec_open_vswitch *cfg)

    1. 遍历 all_bridges 所有 bridge, 如果 bridge 不存在于 cfg->bridges 中或
    存在但是 bridge->type 与 cfg->bridges 对应类型不同, 销毁该 br

    2. 将存在于 cfg->bridges 但不存在于 all_bridges 的 bridge, 创建之.

static int iface_set_netdev_config(const struct ovsrec_interface *iface_cfg, struct netdev *netdev, char **errp)

    调用 netdev->netdev_class->set_config(netdev, iface_cfg ? iface_cfg: SMAP_INITIALIZER(&no_args));

static int iface_do_create(const struct bridge *br, const struct ovsrec_interface *iface_cfg, const struct ovsrec_port *port_cfg, ofp_port_t *ofp_portp, struct netdev **netdevp, char **errp)

    TODO

static bool iface_create(struct bridge *br, const struct ovsrec_interface *iface_cfg, const struct ovsrec_port *port_cfg)

    TODO

static void bridge_configure_forward_bpdu(struct bridge *br)

    br->ofproto->forward_bpdu 为 br->cfg->other_config:forward-bpdu

static void bridge_configure_mac_table(struct bridge *br)

    br->ofproto->ofproto_class->set_mac_table_config(br->cfg->other_config[mac-aging-time], br->cfg->other_config[mac-table-size])

static void bridge_configure_mcast_snooping(struct bridge *br)

    TODO
    ofproto_set_mcast_snooping(br->ofproto, &br_s)
    ofproto_port_set_mcast_snooping(br->ofproto, port, &port_s)

static void find_local_hw_addr(const struct bridge *br, uint8_t ea[ETH_ADDR_LEN], const struct port *fake_br, struct iface **hw_addr_iface)

    遍历 br->cfg 中的非镜像端口 port

    1) 如果满足以下所有条件:
        1) port->cfg->mac 不为空
        2) port->cfg->mac 与 port->ifaces 中某一个 iface 的 mac 相同 iface
        3) mac 地址合法
    将 port->cfg->mac 地址拷贝到 ea, hw_addr_iface 指向对应 iface

    2) 如果满足以下所有条件:
        1) port->cfg->mac 为空
        2) port->ifaces 中 name 最小 iface(按照字母排序)
        3) iface->ofp_port 不等于 OFPP_LOCAL
        4) 如果 fake_br 不为 NULL, port->cfg->tag == fake_br->cfg->tag
        5) mac 地址合法

        将 iface 的 mac 地址拷贝到 ea, hw_addr_iface 指向对应 iface

    3) 不满足 1,2
        将 br->default_ea 的 mac 地址拷贝到 ea, hw_addr_iface 指向 NULL

static void bridge_pick_local_hw_addr(struct bridge *br, uint8_t ea[ETH_ADDR_LEN], struct iface **hw_addr_iface)

    如果 br->cfg->other_config 中 hwaddr 不是广播或全 0 地址, 返回(ea 为 hwaddr, hw_addr_iface 为 NULL.)
    否则, 从 br->ports 中 找到合适的地址.  如果找到合适的, ea 为找到的 mac, hw_addr_iface 为 iface; 如果找不到合适的, ea 为 mac, hw_addr_iface 为 NULL.  参考 find_local_hw_addr

static uint64_t bridge_pick_datapath_id(struct bridge *br, const uint8_t bridge_ea[ETH_ADDR_LEN], struct iface *hw_addr_iface)

    配置 br 的 dpid. 优先以 br->cfg->other_config 中 datapath-id 为准. 否则由 mac 地址映射

static uint64_t dpid_from_hash(const void *data, size_t n)

    根据 sha1 生成 dpid

static void iface_refresh_netdev_status(struct iface *iface)

    更新网卡配置信息, 并写入数据库. TODO

static void iface_refresh_ofproto_status(struct iface *iface)

    TODO

static void iface_refresh_cfm_stats(struct iface *iface)

    TODO 获取 iface 的 cfm 状态信息,  设置 Interface 表中 cfm 相关配置

static void iface_refresh_stats(struct iface *iface)

    将 iface 的统计信息写入 Interface 表

static void br_refresh_datapath_info(struct bridge *br)

    设置 Bridge 的 datapath version

static void br_refresh_stp_status(struct bridge *br)

    设置 Bridge 的 stp_bridge_id, stp_designated_root, stp_root_path_cost

static void port_refresh_stp_status(struct port *port)

    设置 Port 的 stp_port_id, stp_state, stp_sec_in_state, stp_role

static void port_refresh_stp_stats(struct port *port)

    设置 Port 的 stp_tx_count, stp_rx_count, stp_error_count

static void br_refresh_rstp_status(struct bridge *br)

    设置 Bridge 的 rstp_bridge_id, rstp_root_path_cost,
    rstp_root_id, rstp_designated_id, rstp_designated_port_id
    rstp_bridge_port_id 状态

static void port_refresh_rstp_status(struct port *port)

    设置 Port 的 rstp_port_id, rstp_port_role, rstp_port_state
    rstp_designated_bridge_id, rstp_designated_port_id, rstp_designated_path_cost
    rstp_tx_count, rstp_rx_count, rstp_uptime, rstp_error_count

static void port_refresh_bond_status(struct port *port, bool force_update)

    设置 Port 的 bond_active_slave. 来源于 bond->active_slave_mac

static bool enable_system_stats(const struct ovsrec_open_vswitch *cfg)

    获取 Open_vSwitch 的 enable-statistics 状态

static void reconfigure_system_stats(const struct ovsrec_open_vswitch *cfg)

    重新配置 system-stats, 如果 enable 为 true, 创建一个新的线程, 固定间隔统计
    cpu, memory, process, filesys. 并写

static void run_system_stats(void)

    获取 system_stats 状态, 并写入 Open_vSwitch 的 statistics

static const char * ofp12_controller_role_to_str(enum ofp12_controller_role role)

    获取控制器 role

static void refresh_controller_status(void)

    获取与控制器连接状态, 写入 Controller 表(包括 is_connected, status, role)

static void run_stats_update(void)

    以固定间隔将 port, iface, mirror 的统计信息写入 ovsdb 数据库

static void stats_update_wait(void)

    如果当前没有其他事务在进行数据库操作, 设置当前线程的 poll-loop 超时为 stats_timer(即下一次获取统计信息的时间).
    如果当前有其他事务在进行数据库操作:
        如果事务的 status 不为 TXN_UNCOMMITTED, TXN_INCOMPLETE, 立即唤醒当前线程的 poll-loop;
        否则直接返回;

static struct json * where_uuid_equals(const struct uuid *uuid)

    生成如下 json 数据结构

    json->u.array.elems = {
        u.array.elems = {
            { u.string = "_uuid" }
            { u.string = "==" }
            { u.array.elems =
                { u.string = "uuid" }
                { u.string = "uuid as uuid format" }
              u.array.n = 2
              u.array.n_allocated = 2
            }


        }
        u.array.n = 3
        u.array.n_allocated = 3
    }
    json->u.array.n = 1
    json->u.array.n_allocated = 1

static char * uuid_name_from_uuid(const struct uuid *uuid)

    将 uuid 中的 "-" 替代为 "_"

static void run_status_update(void)

    如果 status_txn 为 NULL, 获取当前统计状态写入 ovsdb
    如果 status_txn 不为 NULL, 提交事务, 如果成功, 继续, 如果失败, 设置 status_txn_try_again 为 true
    检查 auto attach 是否需要更新

static void status_update_wait(void)

    如果 status_txn 不为 NULL, 并且不是 TXN_UNCOMMITTED, TXN_INCOMPLETE, 立即唤醒当前 poll-loop
    如果 status_txn 为 NULL, status_txn_try_again = true, 设置 poll-loop 下次唤醒数据为 100 ms 之后
    如果 status_txn 为 NULL, status_txn_try_again = false, 等待 connectivity_seqno 改变

static void bridge_run__(void)
{
    struct bridge *br;
    struct sset types;
    const char *type;

    /* Let each datapath type do the work that it needs to do. */
    sset_init(&types);
    /*
    * 调用 ofproto_classes 每个元素的 enumerate_types 方法初始化 types.(实际上 ofproto_classes
    * 只有 ofproto_dpif_class,types 仅包含 system, netdev)
    * 1. 注册 tunnel port, tunnel arp, dpctl, route 命令
    * 2. 将调用 dpif_netlink_class 和 dpif_netdev_class 初始化, 将其加入 dpif_classes
    * 3. 将 dpif_classes 中的每个元素的 type 加入 types(实际上 types 仅包含 system, netdev)
    */
    ofproto_enumerate_types(&types);
    /*
     * 调用 ofproto_dpif_class->type_run(type)
     * (实际调用 ofproto_dpif_class->type_run("system") 与 ofproto_dpif_class->type_run("netdev"))
     */
    SSET_FOR_EACH (type, &types) {
        ofproto_type_run(type);
    }
    sset_destroy(&types);

    /* Let each bridge do the work that it needs to do. */
    HMAP_FOR_EACH (br, node, &all_bridges) {
        /*
         * 1. 将 ofproto->pins 的所有包发送给控制器
         * 2. 运行 netflow, sflow, ipfix, boundle, stp, rstp, mac_learn, mcast_snooping, ofboundle
         * 3. 遍历 ofproto->up.ports 的每一个端口, 设置 ofport 相关成员
         * 4. 删除过期流表
         * 5. 遍历 ofproto->rule_executes 中的所有 execute 将 execute 构造为 Netlink 消息, 发送给内核,要求内核执行 execute 中指定的的 action
         * 6. 遍历 p->tables 的每张 table, 让每张 table 的所有的 rule,  如果 rule 不是永久存在流表, 如果不在 eviction_group,
         * 加入 eviction_group, 如果已经存在, 计算 rule->evg_node->priority, 并对 table->eviction_groups_by_size 进行重排序
         * 7. 从 ofproto->port_poll_set 中依次取出元素, 更新每个元素对应的 ofport, 直到 ofproto->port_poll_set 为 NULL 或发生错误.
         * 8. 当发生配置更新时, 遍历 ofport->ports 中每一个端口 port, 如果 port->change_seq != port->netdev->change_seq, 表明 port 属性已经更改,更新之
         * 9. 最主要的就是将包发送出去, 然后调用回调函数处理应答. 此外, connmgr 中其他运行起来
         */
        ofproto_run(br->ofproto);
    }
}

void bridge_run(void)
{
    static struct ovsrec_open_vswitch null_cfg;
    const struct ovsrec_open_vswitch *cfg;

    bool vlan_splinters_changed;

    ovsrec_open_vswitch_init(&null_cfg);

    ovsdb_idl_run(idl);

    if_notifier_run();

    if (ovsdb_idl_is_lock_contended(idl)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        struct bridge *br, *next_br;

        VLOG_ERR_RL(&rl, "another ovs-vswitchd process is running, "
                    "disabling this process (pid %ld) until it goes away",
                    (long int) getpid());

        HMAP_FOR_EACH_SAFE (br, next_br, node, &all_bridges) {
            bridge_destroy(br);
        }
        /* Since we will not be running system_stats_run() in this process
         * with the current situation of multiple ovs-vswitchd daemons,
         * disable system stats collection. */
        //调用 system_stats_thread_func() 定时间隔获取系统统计信息, 报告 CPU,Memory, Proce 等等
        system_stats_enable(false);
        return;
    } else if (!ovsdb_idl_has_lock(idl)
               || !ovsdb_idl_has_ever_connected(idl)) {
        /* Returns if not holding the lock or not done retrieving db
         * contents. */
        return;
    }
    cfg = ovsrec_open_vswitch_first(idl);

    /* Initialize the ofproto library.  This only needs to run once, but
     * it must be done after the configuration is set.  If the
     * initialization has already occurred, bridge_init_ofproto()
     * returns immediately. */
    bridge_init_ofproto(cfg);

    /* Once the value of flow-restore-wait is false, we no longer should
     * check its value from the database. */
    if (cfg && ofproto_get_flow_restore_wait()) {
        ofproto_set_flow_restore_wait(smap_get_bool(&cfg->other_config,
                                        "flow-restore-wait", false));
    }

    bridge_run__();

    /* Re-configure SSL.  We do this on every trip through the main loop,
     * instead of just when the database changes, because the contents of the
     * key and certificate files can change without the database changing.
     *
     * We do this before bridge_reconfigure() because that function might
     * initiate SSL connections and thus requires SSL to be configured. */
    if (cfg && cfg->ssl) {
        const struct ovsrec_ssl *ssl = cfg->ssl;

        stream_ssl_set_key_and_cert(ssl->private_key, ssl->certificate);
        stream_ssl_set_ca_cert_file(ssl->ca_cert, ssl->bootstrap_ca_cert);
    }

    /* If VLAN splinters are in use, then we need to reconfigure if VLAN
     * usage has changed. */
    vlan_splinters_changed = false;
    if (vlan_splinters_enabled_anywhere) {
        struct bridge *br;

        HMAP_FOR_EACH (br, node, &all_bridges) {
            if (ofproto_has_vlan_usage_changed(br->ofproto)) {
                vlan_splinters_changed = true;
                break;
            }
        }
    }

    if (ovsdb_idl_get_seqno(idl) != idl_seqno || vlan_splinters_changed
        || ifaces_changed) {
        struct ovsdb_idl_txn *txn;

        ifaces_changed = false;

        idl_seqno = ovsdb_idl_get_seqno(idl);
        txn = ovsdb_idl_txn_create(idl);
        bridge_reconfigure(cfg ? cfg : &null_cfg);

        if (cfg) {
            ovsrec_open_vswitch_set_cur_cfg(cfg, cfg->next_cfg);
            discover_types(cfg);
        }

        /* If we are completing our initial configuration for this run
         * of ovs-vswitchd, then keep the transaction around to monitor
         * it for completion. */
        if (initial_config_done) {
            /* Always sets the 'status_txn_try_again' to check again,
             * in case that this transaction fails. */
            status_txn_try_again = true;
            ovsdb_idl_txn_commit(txn);
            ovsdb_idl_txn_destroy(txn);
        } else {
            initial_config_done = true;
            daemonize_txn = txn;
        }
    }

    if (daemonize_txn) {
        enum ovsdb_idl_txn_status status = ovsdb_idl_txn_commit(daemonize_txn);
        if (status != TXN_INCOMPLETE) {
            ovsdb_idl_txn_destroy(daemonize_txn);
            daemonize_txn = NULL;

            /* ovs-vswitchd has completed initialization, so allow the
             * process that forked us to exit successfully. */
            daemonize_complete();

            vlog_enable_async();

            VLOG_INFO_ONCE("%s (Open vSwitch) %s", program_name, VERSION);
        }
    }

    run_stats_update();
    run_status_update();
    run_system_stats();
}

void bridge_wait(void)
{
    struct sset types;
    const char *type;

    ovsdb_idl_wait(idl);
    if (daemonize_txn) {
        ovsdb_idl_txn_wait(daemonize_txn);
    }

    if_notifier_wait();
    //
    if (ifaces_changed) {
        poll_immediate_wake();
    }

    sset_init(&types);
    //将 ofproto_classes 每个元素的 enumerate_types 方法, 将每个元素 type 加入 types
    ofproto_enumerate_types(&types);
    //遍历 ofproto_classes 每个元素, 调用每个元素的 type_wait 方法
    SSET_FOR_EACH (type, &types) {
        ofproto_type_wait(type);
    }
    sset_destroy(&types);

    if (!hmap_is_empty(&all_bridges)) {
        struct bridge *br;

        HMAP_FOR_EACH (br, node, &all_bridges) {
            ofproto_wait(br->ofproto);
        }
        stats_update_wait();
        status_update_wait();
    }

    system_stats_wait();
}


void bridge_get_memory_usage(struct simap *usage)

    命令 ovs-appctl memory/show 的执行函数.

    例子:
    handlers:5 ofconns:1 ports:11 revalidators:3 rules:19

static void qos_unixctl_show_queue(unsigned int queue_id, const struct smap *details, struct iface *iface, struct ds *ds)

    将参数 queue_id, details, 以及 iface->netdev 的统计信息写入 ds

    包括:
    Queue:queue_id
    tx_packets
    tx_bytes
    tx_errors


static void qos_unixctl_show(struct unixctl_conn *conn, int argc OVS_UNUSED, const char *argv[], void *aux OVS_UNUSED)

    获取 argv[0] 接口对应的 Qos

    ovs-appctl qos/show 命令对应的回调函数

static void bridge_create(const struct ovsrec_bridge *br_cfg)

    根据 br_cfg 创建 bridge, 并且将其加入 all_bridges

static void bridge_destroy(struct bridge *br)

    销毁一个 bridge

static struct bridge * bridge_lookup(const char *name)

    根据 name 从 all_bridges 中查找 name 对应的 bridge

static void bridge_unixctl_dump_flows(struct unixctl_conn *conn, int argc OVS_UNUSED, const char *argv[], void *aux OVS_UNUSED)

    输出所有流表

    ovs-appctl bridge/dump-flows 命令对应的回调函数

static void bridge_unixctl_reconnect(struct unixctl_conn *conn, int argc, const char *argv[], void *aux OVS_UNUSED)

    如果配置 bridge, 只将 bridge 与控制器重新连接
    如果没有配置 bridge, 将所有 bridge 与控制器重新连接

    ovs-appctl bridge/reconnect [bridge] 命令对应的回调函数

static size_t bridge_get_controllers(const struct bridge *br, struct ovsrec_controller ***controllersp)

    读取 br->cfg->controller, br->cfg->n_controllers, 返回 br->cfg->n_controller; controllersp 指向 br->cfg->controller

static void bridge_collect_wanted_ports(struct bridge *br, const unsigned long int *splinter_vlans, struct shash *wanted_ports)

    配置 br->synth_local_ifacep, br->synth_local_port, br->synth_local_iface
    如果 br 控制器配置不为空, 加入 wanted_ports
    TODO

static void bridge_del_ports(struct bridge *br, const struct shash *wanted_ports)

    TODO

static void bridge_ofproto_controller_for_mgmt(const struct bridge *br, struct ofproto_controller *oc)

    初始化进程间通信的 oc

static void bridge_ofproto_controller_from_ovsrec(const struct ovsrec_controller *c, struct ofproto_controller *oc)

    解析 c 配置 oc

static void bridge_configure_local_iface_netdev(struct bridge *br, struct ovsrec_controller *c)

    解析 c 的 local_netmask, local_ip, local_gateway , 配置 br 的 local iface

static bool equal_pathnames(const char *a, const char *b, size_t b_stoplen)

    判断　a 和 b 的路径是否相同

static void bridge_configure_remotes(struct bridge *br, const struct sockaddr_in *managers, size_t n_managers)

    解析 br->cfg, 配置 controller, snoop 两种模式

static void bridge_configure_tables(struct bridge *br)

    TODO 设置 ofproto->tables[table_id]

static void bridge_configure_dp_desc(struct bridge *br)

    配置 br->ofproto 中 (br->cfg->other_config, "dp-desc")

static struct aa_mapping * bridge_aa_mapping_find(struct bridge *br, const int64_t isid)

    从 br->mappings 找到与 isid 对应的 aa_mapping

static struct aa_mapping * bridge_aa_mapping_create(struct bridge *br, const int64_t isid, const int64_t vlan)

    创建一个 aa_mapping, 并加入 br

static void bridge_aa_mapping_destroy(struct aa_mapping *m)

    销毁 aa_mapping

static bool bridge_aa_mapping_configure(struct aa_mapping *m)

    TODO
    调用 ofproto->ofproto_class->aa_mapping_set

static void bridge_configure_aa(struct bridge *br)

    配置 br->mappings 与 br->cfg->auto_attach 一致. 以 br->cfg->auto_attach
    为准. 不存在的 br->mappings 删除, 存在加入 br->mappings

static bool bridge_aa_need_refresh(struct bridge *br)

    TODO 返回 ofproto->ofproto_class->aa_vlan_get_queue_size(ofproto) > 0

static void bridge_aa_update_trunks(struct port *port, struct bridge_aa_vlan *m)

    根据 m->oper 将 m->vlan 从 port->cfg->trunk 中加入或删除. 之后更新 Port 的 trunks, vlan_mode 记录

static void bridge_aa_refresh_queued(struct bridge *br)

    TODO

static struct port * port_create(struct bridge *br, const struct ovsrec_port *cfg)

    创建一个 port, 将其加入 br->ports

static void port_del_ifaces(struct port *port)

    将 port->ifaces 中不存在于 port->cfg->interfaces 的 iface 销毁

static void port_destroy(struct port *port)

    销毁 port

static struct port * port_lookup(const struct bridge *br, const char *name)

    从 br 中找到 name 对应的 port

static bool enable_lacp(struct port *port, bool *activep)

    获取 port->cfg->lacp 状态(Port 中的 lacp)

static struct lacp_settings * port_configure_lacp(struct port *port, struct lacp_settings *s)

    解析 port 的 other_config, 保存到 s 中

    other_config:lacp-system-id : 配置 lacp id(当前选项没有配置时, 为 port 所属 br 的 mac)
    other_config:lacp-system-priority : 默认 0
    other_config:lacp-time : fast
    other_config:lacp-fallback-ab : true | false(default)

static void iface_configure_lacp(struct iface *iface, struct lacp_slave_settings *s)

    解析 iface 的 other_config 保存在 s 中

    other_config:lacp-port-id : 0(default)
    other_config:lacp-port-priority : 0(default)
    other_config:lacp-aggregation-key : 0(default)

static void port_configure_bond(struct port *port, struct bond_settings *s)

    解析 port->cfg 保存在 s 中

    bond_mode : BM_AB | BM_TCP | BM_SLB
    bond-miimon-interval : 200(default)
    bond-detect-mode : carrier | miimon
    bond-hash-basis : 0
    bond_updelay : 0(default)
    bond_downdelay : 0(default)
    bond-rebalance-interval : 10000(default)
    bond_active_slave
    lacp-fallback-ab

    当 bond-detect-mode 为  carrier 或 miimon, miimon_interval 为 0
    与 Bridge 的 n_flood_vlans 冲突

static bool port_is_synthetic(const struct port *port)

    返回 port->cfg->header_->table != NULL

static bool iface_is_internal(const struct ovsrec_interface *iface, const struct ovsrec_bridge *br)

    检查 iface 是否是 internal 类型端口

    返回 iface->type == "internal" | br->name == iface->name

static const char * iface_get_type(const struct ovsrec_interface *iface, const struct ovsrec_bridge *br)

    获取 iface 的端口类型. internal, system 或其他

static void iface_destroy__(struct iface *iface)

    销毁 iface

static void iface_destroy(struct iface *iface)

    销毁 iface, 如果 iface 所属的 port 没有任何 iface, 销毁 port

static struct iface * iface_lookup(const struct bridge *br, const char *name)

    从 br->iface_by_name 找到 name 对应的 iface

static struct iface * iface_find(const char *name)

    遍历 all_bridges 中每个 bridge->iface_by_name 找到 name 对应的 iface

static struct iface * iface_from_ofp_port(const struct bridge *br, ofp_port_t ofp_port)

    遍历 br->ifaces 找到 ofp_port 对应的 iface.

static void iface_set_mac(const struct bridge *br, const struct port *port, struct iface *iface)

    读取 Interface 的 mac(如果没有设置, Port 的 mac 或 Port name 最小的 iface 的 mac), 设置 iface 的 mac 地址

static void iface_set_ofport(const struct ovsrec_interface *if_cfg, ofp_port_t ofport)

    设置 Interface 的 ofport

static void iface_clear_db_record(const struct ovsrec_interface *if_cfg, char *errp)

    如果 if_cfg 不是合成的, 初始化 if_cfg

static bool queue_ids_include(const struct ovsdb_datum *queues, int64_t target)

    target 是否存在于 queues 中

static void iface_configure_qos(struct iface *iface, const struct ovsrec_qos *qos)

    TODO
    以 qos 为准配置 iface 的 Qos.(如果 iface 存在 qos 不存在的删除之)

    Interface
        ingress_policing_rate
        ingress_policing_burst
        type

static void iface_configure_cfm(struct iface *iface)

    TODO
    以 iface->cfg 为准配置 iface 的 cfm

static bool iface_is_synthetic(const struct iface *iface)

    返回 iface->cfg->header_->table == NULL

static ofp_port_t iface_validate_ofport__(size_t n, int64_t *ofport)

    1 < ofport < 0xff00 返回 ofport, 否则返回 OFPP_NONE

static ofp_port_t iface_get_requested_ofp_port(const struct ovsrec_interface *cfg)

    返回 cfg->ofport_request

static ofp_port_t iface_pick_ofport(const struct ovsrec_interface *cfg)

    如果 cfg->ofport_request 合法, 返回 cfg->ofport_request.
    否则返回 cfg->ofport

static struct mirror * mirror_find_by_uuid(struct bridge *br, const struct uuid *uuid)

    从 br->mirrors 找到 uuid 对应的 mirror

static void bridge_configure_mirrors(struct bridge *br)

    将 br->mirrors 中不存在于 br->cfg 的 mirror 删除
    将 br->cfg 中存在但是 br->mirrors 不存在, 创建 mirror

static struct mirror * mirror_create(struct bridge *br, const struct ovsrec_mirror *cfg)

    创建 mirror, 加入 br->mirrors

static void mirror_destroy(struct mirror *m)

    销毁 mirror

static void mirror_collect_ports(struct mirror *m, struct ovsrec_port **in_ports, int n_in_ports, void ***out_portsp, size_t *n_out_portsp)

    如果 in_ports 中的元素可用在 br 找到, 加入 out_portsp.(找不到的会被忽略)

static bool mirror_configure(struct mirror *m)

    读取 m->cfg 配置 mirror

    ofproto_mirror_register(m->bridge->ofproto, m, &s);

static void register_rec(struct ovsrec_port *rec)

    将 rec 加入 recs

static void free_registered_recs(void)

    销毁 recs

static bool vlan_splinters_is_enabled(const struct ovsrec_interface *iface_cfg)

    获取 Interface 的 enable-vlan-splinters 值

static unsigned long int * collect_splinter_vlans(const struct ovsrec_open_vswitch *ovs_cfg)

    TODO

static void configure_splinter_port(struct port *port)

    从 port->bridge->iface_by_name 找到 port->cfg->realdev 对应的 realdev. 调用
    ofproto->ofproto_class->set_realdev TODO


static struct ovsrec_port * synthesize_splinter_port(const char *real_dev_name, const char *vlan_dev_name, int vid)

    以传入参数创建一个 ovsrec_port  加入 recs. 返回该 ovsrec_port

static void add_vlan_splinter_ports(struct bridge *br, const unsigned long int *splinter_vlans, struct shash *ports)

    TODO

static void mirror_refresh_stats(struct mirror *m)

    TODO
    调用 ofproto_mirror_get_stats(ofproto, m, &tx_packets, &tx_bytes)
    获取 mirror 的统计信息, 写入 m->cfg

static void discover_types(const struct ovsrec_open_vswitch *cfg)

    TODO
    调用 dp_enumerate_types(&types) 获取 types, 设置 Bridge 的 datapath_types 和 Interface 的 iface_type
