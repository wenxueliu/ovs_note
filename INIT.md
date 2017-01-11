
## 系统初始化

命令行参数

        {"help",        no_argument, NULL, 'h'},
        {"version",     no_argument, NULL, 'V'},
        {"mlockall",    no_argument, NULL, OPT_MLOCKALL},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        {"detach",             no_argument, NULL, OPT_DETACH},
        {"no-chdir",           no_argument, NULL, OPT_NO_CHDIR},
        {"pidfile",            optional_argument, NULL, OPT_PIDFILE},
        {"pipe-handle",        required_argument, NULL, OPT_PIPE_HANDLE},
        {"service",            no_argument, NULL, OPT_SERVICE},
        {"service-monitor",    no_argument, NULL, OPT_SERVICE_MONITOR}
        {"verbose",       optional_argument, NULL, 'v'},
        {"log-file",      optional_argument, NULL, OPT_LOG_FILE},
        {"syslog-target", required_argument, NULL, OPT_SYSLOG_TARGET}
        {"private-key", required_argument, NULL, 'p'},
        {"certificate", required_argument, NULL, 'c'},
        {"ca-cert",     required_argument, NULL, 'C'}
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        {"enable-dummy", optional_argument, NULL, OPT_ENABLE_DUMMY},
        {"disable-system", no_argument, NULL, OPT_DISABLE_SYSTEM},
        {"dpdk", required_argument, NULL, OPT_DPDK},
        {NULL, 0, NULL, 0},

推荐运行命令选项

    --mlockall
    --verbose : 日志级别
    --log-file: 日志文件路径
    --detach  : daemon 模式

没有文档的选项

    --detach : 2.3.2 不起所用
    --no-chdir :
    --unixctl :
    --pipe-handle :   注:选项没有文档化
    --service : 什么也没做
    --service-monitor : 2.3.2 不起所用
    --enable-dummy :
    --disable-system: 禁止 system 类型的 dp 注册

    更多 man ovs-vswitch

int main(int argc, char *argv[]) {
    char *unixctl_path = NULL;
    struct unixctl_server *unixctl;
    char *remote;
    bool exiting;
    int retval;

    set_program_name(argv[0]);
    //2.3.2 不支持 dpdk, 直接返回 0
    retval = dpdk_init(argc,argv);
    argc -= retval;
    argv += retval;

    //拷贝命令行参数内容, 初始化 argv_size , argv_start
    proctitle_init(argc, argv);
    //仅仅 windows 系统起作用
    service_start(&argc, &argv);
    /*
     * 解析命令行参数, 并进行对应的配置,
     * 返回与 ovsdb 通信的方法, 默认 unix:/usr/local/var/run/openvswitch/db.sock
     */
    remote = parse_options(argc, argv, &unixctl_path);
    //仅仅 windows 系统起作用
    fatal_ignore_sigpipe();
    //初始化 ovs 的所有表结构, 在文件 lib/vswitch-idl.c
    ovsrec_init();

    //根据配置选项是否将当前进程进入后台, 是否监控当前进程
    daemonize_start();

    if (want_mlockall) {
#ifdef HAVE_MLOCKALL
        if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
            VLOG_ERR("mlockall failed: %s", ovs_strerror(errno));
        }
#else
        VLOG_ERR("mlockall not supported on this system");
#endif
    }

    /*
     * 当前进程监听 unix socket, 外部 appctl 可用通过 unix 控制当前进程
     * 2.3.2 目前支持的命令
     *      help
     *      version
     *      exit
     *      qos/show
     *      bridge/dump-flows
     *      bridge/reconnect
     *      memory/show
     */
    retval = unixctl_server_create(unixctl_path, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovs_vswitchd_exit, &exiting);

    //设置与 ovsdb 数据库的所有表, 列, 行及选项, lacp, bond, cfm, stp 初始化
    bridge_init(remote);
    free(remote);

    exiting = false;
    while (!exiting) {
        /*
         * 检查是否到达下一次检查当前进程资源占用时间(间隔时 10 s).
         * 如果到达, 报告资源占用情况;
         * 如果没有到达, 返回
         * 注: 只有上次到这次 rss 增加超过 50 % 才通过日志报告
         */
        memory_run();
        /*
         * 检查是否应该报告资源占用情况:
         * 1. 到达下一次报告间隔
         * 2. 当前在执行 ovs-appctl memory/show 命令
         */
        if (memory_should_report()) {
            struct simap usage;

            simap_init(&usage);
            //报告统计信息, 即应答 ovs-appctl memory/show 命令请求
            bridge_get_memory_usage(&usage);
            memory_report(&usage);
            simap_destroy(&usage);
        }
        bridge_run();
        /*
         * 接收连接, 初始化 unixctl->conns, 与客户端建立连接:
         * 1. 给客户端发送请求,
         * 2. 处理客户端的应答
         * 3. 出错关闭连接
         */
        unixctl_server_run(unixctl);
        /*
         * 遍历 netdev_classes 每个元素并调用对应的 run 方法
         * netdev_dpdk_class
         * netdev_linux_class
         * netdev_internal_class
         * netdev_tap_class
         * netdev_bsd_class
         *  { "patch", VPORT_FUNCTIONS(get_patch_config, set_patch_config, NULL, NULL) }};
         *  { gre, VPORT_FUNCTIONS(get_tunnel_config, set_tunnel_config, get_netdev_tunnel_config, tunnel_get_status) }}
         *  { ipsec_gre64, VPORT_FUNCTIONS(get_tunnel_config, set_tunnel_config, get_netdev_tunnel_config, tunnel_get_status) }}
         *  { gre64, VPORT_FUNCTIONS(get_tunnel_config, set_tunnel_config, get_netdev_tunnel_config, tunnel_get_status) }}
         *  { ipsec_gre64, VPORT_FUNCTIONS(get_tunnel_config, set_tunnel_config, get_netdev_tunnel_config, tunnel_get_status) }}
         *  { vxlan, VPORT_FUNCTIONS(get_tunnel_config, set_tunnel_config, get_netdev_tunnel_config, tunnel_get_status) }}
         *  { lisp, VPORT_FUNCTIONS(get_tunnel_config, set_tunnel_config, get_netdev_tunnel_config, tunnel_get_status) }}
         */
        netdev_run();

        /*
         * 检查是否应该报告资源占用情况:
         * 1. 上面 memory_run 执行发现到达报告间隔
         * 2. 2. 当前在执行 ovs-appctl memory/show 命令
         *
         * 如果满足上述任一条件立即设置当前线程的 poll_loop 超时为 0
         */
        memory_wait();
        /*
         * 满足下面任一条件 poll_loop 立即唤醒:
         * 1. 网卡配置改变
         * 2. 调用每个 datapath_type 的 type_wait 方法
         */
        bridge_wait();
        unixctl_server_wait(unixctl);
        netdev_wait();
        if (exiting) {
            poll_immediate_wake();
        }
        /*
         * 满足如下条件退出
         * 1. 到达下一次报告资源占用时间点.(通过 memory_wait 控制)
         * 2. 
         */
        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
    }
    bridge_exit();
    unixctl_server_destroy(unixctl);
    service_stop();

    return 0;
}


void bridge_run(void) {
    static struct ovsrec_open_vswitch null_cfg;
    const struct ovsrec_open_vswitch *cfg;

    bool vlan_splinters_changed;
    struct bridge *br;
    int stats_interval;

    ovsrec_open_vswitch_init(&null_cfg);

    ovsdb_idl_run(idl);

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
        system_stats_enable(false);
        return;
    } else if (!ovsdb_idl_has_lock(idl)) {
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
        HMAP_FOR_EACH (br, node, &all_bridges) {
            if (ofproto_has_vlan_usage_changed(br->ofproto)) {
                vlan_splinters_changed = true;
                break;
            }
        }
    }

    if (ovsdb_idl_get_seqno(idl) != idl_seqno || vlan_splinters_changed) {
        struct ovsdb_idl_txn *txn;

        idl_seqno = ovsdb_idl_get_seqno(idl);
        txn = ovsdb_idl_txn_create(idl);
        bridge_reconfigure(cfg ? cfg : &null_cfg);

        if (cfg) {
            ovsrec_open_vswitch_set_cur_cfg(cfg, cfg->next_cfg);
        }

        /* If we are completing our initial configuration for this run
         * of ovs-vswitchd, then keep the transaction around to monitor
         * it for completion. */
        if (initial_config_done) {
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

    /* Statistics update interval should always be greater than or equal to
     * 5000 ms. */
    if (cfg) {
        stats_interval = MAX(smap_get_int(&cfg->other_config,
                                          "stats-update-interval",
                                          5000), 5000);
    } else {
        stats_interval = 5000;
    }
    if (stats_timer_interval != stats_interval) {
        stats_timer_interval = stats_interval;
        stats_timer = LLONG_MIN;
    }

    /* Refresh interface and mirror stats if necessary. */
    if (time_msec() >= stats_timer && cfg) {
        enum ovsdb_idl_txn_status status;

        /* Rate limit the update.  Do not start a new update if the
         * previous one is not done. */
        if (!stats_txn) {
            stats_txn = ovsdb_idl_txn_create(idl);
            HMAP_FOR_EACH (br, node, &all_bridges) {
                struct port *port;
                struct mirror *m;

                HMAP_FOR_EACH (port, hmap_node, &br->ports) {
                    struct iface *iface;

                    LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
                        iface_refresh_stats(iface);
                    }
                    port_refresh_stp_stats(port);
                }
                HMAP_FOR_EACH (m, hmap_node, &br->mirrors) {
                    mirror_refresh_stats(m);
                }
            }
            refresh_controller_status();
        }

        status = ovsdb_idl_txn_commit(stats_txn);
        if (status != TXN_INCOMPLETE) {
            stats_timer = time_msec() + stats_timer_interval;
            ovsdb_idl_txn_destroy(stats_txn);
            stats_txn = NULL;
        }
    }

    if (!status_txn) {
        uint64_t seq;

        /* Check the need to update status. */
        seq = seq_read(connectivity_seq_get());
        if (seq != connectivity_seqno || force_status_commit) {
            connectivity_seqno = seq;
            status_txn = ovsdb_idl_txn_create(idl);
            HMAP_FOR_EACH (br, node, &all_bridges) {
                struct port *port;

                br_refresh_stp_status(br);
                HMAP_FOR_EACH (port, hmap_node, &br->ports) {
                    struct iface *iface;

                    port_refresh_stp_status(port);
                    port_refresh_bond_status(port, force_status_commit);
                    LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
                        iface_refresh_netdev_status(iface);
                        iface_refresh_ofproto_status(iface);
                    }
                }
            }
        }
    }

    if (status_txn) {
        enum ovsdb_idl_txn_status status;

        status = ovsdb_idl_txn_commit(status_txn);

        /* If the transaction is incomplete or fails, 'status_txn'
         * needs to be committed next iteration of bridge_run() even if
         * connectivity or netdev sequence numbers do not change. */
        if (status == TXN_SUCCESS || status == TXN_UNCHANGED)
        {
            force_status_commit = false;
        } else {
            force_status_commit = true;
        }

        /* Do not destroy "status_txn" if the transaction is
         * "TXN_INCOMPLETE". */
        if (status != TXN_INCOMPLETE) {
            ovsdb_idl_txn_destroy(status_txn);
            status_txn = NULL;
        }
    }

    run_system_stats();
}


void unixctl_server_run(struct unixctl_server *server) {
    struct unixctl_conn *conn, *next;
    int i;

    if (!server) {
        return;
    }

    for (i = 0; i < 10; i++) {
        struct stream *stream;
        int error;

        error = pstream_accept(server->listener, &stream);
        if (!error) {
            struct unixctl_conn *conn = xzalloc(sizeof *conn);
            list_push_back(&server->conns, &conn->node);
            conn->rpc = jsonrpc_open(stream);
        } else if (error == EAGAIN) {
            break;
        } else {
            VLOG_WARN_RL(&rl, "%s: accept failed: %s",
                         pstream_get_name(server->listener),
                         ovs_strerror(error));
        }
    }

    LIST_FOR_EACH_SAFE (conn, next, node, &server->conns) {
        int error = run_connection(conn);
        if (error && error != EAGAIN) {
            kill_connection(conn);
        }
    }
}





char * long_options_to_short_options(const struct option options[])

    解析 options 每个元素, 将 option.val 加入命令字符串返回.
    如果 required_argument, optional_argument 后面见 ":".

    如果
        {"help",        no_argument, NULL, 'h'},
        {"pidfile",            optional_argument, NULL, OPT_PIDFILE},
    解析成 "hp:"


