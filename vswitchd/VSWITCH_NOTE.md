ovs-vsctl set Open_vSwitch . other-config:n-handler-threads=1 other-config:n-revalidator-threads=1
ovs-vsctl --no-wait set Open_vSwitch .  other_config:n-handler-threads=1
ovs-vsctl get bridge br0  other-config:flow-eviction-threshold
ovs-dpctl show
top -p `pidof ovs-vswitch` -H

ovs-vsctl set Bridge br0 flow_tables:0=@N1 -- \
--id=@N1 create Flow_Table name=table0

ovs-vsctl set Bridge br0 flow_tables:1=@N1 -- \
--id=@N1 create Flow_Table name=table1

ovs-vsctl set Flow_Table table0 prefixes=ip_dst,ip_src
ovs-vsctl set Flow_Table table1 prefixes=[]

http://openvswitch.org/pipermail/discuss/2014-December/015968.html


数据结构

Open_vSwitch
    Bridge
        name
        datapath_types
        protocols : 10,11,12,13,14,15
        fail_mode : standalone, secure
        status
        mcast_snooping_enable
        stp_enable
        rstp_enable
        rstp_status
        flow_tables
        Port
            Interface
                name
                type
                ingress_policing_rate
                ingress_policing_burst
                mac_in_use
                mac
                ifindex
                ofport
                ofport_request
                bfd
                bfd_status
                cfm_mpid
                cfm_remote_mpids
                cfm_flap_count
                cfm_fault
                cfm_fault_status
                cfm_remote_opstate: up, down
                cfm_health
                lacp_current
                lldp
                statistics
                status
                admin_state: up, down
                link_state
                link_resets
                link_speed
                duplex
                mtu
            vlan_mode : trunks, access, native-tagged, native-untagged
            Qos
                Queues
            mac
            bond_mode : balance-tcp, balance-slb, active-backup
            lacp      : active, passive, off
        Mirror
            name
            select_all
            select_src_port
            select_dst_port
            select_vlan
            output_port
            output_vlan
            statistics
        NetFlow
            targets
            engine_type
        sFlow
            targets
            sampling
            polling
            header
            agent
        IPFIX
            targets
            sampling
            obs_domain_id
            obs_point_id
            cache_max_flows
        Controller
            targets
            max_backoff
            inactivity_probe
            connection_mode : in-band, out-of-band
            local_ip
            local_netmask
            local_gateway
            enable_async_messages
            controller_rate_limit
            controller_burst_limit
            is_connected
            role : other, master, slave
            status

        Flow_Table : 0 ~ 254
            name
            flow_limit
            overflow_policy
            groups
            prefixes

        AutoAttach
            system_name
            system_description
            mappings

    Manager
        targets
        max_backoff
        inactivity_probe
        connection_mode
        is_connected
        status

    SSL
        private_key
        certificate
        ca_cert
        bootstrap_ca_cert

    Flow_Sample_Collector_Set
    IPFIX

运行顺序

    bridge_init()
        ovsdb_idl_create()

    bridge_run()
        ovsdb_idl_run(idl)
            jsonrpc_session_run(idl->session);
                jsonrpc_run(rpc)

        bridge_run__();
            ofproto_run(br->ofproto)

    unixctl_server_run(struct unixctl_server *server)
        run_connection(conn)
            jsonrpc_run(conn->rpc)
            jsonrpc_recv(conn->rpc, msg)
            process_command(conn, msg)

void bridge_init(const char *remote)

void bridge_run(void)

struct ovsdb_idl ovsdb_idl_create(request, class, true,true)

    初始化一个 ovsdb_idl 结构对象

void ovsdb_idl_run(struct ovsdb_idl *idl)

void jsonrpc_session_run(struct jsonrpc_session *s)
    1. s->pstream 不为空, ps->pstream 接受请求, 如果收到请求, 通过 s->reconnect
    确认链路是否连接, 初始化 s->rpc

void jsonrpc_run(struct jsonrpc *rpc)

    从 rpc->output 中取出元素, 发送到 rpc-stream

void unixctl_server_run(struct unixctl_server *server)

    pstream_accept() 接受请求, 初始化 10 个 server->conns
    对应每个 server->conns 元素, 接受请求,  处理请求

static init run_connection(struct unixctl_conn *conn)

static void process_command(struct unixctl_conn *conn, struct jsonrpc_msg *request)

    定义 struct unixctl_command *command;
    1. 从 request->params 中提取到 argv
    2. request->method 中初始化 command
    3. 调用 command->cb(conn, argv, argv.names, command->aux);


支持的命令

    unixctl_command_register("list-commands", "", 0, 0, unixctl_list_commands,
                             NULL);
    unixctl_command_register("version", "", 0, 0, unixctl_version, NULL);

    unixctl_command_register("qos/show", "interface", 1, 1,
                             qos_unixctl_show, NULL); unixctl_command_register("bridge/dump-flows", "bridge", 1, 1,
                             bridge_unixctl_dump_flows, NULL);
    unixctl_command_register("bridge/reconnect", "[bridge]", 0, 1,
                             bridge_unixctl_reconnect, NULL);

    //lacp_init()
    unixctl_command_register("lacp/show", "[port]", 0, 1,
                             lacp_unixctl_show, NULL);
    //bond_init()
    unixctl_command_register("bond/list", "", 0, 0, bond_unixctl_list, NULL);
    unixctl_command_register("bond/show", "[port]", 0, 1, bond_unixctl_show,
                             NULL);
    unixctl_command_register("bond/migrate", "port hash slave", 3, 3,
                             bond_unixctl_migrate, NULL);
    unixctl_command_register("bond/set-active-slave", "port slave", 2, 2,
                             bond_unixctl_set_active_slave, NULL);
    unixctl_command_register("bond/enable-slave", "port slave", 2, 2,
                             bond_unixctl_enable_slave, NULL);
    unixctl_command_register("bond/disable-slave", "port slave", 2, 2,
                             bond_unixctl_disable_slave, NULL);
    unixctl_command_register("bond/hash", "mac [vlan] [basis]", 1, 3,
                             bond_unixctl_hash, NULL);
    //cfm_init();
    unixctl_command_register("cfm/show", "[interface]", 0, 1, cfm_unixctl_show,
                             NULL);
    unixctl_command_register("cfm/set-fault", "[interface] normal|false|true",
                             1, 2, cfm_unixctl_set_fault, NULL);
    //bfd_init();
    unixctl_command_register("bfd/show", "[interface]", 0, 1,
                             bfd_unixctl_show, NULL);
    unixctl_command_register("bfd/set-forwarding",
                             "[interface] normal|false|true", 1, 2,
                             bfd_unixctl_set_forwarding_override, NULL);
    //ovs_numa_init();

    //stp_init()
    unixctl_command_register("stp/tcn", "[bridge]", 0, 1, stp_unixctl_tcn,
                             NULL);

    //lldp_init()
    unixctl_command_register("autoattach/status", "[bridge]", 0, 1,
                             aa_unixctl_status, NULL);
    unixctl_command_register("autoattach/show-isid", "[bridge]", 0, 1,
                             aa_unixctl_show_isid, NULL);
    unixctl_command_register("autoattach/statistics", "[bridge]", 0, 1,
                             aa_unixctl_statistics, NULL);



    unixctl_command_register("exit", "", 0, 0, ovs_vswitchd_exit, &exiting);

    unixctl_command_register("memory/show", "", 0, 0, memory_unixctl_show, NULL);


