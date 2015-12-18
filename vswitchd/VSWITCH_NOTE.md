##基本概念

参考 ofproto-provider.h

###ofproto

交换机

###ofport

端口

###rule

流表

###ofgroup


配置

flow-restore-wait : true | false, false : 删除所有流表
flow-limit : 在flow table中flow entry的数量
stats-update-interval ：将统计信息写入数据库的间隔时间

flow-restore-wait :

 为hot-upgrade使用的，如果设为true则不处理任何的包。一般使用的过程为，先停掉ovs-vswitchd，然后将这个值设为true，启
 动ovs-vswitchd，这个时候不处理任何包，然后使用ovs-ofctl将flow table
 restore到一个正确的状态，最后设置这个值为false，开始处理包

enable-statistics 是否统计

    statistics : cpu 统计cpu数量，线程
    statistics : load_average system load
    statistics : memory 总RAM，swap
    statistics : process_NAME ：with NAME replaced by a process name，统计memory size, cpu time等
    statistics : file_systems：mount point, size, used

ovs-vsctl del-port br0 eth-0-5
ovs-vsctl del-port br0 eth-0-6
ovs-vsctl add-bond br0 bond2 eth-0-5 eth-0-5 bond_mode=balance-slb -- set interface eth-0-5 type=switch -- set interface eth-0-6 type=switch

#限速

sudo ovs-vsctl list interface tap1
sudo ovs-vsctl set interface tap1 ingress_policing_burst=100
sudo ovs-vsctl set interface tap1 ingress_policing_rate=1000
sudo ovs-vsctl list Interface tap1

组表

n-revalidator-threads: Revalidation threads which read the datapath flow table and maintains them
n-handler-threads : An array of 'struct handler's for upcall handling and flow installation.

sudo ovs-vsctl list Controller
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

ovs-vsctl add-port ovs-switch p0 -- set Interface p0 ofport_request=100

创建一个端口 p0，设置端口 p0 的 OpenFlow 端口编号为
100（如果在创建端口的时候没有指定 OpenFlow 端口编号，OVS 会自动生成一个）。

ovs-vsctl set Interface p0 type=internal

设置网络接口设备的类型为“internal”。对于 internal 类型的的网络接口，OVS 会同时在
Linux 系统中创建一个可以用来收发数据的模拟网络设备。我们可以为这个网络设备配置
IP 地址、进行数据监听等等。

ovs-dpctl show

system@ovs-system:
lookups: hit:12173 missed:712 lost:0
flows: 0
port 0: ovs-system (internal)
    port 1: ovs-switch (internal)
    port 2: p0 (internal)
    port 3: p1 (internal)
    port 4: p2 (internal)

ovs-ofctl add-flow ovs-switch "table=0,priority=65535,tcp,in_port=4,nw_src=10.1.2.25,nw_dst=10.1.2.100,tp_src=80 actions=output:4"

屏蔽所有进入 OVS 的以太网广播数据包

ovs-ofctl add-flow ovs-switch "table=0, dl_src=01:00:00:00:00:00/01:00:00:00:00:00, actions=drop"


屏蔽 STP 协议的广播数据包

ovs-ofctl add-flow ovs-switch "table=0, dl_dst=01:80:c2:00:00:00/ff:ff:ff:ff:ff:f0, actions=drop"

生成数据包

ovs-appctl ofproto/trace ovs-switch in_port=100,dl_src=66:4e:cc:ae:4d:20, dl_dst=46:54:8a:95:dd:f8 -generate

ovsdb-client dump

ovs-ofctl add-flow s1 "table=0,priority=65535,arp,arp_tpa=10.0.0.254 actions=LOCAL"

sudo ovs-vsctl -- --columns=name,ofport list Interface


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


