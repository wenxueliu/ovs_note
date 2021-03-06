/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "dpif-provider.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "coverage.h"
#include "dpctl.h"
#include "dp-packet.h"
#include "dpif-netdev.h"
#include "dynamic-string.h"
#include "flow.h"
#include "netdev.h"
#include "netlink.h"
#include "odp-execute.h"
#include "odp-util.h"
#include "ofp-errors.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "route-table.h"
#include "seq.h"
#include "shash.h"
#include "sset.h"
#include "timeval.h"
#include "tnl-arp-cache.h"
#include "tnl-ports.h"
#include "util.h"
#include "uuid.h"
#include "valgrind.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif);

COVERAGE_DEFINE(dpif_destroy);
COVERAGE_DEFINE(dpif_port_add);
COVERAGE_DEFINE(dpif_port_del);
COVERAGE_DEFINE(dpif_flow_flush);
COVERAGE_DEFINE(dpif_flow_get);
COVERAGE_DEFINE(dpif_flow_put);
COVERAGE_DEFINE(dpif_flow_del);
COVERAGE_DEFINE(dpif_execute);
COVERAGE_DEFINE(dpif_purge);
COVERAGE_DEFINE(dpif_execute_with_help);

static const struct dpif_class *base_dpif_classes[] = {
#if defined(__linux__) || defined(_WIN32)
    &dpif_netlink_class,
#endif
    &dpif_netdev_class,
};

struct registered_dpif_class {
    const struct dpif_class *dpif_class;
    int refcount;
};
static struct shash dpif_classes = SHASH_INITIALIZER(&dpif_classes);
static struct sset dpif_blacklist = SSET_INITIALIZER(&dpif_blacklist);

/* Protects 'dpif_classes', including the refcount, and 'dpif_blacklist'. */
static struct ovs_mutex dpif_mutex = OVS_MUTEX_INITIALIZER;

/* Rate limit for individual messages going to or from the datapath, output at
 * DBG level.  This is very high because, if these are enabled, it is because
 * we really need to see them. */
static struct vlog_rate_limit dpmsg_rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Not really much point in logging many dpif errors. */
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(60, 5);

static void log_flow_message(const struct dpif *dpif, int error,
                             const char *operation,
                             const struct nlattr *key, size_t key_len,
                             const struct nlattr *mask, size_t mask_len,
                             const ovs_u128 *ufid,
                             const struct dpif_flow_stats *stats,
                             const struct nlattr *actions, size_t actions_len);
static void log_operation(const struct dpif *, const char *operation,
                          int error);
static bool should_log_flow_message(int error);
static void log_flow_put_message(struct dpif *, const struct dpif_flow_put *,
                                 int error);
static void log_flow_del_message(struct dpif *, const struct dpif_flow_del *,
                                 int error);
static void log_execute_message(struct dpif *, const struct dpif_execute *,
                                bool subexecute, int error);
static void log_flow_get_message(const struct dpif *,
                                 const struct dpif_flow_get *, int error);

/* Incremented whenever tnl route, arp, etc changes. */
struct seq *tnl_conf_seq;

/*
 * 注册命令, 并将 dpif_netdev_class, dpif_netlink_class 加入 dpif_classes, 并初始化
 *
 *
 * 1. 注册命令
 *    1) 对 all_commands 中每一个元素 commond, 注册 dpctl/commond 命令
 *    2) 注册
 *       tnl/ports/show
 *       tnl/arp/show
 *       tnl/arp/flush
 *       ovs/route/add
 *       ovs/route/show
 *       ovs/route/del
 *       ovs/route/lookup
 *       dpif-netdev/pmd-stats-show
 *       dpif-netdev/pmd-stats-clear
 * 2. 调用 base_dpif_classes 中元素的 init() 方法并加入 dpif_classes
 * (dpif_netdev_class->init(), dpif_netlink_class->init() 并将 dpif_netdev_class
 * 与 dpif_netlink_class 加入 dpif_classes)
 *
 *
 * ###dpif_netdev_class->init()
 *
 * 注册
 *       dpif-netdev/pmd-stats-show
 *       dpif-netdev/pmd-stats-clear
 * 命令
 *
 * ###dpif_netlink_class->init()
 *
 * 1. 与内核建立 NETLINK_GENERIC 协议连接, 发送请求获取 name (genl_family->name) 对应的 number(genl_family->id)
 * 2. 将 OVS_DATAPATH_FAMILY, OVS_VPORT_FAMILY, OVS_FLOW_FAMILY 加入 genl_families
 * 3. 确保 OVS_VPORT_FAMILY 中存在 OVS_VPORT_MCGROUP 对应 ID 的 ovs_vport_mcgroup
 *
 * genl_family:
 *       id                 name
 * OVS_DATAPATH_FAMILY ovs_datapath_family
 * OVS_VPORT_FAMILY    ovs_vport_family
 * OVS_FLOW_FAMILY     ovs_flow_family
 * OVS_PACKET_FAMILY   ovs_packet_family
 *
 *                   CTRL_ATTR_MCAST_GRP_NAME CTRL_ATTR_MCAST_GRP_ID
 * OVS_VPORT_FAMILY     OVS_VPORT_FAMILY         ovs_vport_mcgroup
 */
static void
dp_initialize(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        int i;

        tnl_conf_seq = seq_create();
        //1. 对 all_commands 中每一个元素 commond, 注册 dpctl/commond 命令
        dpctl_unixctl_register();
        /*
         * classifier_init(&cls, flow_segment_u64s);
         * 2. 注册 tnl/ports/show 命令
         */
        tnl_port_map_init();
        // 3. 注册 tnl/arp/show, tnl/arp/flush 命令
        tnl_arp_cache_init();
        /*
         * 1. classifier_init(&cls, NULL)
         * 2. 注册 route 命令
         *    ovs/route/add
         *    ovs/route/show
         *    ovs/route/del
         *    ovs/route/lookup
         */
        route_table_init();

        /* static const struct dpif_class *base_dpif_classes[] = {
         * #if defined(__linux__) || defined(_WIN32)
         *     &dpif_netlink_class,
         * #endif
         *     &dpif_netdev_class,
         * };
         *
         * 调用 base_dpif_classes 中元素的 init() 方法并加入 dpif_classes
         * 0. 检查 dpif_netlink_class 和 dpif_netdev_class 是否已经加入 dpif_classes 或 dpif_blacklist, 如果加入返回, 否则继续步骤 1
         * 1. 调用 dpif_netlink_class->init() 和 dpif_netdev_class->init())
         * 2. 将 dpif_netdev_class 和 dpif_netlink_class 加入 dpif_classes
         */
        for (i = 0; i < ARRAY_SIZE(base_dpif_classes); i++) {
            dp_register_provider(base_dpif_classes[i]);
        }

        ovsthread_once_done(&once);
    }
}

/*
 * @new_class : 待注册的 dpif_class, 实际为 dpif_netlink_class, dpif_netdev_class
 *
 * 0. 检查 new_class 是否已经加入 dpif_classes 和 dpif_blacklist, 如果加入返回, 否则继续步骤 1
 * 1. 调用 new_class->init() (实际调用 dpif_netlink_class->init() 和 dpif_netdev_class->init())
 * 2. 将 new_class 加入 dpif_classes(将 dpif_netdev_class 和 dpif_netlink_class 加入 dpif_classes)
 *
 * 注意: 在 dpif_classes 中每个 new_class->type 是唯一的
 */
static int
dp_register_provider__(const struct dpif_class *new_class)
{
    struct registered_dpif_class *registered_class;
    int error;

    if (sset_contains(&dpif_blacklist, new_class->type)) {
        VLOG_DBG("attempted to register blacklisted provider: %s",
                 new_class->type);
        return EINVAL;
    }

    if (shash_find(&dpif_classes, new_class->type)) {
        VLOG_WARN("attempted to register duplicate datapath provider: %s",
                  new_class->type);
        return EEXIST;
    }

    error = new_class->init ? new_class->init() : 0;
    if (error) {
        VLOG_WARN("failed to initialize %s datapath class: %s",
                  new_class->type, ovs_strerror(error));
        return error;
    }

    registered_class = xmalloc(sizeof *registered_class);
    registered_class->dpif_class = new_class;
    registered_class->refcount = 0;

    shash_add(&dpif_classes, new_class->type, registered_class);

    return 0;
}

/* Registers a new datapath provider.  After successful registration, new
 * datapaths of that type can be opened using dpif_open(). */
/*
 * @new_class : 待注册的 dpif_class, 实际为 dpif_netlink_class, dpif_netdev_class
 *
 * 0. 检查 new_class 是否已经加入 dpif_classes 或 dpif_blacklist, 如果加入返回, 否则继续步骤 1
 * 1. 调用 new_class->init() (实际调用 dpif_netlink_class->init() 和 dpif_netdev_class->init())
 * 2. 将 new_class 加入 dpif_classes(将 dpif_netdev_class 和 dpif_netlink_class 加入 dpif_classes)
 *
 * 注意: 在 dpif_classes 中每个 new_class->type 是唯一的
 */
int
dp_register_provider(const struct dpif_class *new_class)
{
    int error;

    ovs_mutex_lock(&dpif_mutex);
    error = dp_register_provider__(new_class);
    ovs_mutex_unlock(&dpif_mutex);

    return error;
}

/* Unregisters a datapath provider.  'type' must have been previously
 * registered and not currently be in use by any dpifs.  After unregistration
 * new datapaths of that type cannot be opened using dpif_open(). */
//从 dpif_classes 删除 type 对应的 dpif_class
static int
dp_unregister_provider__(const char *type)
{
    struct shash_node *node;
    struct registered_dpif_class *registered_class;

    node = shash_find(&dpif_classes, type);
    if (!node) {
        VLOG_WARN("attempted to unregister a datapath provider that is not "
                  "registered: %s", type);
        return EAFNOSUPPORT;
    }

    registered_class = node->data;
    if (registered_class->refcount) {
        VLOG_WARN("attempted to unregister in use datapath provider: %s", type);
        return EBUSY;
    }

    shash_delete(&dpif_classes, node);
    free(registered_class);

    return 0;
}

/* Unregisters a datapath provider.  'type' must have been previously
 * registered and not currently be in use by any dpifs.  After unregistration
 * new datapaths of that type cannot be opened using dpif_open(). */
int
dp_unregister_provider(const char *type)
{
    int error;

    dp_initialize();

    ovs_mutex_lock(&dpif_mutex);
    error = dp_unregister_provider__(type);
    ovs_mutex_unlock(&dpif_mutex);

    return error;
}

/* Blacklists a provider.  Causes future calls of dp_register_provider() with
 * a dpif_class which implements 'type' to fail. */
void
dp_blacklist_provider(const char *type)
{
    ovs_mutex_lock(&dpif_mutex);
    sset_add(&dpif_blacklist, type);
    ovs_mutex_unlock(&dpif_mutex);
}

/* Adds the types of all currently registered datapath providers to 'types'.
 * The caller must first initialize the sset. */

/*
 * 注册命令, 并将 dpif_netdev_class, dpif_netlink_class 加入 dpif_classes, 并初始化, 之后将 dpif_classes 中每个元素 type 加入 types
 *
 * 1. 注册命令
 *    1) 对 all_commands 中每一个元素 commond, 注册 dpctl/commond 命令
 *    2) 注册
 *       tnl/ports/show
 *       tnl/arp/show
 *       tnl/arp/flush
 *       ovs/route/add
 *       ovs/route/show
 *       ovs/route/del
 *       ovs/route/lookup
 *       dpif-netdev/pmd-stats-show
 *       dpif-netdev/pmd-stats-clear
 * 2. 调用 dpif_netlink_class 和 dpif_netdev_class 的 init(), 将其加入 dpif_classes
 *    将 base_dpif_classes 中的每个元素的 type 加入 types
 *    (实际上 types 包含 dpif_netlink_class->type(system), dpif_netdev_class->type(netdev) 两个元素)
 * 3. dpif_classes 中的元素 type 加入 types
 */
void
dp_enumerate_types(struct sset *types)
{
    struct shash_node *node;

    /*
     * 注册命令, 并将 dpif_netdev_class, dpif_netlink_class 加入 dpif_classes, 并初始化
     *
     *
     * 1. 注册命令
     *    1) 对 all_commands 中每一个元素 commond, 注册 dpctl/commond 命令
     *    2) 注册
     *       tnl/ports/show
     *       tnl/arp/show
     *       tnl/arp/flush
     *       ovs/route/add
     *       ovs/route/show
     *       ovs/route/del
     *       ovs/route/lookup
     *       dpif-netdev/pmd-stats-show
     *       dpif-netdev/pmd-stats-clear
     * 2. 调用 base_dpif_classes 中元素的 init() 方法并加入 dpif_classes
     * (dpif_netdev_class->init(), dpif_netlink_class->init() 并将 dpif_netdev_class
     * 与 dpif_netlink_class 加入 dpif_classes)
     *
     * ###dpif_netdev_class->init()
     *
     * 注册
     *       dpif-netdev/pmd-stats-show
     *       dpif-netdev/pmd-stats-clear
     * 命令
     *
     * ###dpif_netlink_class->init()
     *
     * 1. 与内核建立 NETLINK_GENERIC 协议连接, 发送请求获取 name (genl_family->name) 对应的 number(genl_family->id)
     * 2. 将 OVS_DATAPATH_FAMILY, OVS_VPORT_FAMILY, OVS_FLOW_FAMILY 加入 genl_families
     * 3. 确保 OVS_VPORT_FAMILY 中存在 OVS_VPORT_MCGROUP 对应 ID 的 ovs_vport_mcgroup
     *
     * genl_family:
     *       id                 name
     * OVS_DATAPATH_FAMILY ovs_datapath_family
     * OVS_VPORT_FAMILY    ovs_vport_family
     * OVS_FLOW_FAMILY     ovs_flow_family
     * OVS_PACKET_FAMILY   ovs_packet_family
     *
     *                   CTRL_ATTR_MCAST_GRP_NAME CTRL_ATTR_MCAST_GRP_ID
     * OVS_VPORT_FAMILY     OVS_VPORT_FAMILY         ovs_vport_mcgroup
     */
    dp_initialize();

    //3. dpif_classes 中的元素 type 加入 types
    ovs_mutex_lock(&dpif_mutex);
    SHASH_FOR_EACH(node, &dpif_classes) {
        const struct registered_dpif_class *registered_class = node->data;
        sset_add(types, registered_class->dpif_class->type);
    }
    ovs_mutex_unlock(&dpif_mutex);
}

static void
dp_class_unref(struct registered_dpif_class *rc)
{
    ovs_mutex_lock(&dpif_mutex);
    ovs_assert(rc->refcount);
    rc->refcount--;
    ovs_mutex_unlock(&dpif_mutex);
}

/*
 * @type: dpif_class->type. system, netdev is optional
 *
 * 在 dpif_classes 中查找 type 对应的 registered_dpif_class.
 *
 * NOTE:实际 dpif_classes 包含 dpif_netlink_class 和 dpif_netdev_class
 */
static struct registered_dpif_class *
dp_class_lookup(const char *type)
{
    struct registered_dpif_class *rc;

    ovs_mutex_lock(&dpif_mutex);
    rc = shash_find_data(&dpif_classes, type);
    if (rc) {
        rc->refcount++;
    }
    ovs_mutex_unlock(&dpif_mutex);

    return rc;
}

/* Clears 'names' and enumerates the names of all known created datapaths with
 * the given 'type'.  The caller must first initialize the sset.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * Some kinds of datapaths might not be practically enumerable.  This is not
 * considered an error. */
/*
 * @type  : 目前为 system 或 netdev
 * @names : 目前 type=system, 包含内核所有 dpif_netlink_dp 的 name; type=netdev, 包含 dp_netdev 的 name
 *
 * 将 type 的 dpif_class 的 name 加入 names
 *
 * 1. 在 dpif_classes 中查找 type 对应的 registered_dpif_class.
 * 2. 调用 registered_class->dpif_class->enumerate(names, registered_dpif_class->dpif_class) 方法初始化 names
 *
 * NOTE: 实际调用 dpif_netlink_class->enumerate 或 dpif_netdev_class->enumerate
 * 当为 dpif_netdev_class  : 从 dp_netdevs 中找到 class = dpif_nedev_class 的 dp_netdev 对象, 将 dp_netdev->name 保存在 names 中
 * 当为 dpif_netlink_class : 遍历查询内核中的所有 dpif_netlink_dp 对象, 将其 name 加入 names
 */
int
dp_enumerate_names(const char *type, struct sset *names)
{
    struct registered_dpif_class *registered_class;
    const struct dpif_class *dpif_class;
    int error;

    /*
    * 1. 注册 dpctl 命令
    * 2. 注册 tunnel port 命令
    * 3. 注册 tunnel arp cache 初始化
    * 4. 注册 route 命令
    * 4. 调用 base_dpif_classes 中元素的 init() 方法并加入 dpif_classes
    * (调用 dpif_netlink_class 和 dpif_netdev_class 初始化, 将其加入 dpif_classes)
    *
    */
    dp_initialize();
    sset_clear(names);

    //在 dpif_classes 中查找 type 对应的 registered_dpif_class.
    registered_class = dp_class_lookup(type);
    if (!registered_class) {
        VLOG_WARN("could not enumerate unknown type: %s", type);
        return EAFNOSUPPORT;
    }

    //调用 registered_class->dpif_class->enumerate 方法.
    dpif_class = registered_class->dpif_class;
    error = (dpif_class->enumerate
             ? dpif_class->enumerate(names, dpif_class)
             : 0);
    if (error) {
        VLOG_WARN("failed to enumerate %s datapaths: %s", dpif_class->type,
                   ovs_strerror(error));
    }
    dp_class_unref(registered_class);

    return error;
}

/* Parses 'datapath_name_', which is of the form [type@]name into its
 * component pieces.  'name' and 'type' must be freed by the caller.
 *
 * The returned 'type' is normalized, as if by dpif_normalize_type(). */

/*
 * $ sudo ovs-dpctl show
 * system@ovs-system:
 *     lookups: hit:0 missed:0 lost:0
 *     flows: 0
 *     masks: hit:0 total:0 hit/pkt:0.00
 *     port 0: ovs-system (internal)
 *     port 1: ovs-switch (internal)
 */
void
dp_parse_name(const char *datapath_name_, char **name, char **type)
{
    char *datapath_name = xstrdup(datapath_name_);
    char *separator;

    separator = strchr(datapath_name, '@');
    if (separator) {
        *separator = '\0';
        *type = datapath_name;
        *name = xstrdup(dpif_normalize_type(separator + 1));
    } else {
        *name = datapath_name;
        *type = xstrdup(dpif_normalize_type(NULL));
    }
}

/*
 * @type   : 目前为 system, netdev
 * @create : 是否创建
 * @dpifp  : dpif_classes 中 type 对应的 dpif_class
 *
 * 在 dpif_classes 根据 type 找到注册的 dpif_class, 调用 dpif_class->dpif_class->open() 方法
 *
 * 如果 type = system 调用 dpif_netlink_class->open(dpif_netlink_class,name,create,dpifp)
 *
 *     由 create, name 构造一个 NETLINK_GENERIC 协议请求消息, 向内核发送请求创建或设置 datapath, 并根据应答消息初始化一个 dpif_netlink 对象
 *
 *     1. 将 OVS_DATAPATH_FAMILY, OVS_VPORT_FAMILY, OVS_FLOW_FAMILY 加入 genl_families
 *     2. 确保 OVS_VPORT_FAMILY 对应的组属性中存在 OVS_VPORT_MCGROUP
 *     3. 由 create, name 构造一个创建或设置 datapath 的 NETLINK 请求消息
 *     4. 由 3 构造 NETLINK_GENERIC 协议消息, 发送请求, 根据应答消息初始化一个 dpif_netlink 对象
 *
 *     其中 3:
 *       如果 create = true
 *          dp_request.cmd = OVS_DP_CMD_NEW;
 *          dp_request.upcall_pid = 0;
 *          dp_request.name = name;
 *          dp_request.user_features = OVS_DP_F_UNALIGNED | OVS_DP_F_VPORT_PIDS;
 *       否则
 *          dp_request.cmd = OVS_DP_CMD_SET;
 *          dp_request.upcall_pid = 0;
 *          dp_request.name = name;
 *          dp_request.user_features = OVS_DP_F_UNALIGNED | OVS_DP_F_VPORT_PIDS;
 *
 * 如果 type = netdev 调用 dpif_netdev_class->open(dpif_netdev_class,name,create,dpifp)
 *
 *     检查 name, class 对应的 dp_netdev 是否存在, 如果不存在创建, 如果存在, create = false,
 *     返回 0, 否则返回错误值
 *
 *     如果 name 在 dp_netdevs 并且 dp->class = class && create = true, 返回 EEXIST
 *     如果 name 在 dp_netdevs 并且 dp->class = class && create = false,  返回 0
 *     如果 name 在 dp_netdevs 并且 dp->class != class,  返回 EINVAL
 *     如果 name 不在 dp_netdevs 并且 create = true,  dp_netdevs 增加 name 的 dp_netdev 对象并初始化该对象, dpifp 指向新的 dp_netdev
 *     如果 name 不在 dp_netdevs 并且 create = false, 返回 ENODEV
 *
 */
static int
do_open(const char *name, const char *type, bool create, struct dpif **dpifp)
{
    struct dpif *dpif = NULL;
    int error;
    struct registered_dpif_class *registered_class;

    dp_initialize();

    type = dpif_normalize_type(type);
    /*
    * 在 dpif_classes 中查找 type 对应的 registered_dpif_class.
    * NOTE:实际 dpif_classes 包含 dpif_netlink_class 和 dpif_netdev_class
    */
    registered_class = dp_class_lookup(type);
    if (!registered_class) {
        VLOG_WARN("could not create datapath %s of unknown type %s", name,
                  type);
        error = EAFNOSUPPORT;
        goto exit;
    }

    error = registered_class->dpif_class->open(registered_class->dpif_class,
                                               name, create, &dpif);
    if (!error) {
        ovs_assert(dpif->dpif_class == registered_class->dpif_class);
    } else {
        //registered_class->refcount--
        dp_class_unref(registered_class);
    }

exit:
    *dpifp = error ? NULL : dpif;
    return error;
}

/* Tries to open an existing datapath named 'name' and type 'type'.  Will fail
 * if no datapath with 'name' and 'type' exists.  'type' may be either NULL or
 * the empty string to specify the default system type.  Returns 0 if
 * successful, otherwise a positive errno value.  On success stores a pointer
 * to the datapath in '*dpifp', otherwise a null pointer. */
/*
 * 在 dpif_classes 根据 type 找到注册的 dpif_class, 调用 dpif_class->dpif_class->open() 方法
 *
 * NOTE
 * 如果 type = system 调用 dpif_netlink_class->open(dpif_netlink_class,name,false,dpifp) : 向内核发送创建 datapath 的消息, 并用内核应答初始化一个 dpif_netlink 对象. dpifp 指向该对象
 * 如果 type = netdev 调用 dpif_netdev_class->open(dpif_netlink_class,name,false,dpifp) : 在 dp_netdevs 中创建 name 对应的 dp_netdev 对象, 并初始化, dpifp 指向该对象
 *
 * 详细见 do_open
 */
int
dpif_open(const char *name, const char *type, struct dpif **dpifp)
{
    return do_open(name, type, false, dpifp);
}

/* Tries to create and open a new datapath with the given 'name' and 'type'.
 * 'type' may be either NULL or the empty string to specify the default system
 * type.  Will fail if a datapath with 'name' and 'type' already exists.
 * Returns 0 if successful, otherwise a positive errno value.  On success
 * stores a pointer to the datapath in '*dpifp', otherwise a null pointer. */

/*
 * 在 dpif_classes 根据 type 找到注册的 dpif_class, 调用 dpif_class->dpif_class->open() 方法
 * (
 * 如果 type = system 调用 dpif_netlink_class->open(dpif_netlink_class,name,create,dpifp)
 * 如果 type = netdev 调用 dpif_netdev_class->open(dpif_netlink_class,name,create,dpifp)
 * )
 *
 * NOTE
 * 如果 type = system 调用 dpif_netlink_class->open(dpif_netlink_class,name,false,dpifp) : 向内核发送创建 datapath 的消息, 并用内核应答初始化一个 dpif_netlink 对象. dpifp 指向该对象
 * 如果 type = netdev 调用 dpif_netdev_class->open(dpif_netlink_class,name,false,dpifp) : 在 dp_netdevs 中创建 name 对应的 dp_netdev 对象, 并初始化, dpifp 指向该对象
 *
 * 详细见 do_open
 */
int
dpif_create(const char *name, const char *type, struct dpif **dpifp)
{
    //详细见 do_open
    return do_open(name, type, true, dpifp);
}

/* Tries to open a datapath with the given 'name' and 'type', creating it if it
 * does not exist.  'type' may be either NULL or the empty string to specify
 * the default system type.  Returns 0 if successful, otherwise a positive
 * errno value. On success stores a pointer to the datapath in '*dpifp',
 * otherwise a null pointer. */
/*
 * 在 dpif_classes 根据 type 找到注册的 dpif_class, 调用 dpif_class->dpif_class->open() 方法, dpifp 指向创建的对象
 * (
 * 如果 type = system 调用 dpif_netlink_class->open(dpif_netlink_class,name,create,dpifp)
 * 如果 type = netdev 调用 dpif_netdev_class->open(dpif_netlink_class,name,create,dpifp)
 * )
 */
int
dpif_create_and_open(const char *name, const char *type, struct dpif **dpifp)
{
    int error;

    error = dpif_create(name, type, dpifp);
    if (error == EEXIST || error == EBUSY) {
        error = dpif_open(name, type, dpifp);
        if (error) {
            VLOG_WARN("datapath %s already exists but cannot be opened: %s",
                      name, ovs_strerror(error));
        }
    } else if (error) {
        VLOG_WARN("failed to create datapath %s: %s",
                  name, ovs_strerror(error));
    }
    return error;
}

/* Closes and frees the connection to 'dpif'.  Does not destroy the datapath
 * itself; call dpif_delete() first, instead, if that is desirable. */
void
dpif_close(struct dpif *dpif)
{
    if (dpif) {
        struct registered_dpif_class *rc;

        rc = shash_find_data(&dpif_classes, dpif->dpif_class->type);
        dpif_uninit(dpif, true);
        dp_class_unref(rc);
    }
}

/* Performs periodic work needed by 'dpif'. */
/*
 * 如果 type = netdev  dpif_netdev_run
 *     从 dp_netdev 的每个端口的接受队列中取出端口收到的包, 在
 *     dp_netdev->poll_threads 的 dp_netdev_pmd_thread 中查找
 *     匹配的流表, 如果找到就是执行对应的 action, 如果找不到就
 *     发送给 upcall(控制器或?)
 *
 *     从 dpif 定位到所属的 dp_netdev 对象 dp
 *     1. 从 dp->poll_threads 中定位到线程 id 为 non_pmd_core_id 的 dp_netdev_pmd_thread 对象 pmd
 *     2. 遍历 dp->ports 所有 port, 遍历 port->rxq 所有数据包 packet
 *     如果在 pmd->flow_cache 中有对应的 flow, 并且 flow->batch 不为 null, 将 packet 加入 flow->batch 并更新 flow->batch
 *     如果在 pmd->flow_cache 中有对应的 flow, 并且 flow->batch 为 null, 如果 pmd->cls 中存在对应的 flow, 将 packet 加入 flow->batch 并更新 flow->batch
 *     如果在 pmd->flow_cache 中没有对应的 flow, 如果 pmd->cls 中存在对应的 flow, 将 packet 加入 flow->batch 并更新 flow->batch
 *     如果 pmd->cls 中不存在对应的 flow, 调用 upcall,  upcall 后重新, 递归查询 pmd->flow_cache 和 pmd->cls
 *
 * 如果 type = system  dpif_netdev_run
 *     如果需要刷新 dpif 的 channel 就刷新. 返回 false
 *
 *     NOTE:
 *     当存在的端口被删除的时候 refresh_channels = true
 */
bool
dpif_run(struct dpif *dpif)
{
    if (dpif->dpif_class->run) {
        return dpif->dpif_class->run(dpif);
    }
    return false;
}

/* Arranges for poll_block() to wake up when dp_run() needs to be called for
 * 'dpif'. */

/*
 * type=netdev dpif_netdev_wait
 *    dpif 所属的 dp_netdev 的所有 port 的所有 rxq 如果有数据包准备好, 将数据包加入 rxq
 *
 * type=system
 *    什么也不做
 */
void
dpif_wait(struct dpif *dpif)
{
    if (dpif->dpif_class->wait) {
        dpif->dpif_class->wait(dpif);
    }
}

/* Returns the name of datapath 'dpif' prefixed with the type
 * (for use in log messages). */
const char *
dpif_name(const struct dpif *dpif)
{
    return dpif->full_name;
}

/* Returns the name of datapath 'dpif' without the type
 * (for use in device names). */
const char *
dpif_base_name(const struct dpif *dpif)
{
    return dpif->base_name;
}

/* Returns the type of datapath 'dpif'. */
const char *
dpif_type(const struct dpif *dpif)
{
    return dpif->dpif_class->type;
}

/* Returns the fully spelled out name for the given datapath 'type'.
 *
 * Normalized type string can be compared with strcmp().  Unnormalized type
 * string might be the same even if they have different spellings. */
const char *
dpif_normalize_type(const char *type)
{
    return type && type[0] ? type : "system";
}

/* Destroys the datapath that 'dpif' is connected to, first removing all of its
 * ports.  After calling this function, it does not make sense to pass 'dpif'
 * to any functions other than dpif_name() or dpif_close(). */

/*
 * type=system
 *     向内核发送消息删除 dpif_ 对应的 datapath
 *
 * type=netdev
 *     如果 dpif 对应的 dp_netdev 还没有销毁, 引用计数减一
 */
int
dpif_delete(struct dpif *dpif)
{
    int error;

    COVERAGE_INC(dpif_destroy);

    error = dpif->dpif_class->destroy(dpif);
    log_operation(dpif, "delete", error);
    return error;
}

/* Retrieves statistics for 'dpif' into 'stats'.  Returns 0 if successful,
 * otherwise a positive errno value. */

/*
 * type=netdev dpif_netdev_get_stats
 *    对 dpif 所属的 dp_netdev 对象 dp, 遍历 dp->poll_threads 的所有元素 pmd
 *    将所有 pmd->stats.n[DP_STAT_MASKED_HIT] 和 pmd->stats.n[DP_STAT_EXACT_HIT] 加起来作为命中的包数
 *    将所有 pmd->stats.n[DP_STAT_MISS] 加起来作为没有命中的包数
 *    将所有 pmd->stats.n[DP_STAT_LOST] 加起来作为丢失的包数
 *    最后将结果写入 stats
 *
 * type=netlink, dpif_netlink_get_stats
 *    向内核发送消息获取 dpif_ 所在的 dpif_netlink 对象对应的 dpif_netlink_dp 对象 dp 的状态信息
 */
int
dpif_get_dp_stats(const struct dpif *dpif, struct dpif_dp_stats *stats)
{
    int error = dpif->dpif_class->get_stats(dpif, stats);
    if (error) {
        memset(stats, 0, sizeof *stats);
    }
    log_operation(dpif, "get_stats", error);
    return error;
}

/*
 * 将 datapath_type 解析后复制给 port_type
 *
 * 如果 datapath_type = system, 调用 dpif_netlink_class->port_open_type(dpif_netlink_class, port_type)
 *     什么也不做
 *
 * 如果 datapath_type = netdev, 调用 dpif_netdev_class->port_open_type(dpif_netdev_class, port_type)
 *     如果 type=internal, class=dpif_netdev_class 返回 dummy
 *     如果 type=internal, class!=dpif_netdev_class 返回 tap
 *     如果 type!=internal, 直接返回 type
 */
const char *
dpif_port_open_type(const char *datapath_type, const char *port_type)
{
    struct registered_dpif_class *rc;

    datapath_type = dpif_normalize_type(datapath_type);

    ovs_mutex_lock(&dpif_mutex);
    rc = shash_find_data(&dpif_classes, datapath_type);
    if (rc && rc->dpif_class->port_open_type) {
        port_type = rc->dpif_class->port_open_type(rc->dpif_class, port_type);
    }
    ovs_mutex_unlock(&dpif_mutex);

    return port_type;
}

/* Attempts to add 'netdev' as a port on 'dpif'.  If 'port_nop' is
 * non-null and its value is not ODPP_NONE, then attempts to use the
 * value as the port number.
 *
 * If successful, returns 0 and sets '*port_nop' to the new port's port
 * number (if 'port_nop' is non-null).  On failure, returns a positive
 * errno value and sets '*port_nop' to ODPP_NONE (if 'port_nop' is
 * non-null). */

/*
 * type=netdev
 *     如果 port_nop 不为 ODPP_NONE, 查找释放存在 port_nop 的端口, 如果存在, 返回
 *     EBUGS, 如果不存在, 增加之
 *
 *     如果 port_nop 为 ODPP_NONE, 选择一个端口, 增加之
 *
 * type=system
 *     向内核发送在 dpif 中创建端口的消息, 并且关联 dpif->nl_handlers 个 nl_sock 与创建端口,
 *     绑定与端口关联 fd POLLIN 消息, 即内核该端口的包需要与用户空间交互的时候, 发往对应的 fd.
 */
int
dpif_port_add(struct dpif *dpif, struct netdev *netdev, odp_port_t *port_nop)
{
    const char *netdev_name = netdev_get_name(netdev);
    odp_port_t port_no = ODPP_NONE;
    int error;

    COVERAGE_INC(dpif_port_add);

    if (port_nop) {
        port_no = *port_nop;
    }

    error = dpif->dpif_class->port_add(dpif, netdev, &port_no);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: added %s as port %"PRIu32,
                    dpif_name(dpif), netdev_name, port_no);
    } else {
        VLOG_WARN_RL(&error_rl, "%s: failed to add %s as port: %s",
                     dpif_name(dpif), netdev_name, ovs_strerror(error));
        port_no = ODPP_NONE;
    }
    if (port_nop) {
        *port_nop = port_no;
    }
    return error;
}

/* Attempts to remove 'dpif''s port number 'port_no'.  Returns 0 if successful,
 * otherwise a positive errno value. */

/*
 * type=netdev
 *      从 dpif 删除端口 port_no 对应的端口
 * type=netlink
 *      向内核发送从 dpif 删除端口 port_no 的请求
 */
int
dpif_port_del(struct dpif *dpif, odp_port_t port_no)
{
    int error;

    COVERAGE_INC(dpif_port_del);

    error = dpif->dpif_class->port_del(dpif, port_no);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: port_del(%"PRIu32")",
                    dpif_name(dpif), port_no);
    } else {
        log_operation(dpif, "port_del", error);
    }
    return error;
}

/* Makes a deep copy of 'src' into 'dst'. */
void
dpif_port_clone(struct dpif_port *dst, const struct dpif_port *src)
{
    dst->name = xstrdup(src->name);
    dst->type = xstrdup(src->type);
    dst->port_no = src->port_no;
}

/* Frees memory allocated to members of 'dpif_port'.
 *
 * Do not call this function on a dpif_port obtained from
 * dpif_port_dump_next(): that function retains ownership of the data in the
 * dpif_port. */
void
dpif_port_destroy(struct dpif_port *dpif_port)
{
    free(dpif_port->name);
    free(dpif_port->type);
}

/* Checks if port named 'devname' exists in 'dpif'.  If so, returns
 * true; otherwise, returns false. */
bool
dpif_port_exists(const struct dpif *dpif, const char *devname)
{
    int error = dpif->dpif_class->port_query_by_name(dpif, devname, NULL);
    if (error != 0 && error != ENOENT && error != ENODEV) {
        VLOG_WARN_RL(&error_rl, "%s: failed to query port %s: %s",
                     dpif_name(dpif), devname, ovs_strerror(error));
    }

    return !error;
}

/* Looks up port number 'port_no' in 'dpif'.  On success, returns 0 and
 * initializes '*port' appropriately; on failure, returns a positive errno
 * value.
 *
 * The caller owns the data in 'port' and must free it with
 * dpif_port_destroy() when it is no longer needed. */

/*
 * type=netdev
 *      将 port_no 对应的 dp_netdev_port 的 name, type, port_no 初始化 dpif_port
 *
 * type=netlink
 *      向内核发送获取 dpif 中 port_no 的消息. 如果 dpif_port != NULL, 将返回的消息保持在 dpif_port
 */
int
dpif_port_query_by_number(const struct dpif *dpif, odp_port_t port_no,
                          struct dpif_port *port)
{
    int error = dpif->dpif_class->port_query_by_number(dpif, port_no, port);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: port %"PRIu32" is device %s",
                    dpif_name(dpif), port_no, port->name);
    } else {
        memset(port, 0, sizeof *port);
        VLOG_WARN_RL(&error_rl, "%s: failed to query port %"PRIu32": %s",
                     dpif_name(dpif), port_no, ovs_strerror(error));
    }
    return error;
}

/* Looks up port named 'devname' in 'dpif'.  On success, returns 0 and
 * initializes '*port' appropriately; on failure, returns a positive errno
 * value.
 *
 * The caller owns the data in 'port' and must free it with
 * dpif_port_destroy() when it is no longer needed. */
/*
 * @dpif ;
 * @port : 指向找到的 port
 * @return : 查找到返回 0
 *
 *  type="system":
 *      向内核发送获取 dpif 中 port_no 的消息. 如果 dpif_port != NULL, 将返回的消息保持在 dpif_port
 *  type="netdev":
 *      由 dpif 定位到 dp_netdev, 从 dp_netdev->ports 中找到 dp->ports[i]->netdev->name = devname 的 port, 并返回 0. 如果没有找到返回错误代码
 */
int
dpif_port_query_by_name(const struct dpif *dpif, const char *devname,
                        struct dpif_port *port)
{
    int error = dpif->dpif_class->port_query_by_name(dpif, devname, port);
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: device %s is on port %"PRIu32,
                    dpif_name(dpif), devname, port->port_no);
    } else {
        memset(port, 0, sizeof *port);

        /* For ENOENT or ENODEV we use DBG level because the caller is probably
         * interested in whether 'dpif' actually has a port 'devname', so that
         * it's not an issue worth logging if it doesn't.  Other errors are
         * uncommon and more likely to indicate a real problem. */
        VLOG_RL(&error_rl,
                error == ENOENT || error == ENODEV ? VLL_DBG : VLL_WARN,
                "%s: failed to query port %s: %s",
                dpif_name(dpif), devname, ovs_strerror(error));
    }
    return error;
}

/* Returns the Netlink PID value to supply in OVS_ACTION_ATTR_USERSPACE
 * actions as the OVS_USERSPACE_ATTR_PID attribute's value, for use in
 * flows whose packets arrived on port 'port_no'.  In the case where the
 * provider allocates multiple Netlink PIDs to a single port, it may use
 * 'hash' to spread load among them.  The caller need not use a particular
 * hash function; a 5-tuple hash is suitable.
 *
 * (The datapath implementation might use some different hash function for
 * distributing packets received via flow misses among PIDs.  This means
 * that packets received via flow misses might be reordered relative to
 * packets received via userspace actions.  This is not ordinarily a
 * problem.)
 *
 * A 'port_no' of ODPP_NONE is a special case: it returns a reserved PID, not
 * allocated to any port, that the client may use for special purposes.
 *
 * The return value is only meaningful when DPIF_UC_ACTION has been enabled in
 * the 'dpif''s listen mask.  It is allowed to change when DPIF_UC_ACTION is
 * disabled and then re-enabled, so a client that does that must be prepared to
 * update all of the flows that it installed that contain
 * OVS_ACTION_ATTR_USERSPACE actions. */
/*
 *
 * type=system
 *      返回 dpif->handlers[hash % dpif->n_handlers]->channels[port_no].sock->pid
 *      NOTE: 这里 dpif 为 dpif_netlink
 *
 * type=netdev
 *      什么也不做
 */
uint32_t
dpif_port_get_pid(const struct dpif *dpif, odp_port_t port_no, uint32_t hash)
{
    return (dpif->dpif_class->port_get_pid
            ? (dpif->dpif_class->port_get_pid)(dpif, port_no, hash)
            : 0);
}

/* Looks up port number 'port_no' in 'dpif'.  On success, returns 0 and copies
 * the port's name into the 'name_size' bytes in 'name', ensuring that the
 * result is null-terminated.  On failure, returns a positive errno value and
 * makes 'name' the empty string. */
/*
 * 根据 port_no 查询 port, 将 port.name 拷贝到 name
 */
int
dpif_port_get_name(struct dpif *dpif, odp_port_t port_no,
                   char *name, size_t name_size)
{
    struct dpif_port port;
    int error;

    ovs_assert(name_size > 0);

    error = dpif_port_query_by_number(dpif, port_no, &port);
    if (!error) {
        ovs_strlcpy(name, port.name, name_size);
        dpif_port_destroy(&port);
    } else {
        *name = '\0';
    }
    return error;
}

/* Initializes 'dump' to begin dumping the ports in a dpif.
 *
 * This function provides no status indication.  An error status for the entire
 * dump operation is provided when it is completed by calling
 * dpif_port_dump_done().
 */
void
dpif_port_dump_start(struct dpif_port_dump *dump, const struct dpif *dpif)
{
    dump->dpif = dpif;
    dump->error = dpif->dpif_class->port_dump_start(dpif, &dump->state);
    log_operation(dpif, "port_dump_start", dump->error);
}

/* Attempts to retrieve another port from 'dump', which must have been
 * initialized with dpif_port_dump_start().  On success, stores a new dpif_port
 * into 'port' and returns true.  On failure, returns false.
 *
 * Failure might indicate an actual error or merely that the last port has been
 * dumped.  An error status for the entire dump operation is provided when it
 * is completed by calling dpif_port_dump_done().
 *
 * The dpif owns the data stored in 'port'.  It will remain valid until at
 * least the next time 'dump' is passed to dpif_port_dump_next() or
 * dpif_port_dump_done(). */

/*
 * type=netdev
 *      从 dp->ports 的 state_->postion 中找到下一个节点, 初始化 dpif_port
 *
 * type=netlink
 *      如果 buffer->size == 0, 非阻塞接受 dump->sock->fd 的 struct nlmsghdr 结构的消息格式化为 dpif_netlink_vport 保存在 vport 中
 *      如果 buffer->size != 0, 将 buffer 中的 struct nlmsghdr 格式化为 dpif_netlink_vport 保存在 vport 中.
 *      成功返回 0, 读完返回 EOF, 失败返回错误码
 *
 */
bool
dpif_port_dump_next(struct dpif_port_dump *dump, struct dpif_port *port)
{
    const struct dpif *dpif = dump->dpif;

    if (dump->error) {
        return false;
    }

    dump->error = dpif->dpif_class->port_dump_next(dpif, dump->state, port);
    if (dump->error == EOF) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: dumped all ports", dpif_name(dpif));
    } else {
        log_operation(dpif, "port_dump_next", dump->error);
    }

    if (dump->error) {
        dpif->dpif_class->port_dump_done(dpif, dump->state);
        return false;
    }
    return true;
}

/* Completes port table dump operation 'dump', which must have been initialized
 * with dpif_port_dump_start().  Returns 0 if the dump operation was
 * error-free, otherwise a positive errno value describing the problem. */
int
dpif_port_dump_done(struct dpif_port_dump *dump)
{
    const struct dpif *dpif = dump->dpif;
    if (!dump->error) {
        dump->error = dpif->dpif_class->port_dump_done(dpif, dump->state);
        log_operation(dpif, "port_dump_done", dump->error);
    }
    return dump->error == EOF ? 0 : dump->error;
}

/* Polls for changes in the set of ports in 'dpif'.  If the set of ports in
 * 'dpif' has changed, this function does one of the following:
 *
 * - Stores the name of the device that was added to or deleted from 'dpif' in
 *   '*devnamep' and returns 0.  The caller is responsible for freeing
 *   '*devnamep' (with free()) when it no longer needs it.
 *
 * - Returns ENOBUFS and sets '*devnamep' to NULL.
 *
 * This function may also return 'false positives', where it returns 0 and
 * '*devnamep' names a device that was not actually added or deleted or it
 * returns ENOBUFS without any change.
 *
 * Returns EAGAIN if the set of ports in 'dpif' has not changed.  May also
 * return other positive errno values to indicate that something has gone
 * wrong. */
/*
 * @dpif
 * @devnamep :被改变, 创建, 或删除的端口的名称
 * @return : ENOBUFS, EAGAIN, 0
 *
 * dpif->type:"system" :
 *     如果 dpif->port_notifier = NULL, 将 sock->fd 加入 ovs_vport_mcgroup　并返回 ENOBUF
 *     否则非阻塞地无限循环接受 sock->fd 消息保存在 buf, 将 buf 转为 vport. 直到发生错误或遇到端口 NEW, SET, DEL 返回 0, 返回错误
 *     返回只能是 EAGAIN, ENOBUFS, 0
 *     NOTE:devnamep : 被改变, 创建, 或删除的端口的名称
 *
 * dpif->type:"netdev" :
 *     从 dpif 定位到 dpif_netdev, 读取 dpif_netdev->dp->port_seq
 *     如果 dpif_netdev->last_port_seq != dpif_netdev->dp->port_seq 返回 ENOBUFS
 *     如果 dpif_netdev->last_port_seq == dpif_netdev->dp->port_seq 返回 EAGAIN
 *     NOTE:devnamep : 没有用到, 保持原参数
 *
 */
int
dpif_port_poll(const struct dpif *dpif, char **devnamep)
{
    int error = dpif->dpif_class->port_poll(dpif, devnamep);
    if (error) {
        *devnamep = NULL;
    }
    return error;
}

/* Arranges for the poll loop to wake up when port_poll(dpif) will return a
 * value other than EAGAIN. */

/*
 * type=netdev
 *     等待 dpif->dp->ports 中端口发生变化
 * type=netlink
 *     等待内核发送端口发生变化的广播信息
 */
void
dpif_port_poll_wait(const struct dpif *dpif)
{
    dpif->dpif_class->port_poll_wait(dpif);
}

/* Extracts the flow stats for a packet.  The 'flow' and 'packet'
 * arguments must have been initialized through a call to flow_extract().
 * 'used' is stored into stats->used. */
/*
 * 用 flow, packet 和 used 初始化 stats
 *
 */
void
dpif_flow_stats_extract(const struct flow *flow, const struct dp_packet *packet,
                        long long int used, struct dpif_flow_stats *stats)
{
    stats->tcp_flags = ntohs(flow->tcp_flags);
    stats->n_bytes = dp_packet_size(packet);
    stats->n_packets = 1;
    stats->used = used;
}

/* Appends a human-readable representation of 'stats' to 's'. */
void
dpif_flow_stats_format(const struct dpif_flow_stats *stats, struct ds *s)
{
    ds_put_format(s, "packets:%"PRIu64", bytes:%"PRIu64", used:",
                  stats->n_packets, stats->n_bytes);
    if (stats->used) {
        ds_put_format(s, "%.3fs", (time_msec() - stats->used) / 1000.0);
    } else {
        ds_put_format(s, "never");
    }
    if (stats->tcp_flags) {
        ds_put_cstr(s, ", flags:");
        packet_format_tcp_flags(s, stats->tcp_flags);
    }
}

/* Places the hash of the 'key_len' bytes starting at 'key' into '*hash'. */
// 用 key 和 key_len 设置 hash
void
dpif_flow_hash(const struct dpif *dpif OVS_UNUSED,
               const void *key, size_t key_len, ovs_u128 *hash)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static uint32_t secret;

    if (ovsthread_once_start(&once)) {
        secret = random_uint32();
        ovsthread_once_done(&once);
    }
    hash_bytes128(key, key_len, secret, hash);
    uuid_set_bits_v4((struct uuid *)hash);
}

/* Deletes all flows from 'dpif'.  Returns 0 if successful, otherwise a
 * positive errno value.  */

/*
 * type=netlink
 *      由 flow 构造 Netlink 消息发送给内核, 请求删除所有流表
 * type=netdev
 *      删除 dp->poll_threads 每个线程 pmd 下的 flow_table
 */
int
dpif_flow_flush(struct dpif *dpif)
{
    int error;

    COVERAGE_INC(dpif_flow_flush);

    error = dpif->dpif_class->flow_flush(dpif);
    log_operation(dpif, "flow_flush", error);
    return error;
}

/* Attempts to install 'key' into the datapath, fetches it, then deletes it.
 * Returns true if the datapath supported installing 'flow', false otherwise.
 */
/*
 * 1. 安装流
 * 2. 提取流
 * 3. 删除流
 */
bool
dpif_probe_feature(struct dpif *dpif, const char *name,
                   const struct ofpbuf *key, const ovs_u128 *ufid)
{
    struct dpif_flow flow;
    struct ofpbuf reply;
    uint64_t stub[DPIF_FLOW_BUFSIZE / 8];
    bool enable_feature = false;
    int error;

    /* Use DPIF_FP_MODIFY to cover the case where ovs-vswitchd is killed (and
     * restarted) at just the right time such that feature probes from the
     * previous run are still present in the datapath. */
    error = dpif_flow_put(dpif, DPIF_FP_CREATE | DPIF_FP_MODIFY | DPIF_FP_PROBE,
                          key->data, key->size, NULL, 0, NULL, 0,
                          ufid, PMD_ID_NULL, NULL);
    if (error) {
        if (error != EINVAL) {
            VLOG_WARN("%s: %s flow probe failed (%s)",
                      dpif_name(dpif), name, ovs_strerror(error));
        }
        return false;
    }

    ofpbuf_use_stack(&reply, &stub, sizeof stub);
    /*
     * 向内核查询流表, 保持在 flow.
     */
    error = dpif_flow_get(dpif, key->data, key->size, ufid,
                          PMD_ID_NULL, &reply, &flow);
    if (!error
        && (!ufid || (flow.ufid_present
                      && ovs_u128_equals(ufid, &flow.ufid)))) {
        enable_feature = true;
    }

    error = dpif_flow_del(dpif, key->data, key->size, ufid,
                          PMD_ID_NULL, NULL);
    if (error) {
        VLOG_WARN("%s: failed to delete %s feature probe flow",
                  dpif_name(dpif), name);
    }

    return enable_feature;
}

/* A dpif_operate() wrapper for performing a single DPIF_OP_FLOW_GET. */
/*
 * type=netlink
 *      向内核查询流表, 保持在 flow.
 * type=netdev
 *      获取流表项
 */
int
dpif_flow_get(struct dpif *dpif,
              const struct nlattr *key, size_t key_len, const ovs_u128 *ufid,
              const unsigned pmd_id, struct ofpbuf *buf, struct dpif_flow *flow)
{
    struct dpif_op *opp;
    struct dpif_op op;

    op.type = DPIF_OP_FLOW_GET;
    op.u.flow_get.key = key;
    op.u.flow_get.key_len = key_len;
    op.u.flow_get.ufid = ufid;
    op.u.flow_get.pmd_id = pmd_id;
    op.u.flow_get.buffer = buf;

    memset(flow, 0, sizeof *flow);
    op.u.flow_get.flow = flow;
    op.u.flow_get.flow->key = key;
    op.u.flow_get.flow->key_len = key_len;

    opp = &op;
    dpif_operate(dpif, &opp, 1);

    return op.error;
}

/* A dpif_operate() wrapper for performing a single DPIF_OP_FLOW_PUT. */
int
dpif_flow_put(struct dpif *dpif, enum dpif_flow_put_flags flags,
              const struct nlattr *key, size_t key_len,
              const struct nlattr *mask, size_t mask_len,
              const struct nlattr *actions, size_t actions_len,
              const ovs_u128 *ufid, const unsigned pmd_id,
              struct dpif_flow_stats *stats)
{
    struct dpif_op *opp;
    struct dpif_op op;

    op.type = DPIF_OP_FLOW_PUT;
    op.u.flow_put.flags = flags;
    op.u.flow_put.key = key;
    op.u.flow_put.key_len = key_len;
    op.u.flow_put.mask = mask;
    op.u.flow_put.mask_len = mask_len;
    op.u.flow_put.actions = actions;
    op.u.flow_put.actions_len = actions_len;
    op.u.flow_put.ufid = ufid;
    op.u.flow_put.pmd_id = pmd_id;
    op.u.flow_put.stats = stats;

    opp = &op;
    dpif_operate(dpif, &opp, 1);

    return op.error;
}

/* A dpif_operate() wrapper for performing a single DPIF_OP_FLOW_DEL. */
int
dpif_flow_del(struct dpif *dpif,
              const struct nlattr *key, size_t key_len, const ovs_u128 *ufid,
              const unsigned pmd_id, struct dpif_flow_stats *stats)
{
    struct dpif_op *opp;
    struct dpif_op op;

    op.type = DPIF_OP_FLOW_DEL;
    op.u.flow_del.key = key;
    op.u.flow_del.key_len = key_len;
    op.u.flow_del.ufid = ufid;
    op.u.flow_del.pmd_id = pmd_id;
    op.u.flow_del.stats = stats;
    op.u.flow_del.terse = false;

    opp = &op;
    dpif_operate(dpif, &opp, 1);

    return op.error;
}

/* Creates and returns a new 'struct dpif_flow_dump' for iterating through the
 * flows in 'dpif'. If 'terse' is true, then only UFID and statistics will
 * be returned in the dump. Otherwise, all fields will be returned.
 *
 * This function always successfully returns a dpif_flow_dump.  Error
 * reporting is deferred to dpif_flow_dump_destroy(). */
/*
 * @terse : 如果为 true, 用 ufid, 否则不用
 * @dpif  :
 *
 * type=system
 *      构造 genl Netlink 消息, 向内核发送 NETLINK_GENERIC 协议消息, 并初始化 dump 后返回 dump
 * type=netdev
 *      创建 dpif_netdev_flow_dump 对象, 并初始化
 */
struct dpif_flow_dump *
dpif_flow_dump_create(const struct dpif *dpif, bool terse)
{
    return dpif->dpif_class->flow_dump_create(dpif, terse);
}

/* Destroys 'dump', which must have been created with dpif_flow_dump_create().
 * All dpif_flow_dump_thread structures previously created for 'dump' must
 * previously have been destroyed.
 *
 * Returns 0 if the dump operation was error-free, otherwise a positive errno
 * value describing the problem. */
/*
 * type=system
 *      如果 dump->nl_dump->state = 0, 继续接受数据直到数据接受完或发生错误. 之后将 dump->nl_dump->sock 保存在 pools 中
 *      如果数据接受完, 返回0, 否则返回具体错误代码
 *      最后释放 dump 所占内存
 * type=netdev
 *      销毁 dpif_netdev_flow_dump 对象.
 */
int
dpif_flow_dump_destroy(struct dpif_flow_dump *dump)
{
    const struct dpif *dpif = dump->dpif;
    int error = dpif->dpif_class->flow_dump_destroy(dump);
    log_operation(dpif, "flow_dump_destroy", error);
    return error == EOF ? 0 : error;
}

/* Returns new thread-local state for use with dpif_flow_dump_next(). */
/*
 * type=system
 *     初始化一个线程对象 thread, 返回线程对象所在的 thread->up
 *     thread->up->dpif = dump->up->dpif
 *     thread->dump = dump
 *     thread->nl_flows = malloc(NL_DUMP_BUFSIZE)
 *     thread->nl_actions = NULL
 *
 * type=netdev
 *     初始化 dpif_netdev_flow_dump_thread 对象
 */
struct dpif_flow_dump_thread *
dpif_flow_dump_thread_create(struct dpif_flow_dump *dump)
{
    return dump->dpif->dpif_class->flow_dump_thread_create(dump);
}

/* Releases 'thread'. */
/*
 * type=system
 *      销毁 thread 对象
 * type=netdev
 *      销毁 dpif_netdev_flow_dump_thread 对象
 */
void
dpif_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread)
{
    thread->dpif->dpif_class->flow_dump_thread_destroy(thread);
}

/* Attempts to retrieve up to 'max_flows' more flows from 'thread'.  Returns 0
 * if and only if no flows remained to be retrieved, otherwise a positive
 * number reflecting the number of elements in 'flows[]' that were updated.
 * The number of flows returned might be less than 'max_flows' because
 * fewer than 'max_flows' remained, because this particular datapath does not
 * benefit from batching, or because an error occurred partway through
 * retrieval.  Thus, the caller should continue calling until a 0 return value,
 * even if intermediate return values are less than 'max_flows'.
 *
 * No error status is immediately provided.  An error status for the entire
 * dump operation is provided when it is completed by calling
 * dpif_flow_dump_destroy().
 *
 * All of the data stored into 'flows' is owned by the datapath, not by the
 * caller, and the caller must not modify or free it.  The datapath guarantees
 * that it remains accessible and unchanged until the first of:
 *  - The next call to dpif_flow_dump_next() for 'thread', or
 *  - The next rcu quiescent period. */
/*
 * @thread_ :
 * @flows   : 保持从 thread->dump->nl_dump->sock->fd 中收到的数据
 * @max_flows : 期望最多的 flows 的大小, 如果 flows 中 flow 的数量大于 max_flows 退出
 *
 * type=system
 *      从 thread->dump->nl_dump->sock->fd 中收数据保持保存在 flows 中, 直到遇到错误或收到 max_flows 个 flow
 *      返回 flows 收的的流表数量
 *
 *      NOTE:
 *      flows 中 flow 的数量可能小于 max_flow
 *      如果遇到 flow 没有 actions 重新从内核中查询.
 *
 * type=netdev
 *      从 thread_->dump 开始遍历所有 pmd 下的 flow, 将 dump 之后的 flow 转换后, 保存在 flows 中
 */
int
dpif_flow_dump_next(struct dpif_flow_dump_thread *thread,
                    struct dpif_flow *flows, int max_flows)
{
    struct dpif *dpif = thread->dpif;
    int n;

    ovs_assert(max_flows > 0);
    n = dpif->dpif_class->flow_dump_next(thread, flows, max_flows);
    if (n > 0) {
        struct dpif_flow *f;

        for (f = flows; f < &flows[n] && should_log_flow_message(0); f++) {
            log_flow_message(dpif, 0, "flow_dump",
                             f->key, f->key_len, f->mask, f->mask_len,
                             &f->ufid, &f->stats, f->actions, f->actions_len);
        }
    } else {
        VLOG_DBG_RL(&dpmsg_rl, "%s: dumped all flows", dpif_name(dpif));
    }
    return n;
}

struct dpif_execute_helper_aux {
    struct dpif *dpif;
    int error;
};

/* This is called for actions that need the context of the datapath to be
 * meaningful. */
static void
dpif_execute_helper_cb(void *aux_, struct dp_packet **packets, int cnt,
                       const struct nlattr *action, bool may_steal OVS_UNUSED)
{
    struct dpif_execute_helper_aux *aux = aux_;
    int type = nl_attr_type(action);
    struct dp_packet *packet = *packets;

    ovs_assert(cnt == 1);

    switch ((enum ovs_action_attr)type) {
    case OVS_ACTION_ATTR_OUTPUT:
    case OVS_ACTION_ATTR_TUNNEL_PUSH:
    case OVS_ACTION_ATTR_TUNNEL_POP:
    case OVS_ACTION_ATTR_USERSPACE:
    case OVS_ACTION_ATTR_RECIRC: {
        struct dpif_execute execute;
        struct ofpbuf execute_actions;
        uint64_t stub[256 / 8];
        struct pkt_metadata *md = &packet->md;

        if (md->tunnel.ip_dst) {
            /* The Linux kernel datapath throws away the tunnel information
             * that we supply as metadata.  We have to use a "set" action to
             * supply it. */
            ofpbuf_use_stub(&execute_actions, stub, sizeof stub);
            odp_put_tunnel_action(&md->tunnel, &execute_actions);
            ofpbuf_put(&execute_actions, action, NLA_ALIGN(action->nla_len));

            execute.actions = execute_actions.data;
            execute.actions_len = execute_actions.size;
        } else {
            execute.actions = action;
            execute.actions_len = NLA_ALIGN(action->nla_len);
        }

        execute.packet = packet;
        execute.needs_help = false;
        execute.probe = false;
        /*
         * type=system
         *      将 execute 构造为 Netlink 消息, 发送给内核,要求内核执行 execute 中指定的的 action
         * type=netdev
         */
        aux->error = dpif_execute(aux->dpif, &execute);
        log_execute_message(aux->dpif, &execute, true, aux->error);

        if (md->tunnel.ip_dst) {
            ofpbuf_uninit(&execute_actions);
        }
        break;
    }

    case OVS_ACTION_ATTR_HASH:
    case OVS_ACTION_ATTR_PUSH_VLAN:
    case OVS_ACTION_ATTR_POP_VLAN:
    case OVS_ACTION_ATTR_PUSH_MPLS:
    case OVS_ACTION_ATTR_POP_MPLS:
    case OVS_ACTION_ATTR_SET:
    case OVS_ACTION_ATTR_SET_MASKED:
    case OVS_ACTION_ATTR_SAMPLE:
    case OVS_ACTION_ATTR_UNSPEC:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }
}

/* Executes 'execute' by performing most of the actions in userspace and
 * passing the fully constructed packets to 'dpif' for output and userspace
 * actions.
 *
 * This helps with actions that a given 'dpif' doesn't implement directly. */
static int
dpif_execute_with_help(struct dpif *dpif, struct dpif_execute *execute)
{
    struct dpif_execute_helper_aux aux = {dpif, 0};
    struct dp_packet *pp;

    COVERAGE_INC(dpif_execute_with_help);

    pp = execute->packet;
    odp_execute_actions(&aux, &pp, 1, false, execute->actions,
                        execute->actions_len, dpif_execute_helper_cb);
    return aux.error;
}

/* Returns true if the datapath needs help executing 'execute'. */
static bool
dpif_execute_needs_help(const struct dpif_execute *execute)
{
    return execute->needs_help || nl_attr_oversized(execute->actions_len);
}

/* A dpif_operate() wrapper for performing a single DPIF_OP_EXECUTE. */
/*
 * type=system
 *      将 execute 构造为 Netlink 消息, 发送给内核,要求内核执行 execute 中指定的的 action
 *
 * type=netdev
 */
int
dpif_execute(struct dpif *dpif, struct dpif_execute *execute)
{
    if (execute->actions_len) {
        struct dpif_op *opp;
        struct dpif_op op;

        op.type = DPIF_OP_EXECUTE;
        op.u.execute = *execute;

        opp = &op;
        dpif_operate(dpif, &opp, 1);

        return op.error;
    } else {
        return 0;
    }
}

/* Executes each of the 'n_ops' operations in 'ops' on 'dpif', in the order in
 * which they are specified.  Places each operation's results in the "output"
 * members documented in comments, and 0 in the 'error' member on success or a
 * positive errno on failure. */
/*
 * 遍历 ops 所有元素 op, 如果 op 类型为 DPIF_OP_EXECUTE 就将 dpif->dpif_operate>operate(dpif, ops, chunk)
 * 立即应用从开始到当前索引的所有操作. 并将内核应答初始化 ops[i]->u.{type}.stats]
 */
void
dpif_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops)
{
    while (n_ops > 0) {
        size_t chunk;

        /* Count 'chunk', the number of ops that can be executed without
         * needing any help.  Ops that need help should be rare, so we
         * expect this to ordinarily be 'n_ops', that is, all the ops. */
        for (chunk = 0; chunk < n_ops; chunk++) {
            struct dpif_op *op = ops[chunk];

            if (op->type == DPIF_OP_EXECUTE
                && dpif_execute_needs_help(&op->u.execute)) {
                break;
            }
        }

        if (chunk) {
            /* Execute a chunk full of ops that the dpif provider can
             * handle itself, without help. */
            size_t i;

            /*
             * 1. 遍历 ops 的每个元素 ops[i], 根据 ops[i]->type 转换为对应的 ofpbuf, 并存入 txnsp
             * 2. 将 txnp 中的所有请求一次发送给内核, 并接受内核的应答.
             * 3. 解析内核的应答初始化 ops[i]->u.{type}.stats
             */
            dpif->dpif_class->operate(dpif, ops, chunk);

            for (i = 0; i < chunk; i++) {
                struct dpif_op *op = ops[i];
                int error = op->error;

                switch (op->type) {
                case DPIF_OP_FLOW_PUT: {
                    struct dpif_flow_put *put = &op->u.flow_put;

                    COVERAGE_INC(dpif_flow_put);
                    log_flow_put_message(dpif, put, error);
                    if (error && put->stats) {
                        memset(put->stats, 0, sizeof *put->stats);
                    }
                    break;
                }

                case DPIF_OP_FLOW_GET: {
                    struct dpif_flow_get *get = &op->u.flow_get;

                    COVERAGE_INC(dpif_flow_get);
                    if (error) {
                        memset(get->flow, 0, sizeof *get->flow);
                    }
                    log_flow_get_message(dpif, get, error);

                    break;
                }

                case DPIF_OP_FLOW_DEL: {
                    struct dpif_flow_del *del = &op->u.flow_del;

                    COVERAGE_INC(dpif_flow_del);
                    log_flow_del_message(dpif, del, error);
                    if (error && del->stats) {
                        memset(del->stats, 0, sizeof *del->stats);
                    }
                    break;
                }

                case DPIF_OP_EXECUTE:
                    COVERAGE_INC(dpif_execute);
                    log_execute_message(dpif, &op->u.execute, false, error);
                    break;
                }
            }

            ops += chunk;
            n_ops -= chunk;
        } else {
            /* Help the dpif provider to execute one op. */
            struct dpif_op *op = ops[0];

            COVERAGE_INC(dpif_execute);
            op->error = dpif_execute_with_help(dpif, &op->u.execute);
            ops++;
            n_ops--;
        }
    }
}

/* Returns a string that represents 'type', for use in log messages. */
const char *
dpif_upcall_type_to_string(enum dpif_upcall_type type)
{
    switch (type) {
    case DPIF_UC_MISS: return "miss";
    case DPIF_UC_ACTION: return "action";
    case DPIF_N_UC_TYPES: default: return "<unknown>";
    }
}

/* Enables or disables receiving packets with dpif_recv() on 'dpif'.  Returns 0
 * if successful, otherwise a positive errno value.
 *
 * Turning packet receive off and then back on may change the Netlink PID
 * assignments returned by dpif_port_get_pid().  If the client does this, it
 * must update all of the flows that have OVS_ACTION_ATTR_USERSPACE actions
 * using the new PID assignment. */

/*
 * type=netdev : 什么也不做
 * type=netlink :
 *     如果 enable = true; dpif->handlers != NULL, 返回 0
 *     如果 enable = true; dpif->handlers = NULL, 刷新所有的 channels
 *     如果 enable = false; dpif->handlers = NULL, 返回 0
 *     如果 enable = false; dpif->handlers != NULL, 删除所有 channels
 */
int
dpif_recv_set(struct dpif *dpif, bool enable)
{
    int error = 0;

    if (dpif->dpif_class->recv_set) {
        error = dpif->dpif_class->recv_set(dpif, enable);
        log_operation(dpif, "recv_set", error);
    }
    return error;
}

/* Refreshes the poll loops and Netlink sockets associated to each port,
 * when the number of upcall handlers (upcall receiving thread) is changed
 * to 'n_handlers' and receiving packets for 'dpif' is enabled by
 * recv_set().
 *
 * Since multiple upcall handlers can read upcalls simultaneously from
 * 'dpif', each port can have multiple Netlink sockets, one per upcall
 * handler.  So, handlers_set() is responsible for the following tasks:
 *
 *    When receiving upcall is enabled, extends or creates the
 *    configuration to support:
 *
 *        - 'n_handlers' Netlink sockets for each port.
 *
 *        - 'n_handlers' poll loops, one for each upcall handler.
 *
 *        - registering the Netlink sockets for the same upcall handler to
 *          the corresponding poll loop.
 *
 * Returns 0 if successful, otherwise a positive errno value. */

/*
 * type=system : 重新配置 dpif->handlers 的数量
 *     当 dpif->n_handlers 发生变化,遍历所有 vport 的 upcall_pids 是否与原来一样, 如果不一样, 向内核发送 NETLINK 消息, 更新 vport. 并删除已经不在用的端口对应的 channel
 *
 *     1. 如果 dpif->n_handlers != n_handlers, 销毁已经存在的 channels, 重新初始化 dpif 的 n_handlers 个 handler
 *     2. 置 dpif 每个 handler 的 event_offset n_events 为 0
 *     3. 遍历内核所有端口, 设置端口的 upcall_pids, 删除不在用的 channel
 *
 * type=netdev
 *
 *     什么也不做
 */
int
dpif_handlers_set(struct dpif *dpif, uint32_t n_handlers)
{
    int error = 0;

    if (dpif->dpif_class->handlers_set) {
        error = dpif->dpif_class->handlers_set(dpif, n_handlers);
        log_operation(dpif, "handlers_set", error);
    }
    return error;
}

/*
 * type=netdev: 用 aux 初始化 dpif->upcall_aux, 用 cb 初始化 dpif->cb
 * type=system: 什么也不做
 */
void
dpif_register_upcall_cb(struct dpif *dpif, upcall_callback *cb, void *aux)
{
    if (dpif->dpif_class->register_upcall_cb) {
        dpif->dpif_class->register_upcall_cb(dpif, cb, aux);
    }
}

/*
 * type=netdev : dp_netdev->upcall_rwlock 解锁
 * type=system: 什么也不做
 *
 * 调用方: ofproto/ofoproto-dpif-upcall.c
 */
void
dpif_enable_upcall(struct dpif *dpif)
{
    if (dpif->dpif_class->enable_upcall) {
        dpif->dpif_class->enable_upcall(dpif);
    }
}

/*
 * type=netdev : dp_netdev->upcall_rwlock 加锁
 * type=system: 什么也不做
 *
 * 调用方: ofproto/ofoproto-dpif-upcall.c
 */
void
dpif_disable_upcall(struct dpif *dpif)
{
    if (dpif->dpif_class->disable_upcall) {
        dpif->dpif_class->disable_upcall(dpif);
    }
}

void
dpif_print_packet(struct dpif *dpif, struct dpif_upcall *upcall)
{
    if (!VLOG_DROP_DBG(&dpmsg_rl)) {
        struct ds flow;
        char *packet;

        packet = ofp_packet_to_string(dp_packet_data(&upcall->packet),
                                      dp_packet_size(&upcall->packet));

        ds_init(&flow);
        odp_flow_key_format(upcall->key, upcall->key_len, &flow);

        VLOG_DBG("%s: %s upcall:\n%s\n%s",
                 dpif_name(dpif), dpif_upcall_type_to_string(upcall->type),
                 ds_cstr(&flow), packet);

        ds_destroy(&flow);
        free(packet);
    }
}

/* If 'dpif' creates its own I/O polling threads, refreshes poll threads
 * configuration. */
/*
 * type=netdev : 如果 dp->n_dpdk_rxqs 或 dp->pmd_cmask 与 n_rxqs 与 cmask 不同, 删除 dp->poll_threads 所有元素之后重新初始化
 * type=system : 什么也不做
 *
 * 在 ofproto/ofproto-dpif.c
 */
int
dpif_poll_threads_set(struct dpif *dpif, unsigned int n_rxqs,
                      const char *cmask)
{
    int error = 0;

    if (dpif->dpif_class->poll_threads_set) {
        error = dpif->dpif_class->poll_threads_set(dpif, n_rxqs, cmask);
        if (error) {
            log_operation(dpif, "poll_threads_set", error);
        }
    }

    return error;
}

/* Polls for an upcall from 'dpif' for an upcall handler.  Since there
 * there can be multiple poll loops, 'handler_id' is needed as index to
 * identify the corresponding poll loop.  If successful, stores the upcall
 * into '*upcall', using 'buf' for storage.  Should only be called if
 * 'recv_set' has been used to enable receiving packets from 'dpif'.
 *
 * 'upcall->key' and 'upcall->userdata' point into data in the caller-provided
 * 'buf', so their memory cannot be freed separately from 'buf'.
 *
 * The caller owns the data of 'upcall->packet' and may modify it.  If
 * packet's headroom is exhausted as it is manipulated, 'upcall->packet'
 * will be reallocated.  This requires the data of 'upcall->packet' to be
 * released with ofpbuf_uninit() before 'upcall' is destroyed.  However,
 * when an error is returned, the 'upcall->packet' may be uninitialized
 * and should not be released.
 *
 * Returns 0 if successful, otherwise a positive errno value.  Returns EAGAIN
 * if no upcall is immediately available. */

/*
 * type=netdev : 什么也不做
 *
 * type=system :
 *
 *     handler = dpif->handlers[handler_id]
 *     如果 handler->event_offset 小于 handler->n_event 表面上次 epoll_wait 的数据没有处理完, 继续处理.
 *     否则 非阻塞地检查 handler->epoll_fd 是否有内核的 PACKET_IN 事件的数据包, 将可读的事件数量初始化 handler->n_event.
 *     遍历 handler->events 数组, 成功读取一次数据后并初始化 upcall, 返回. 因此这个函数需要反复调用.
 *
 *     注: 这里假设 dpif->handlers[handler_id]->events 为 POLLIN 事件. 因为调用 recv 接受数据. 而不是发送数据
 *
 *     如果 handler->event_offset >= handler->n_handlers, 表明所有的事件都已经处理完成, 重新监听 handler->epoll_fd 的 handler->epoll_events 事件
 *     否则
 *         轮询接受所有的 handler->epoll_events, 阻塞地接受 ch->sock 准备好的数据:
 *         如果成功接收, 初始化 upcall 后返回.
 *         如果缓存不够, 重试 50 次后放弃.
 *         如果数据 ch->sock 为非阻塞, event_offset++ 遍历下一个 epoll_events
 *
 *     注: 应该轮询的调用该函数直到返回 EAGAIN
 *
 *  在 ofoproto-dpif-upcall.c 中 recv_upcalls(struct handler *handler) 中调用该函数
 */
int
dpif_recv(struct dpif *dpif, uint32_t handler_id, struct dpif_upcall *upcall,
          struct ofpbuf *buf)
{
    int error = EAGAIN;

    if (dpif->dpif_class->recv) {
        error = dpif->dpif_class->recv(dpif, handler_id, upcall, buf);
        if (!error) {
            dpif_print_packet(dpif, upcall);
        } else if (error != EAGAIN) {
            log_operation(dpif, "recv", error);
        }
    }
    return error;
}

/* Discards all messages that would otherwise be received by dpif_recv() on
 * 'dpif'. */

/*
 * type=netdev : 什么也不做
 * type=system : 将 dpif->handlers 中所有的 fd 监听的数据都丢弃
 */
void
dpif_recv_purge(struct dpif *dpif)
{
    COVERAGE_INC(dpif_purge);
    if (dpif->dpif_class->recv_purge) {
        dpif->dpif_class->recv_purge(dpif);
    }
}

/* Arranges for the poll loop for an upcall handler to wake up when 'dpif'
 * 'dpif' has a message queued to be received with the recv member
 * function.  Since there can be multiple poll loops, 'handler_id' is
 * needed as index to identify the corresponding poll loop. */
/*
 * type=netdev :
 *
 *      什么也不做
 *
 * type=netlink :
 *
 *     dpif->hanelers[handler_id]->epoll_fd 中加入对 POLLIN 的监听
 *     对于 dpif->hanelers[handler_id]->epoll_fd 所对应的 poll_node 节点,
 *     如果已经存在于 poll_loop()->poll_nodes, 增加 POLLIN 事件.
 *     否则加入 poll_loop()->poll_nodes
 *
 */
void
dpif_recv_wait(struct dpif *dpif, uint32_t handler_id)
{
    if (dpif->dpif_class->recv_wait) {
        dpif->dpif_class->recv_wait(dpif, handler_id);
    }
}

/*
 * Return the datapath version. Caller is responsible for freeing
 * the string.
 */
/*
 * 如果 type=netdev, 返回 <built-in>
 * 如果 type=netlink, 读取文件 /sys/module/openvswitch/version 中 80 个字符之后返回
 *
 */
char *
dpif_get_dp_version(const struct dpif *dpif)
{
    char *version = NULL;

    if (dpif->dpif_class->get_datapath_version) {
        version = dpif->dpif_class->get_datapath_version();
    }

    return version;
}

/* Obtains the NetFlow engine type and engine ID for 'dpif' into '*engine_type'
 * and '*engine_id', respectively. */

/*
 * 将 dpif->netflow_engine_type 和 dpif->netflow_engine_id 分别保存在
 * engine_type, engine_id
 */
void
dpif_get_netflow_ids(const struct dpif *dpif,
                     uint8_t *engine_type, uint8_t *engine_id)
{
    *engine_type = dpif->netflow_engine_type;
    *engine_id = dpif->netflow_engine_id;
}

/* Translates OpenFlow queue ID 'queue_id' (in host byte order) into a priority
 * value used for setting packet priority.
 * On success, returns 0 and stores the priority into '*priority'.
 * On failure, returns a positive errno value and stores 0 into '*priority'. */
/*
 * type = "netdev" : 设置 priority = queue_id, 返回 0
 * type = "system" : if queue_id < 0xf000, *priority =  0x00010000 + queue_id + 1 返回 0, 否则 *priority = 0, 返回 EINVAL
 */
int
dpif_queue_to_priority(const struct dpif *dpif, uint32_t queue_id,
                       uint32_t *priority)
{
    int error = (dpif->dpif_class->queue_to_priority
                 ? dpif->dpif_class->queue_to_priority(dpif, queue_id,
                                                       priority)
                 : EOPNOTSUPP);
    if (error) {
        *priority = 0;
    }
    log_operation(dpif, "queue_to_priority", error);
    return error;
}

/*
 * 用 name, netflow_engine_type, netflow_engine_id 初始化 dpif
 */
void
dpif_init(struct dpif *dpif, const struct dpif_class *dpif_class,
          const char *name,
          uint8_t netflow_engine_type, uint8_t netflow_engine_id)
{
    dpif->dpif_class = dpif_class;
    dpif->base_name = xstrdup(name);
    dpif->full_name = xasprintf("%s@%s", dpif_class->type, name);
    dpif->netflow_engine_type = netflow_engine_type;
    dpif->netflow_engine_id = netflow_engine_id;
}

/* Undoes the results of initialization.
 *
 * Normally this function only needs to be called from dpif_close().
 * However, it may be called by providers due to an error on opening
 * that occurs after initialization.  It this case dpif_close() would
 * never be called. */
/*
 * 销毁 dpif
 */
void
dpif_uninit(struct dpif *dpif, bool close)
{
    char *base_name = dpif->base_name;
    char *full_name = dpif->full_name;

    if (close) {
        dpif->dpif_class->close(dpif);
    }

    free(base_name);
    free(full_name);
}

static void
log_operation(const struct dpif *dpif, const char *operation, int error)
{
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: %s success", dpif_name(dpif), operation);
    } else if (ofperr_is_valid(error)) {
        VLOG_WARN_RL(&error_rl, "%s: %s failed (%s)",
                     dpif_name(dpif), operation, ofperr_get_name(error));
    } else {
        VLOG_WARN_RL(&error_rl, "%s: %s failed (%s)",
                     dpif_name(dpif), operation, ovs_strerror(error));
    }
}

/*
 * error 不等于 0 且不等于 EEXIST, 返回 VLL_WARN; 否则 返回 VLL_DBG
 */
static enum vlog_level
flow_message_log_level(int error)
{
    /* If flows arrive in a batch, userspace may push down multiple
     * unique flow definitions that overlap when wildcards are applied.
     * Kernels that support flow wildcarding will reject these flows as
     * duplicates (EEXIST), so lower the log level to debug for these
     * types of messages. */
    return (error && error != EEXIST) ? VLL_WARN : VLL_DBG;
}

/*
 * error 不等于 0 且不等于 EEXIST, 不应该 VLL_WARN; 否则 返回 VLL_DBG
 * TODO
 */
static bool
should_log_flow_message(int error)
{
    return !vlog_should_drop(THIS_MODULE, flow_message_log_level(error),
                             error ? &error_rl : &dpmsg_rl);
}

static void
log_flow_message(const struct dpif *dpif, int error, const char *operation,
                 const struct nlattr *key, size_t key_len,
                 const struct nlattr *mask, size_t mask_len,
                 const ovs_u128 *ufid, const struct dpif_flow_stats *stats,
                 const struct nlattr *actions, size_t actions_len)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_format(&ds, "%s: ", dpif_name(dpif));
    if (error) {
        ds_put_cstr(&ds, "failed to ");
    }
    ds_put_format(&ds, "%s ", operation);
    if (error) {
        ds_put_format(&ds, "(%s) ", ovs_strerror(error));
    }
    if (ufid) {
        odp_format_ufid(ufid, &ds);
        ds_put_cstr(&ds, " ");
    }
    odp_flow_format(key, key_len, mask, mask_len, NULL, &ds, true);
    if (stats) {
        ds_put_cstr(&ds, ", ");
        dpif_flow_stats_format(stats, &ds);
    }
    if (actions || actions_len) {
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, actions_len);
    }
    vlog(THIS_MODULE, flow_message_log_level(error), "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
log_flow_put_message(struct dpif *dpif, const struct dpif_flow_put *put,
                     int error)
{
    if (should_log_flow_message(error) && !(put->flags & DPIF_FP_PROBE)) {
        struct ds s;

        ds_init(&s);
        ds_put_cstr(&s, "put");
        if (put->flags & DPIF_FP_CREATE) {
            ds_put_cstr(&s, "[create]");
        }
        if (put->flags & DPIF_FP_MODIFY) {
            ds_put_cstr(&s, "[modify]");
        }
        if (put->flags & DPIF_FP_ZERO_STATS) {
            ds_put_cstr(&s, "[zero]");
        }
        log_flow_message(dpif, error, ds_cstr(&s),
                         put->key, put->key_len, put->mask, put->mask_len,
                         put->ufid, put->stats, put->actions,
                         put->actions_len);
        ds_destroy(&s);
    }
}

static void
log_flow_del_message(struct dpif *dpif, const struct dpif_flow_del *del,
                     int error)
{
    if (should_log_flow_message(error)) {
        log_flow_message(dpif, error, "flow_del", del->key, del->key_len,
                         NULL, 0, del->ufid, !error ? del->stats : NULL,
                         NULL, 0);
    }
}

/* Logs that 'execute' was executed on 'dpif' and completed with errno 'error'
 * (0 for success).  'subexecute' should be true if the execution is a result
 * of breaking down a larger execution that needed help, false otherwise.
 *
 *
 * XXX In theory, the log message could be deceptive because this function is
 * called after the dpif_provider's '->execute' function, which is allowed to
 * modify execute->packet and execute->md.  In practice, though:
 *
 *     - dpif-netlink doesn't modify execute->packet or execute->md.
 *
 *     - dpif-netdev does modify them but it is less likely to have problems
 *       because it is built into ovs-vswitchd and cannot have version skew,
 *       etc.
 *
 * It would still be better to avoid the potential problem.  I don't know of a
 * good way to do that, though, that isn't expensive. */
static void
log_execute_message(struct dpif *dpif, const struct dpif_execute *execute,
                    bool subexecute, int error)
{
    if (!(error ? VLOG_DROP_WARN(&error_rl) : VLOG_DROP_DBG(&dpmsg_rl))
        && !execute->probe) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        char *packet;

        packet = ofp_packet_to_string(dp_packet_data(execute->packet),
                                      dp_packet_size(execute->packet));
        ds_put_format(&ds, "%s: %sexecute ",
                      dpif_name(dpif),
                      (subexecute ? "sub-"
                       : dpif_execute_needs_help(execute) ? "super-"
                       : ""));
        format_odp_actions(&ds, execute->actions, execute->actions_len);
        if (error) {
            ds_put_format(&ds, " failed (%s)", ovs_strerror(error));
        }
        ds_put_format(&ds, " on packet %s", packet);
        vlog(THIS_MODULE, error ? VLL_WARN : VLL_DBG, "%s", ds_cstr(&ds));
        ds_destroy(&ds);
        free(packet);
    }
}

static void
log_flow_get_message(const struct dpif *dpif, const struct dpif_flow_get *get,
                     int error)
{
    if (should_log_flow_message(error)) {
        log_flow_message(dpif, error, "flow_get",
                         get->key, get->key_len,
                         get->flow->mask, get->flow->mask_len,
                         get->ufid, &get->flow->stats,
                         get->flow->actions, get->flow->actions_len);
    }
}

/*
 * type=system: 返回 false
 * type=netdev: 返回 true
 *
 */
bool
dpif_supports_tnl_push_pop(const struct dpif *dpif)
{
    return dpif_is_netdev(dpif);
}
