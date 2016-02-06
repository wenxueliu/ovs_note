# Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#详细文档见 https://www.gnu.org/software/autoconf/manual/autoconf-2.69/
AC_PREREQ(2.63)
AC_INIT(openvswitch, 2.4.90, bugs@openvswitch.org)
AC_CONFIG_SRCDIR([datapath/datapath.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_TESTDIR([tests])
AM_INIT_AUTOMAKE([tar-pax])

AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_MKDIR_P
AC_PROG_FGREP
AC_PROG_EGREP

AC_ARG_VAR([PERL], [path to Perl interpreter])
AC_PATH_PROG([PERL], perl, no)
if test "$PERL" = no; then
   AC_MSG_ERROR([Perl interpreter not found in $PATH or $PERL.])
fi

AM_MISSING_PROG([AUTOM4TE], [autom4te])

AC_USE_SYSTEM_EXTENSIONS
AC_C_BIGENDIAN
AC_SYS_LARGEFILE

LT_INIT([disable-shared])
m4_pattern_forbid([LT_INIT]) dnl Make autoconf fail if libtool is missing.

# The following explanation may help to understand the use of the
# version number fields: current, revision, and age.
#
# Consider that there are three possible kinds of reactions from
# users of your library to changes in a shared library:
#
# 1. Programs using the previous version may use the new version as drop-in
#    replacement, and programs using the new version can also work with the
#    previous one. In other words, no recompiling nor relinking is needed.
#    In short, there are no changes to any symbols, no symbols removed,
#    and no symbols added. In this case, bump revision only, don't touch
#    current nor age.
#
# 2. Programs using the previous version may use the new version as drop-in
#    replacement, but programs using the new version may use APIs not
#    present in the previous one. In other words, new symbols have been
#    added and a program linking against the new version may fail with
#    "unresolved symbols." If linking against the old version at runtime:
#    set revision to 0, bump current and age.
#
# 3. Programs may need to be changed, recompiled, relinked in order to use
#    the new version. This is the case when symbols have been modified or
#    deleted. Bump current, set revision and age to 0.

m4_define([libopenvswitch_lt_current],    [1])
m4_define([libopenvswitch_lt_revision],   [0])
m4_define([libopenvswitch_lt_age],        [0])

LT_CURRENT=libopenvswitch_lt_current
AC_SUBST([LT_CURRENT])
LT_REVISION=libopenvswitch_lt_revision
AC_SUBST([LT_REVISION])
LT_AGE=libopenvswitch_lt_age
AC_SUBST([LT_AGE])

AC_SEARCH_LIBS([pow], [m])
AC_SEARCH_LIBS([clock_gettime], [rt])
AC_SEARCH_LIBS([timer_create], [rt])
AC_SEARCH_LIBS([pthread_create], [pthread])
AC_FUNC_STRERROR_R

OVS_CHECK_ESX
OVS_CHECK_WIN32
OVS_CHECK_VISUAL_STUDIO_DDK
OVS_CHECK_COVERAGE             #--enable-coverage 如果打开, CFLAGS 删除 -02
OVS_CHECK_NDEBUG               #--enable-ndebug 定义宏 NDEBUG true|false
OVS_CHECK_NETLINK              #检查头文件 linux/netlink.h 是否存在, 并定义宏 HAVE_NETLINK
OVS_CHECK_OPENSSL              #--disable-ssl 配置 openssl
OVS_CHECK_LOGDIR               #--with-logdir=DIR 指定日志路径
OVS_CHECK_PYTHON               #检查 python > 2.7
OVS_CHECK_DOT                  #TODO:文档工具
OVS_CHECK_IF_PACKET            #检查头文件 net/if_packet.h 是否存在, 定义宏 HAVE_IF_PACKET
OVS_CHECK_IF_DL                #检查头文件 net/if_dl.h 是否存在, 定义宏 HAVE_IF_DL
OVS_CHECK_STRTOK_R             #检查对 strtok_r bug是否存在, 定义宏 HAVE_STRTOK_R_BUG
AC_CHECK_DECLS([sys_siglist], [], [], [[#include <signal.h>]]) #在检查之前加入头文件signal.h, 是否存在 sys_siglist syubol 检查对 HAVE_DECL_SYS_SIGLIST 的支持
AC_CHECK_MEMBERS([struct stat.st_mtim.tv_nsec, struct stat.st_mtimensec],
  [], [], [[#include <sys/stat.h>]])

# 检查 ifreq.ifr_flagshigh 是否存在, 定义宏 HAVE_IFREQ_IFR_FLAGSHIGH
AC_CHECK_MEMBERS([struct ifreq.ifr_flagshigh], [], [], [[#include <net/if.h>]])

# 检查 mlockall, strnlen, getloadavg, statvfs, getmntent_r 函数是支持, 定义
# HAVE_MLOCKALL, HAVE_STRNLEN, HAVE_GETLOADAVG, HAVE_STATVFS, HAVE_GETMNTENT_R
AC_CHECK_FUNCS([mlockall strnlen getloadavg statvfs getmntent_r])

# 检查 mntent.h sys/statvfs.h linux/types.h linux/if_ether.h stdatomic.h 头文件是否存在, 定义
# HAVE_MNTENT_H, HAVE_STATVFS_H, HAVE_LINUX_TYPES_H, HAVE_LINUX_IF_ETHER_H, HAVE_STDATOMIC_H
AC_CHECK_HEADERS([mntent.h sys/statvfs.h linux/types.h linux/if_ether.h stdatomic.h])
# 见上
AC_CHECK_HEADERS([net/if_mib.h], [], [], [[#include <sys/types.h>
#include <net/if.h>]])

OVS_CHECK_PKIDIR                   #--with-pkidir=DIR, 定义 PKIDIR 保存 PKI
OVS_CHECK_RUNDIR                   #--with-rundir=DIR, 定义 RUNDIR 保存运行目录
OVS_CHECK_DBDIR                    #--with-dbdir=DIR, 定义数据库文件夹
OVS_CHECK_BACKTRACE                #是否支持 backtrace() 打印堆栈信息
OVS_CHECK_PERF_EVENT               #检查头文件 linux/perf_event.h
OVS_CHECK_VALGRIND                 #检查头文件 valgrind/valgrind.h
OVS_CHECK_SOCKET_LIBS              #通过链接 connect 测试 socket 是否可用, 搜索 gethostbyname, resolv
OVS_CHECK_XENSERVER_VERSION        #检查 XEN 版本, 忽略
OVS_CHECK_GROFF                    #文档工具 groff, 订阅宏 HAVE_GROFF
OVS_CHECK_GNU_MAKE                 #通过 make 版本检查是否是 GUN make
OVS_CHECK_TLS                      #检查 thread-local 的支持, 定义宏 HAVE_THREAD_LOCAL
OVS_CHECK_ATOMIC_LIBS              #-latomic 测试 __atomic_load_8 是否可用
OVS_CHECK_GCC4_ATOMICS             #是否支持 GCC4.0+ 对各种类型的原子操作, 定义宏 HAVE_GCC4_ATOMICS
OVS_CHECK_ATOMIC_ALWAYS_LOCK_FREE(1) #__atomic_always_lock_free 对不同字节的支持
OVS_CHECK_ATOMIC_ALWAYS_LOCK_FREE(2)
OVS_CHECK_ATOMIC_ALWAYS_LOCK_FREE(4)
OVS_CHECK_ATOMIC_ALWAYS_LOCK_FREE(8)
OVS_CHECK_POSIX_AIO                #链接 -lrt, 测试 aio_write 是否支持
OVS_CHECK_PTHREAD_SET_NAME         #检查对 pthread_setname_np 的支持
OVS_CHECK_LINUX_HOST               #通过检查 __linux__, 检查是否在 LINUX 主机运行 ovs, 定义宏 LINUX
AX_FUNC_POSIX_MEMALIGN             #通过 posix_memalign 检查一些版本对 glibc 对齐的支持, 定义宏 HAVE_POSIX_MEMALIGN

OVS_CHECK_INCLUDE_NEXT([stdio.h string.h]) #TODO
AC_CONFIG_FILES([
    lib/stdio.h
    lib/string.h
    ovsdb/libovsdb.sym
    ofproto/libofproto.sym
    lib/libsflow.sym
    lib/libopenvswitch.sym
    ovn/lib/libovn.sym
    vtep/libvtep.sym])

OVS_ENABLE_OPTION([-Wall])
OVS_ENABLE_OPTION([-Wextra])
OVS_ENABLE_OPTION([-Wno-sign-compare])
OVS_ENABLE_OPTION([-Wpointer-arith])
OVS_ENABLE_OPTION([-Wformat-security])
OVS_ENABLE_OPTION([-Wswitch-enum])
OVS_ENABLE_OPTION([-Wunused-parameter])
OVS_ENABLE_OPTION([-Wbad-function-cast])
OVS_ENABLE_OPTION([-Wcast-align])
OVS_ENABLE_OPTION([-Wstrict-prototypes])
OVS_ENABLE_OPTION([-Wold-style-definition])
OVS_ENABLE_OPTION([-Wmissing-prototypes])
OVS_ENABLE_OPTION([-Wmissing-field-initializers])
OVS_ENABLE_OPTION([-Wthread-safety])
OVS_ENABLE_OPTION([-fno-strict-aliasing])
OVS_ENABLE_OPTION([-Qunused-arguments])
OVS_CONDITIONAL_CC_OPTION([-Wno-unused], [HAVE_WNO_UNUSED])
OVS_CONDITIONAL_CC_OPTION([-Wno-unused-parameter], [HAVE_WNO_UNUSED_PARAMETER])
OVS_ENABLE_WERROR
OVS_ENABLE_SPARSE

AC_ARG_VAR(KARCH, [Kernel Architecture String])
AC_SUBST(KARCH)
OVS_CHECK_LINUX
OVS_CHECK_DPDK
OVS_CHECK_PRAGMA_MESSAGE
AC_SUBST([OVS_CFLAGS])
AC_SUBST([OVS_LDFLAGS])

AC_CONFIG_FILES(Makefile)
AC_CONFIG_FILES(datapath/Makefile)
AC_CONFIG_FILES(datapath/linux/Kbuild)
AC_CONFIG_FILES(datapath/linux/Makefile)
AC_CONFIG_FILES(datapath/linux/Makefile.main)
AC_CONFIG_FILES(tests/atlocal)
AC_CONFIG_FILES(lib/libopenvswitch.pc)
AC_CONFIG_FILES(lib/libsflow.pc)
AC_CONFIG_FILES(ofproto/libofproto.pc)
AC_CONFIG_FILES(ovsdb/libovsdb.pc)
AC_CONFIG_FILES(include/openvswitch/version.h)

dnl This makes sure that include/openflow gets created in the build directory.
AC_CONFIG_COMMANDS([include/openflow/openflow.h.stamp])

AC_CONFIG_COMMANDS([utilities/bugtool/dummy], [:])
AC_CONFIG_COMMANDS([ovn/dummy], [:])
AC_CONFIG_COMMANDS([ovn/utilities/dummy], [:])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

AC_OUTPUT
