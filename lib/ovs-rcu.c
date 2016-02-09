/*
 * Copyright (c) 2014 Nicira, Inc.
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
#include "ovs-rcu.h"
#include "fatal-signal.h"
#include "guarded-list.h"
#include "list.h"
#include "ovs-thread.h"
#include "poll-loop.h"
#include "seq.h"
#include "timeval.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovs_rcu);

struct ovsrcu_cb {
    void (*function)(void *aux);
    void *aux;
};

struct ovsrcu_cbset {
    struct ovs_list list_node;
    //16 是线程专有回调函数刷入全局 flushed_cbsets 的阈值
    struct ovsrcu_cb cbs[16]; //为什么是 16 ?,
    //实际 cbs 大小
    int n_cbs;
};

struct ovsrcu_perthread {
    struct ovs_list list_node;  /* In global list. */

    struct ovs_mutex mutex;
    uint64_t seqno;
    struct ovsrcu_cbset *cbset;
    char name[16];              /* This thread's name. */
};

//标记旧版本操作完成(即线程的局部 cbset 刷新到全局 flushed_cbsets)
static struct seq *global_seqno;

//线程专有数据
static pthread_key_t perthread_key;
//保存所有线程专有数据 perthread_key 对应的 ovsrcu_perthread
static struct ovs_list ovsrcu_threads;
//ovsrcu_threads 的锁
static struct ovs_mutex ovsrcu_threads_mutex;

static struct guarded_list flushed_cbsets;
static struct seq *flushed_cbsets_seq;

static void ovsrcu_init_module(void);
static void ovsrcu_flush_cbset(struct ovsrcu_perthread *);
static void ovsrcu_unregister__(struct ovsrcu_perthread *);
static bool ovsrcu_call_postponed(void);
static void *ovsrcu_postpone_thread(void *arg OVS_UNUSED);

/*
 * 初始化线程专有数据 perthread_key 为 ovsrcu_perthread, 并返回 ovsrcu_perthread
 *
 * 注: 在 perthread_key 没有通过 pthread_key_create() 创建, 或已经通
 * 过 pthread_key_delete() 删除, 调用 pthread_getspecific() 或
 * pthread_setspecific() 是未定义的行为.
 */
static struct ovsrcu_perthread *
ovsrcu_perthread_get(void)
{
    struct ovsrcu_perthread *perthread;

    ovsrcu_init_module();

    perthread = pthread_getspecific(perthread_key);
    if (!perthread) {
        const char *name = get_subprogram_name();

        perthread = xmalloc(sizeof *perthread);
        ovs_mutex_init(&perthread->mutex);
        perthread->seqno = seq_read(global_seqno);
        perthread->cbset = NULL;
        ovs_strlcpy(perthread->name, name[0] ? name : "main",
                    sizeof perthread->name);

        ovs_mutex_lock(&ovsrcu_threads_mutex);
        list_push_back(&ovsrcu_threads, &perthread->list_node);
        ovs_mutex_unlock(&ovsrcu_threads_mutex);

        pthread_setspecific(perthread_key, perthread);
    }
    return perthread;
}

/* Indicates the end of a quiescent state.  See "Details" near the top of
 * ovs-rcu.h.
 *
 * Quiescent states don't stack or nest, so this always ends a quiescent state
 * even if ovsrcu_quiesce_start() was called multiple times in a row. */
/*
 * 初始化线程专有数据 perthread_key 为 ovsrcu_perthread
 */
void
ovsrcu_quiesce_end(void)
{
    ovsrcu_perthread_get();
}

/*
 * 如果是单线程:
 *      遍历 flushed_cbsets 的每个元素的回调函数
 * 如果是多线程:
 *      创建新线程, 脱离主线程, 循环遍历 flushed_cbsets 中的每个元素, 并调用对应的回调函数
 */
static void
ovsrcu_quiesced(void)
{
    if (single_threaded()) {
        /*
         * 如果 flushed_cbsets 为 null, 返回 false;
         * 否则 调用 flushed_cbsets 的每个元素的回调函数, 返回 true
         */
        ovsrcu_call_postponed();
    } else {
        static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
        if (ovsthread_once_start(&once)) {
            ovs_thread_create("urcu", ovsrcu_postpone_thread, NULL);
            ovsthread_once_done(&once);
        }
    }
}

/* Indicates the beginning of a quiescent state.  See "Details" near the top of
 * ovs-rcu.h. */
/*
 * 设置当前线程专有数据 perthread_key 对应的 perthread 为 null, 并调用对应的回调函数
 *
 * 如果 perthread 不为 null, 设置 perthread_key 对应的 perthread 为 null
 *      从 ovsrcu_threads 中删除 perthread_key 对应的值 perthread, 并释放 perthread 内存,
 *      并通知其他线程有线程专有数据 perthread_key 被删除退出
 *
 *      如果是单线程:
 *          遍历 flushed_cbsets 的每个元素的回调函数, 返回 true
 *      如果是多线程:
 *          创建新线程, 脱离主线程, 循环遍历 flushed_cbsets 中的每个元素, 并调用对应的回调函数
 * 否则
 *      如果是单线程:
 *          遍历 flushed_cbsets 的每个元素的回调函数, 返回 true
 *      如果是多线程:
 *          创建新线程, 脱离主线程, 循环遍历 flushed_cbsets 中的每个元素, 并调用对应的回调函数
 *
 *  问题: 如果调用 该函数多次, 将会有多个线程执行 flushed_cbsets 是否是期望的?
 */
void
ovsrcu_quiesce_start(void)
{
    struct ovsrcu_perthread *perthread;

    ovsrcu_init_module();
    perthread = pthread_getspecific(perthread_key);
    if (perthread) {
        pthread_setspecific(perthread_key, NULL);
        /*
         * 从 ovsrcu_threads 中删除当前线程 perthread_key 对应的值 perthread, 并释放 perthread 内存,
         * 并通知其他线程有线程专有数据 perthread_key 被删除退出
         */
        ovsrcu_unregister__(perthread);
    }

    /*
     * 如果是单线程:
     *      遍历 flushed_cbsets 的每个元素的回调函数
     * 如果是多线程:
     *      创建新线程, 脱离主线程, 循环遍历 flushed_cbsets 中的每个元素, 并调用对应的回调函数
     */
    ovsrcu_quiesced();
}

/* Indicates a momentary quiescent state.  See "Details" near the top of
 * ovs-rcu.h.
 *
 * Provides a full memory barrier via seq_change().
 */
/*
 * 将当前线程专有数据 perthread_key 对应的 perthread 的 flushed_cbsets
 * 刷新到全局变量 flushed_cbsets, 并调用对应的回调函数
 *
 * 1. 将线程局部数据 perthread->cbset 加入全局数据 flushed_cbsets. 并通知其他线程, flushed_cbsets 被更新了
 * 2. 通知当前线程 seqno 改变了
 * 3. 如果是单线程: 遍历 flushed_cbsets 的每个元素的回调函数
 *    如果是多线程: 创建新线程, 脱离主线程, 循环遍历 flushed_cbsets 中的每个元素, 并调用对应的回调函数
 */
void
ovsrcu_quiesce(void)
{
    struct ovsrcu_perthread *perthread;

    perthread = ovsrcu_perthread_get();
    perthread->seqno = seq_read(global_seqno);
    if (perthread->cbset) {
        //1. 将线程局部数据 perthread->cbset 加入全局数据 flushed_cbsets. 并通知其他线程, flushed_cbsets 被更新了
        ovsrcu_flush_cbset(perthread);
    }
    seq_change(global_seqno);

    /*
     * 如果是单线程:
     *      遍历 flushed_cbsets 的每个元素的回调函数
     * 如果是多线程:
     *      创建新线程, 脱离主线程, 循环遍历 flushed_cbsets 中的每个元素, 并调用对应的回调函数
     */
    ovsrcu_quiesced();
}

//当前线程的 perthread_key 是否为 NULL
bool
ovsrcu_is_quiescent(void)
{
    ovsrcu_init_module();
    return pthread_getspecific(perthread_key) == NULL;
}

/*
 * 释放当前线程的 perthread_key, 新创建线程调用 flushed_cbsets 回调函数, 等待所有线程 seqno 变化, 然后初始化当前线程的 perthread_key
 *
 * 1. 如果是单线程, 返回
 * 2. 如果是多线程, 删除当前线程 perthread_key 对应的 perthread, 之后, 等待所有
 * 线程都删除该 perthread_key, 退出, 之后重新初始化该线程的 perthread_key
 *
 * NOTE: 这是 RCU 的核心机理, 等待所有的读者都释放旧值, 才初始化新的写者(seqno),
 * 这里的需要注意的 RCU 操作必须尽量短, 如果是网络IO, 尽量是非阻塞的接口.
 */
void
ovsrcu_synchronize(void)
{
    unsigned int warning_threshold = 1000;
    uint64_t target_seqno;
    long long int start;

    if (single_threaded()) {
        return;
    }

    target_seqno = seq_read(global_seqno);
    /*
     * 设置当前线程专有数据 perthread_key 对应的 perthread 为 null, 并调用对应的回调函数
     *
     * 1. 从 ovsrcu_threads 中删除 perthread_key 对应的值 perthread, 并释放 perthread 内存,
     * 并通知其他线程有线程专有数据 perthread_key 被删除退出
     *
     * 2. 创建新线程, 脱离主线程, 循环遍历 flushed_cbsets 中的每个元素, 并调用对应的回调函数
     */
    ovsrcu_quiesce_start();
    start = time_msec();

    for (;;) {
        uint64_t cur_seqno = seq_read(global_seqno);
        struct ovsrcu_perthread *perthread;
        char stalled_thread[16];
        unsigned int elapsed;
        bool done = true;

        //等待所有线程的 seqno 都大于 target_seqno
        ovs_mutex_lock(&ovsrcu_threads_mutex);
        LIST_FOR_EACH (perthread, list_node, &ovsrcu_threads) {
            if (perthread->seqno <= target_seqno) {
                ovs_strlcpy(stalled_thread, perthread->name,
                            sizeof stalled_thread);
                done = false;
                break;
            }
        }
        ovs_mutex_unlock(&ovsrcu_threads_mutex);

        if (done) {
            break;
        }

        elapsed = time_msec() - start;
        if (elapsed >= warning_threshold) {
            VLOG_WARN("blocked %u ms waiting for %s to quiesce",
                      elapsed, stalled_thread);
            warning_threshold *= 2;
        }
        poll_timer_wait_until(start + warning_threshold);

        seq_wait(global_seqno, cur_seqno);
        poll_block();
    }
    ovsrcu_quiesce_end();
}

/* Registers 'function' to be called, passing 'aux' as argument, after the
 * next grace period.
 *
 * The call is guaranteed to happen after the next time all participating
 * threads have quiesced at least once, but there is no quarantee that all
 * registered functions are called as early as possible, or that the functions
 * registered by different threads would be called in the order the
 * registrations took place.  In particular, even if two threads provably
 * register a function each in a specific order, the functions may still be
 * called in the opposite order, depending on the timing of when the threads
 * call ovsrcu_quiesce(), how many functions they postpone, and when the
 * ovs-rcu thread happens to grab the functions to be called.
 *
 * All functions registered by a single thread are guaranteed to execute in the
 * registering order, however.
 *
 * This function is more conveniently called through the ovsrcu_postpone()
 * macro, which provides a type-safe way to allow 'function''s parameter to be
 * any pointer type. */
/*
 * 为当前线程增加回调函数, 如果 perthread->cbset 实际数量多于 cbset->cbs 的大小,
 * 将当前线程的 cbset 加入全局的 flushed_cbsets.
 */
void
ovsrcu_postpone__(void (*function)(void *aux), void *aux)
{
    struct ovsrcu_perthread *perthread = ovsrcu_perthread_get();
    struct ovsrcu_cbset *cbset;
    struct ovsrcu_cb *cb;

    cbset = perthread->cbset;
    if (!cbset) {
        cbset = perthread->cbset = xmalloc(sizeof *perthread->cbset);
        cbset->n_cbs = 0;
    }

    cb = &cbset->cbs[cbset->n_cbs++];
    cb->function = function;
    cb->aux = aux;

    if (cbset->n_cbs >= ARRAY_SIZE(cbset->cbs)) {
        ovsrcu_flush_cbset(perthread);
    }
}

/*
 * 当前处于 Quiescent 状态, 返回 false, 不处于 Quiescent, 等待直到进入 Quiescent, 返回 true.
 *
 * 如果 flushed_cbsets 为 null, 返回 false;
 * 否则 调用 flushed_cbsets 的每个元素的回调函数, 返回 true
 */
static bool
ovsrcu_call_postponed(void)
{
    struct ovsrcu_cbset *cbset;
    struct ovs_list cbsets;

    guarded_list_pop_all(&flushed_cbsets, &cbsets);
    if (list_is_empty(&cbsets)) {
        return false;
    }

    /*
     * 等待所有线程 perthread_key 都释放, 然后初始化当前线程的 perthread_key
     *
     * 1. 如果是单线程, 返回
     * 2. 如果是多线程, 删除当前线程 perthread_key 对应的 perthread, 之后, 等待所有
     * 线程都删除该 perthread_key, 退出, 之后重新初始化该线程的 perthread_key
     *
     * NOTE: 这是 RCU 的核心机理, 等待所有的读者都释放旧值, 才初始化新的写者, 这里的
     * 需要注意的 RCU 操作必须尽量短, 如果是网络IO, 尽量是非阻塞的接口.
     */
    ovsrcu_synchronize();

    //调用 flushed_cbsets 的每个元素的回调函数
    LIST_FOR_EACH_POP (cbset, list_node, &cbsets) {
        struct ovsrcu_cb *cb;

        for (cb = cbset->cbs; cb < &cbset->cbs[cbset->n_cbs]; cb++) {
            cb->function(cb->aux);
        }
        free(cbset);
    }

    return true;
}

//当前线程脱离主线程, 循环遍历 flushed_cbsets 中的每个元素, 并调用对应的回调函数
static void *
ovsrcu_postpone_thread(void *arg OVS_UNUSED)
{
    pthread_detach(pthread_self());

    for (;;) {
        uint64_t seqno = seq_read(flushed_cbsets_seq);
        /*
         * 当前处于 Quiescent 状态, 返回 false, 不处于 Quiescent, 等待直到进入 Quiescent, 返回 true.
         *
         * 如果 flushed_cbsets 为 null, 返回 false;
         * 否则 调用 flushed_cbsets 的每个元素的回调函数, 返回 true
         */
        if (!ovsrcu_call_postponed()) {
            seq_wait(flushed_cbsets_seq, seqno);
            poll_block();
        }
    }

    OVS_NOT_REACHED();
}

//将线程局部数据 perthread->cbset 加入全局数据 flushed_cbsets. 并通知其他线程,
//flushed_cbsets 被更新了
static void
ovsrcu_flush_cbset(struct ovsrcu_perthread *perthread)
{
    struct ovsrcu_cbset *cbset = perthread->cbset;

    if (cbset) {
        guarded_list_push_back(&flushed_cbsets, &cbset->list_node, SIZE_MAX);
        perthread->cbset = NULL;

        seq_change(flushed_cbsets_seq);
    }
}

/*
 * 从 ovsrcu_threads 中删除 perthread_key 对应的值 perthread, 并释放 perthread 内存,
 * 并通知其他线程有线程专有数据 perthread_key 被删除退出
 */
static void
ovsrcu_unregister__(struct ovsrcu_perthread *perthread)
{
    if (perthread->cbset) {
        ovsrcu_flush_cbset(perthread);
    }

    ovs_mutex_lock(&ovsrcu_threads_mutex);
    list_remove(&perthread->list_node);
    ovs_mutex_unlock(&ovsrcu_threads_mutex);

    ovs_mutex_destroy(&perthread->mutex);
    free(perthread);

    seq_change(global_seqno);
}

//线程专有数据 perthread_key 被删除时的回调函数
static void
ovsrcu_thread_exit_cb(void *perthread)
{
    ovsrcu_unregister__(perthread);
}

/* Cancels the callback to ovsrcu_thread_exit_cb().
 *
 * Cancelling the call to the destructor during the main thread exit
 * is needed while using pthreads-win32 library in Windows. It has been
 * observed that in pthreads-win32, a call to the destructor during
 * main thread exit causes undefined behavior. */
//TODO
static void
ovsrcu_cancel_thread_exit_cb(void *aux OVS_UNUSED)
{
    pthread_setspecific(perthread_key, NULL);
}

/*
 * 保证线程专有数据和全局数据只被初始化一次
 */
static void
ovsrcu_init_module(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    if (ovsthread_once_start(&once)) {
        global_seqno = seq_create();
        xpthread_key_create(&perthread_key, ovsrcu_thread_exit_cb);
        fatal_signal_add_hook(ovsrcu_cancel_thread_exit_cb, NULL, NULL, true);
        list_init(&ovsrcu_threads);
        ovs_mutex_init(&ovsrcu_threads_mutex);

        guarded_list_init(&flushed_cbsets);
        flushed_cbsets_seq = seq_create();

        ovsthread_once_done(&once);
    }
}
