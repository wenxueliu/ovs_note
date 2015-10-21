/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013 Nicira, Inc.
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

/* High-level wrapper around the "poll" system call.
 *
 * The intended usage is for each thread's main loop to go about its business
 * servicing whatever events it needs to.  Then, when it runs out of immediate
 * tasks, it calls each subordinate module's "wait" function, which in turn
 * calls one (or more) of the functions poll_fd_wait(), poll_immediate_wake(),
 * and poll_timer_wait() to register to be awakened when the appropriate event
 * occurs.  Then the main loop calls poll_block(), which blocks until one of
 * the registered events happens.
 *
 *
 * Thread-safety
 * =============
 *
 * The poll set is per-thread, so all functions in this module are thread-safe.
 */
#ifndef POLL_LOOP_H
#define POLL_LOOP_H 1

#include <poll.h>
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * poll_fd_wait_at(int fd, short int events, const char *where)
 *
 * 1. 当前线程对应的 poll_loop 对象(不存在就创建), 
 * 2. 在 poll_loop 中查找 fd 对应的 poll_node:
 *    如果找到就设置该节点的监听的事件为 events
 *    如果找不到创建之后, 设置该节点的监听的事件为 events
 *
 * poll_timer_wait_at(long long int msec, const char *where)
 *
 * 1. 如果 msec <= 0, 则 poll_loop->timeout_when = LLONG_MIN
 * 2. 如果 now + msec <= LLONG_MAX, 如果 now + msec < poll_loop->timeout_when, 设置 poll_loop()->timeout_when = now + msec
 * 3. 如果 now + msec <= LLONG_MAX, poll_loop()->timeout_when = LLONG_MAX
 *
 * poll_timer_wait_until_at(long long int when, const char *where)
 *
 * 如果 when < poll_loop->timeout_when; 设置 poll_loop()->timeout_when = when; poll_loop()->timeout_where = where
 *
 * poll_immediate_wake_at(const char *where)
 *
 * 调用 poll_timer_wait_at(0, where);
 *
 * poll_block(void) TODO
 * 1. 分配 poll_loop->poll_nodes 个 pollfds
 * 2. 遍历当前线程的所有 poll_node, 将 poll_node->fd 加入 pollfds
 * 3. 等待事件发生
 * 4. 删除 poll_loop 中所有节点
 *
 */

/* Schedule events to wake up the following poll_block().
 *
 * The poll_loop logs the 'where' argument to each function at "debug" level
 * when an event causes a wakeup.  Each of these ways to schedule an event has
 * a function and a macro wrapper.  The macro version automatically supplies
 * the source code location of the caller.  The function version allows the
 * caller to supply a location explicitly, which is useful if the caller's own
 * caller would be more useful in log output.  See timer_wait_at() for an
 * example. */
void poll_fd_wait_at(int fd, short int events, const char *where);
#define poll_fd_wait(fd, events) poll_fd_wait_at(fd, events, OVS_SOURCE_LOCATOR)

#ifdef _WIN32
#define poll_wevent_wait(wevent) poll_wevent_wait_at(wevent, OVS_SOURCE_LOCATOR)
#endif /* _WIN32 */

void poll_timer_wait_at(long long int msec, const char *where);
#define poll_timer_wait(msec) poll_timer_wait_at(msec, OVS_SOURCE_LOCATOR)

void poll_timer_wait_until_at(long long int msec, const char *where);
#define poll_timer_wait_until(msec)             \
    poll_timer_wait_until_at(msec, OVS_SOURCE_LOCATOR)

void poll_immediate_wake_at(const char *where);
#define poll_immediate_wake() poll_immediate_wake_at(OVS_SOURCE_LOCATOR)

/* Wait until an event occurs. */
void poll_block(void);

#ifdef  __cplusplus
}
#endif

#endif /* poll-loop.h */
