/*
 * Copyright (c) 2013, 2014 Nicira, Inc.
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

#ifndef FAT_RWLOCK_H
#define FAT_RWLOCK_H 1

#include "compiler.h"
#include "list.h"
#include "ovs-thread.h"

/* "Fat rwlock".
 *
 * This implements a reader-writer lock that uses a lot of memory (128 to 192
 * bytes per thread that takes the lock) but avoids cache line bouncing when
 * taking the read side.  Thus, a fat_rwlock is a good choice for rwlocks taken
 * frequently by readers.
 */

/*
 * ###多读少些锁
 *
 * 例如, 定义一个 fat_rwlock 对象 fat, key = "t_lock"
 *
 * fat_rwlock_init(fat) :
 * 在当前线程创建一个 t_lock 对应的 fat_rwlock_slot 对象 slot, 在当前线程的任何地方可以通过 t_lock 访问该 slot. 而其他线程不会看到该 slot
 *
 * fat_rwlock_rdlock(fat) :
 * 1. 如果当前线程不存在 t_lock 对应的 slot, 创建 t_lock 对应的 slot 并加入 t_lock->threads, 并对 slot->mutex 加锁
 * 2. 如果当前线程存在 t_lock 对应的 slot, slot->mutx 没有被写锁, 那么 slot->depth++,　因此可以多次调用
 * 3. 如果当前线程存在 t_lock 对应的 slot, slot->mutx 有被写锁, 直接退出
 *
 * NOTE
 * 这里仍然是有锁的, 维护key 每个线程的列表, 需要操作的原子性. 即
 * 如果其他线程正在给 fat->threads 进行操作, 那么 1 很可能需要等待, 直到对 fat->threads 的操作被释放.
 *
 * fat_rwlock_tryrdlock(fat) :
 * 如果当前线程不存在 t_lock 对应的 slot, 创建 t_lock 对应的 slot, 如果 fat->threads 没有在被其他线程加锁, 创建 slot 加入 t_lock->threads, 并对 slot->mutex 尝试加锁
 * 如果当前线程不存在 t_lock 对应的 slot, 创建 t_lock 对应的 slot, 如果 fat->threads 有在被其他线程加锁, 返回 EBUSY
 * 如果当前线程存在 t_lock 对应的 slot, slot->mutx 没有被写锁, 那么 slot->depth++,　因此可以多次调用
 * 如果当前线程存在 t_lock 对应的 slot, slot->mutx 有被写锁, 返回 EBUSY
 *
 * fat_rwlock_unlock(fat)
 * 如果当前线程被读锁, 那么, 1 < thid->depth < UINT_MAX this->depth--
 * 如果当前线程被读锁, 那么, this->depth=1, this->mutex 解锁
 * 如果当前线程被写锁, 那么, 与 t_lock 管理的所有线程, TODO this->depth=0, this->mutex 解锁
 *
 * fat_rwlock_wrlock(fat) : 全局锁
 * 等待直到所有线程 t_lock 对应的 slot 的读锁都释放. 后续任何线程的不管是读锁还是写锁都阻塞. 直到 fat_rwlock_unlock() 调用释放掉锁.
 *
 * 由上分析, 适合多读少些的情况. 如果经常写, 显然与平常的锁没有什么区别了.
 *
 */
struct OVS_LOCKABLE fat_rwlock {
    ovsthread_key_t key;

    /* Contains "struct fat_rwlock_slot"s, one for each thread that has taken
     * this lock.  Guarded by 'mutex'. */
    struct ovs_list threads OVS_GUARDED; //每个线程与 key 关联的 fat_rwlock_slot 保存在这里
    struct ovs_mutex mutex; //保护 threads 防止被多个线程访问. 也即保证链表在多线程下操作的原子性
};

void fat_rwlock_init(struct fat_rwlock *);
void fat_rwlock_destroy(struct fat_rwlock *);

void fat_rwlock_rdlock(const struct fat_rwlock *rwlock) OVS_ACQ_RDLOCK(rwlock);
int fat_rwlock_tryrdlock(const struct fat_rwlock *rwlock)
    OVS_TRY_RDLOCK(0, rwlock);
void fat_rwlock_wrlock(const struct fat_rwlock *rwlock) OVS_ACQ_WRLOCK(rwlock);
void fat_rwlock_unlock(const struct fat_rwlock *rwlock) OVS_RELEASES(rwlock);

#endif /* fat-rwlock.h */
