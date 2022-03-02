/************************************************************
 Copyright (c) Huawei Technologies Co., Ltd. 2015-2020. All rights reserved.
  FileName: agent_dead_loop.c
  Author:   
  Version :
  Date: 2015-12-02
  Description:
  Version:
  Function List:
  History:
      <author>  <time>   <version >   <desc>
 ***********************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <syscall.h>

#include "../interface/dswareAgent_interface.h"
#include "../utility/agent_op_log.h"
#include "../config/dsware_agent_conf.h"

bool is_process_monitor_exited = false;

extern void close_file_descript(void);

#define PTHREAD_CHECK_USED 1
#define PTHREAD_CHECK_FREE 0

#define DEFUALT_THREAD_CHECK_TIME 30

#define gettid() syscall(__NR_gettid)

typedef struct agent_pthread_check {
    list_head_t list;
    pthread_mutex_t lock;
    dsw_u16 cur_times; // 记录当前线程运行次数
} agent_pthread_check_t;

typedef struct agent_thread_hb_monitor {
    dsw_int flag;
    dsw_u8 pthread_id;
    dsw_u16 cur_times;
    dsw_u32 time_out;
    pid_t  os_thread_id; // 真实的线程ID,上面那个是假的,被其他同学挪作他用了
    void (*func)(void);
} agent_thread_hb_monitor_t;

agent_pthread_check_t g_agent_pthread_t;

dsw_int g_agent_inner_thread_check_flag = 1;

agent_thread_hb_monitor_t agent_pthread_hb[AGENT_THREAD_NUM];

pthread_t g_agent_dead_loop_thread;

void agent_thread_set_hb(dsw_u8 thread_id)
{
    if (thread_id >= AGENT_THREAD_NUM) {
        return;
    }

    (void)pthread_mutex_lock(&g_agent_pthread_t.lock);
    agent_pthread_hb[thread_id].cur_times = 0;
    (void)pthread_mutex_unlock(&g_agent_pthread_t.lock);

    return;
}

void agent_regsiter_inner_thread(dsw_u8 thread_id, dsw_u32 time_out, void *func)
{
    if (thread_id >= AGENT_THREAD_NUM) {
        return;
    }

    (void)pthread_mutex_lock(&g_agent_pthread_t.lock);

    agent_pthread_hb[thread_id].flag = PTHREAD_CHECK_USED;
    agent_pthread_hb[thread_id].pthread_id = thread_id;
    agent_pthread_hb[thread_id].time_out = time_out * g_agent_sys_val.agent_thread_check_timeout;
    agent_pthread_hb[thread_id].os_thread_id = gettid();

    // 当前的线程中，有很多流程会卡时间很长，如果时间太短，会导致agent重启
    // 未来版本，需要合并线程，将耗时长的处理放在后台处理
    if (agent_pthread_hb[thread_id].time_out < DEFUALT_THREAD_CHECK_TIME *
        g_agent_sys_val.agent_thread_check_timeout) {
        agent_pthread_hb[thread_id].time_out = DEFUALT_THREAD_CHECK_TIME * g_agent_sys_val.agent_thread_check_timeout;
    }

    agent_pthread_hb[thread_id].func = NULL;

    if (NULL != func) {
        agent_pthread_hb[thread_id].func = func;
    }

    LOG_INFO("regsiter inner thread ,id=%d,time_out=%d.", agent_pthread_hb[thread_id].pthread_id,
             agent_pthread_hb[thread_id].time_out);

    (void)pthread_mutex_unlock(&g_agent_pthread_t.lock);

    return;
}

void agent_unregsiter_inner_thread(dsw_u8 thread_id)
{
    if (thread_id >= AGENT_THREAD_NUM) {
        return;
    }

    (void)pthread_mutex_lock(&g_agent_pthread_t.lock);
    memset_s(&agent_pthread_hb[thread_id], sizeof(agent_thread_hb_monitor_t), 0, sizeof(agent_thread_hb_monitor_t));
    agent_pthread_hb[thread_id].flag = PTHREAD_CHECK_FREE;
    (void)pthread_mutex_unlock(&g_agent_pthread_t.lock);

    return;
}

void *agent_thread_dead_loop_check(void *arg)
{
    dsw_int cur_pid = 0;

    LOG_INFO("start inner thread dead loop check.");

    while (g_agent_inner_thread_check_flag) {
        sleep(DEFUALT_THREAD_CHECK_TIME);

        (void)pthread_mutex_lock(&g_agent_pthread_t.lock);

        for (cur_pid = 0; cur_pid < AGENT_THREAD_NUM; cur_pid++) {
            if (agent_pthread_hb[cur_pid].flag != PTHREAD_CHECK_USED) {
                continue;
            }

            if (agent_pthread_hb[cur_pid].cur_times * DEFUALT_THREAD_CHECK_TIME > agent_pthread_hb[cur_pid].time_out) {
                LOG_ERROR("agent thread %d:%d abnormal,%d no response.", cur_pid, agent_pthread_hb[cur_pid].os_thread_id, agent_pthread_hb[cur_pid].time_out);
                dsware_agent_exit();
                close_file_descript();
                is_process_monitor_exited = true;
                exit(1);
            }

            agent_pthread_hb[cur_pid].cur_times++;
            if (NULL != agent_pthread_hb[cur_pid].func) {
                agent_pthread_hb[cur_pid].func();
            }
        }
        (void)pthread_mutex_unlock(&g_agent_pthread_t.lock);
    }

    return (void *)0;
}

dsw_int start_inner_dead_loop_thread(void)
{
    dsw_int ret = 0;
    dsw_int cur_pid = 0;

    list_init_head(&g_agent_pthread_t.list);

    for (cur_pid = 0; cur_pid < AGENT_THREAD_NUM; cur_pid++) {
        memset_s(&agent_pthread_hb[cur_pid], sizeof(agent_thread_hb_monitor_t), 0, sizeof(agent_thread_hb_monitor_t));
        agent_pthread_hb[cur_pid].flag = PTHREAD_CHECK_FREE;
    }

    if (pthread_mutex_init(&g_agent_pthread_t.lock, NULL)) {
        LOG_ERROR("init agent inner thread lock error.");
        return 1;
    }

    ret = pthread_create(&g_agent_dead_loop_thread, NULL, agent_thread_dead_loop_check, NULL);

    if (ret) {
        int errnum = ret;
        DSA_ERRNO_PRINT(errnum);
        LOG_ERROR("failed to create a inner dead loop check thread");
        return 1;
    }

    return 0;
}

dsw_s32 InitDeadLoopModule(void)
{
    if (start_inner_dead_loop_thread() != DSWARE_AGENT_OK) {
        return DSWARE_AGENT_ERR;
    }

    return DSWARE_AGENT_OK;
}

