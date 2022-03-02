 /*
  * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
  * Description: 
  * Author: 
  * Create: 2017-02-18
  * Notes: 
  * History: 
  * No      Data             Author                  Modification
  *	1.     2017-02-18    wangyuheng(00385604)        Created file.		 
  */
#ifndef THIRD_SERVICE_MONITOR_H
#define THIRD_SERVICE_MONITOR_H

#include "../interface/dswareAgent_interface.h"
#include "../../include/smartdata/include/smio.h"

#define DSA_DISK_MONITOR_CONFIG(file) do { \
        snprintf_s(file, sizeof(file), sizeof(file) - 1, "%s/conf/disk_monitor.cfg", g_fsm_agent_dir); \
    } while (0)

typedef struct sdi_ep_alarm {
    int normal_time;        // 记录正常次数用于恢复告警
    int alarm_send_flag;    // 记录上次告警是否发送成功
    int alarm_status;       // 当前EP状态
    int alarm_send_status;  // 上次发送告警的状态
    pthread_mutex_t alarm_lock;
} sdi_ep_alarm_t;

// 通知元数据盘状态的抑制标识位
// （-1：初始状态|0：已发送恢复消息|1：已发送故障消息）
typedef struct ds_notify_flag {
    int disk_not_exist;     // 盘不在位
    int disk_smart_exceed;  // 盘SMART信息超标
    int disk_high_temp;     // 盘高温
    int disk_slow;          // 慢盘
    int disk_io_block;      // 盘IO Block
} ds_notify_flag_t;

enum DS_NOTIFY_FLAG {
    DS_DISK_NOT_EXIST = 0,          // 盘不在位
    DS_DISK_SMART_EXCEED = 1,       // 盘SMART信息超标
    DS_DISK_HIGH_TMEP = 2,          // 盘高温
    DS_DISK_SLOW = 3,               // 慢盘
    DS_DISK_IO_BLOCK = 4,           // 盘IO Block
    DS_DISK_RAID_DOWN_GRADE = 5,    // raid降级
    DS_DISK_MEDIA_FAULT = 6	        // 介质故障
};

typedef struct ds_disk_info {
    pthread_mutex_t ds_disk_info_lock;
    int dev_slot;
    char dev_esn[SMIO_DEV_ESN_MAX_LEN];
    char dev_name[SMIO_DEV_NAME_MAX_LEN];
    int dev_type;    // 磁盘类型：-1/UNKNOWN;0/HDD;1/SSD
} ds_disk_info_t;

typedef struct _ds_sys_disk_info {
    int dev_slot;
    char dev_esn[SMIO_DEV_ESN_MAX_LEN];
    char dev_name[SMIO_DEV_NAME_MAX_LEN];
    int dev_type;    // 磁盘类型：-1/UNKNOWN;0/HDD;1/SSD
    int status;     // 磁盘状态：0/正常;其他/亚健康
} _ds_sys_disk_info_t;

typedef struct ds_sys_disk_info {
    pthread_mutex_t ds_sys_disk_info_lock;
    int raid_type;
    dsw_u16 disk_num;
    _ds_sys_disk_info_t sys_disk_info[SMIO_MEDIA_MAX_PER_ENCLOURSE];
} ds_sys_disk_info_t;


// 慢盘计数
typedef struct ds_slow_disk_count {
    unsigned long max_loop_period_counter;    // 大周期循环计数
    unsigned long has_io_period_counter;      // 有IO周期计数
    unsigned long max_loop_slipping_flag;     // 大周期跳过标记
    unsigned long slow_disk_counter;          // 慢周期计数
    unsigned long serious_slow_disk_counter;  // 严重慢周期计数
    unsigned long rd_ios;
    unsigned long wr_ios;
    unsigned int  tot_ticks;
    unsigned int  rq_ticks;
    unsigned long long limit_svctm;
    unsigned char block_io_detect_counter;
    unsigned char block_io_alarm_flag;
    unsigned char no_block_io_detect_cnt;
    unsigned long no_slow_disk_counter;         // 非慢盘计数
    unsigned char slow_disk_alarm_flag;
    dsw_u32       sdisk_sd;                     // 慢周期阈值(hdd和ssd不同)
    unsigned long query_time;                   // 查询IO统计值的时间
} ds_slow_disk_count_t;

// io block计数
typedef struct ds_io_block_count {
    int io_block_count;     // 连续io block计数
    int io_no_block_count;  // 连续未io block计数
    unsigned long rd_ios;
    unsigned long wr_ios;
    unsigned int  tot_ticks;
    unsigned int  rq_ticks;
} ds_io_block_count_t;

// 保电盘
typedef struct _ds_m2_disk_info {
    int dev_slot;
    char dev_esn[SMIO_DEV_ESN_MAX_LEN];
    char dev_name[SMIO_DEV_NAME_MAX_LEN];
    int notify_flag;
    dsw_u32 notify_count;
} _ds_m2_disk_info_t;

typedef struct ds_m2_disk_info {
    pthread_mutex_t ds_m2_disk_info_lock;
    int disk_num;
    _ds_m2_disk_info_t m2_disk_info[SMIO_MEDIA_MAX_PER_ENCLOURSE];
} ds_m2_disk_info_t;

int ds_update_m2disk_info(void);
void ds_init_m2_disk_notify_flag(void);
extern void sdi_ep_check_init(void);

extern ds_sys_disk_info_t g_ds_sys_disk_info;
void SetZkSubhealthCheckSwitch(bool switchValue);

#endif /* THIRD_SERVICE_MONITOR_H */
