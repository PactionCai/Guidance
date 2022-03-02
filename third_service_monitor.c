
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * File name: third_service_monitor.c
 * Description: 
 * Author: 
 * Create: 2017-02-18
 * Notes: 
 * History: 
 *	 No      Data             Author                  Modification
 *   1.     2017-02-18    wangyuheng(00385604)        Created file.		
 */
#include "third_service_monitor.h"
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../../include/hardware_fault/hardware_fault.h"
#include "../alarm/dsware_agent_alarm.h"
#include "../monitor/dsware_agent_timer_zk.h"
#include "../config/dsware_agent_conf.h"
#include "../utility/agent_op_log.h"
#include "../interface/dsware_agent_disk_monitor.h"
#include "../rep/rep_volume_define.h"
#include "./interface/fsa_op_media.h"
#include "../net_module/dev_mon/devmon_env.h"
#include "../interface/dsa_get_disk_info.h"
#include "../interface/rep_custom_cmd.h"
#include "dsware_agent_handle.h"

#define SDI_NO_SEND_ALARM 0
#define SDI_ALARM_SEND_OK 1
#define SDI_ALARM_SEND_FAIL 2
#define SDI_NORMAL_THRESHOLD 3
#define SDI_EP_CHECK_INTERVAL 60
#define LINK_DOWN_BIT 0
#define HEART_LOST_BIT 1
#define SYNC_TIMEOUT_BIT 2
#define SPEED_ERROR_BIT 3
#define DRIVER_UNLOAD_BIT 15
#define SDI_EP_ALARM_SYNC_INTERVAL (10*60)
#define EP_CHECK_FILE "/sys/kernel/epback/ep_event"
#define SDI_NO_HAVE_VALUE   "NA"
#define SDI_HAVE_VALUE   "[YES]"
#define SDI_EP_OK 0
#define DSIK_STATE_CHECK_LONG 7
#define NUM0 0
#define NO_IBMC_ALARM_STATE 0
#define HT_CHECK_EXCEP_ALARM_STATE 1
#define IBMC_AUTH_FAIL_ALARM_STATE 2
#define DEFAULT_THRID_34_SLEEP_TIME 120
#define DA_OP_SYS_RAID_ENV_CHECK "sys_raid_env_check"


sdi_ep_alarm_t g_sdi_ep_alarm;
pthread_t g_update_metadisk_info_thread;
pthread_t g_timer_zk_thread;
pthread_mutex_t g_ntp_check_mutex;
pthread_t g_timer_sysdisk_subhealth_thread;
pthread_t g_cpuTuyeyeTemMonThread;
pthread_t g_diskTemMonThread;


ds_disk_info_t g_ds_metadisk_info_zk;
ds_disk_info_t g_ds_metadisk_info_eds_ccdb;
ds_disk_info_t g_ds_metadisk_info_rep_ccdb;
ds_sys_disk_info_t g_ds_sys_disk_info;
ds_m2_disk_info_t g_ds_m2_disk_info;

bool g_ds_need_resume_zk = DSW_FALSE;
bool g_ds_need_resume_eds_ccdb = DSW_FALSE;
bool g_ds_need_resume_rep_ccdb = DSW_FALSE;
bool g_ds_need_resume_sys = DSW_FALSE;
bool g_sys_raid_flag = DSW_TRUE;
dsw_s16 g_ibmc_alarm_flag = -1;
int g_lastExCheckResult = 0;
extern component_vol_list g_component_vol;
extern bool g_ds_ccdb_ok;
bool g_ds_zk_subhealth_check = DSW_FALSE;

ds_notify_table g_ds_notify_table[] = {
    { DS_HEALTH_MASK_INVALID, DS_HEALTH_MASK_INVALID, DS_DISK_STAT_NOT_EXIST, DS_DISK_NOT_EXIST },
    { DS_HEALTH_MASK_INVALID, DS_HEALTH_MASK_INVALID, DS_DISK_STAT_SMART_EXCEED, DS_DISK_SMART_EXCEED },
    { DS_HEALTH_MASK_INVALID, DS_HEALTH_MASK_INVALID, DS_DISK_STAT_HIGH_TEMP, DS_DISK_HIGH_TMEP },
    { DS_HEALTH_MASK_INVALID, DS_HEALTH_MASK_INVALID, DS_DISK_STAT_SLOW, DS_DISK_SLOW },
    { DS_HEALTH_MASK_INVALID, DS_HEALTH_MASK_INVALID, DS_DISK_STAT_IO_BLOCK, DS_DISK_IO_BLOCK },
};


extern int start_slow_component_disk_check(void);
extern int stop_slow_component_disk_check(void);
extern int ds_notify(int, dsw_s32, int, int, char *, char *);
int ds_get_rep_ccdb_vol(process_vol *OUT result_vol);


static inline void construct_ep_exception(dsw_u32 status, dsw_u32 bit_num, char *OUT display, dsw_u32 len)
{
    dsw_u32 bit_flag = 0x00000001 << bit_num;
    if (bit_flag & status) {
        strncpy_s(display, len, SDI_HAVE_VALUE, len - 1);
    } else {
        strncpy_s(display, len, SDI_NO_HAVE_VALUE, len - 1);
    }
}

static int get_additional_info_from_status(char* additional_info, int status, int len)
{
    if (additional_info == NULL || len <= 0) {
        LOG_ERROR("param error");
        return DA_FAIL;
    }

    char *alarm_format = "%s;%s;%s;%s;%s";
    char link_down[BUFSIZE_32] = {0};
    char heart_lose[BUFSIZE_32] = {0};
    char sync_timeout[BUFSIZE_32] = {0};
    char speed_error[BUFSIZE_32] = {0};
    char driver_unload[BUFSIZE_32] = {0};
    int ret = 0;

    construct_ep_exception((dsw_u32)status, LINK_DOWN_BIT, link_down, BUFSIZE_32);
    construct_ep_exception((dsw_u32)status, HEART_LOST_BIT, heart_lose, BUFSIZE_32);
    construct_ep_exception((dsw_u32)status, SYNC_TIMEOUT_BIT, sync_timeout, BUFSIZE_32);
    construct_ep_exception((dsw_u32)status, SPEED_ERROR_BIT, speed_error, BUFSIZE_32);
    construct_ep_exception((dsw_u32)status, DRIVER_UNLOAD_BIT, driver_unload, BUFSIZE_32);

    ret = snprintf_s(additional_info, len, len - 1, alarm_format, link_down, heart_lose, sync_timeout, speed_error,
                     driver_unload);
    if (ret == -1) {
        LOG_ERROR("snprintf_s fail,%s;%s;%s;%s;%s;%s", alarm_format, link_down, heart_lose, sync_timeout, speed_error,
                  driver_unload);
        return DA_FAIL;
    }

    LOG_INFO("format:link_down:;heart_lose:;sync_timeout:;speed_error:;driver_unload");
    LOG_INFO("ep alarm additional:%s", additional_info);
        
    return DA_OK;
}

static int send_sdi_ep_alarm(int status)
{
    char additional_info[FML_ALARM_ADD_LEN];
    int ret = 0;

    ret = get_additional_info_from_status(additional_info, status, FML_ALARM_ADD_LEN);
    if (ret != DA_OK) {
        LOG_ERROR("get addition info fail");
        return DA_FAIL;
    }

    if (status == SDI_EP_OK) {
        ret = send_sdi_alarm(DSA_ALARM_ID_EP_ALARM, RESUME_ALARM, additional_info);
    } else {
        ret = send_sdi_alarm(DSA_ALARM_ID_EP_ALARM, SEND_ALARM, additional_info);
    }

    if (ret != DA_OK) {
        LOG_ERROR("send ep alarm fail");
        return DA_FAIL; 
    }

    return DA_OK;
}

static int check_ep_status(int* status)
{

    FILE *p_fd = NULL;
    char buf[BUFSIZE_1024];

    memset_s(buf, BUFSIZE_1024, 0, BUFSIZE_1024);

    if ((p_fd = fopen(EP_CHECK_FILE, "r")) == NULL) {
        int errnum = errno;
        DSA_ERRNO_PRINT(errnum);
        LOG_ERROR("Open conf file error, file name = %s", EP_CHECK_FILE);
        return DA_FAIL;
    }

    if (fgets(buf, BUFSIZE_1024, p_fd) == NULL) {
        LOG_ERROR("read conf file error, file name = %s", EP_CHECK_FILE);
        fclose(p_fd);
        return DA_FAIL;
    }

    if (status != NULL) {
        if (sscanf_s(buf, "%x", status) != 1) {
            LOG_ERROR("sscanf_s failed");
            fclose(p_fd);
            return DA_FAIL;
        }
        LOG_DEBUG("sdi ep channel status is %d", *status);
    }
    
    fclose(p_fd);
    return DA_OK;
}

static void sdi_ep_alarm_send_when_failed(void)
{

    int ret = DA_OK;

    DSW_THREAD_MUTEX_LOCK(&(g_sdi_ep_alarm.alarm_lock));
    if (g_sdi_ep_alarm.alarm_send_flag == SDI_ALARM_SEND_FAIL) {
        ret = send_sdi_ep_alarm(g_sdi_ep_alarm.alarm_send_status);
        if (ret != DA_OK) {
            LOG_ERROR("send sdi ep alarm fail");
            g_sdi_ep_alarm.alarm_send_flag = SDI_ALARM_SEND_FAIL;
        } else {
            g_sdi_ep_alarm.alarm_send_flag = SDI_ALARM_SEND_OK;
        }
        
    }
    DSW_THREAD_MUTEX_UNLOCK(&(g_sdi_ep_alarm.alarm_lock));
}

static void sync_sdi_ep_alarm(void)
{
    DSW_THREAD_MUTEX_LOCK(&(g_sdi_ep_alarm.alarm_lock));
    if (g_sdi_ep_alarm.alarm_send_flag == SDI_NO_SEND_ALARM) {
        DSW_THREAD_MUTEX_UNLOCK(&(g_sdi_ep_alarm.alarm_lock));
        return;
    }
    // 告警同步不会改变任何状态
    if (send_sdi_ep_alarm(g_sdi_ep_alarm.alarm_send_status) != DA_OK) {
        LOG_ERROR("sync_sdi_ep_alarm fail");
    }
    DSW_THREAD_MUTEX_UNLOCK(&(g_sdi_ep_alarm.alarm_lock));
}


static void send_sdi_ep_alarm_and_set_status(int status)
{
    int ret = 0;

    ret = send_sdi_ep_alarm(status);
    if (ret != DA_OK) {
        g_sdi_ep_alarm.alarm_send_flag = SDI_ALARM_SEND_FAIL;
    } else {
        g_sdi_ep_alarm.alarm_send_flag = SDI_ALARM_SEND_OK;
    }
    g_sdi_ep_alarm.alarm_send_status = status;
}

static void handle_sdi_ep_alarm(void)
{
    int ret = 0;
    int status = 0;

    // 检查EP状态
    ret = check_ep_status(&status);
    if (ret != DA_OK) {
        LOG_ERROR("check ep status fail");
        return;
    }

    DSW_THREAD_MUTEX_LOCK(&(g_sdi_ep_alarm.alarm_lock));
    // 如果连续3次,正常发送恢复，启动时连续3次正常会默认发送一次告警
    if (status == SDI_EP_OK) {
        if (g_sdi_ep_alarm.normal_time < SDI_NORMAL_THRESHOLD) {
            ++(g_sdi_ep_alarm.normal_time);
            if (g_sdi_ep_alarm.normal_time >= SDI_NORMAL_THRESHOLD) {
                send_sdi_ep_alarm_and_set_status(status);
                g_sdi_ep_alarm.alarm_status = status;
            }
        }
    } else {
        // 告警状态改变更新告警
        g_sdi_ep_alarm.normal_time = 0;
        if (g_sdi_ep_alarm.alarm_send_status != status) {
            send_sdi_ep_alarm_and_set_status(status);
            g_sdi_ep_alarm.alarm_status = status;
        }
    }
    DSW_THREAD_MUTEX_UNLOCK(&(g_sdi_ep_alarm.alarm_lock));
    
}

static void check_and_alarm_ep_status(dsw_u32 count)
{
    if (get_agent_server_flag() != DSW_SERVER_ARM_SDI_T) {
        LOG_DEBUG("server type is not sdi no need check");
        return;     
    }

    // 每一分钟检查一次
    if ((count % SDI_EP_CHECK_INTERVAL) != 0) {
        LOG_DEBUG("period no effect,no need check");
        return;
    }

    // 发送失败重发告警
    sdi_ep_alarm_send_when_failed();

    // 检查状态并发送告警
    handle_sdi_ep_alarm();

    if ((count % SDI_EP_ALARM_SYNC_INTERVAL) == 0) {
        // 没10分钟同步一次告警
        sync_sdi_ep_alarm();
    }
}

/*************************************************
  函数: ds_init_notify_flag
  描述: 初始化盘亚健康通知抑制标识位
  入参: no
  出参: notify_flag
  返回: void
  其它: c00473536 20190614
*************************************************/
void ds_init_notify_flag(int *OUT notify_flag)
{
    *(notify_flag + DS_DISK_NOT_EXIST)          = DS_NOTIFY_INIT;
    *(notify_flag + DS_DISK_SMART_EXCEED)       = DS_NOTIFY_INIT;
    *(notify_flag + DS_DISK_HIGH_TMEP)          = DS_NOTIFY_INIT;
    *(notify_flag + DS_DISK_SLOW)               = DS_NOTIFY_INIT;
    *(notify_flag + DS_DISK_IO_BLOCK)           = DS_NOTIFY_INIT;
	*(notify_flag + DS_DISK_RAID_DOWN_GRADE)    = DS_NOTIFY_INIT;
    *(notify_flag + DS_DISK_MEDIA_FAULT)        = DS_NOTIFY_INIT;

    return;
}

/*************************************************
  函数: ds_init_slow_disk_count
  描述: 初始化慢盘计数
  入参: ds_slow_disk_count_t
  出参: slow_disk_count
  返回: void
  其它: c00473536 20190614
*************************************************/
void ds_init_slow_disk_count(ds_slow_disk_count_t *OUT slow_disk_count)
{
    slow_disk_count->max_loop_period_counter = 0;
    slow_disk_count->has_io_period_counter = 0;
    slow_disk_count->max_loop_slipping_flag = 0;
    slow_disk_count->slow_disk_counter = 0;
    slow_disk_count->serious_slow_disk_counter = 0;
    return;
}

/*************************************************
  函数: ds_init_io_block_count
  描述: 初始化盘io block计数
  入参: void
  出参: io_block_count
  返回: void
  其它: c00473536 20190614
*************************************************/
void ds_init_io_block_count(ds_io_block_count_t *OUT io_block_count)
{
    io_block_count->io_block_count      = DEFAULT_VALUE;
    io_block_count->io_no_block_count   = DEFAULT_VALUE;
    io_block_count->rd_ios              = DEFAULT_VALUE;
    io_block_count->wr_ios              = DEFAULT_VALUE;
    io_block_count->tot_ticks           = DEFAULT_VALUE;
    io_block_count->rq_ticks            = DEFAULT_VALUE;
    return;
}

/*************************************************
  函数: ds_init_metadisk_info
  描述: 初始化zk和eds ccdb的元数据盘信息
  入参: void
  出参: void
  返回: int
  其它: c00473536 20190617
*************************************************/
int InitFsaMetadiskInfo(void)
{
    if (pthread_mutex_init(&g_ds_metadisk_info_zk.ds_disk_info_lock, NULL)) {
        LOG_ERROR("Init zk disk monitor lock error.");
        return DA_ERR_METADISK_INFO_INIT;
    }

    if (pthread_mutex_init(&g_ds_metadisk_info_eds_ccdb.ds_disk_info_lock, NULL)) {
        LOG_ERROR("Init eds disk monitor lock error.");
        return DA_ERR_METADISK_INFO_INIT;
    }

    if (pthread_mutex_init(&g_ds_metadisk_info_rep_ccdb.ds_disk_info_lock, NULL)) {
        LOG_ERROR("Init rep disk monitor lock error.");
        return DA_ERR_METADISK_INFO_INIT;
    }

    if (pthread_mutex_init(&g_ds_sys_disk_info.ds_sys_disk_info_lock, NULL)) {
        LOG_ERROR("Init sys disk monitor lock error.");
        return DA_ERR_METADISK_INFO_INIT;
    }

    if (pthread_mutex_init(&g_ds_m2_disk_info.ds_m2_disk_info_lock, NULL)) {
        LOG_ERROR("Init m2 disk monitor lock error.");
        return DA_ERR_METADISK_INFO_INIT;
    }
    
    return DA_OK;
}

/*************************************************
  函数: ds_init_m2_disk_notify_flag
  描述: 初始化保电盘亚健康通知抑制标识位和通知计数
  入参: void
  出参: no
  返回: void
  其它: c00473536 20190614
*************************************************/
void ds_init_m2_disk_notify_flag(void)
{
    (void)pthread_mutex_lock(&g_ds_m2_disk_info.ds_m2_disk_info_lock);
    g_ds_m2_disk_info.disk_num = NUM0;
    for (int i = 0; i < NUM_10; i++) {
        g_ds_m2_disk_info.m2_disk_info[i].notify_flag = DS_NOTIFY_INIT;
        g_ds_m2_disk_info.m2_disk_info[i].notify_count = NUM0;
        g_ds_m2_disk_info.m2_disk_info[i].dev_slot = DS_NOTIFY_INIT;
        strncpy_s(g_ds_m2_disk_info.m2_disk_info[i].dev_esn, SMIO_DEV_ESN_MAX_LEN, "unknown", SMIO_DEV_ESN_MAX_LEN - 1);
        strncpy_s(g_ds_m2_disk_info.m2_disk_info[i].dev_name, SMIO_DEV_NAME_MAX_LEN, "unknown", SMIO_DEV_NAME_MAX_LEN - 1);
    }
    (void)pthread_mutex_unlock(&g_ds_m2_disk_info.ds_m2_disk_info_lock);

    return;
}


/*************************************************
  函数: ds_update_metadisk_info
  描述: 更新zk和eds ccdb的元数据盘信息
  入参: void
  出参: void
  返回: void
  其它: c00473536 20190627
*************************************************/
void ds_update_metadisk_info(void)
{
    char *p_val = NULL;
    int dev_slot = ZK_SLOT_ORIGINAL;
    char dev_esn[SMIO_DEV_ESN_MAX_LEN] = {DEFAULT_VALUE};
    char dev_name[SMIO_DEV_NAME_MAX_LEN] = {DEFAULT_VALUE};
    char metadisk_info_file[DSA_DIR_PATH_MAX] = {DEFAULT_VALUE};
    process_vol rep_ccdb_vol;
	
    // zk slot
    ZK_SLOT_FILE(metadisk_info_file);
    if (get_conf_var(metadisk_info_file, ZK_SLOT, &p_val) == DSWARE_AGENT_OK) {
        dev_slot = atoi(p_val);
        FREE(p_val);
        if ((dev_slot < 0) || (dev_slot > MAX_VAL_VALUE)) {
            LOG_ERROR("got wrong zk slot, slot=%d", dev_slot);
            dev_slot = ZK_SLOT_ORIGINAL;
        }
    }
    // zk esn
    if (get_conf_var(metadisk_info_file, ZK_ESN, &p_val) == DSWARE_AGENT_OK) {
        strncpy_s(dev_esn, SMIO_DEV_ESN_MAX_LEN, p_val, strnlen(p_val, BUFSIZE_64 - 1));
        FREE(p_val);
    }
    // zk盘符
    if (GetZkDiskPath(dev_slot, dev_name, BUFSIZE_64, dev_esn) != DA_OK) {
        LOG_DEBUG("get zk disk name by slot and esn failed. slot=%d, esn=%s", dev_slot, dev_esn);
    }
    if (strlen(dev_name) == 0) {
        strncpy_s(dev_name, SMIO_DEV_NAME_MAX_LEN, "unknown", SMIO_DEV_NAME_MAX_LEN - 1);
    }
    // 磁盘类型
    int disk_type = ds_get_disk_type_by_slot_from_smio(dev_slot);
    pthread_mutex_lock(&g_ds_metadisk_info_zk.ds_disk_info_lock);
    g_ds_metadisk_info_zk.dev_slot = dev_slot;
    g_ds_metadisk_info_zk.dev_type = disk_type;
    strncpy_s(g_ds_metadisk_info_zk.dev_esn, SMIO_DEV_ESN_MAX_LEN, dev_esn, SMIO_DEV_ESN_MAX_LEN - 1);
    strncpy_s(g_ds_metadisk_info_zk.dev_name, SMIO_DEV_NAME_MAX_LEN, dev_name, SMIO_DEV_NAME_MAX_LEN - 1);
    pthread_mutex_unlock(&g_ds_metadisk_info_zk.ds_disk_info_lock);

    LOG_DEBUG("g_ds_metadisk_info_zk:dev_slot:%d,dev_type:%d,dev_esn:%s,dev_name:%s", dev_slot, disk_type, dev_esn,
              dev_name);

    // eds ccdb slot
    dev_slot = ZK_SLOT_ORIGINAL;
    EDS_CCDB_SLOT_FILE(metadisk_info_file);
    if (get_conf_var(metadisk_info_file, EDS_CCDB_SLOT, &p_val) == DSWARE_AGENT_OK) {
        dev_slot = atoi(p_val);
        FREE(p_val);
        if ((dev_slot < 0) || (dev_slot > MAX_VAL_VALUE)) {
            LOG_DEBUG("got wrong eds ccdb slot, slot=%d", dev_slot);
            dev_slot = EDS_CCDB_SLOT_ORIGINAL;
        }
    }
    // eds ccdb esn
    if (get_conf_var(metadisk_info_file, EDS_CCDB_ESN, &p_val) == DSWARE_AGENT_OK) {
        strncpy_s(dev_esn, SMIO_DEV_ESN_MAX_LEN, p_val, strnlen(p_val, BUFSIZE_64 - 1));
        FREE(p_val);
    } else {
        strncpy_s(dev_esn, SMIO_DEV_ESN_MAX_LEN, "unknown", SMIO_DEV_ESN_MAX_LEN - 1);
    }
    // eds ccdb盘符
    if (GetZkDiskPath(dev_slot, dev_name, BUFSIZE_64, dev_esn) != DA_OK) {
        LOG_DEBUG("get eds ccdb disk name by slot and esn failed. slot=%d, esn=%s", dev_slot, dev_esn);
    }
    if (strlen(dev_name) == 0) {
        strncpy_s(dev_name, SMIO_DEV_NAME_MAX_LEN, "unknown", SMIO_DEV_NAME_MAX_LEN - 1);
    }
    // 磁盘类型
    disk_type = ds_get_disk_type_by_slot_from_smio(dev_slot);

    pthread_mutex_lock(&g_ds_metadisk_info_eds_ccdb.ds_disk_info_lock);
    g_ds_metadisk_info_eds_ccdb.dev_slot = dev_slot;
    g_ds_metadisk_info_eds_ccdb.dev_type = disk_type;
    strncpy_s(g_ds_metadisk_info_eds_ccdb.dev_esn, SMIO_DEV_ESN_MAX_LEN, dev_esn, SMIO_DEV_ESN_MAX_LEN - 1);
    strncpy_s(g_ds_metadisk_info_eds_ccdb.dev_name, SMIO_DEV_NAME_MAX_LEN, dev_name, SMIO_DEV_NAME_MAX_LEN - 1);
    pthread_mutex_unlock(&g_ds_metadisk_info_eds_ccdb.ds_disk_info_lock);
    LOG_DEBUG("g_ds_metadisk_info_eds_ccdb:dev_slot:%d,dev_type:%d,dev_esn:%s,dev_name:%s", dev_slot, disk_type,
              dev_esn, dev_name);

    // rep ccdb 磁盘信息
    if (ds_get_rep_ccdb_vol(&rep_ccdb_vol) != DA_OK) {
        LOG_DEBUG("get_rep_ccdb_vol failed.");
        return;
    }
    pthread_mutex_lock(&g_ds_metadisk_info_rep_ccdb.ds_disk_info_lock);
    g_ds_metadisk_info_rep_ccdb.dev_slot = rep_ccdb_vol.slot;
    g_ds_metadisk_info_rep_ccdb.dev_type = ds_get_disk_type_by_slot_from_smio(rep_ccdb_vol.slot);
    strncpy_s(g_ds_metadisk_info_rep_ccdb.dev_esn, SMIO_DEV_ESN_MAX_LEN, rep_ccdb_vol.value, SMIO_DEV_ESN_MAX_LEN - 1);
    strncpy_s(g_ds_metadisk_info_rep_ccdb.dev_name, SMIO_DEV_NAME_MAX_LEN, rep_ccdb_vol.disk_name,
              SMIO_DEV_NAME_MAX_LEN - 1);
    pthread_mutex_unlock(&g_ds_metadisk_info_rep_ccdb.ds_disk_info_lock);
    LOG_DEBUG("g_ds_metadisk_info_rep_ccdb:dev_slot:%d,dev_type:%d,dev_esn:%s,dev_name:%s", dev_slot, disk_type,
              dev_esn, dev_name);
}

/*************************************************
  函数: ds_update_sysdisk_info
  描述: 更新系统盘信息
  入参: void
  出参: no
  返回: void
  其它: z00424050 20190627
*************************************************/
void ds_update_sysdisk_info(void)
{
    int ret = DA_OK;
    int ret1 = DA_OK;
    int i = 0;
    ds_sys_disk_info_t sys_disk_info;
    char dev_name[SMIO_DEV_NAME_MAX_LEN] = {DEFAULT_VALUE};

    // system盘符  ,获取系统盘slot/esn/dev_name
    ret = get_sys_disk_info(&sys_disk_info);

    // 如果系统盘arm场景系统盘软raid1系统盘类型需要相同否则禁用系统盘亚健康功能
    if (sys_disk_info.raid_type == SYS_DISK_SOFT_RAID_TYPE && sys_disk_info.disk_num == SOFT_RAID_SYS_DISK_NUM) {
        if (sys_disk_info.sys_disk_info[0].dev_type != sys_disk_info.sys_disk_info[1].dev_type) {
            LOG_INFO("there are different types of disks in the system disk, skip.");
            ret1 = DA_FAIL;
        }
    }
    // 如果系统盘数量大于两个组raid1，禁用系统盘亚健康功能，x86场景对外体现系统盘数量1，arm场景系统盘软raid1系统盘数量2
    if (ret != DA_OK || ret1 != DA_OK ||
        (sys_disk_info.disk_num != SOFT_RAID_SYS_DISK_NUM && sys_disk_info.disk_num != HARD_RAID_SYS_DISK_NUM)) {
        LOG_INFO("get sysdisk info faild.");
        (void)pthread_mutex_lock(&g_ds_sys_disk_info.ds_sys_disk_info_lock);
        g_ds_sys_disk_info.raid_type = SYS_DISK_HARD_RAID_TYPE;
        g_ds_sys_disk_info.disk_num = DEFAULT_SYS_DISK_NUM;
        (void)pthread_mutex_unlock(&g_ds_sys_disk_info.ds_sys_disk_info_lock);
        return;
    }

    LOG_DEBUG("update sysdisk info to global variables.");
    (void)pthread_mutex_lock(&g_ds_sys_disk_info.ds_sys_disk_info_lock);
    g_ds_sys_disk_info.raid_type = sys_disk_info.raid_type;
    g_ds_sys_disk_info.disk_num = sys_disk_info.disk_num;
    for (i = 0; i < sys_disk_info.disk_num; i++) {
        strncpy_s(dev_name, BUFSIZE_64, "/dev/", BUFSIZE_64 - 1);
        strncat_s(dev_name, BUFSIZE_64, sys_disk_info.sys_disk_info[i].dev_name, BUFSIZE_64 - sizeof("/dev/"));

        g_ds_sys_disk_info.sys_disk_info[i].dev_slot = sys_disk_info.sys_disk_info[i].dev_slot;
        g_ds_sys_disk_info.sys_disk_info[i].dev_type = sys_disk_info.sys_disk_info[i].dev_type;
        strncpy_s(g_ds_sys_disk_info.sys_disk_info[i].dev_esn, SMIO_DEV_ESN_MAX_LEN,
                  sys_disk_info.sys_disk_info[i].dev_esn, SMIO_DEV_ESN_MAX_LEN - 1);
        strncpy_s(g_ds_sys_disk_info.sys_disk_info[i].dev_name, SMIO_DEV_NAME_MAX_LEN, dev_name,
                  SMIO_DEV_NAME_MAX_LEN - 1);
    }

    init_sys_disk_status();
    (void)pthread_mutex_unlock(&g_ds_sys_disk_info.ds_sys_disk_info_lock);

    LOG_DEBUG("g_ds_sysdisk_info:raid_type:%d,disk_num:%d", sys_disk_info.raid_type, sys_disk_info.disk_num);

    for (i = 0; i < sys_disk_info.disk_num; i++) {
        LOG_DEBUG("g_ds_sysdisk_info:dev_slot:%d,dev_type:%d,dev_esn:%s,dev_name:%s",
                  sys_disk_info.sys_disk_info[i].dev_slot, sys_disk_info.sys_disk_info[i].dev_type,
                  sys_disk_info.sys_disk_info[i].dev_esn, sys_disk_info.sys_disk_info[i].dev_name);
    }
    return;
}

/*************************************************
  函数: ds_update_m2disk_info
  描述: 更新保电盘盘信息
  入参: void
  出参: no
  返回: int
  其它: no
*************************************************/
int ds_update_m2disk_info(void)
{
    int ret = DA_OK;
    int j = 0;
    char dev_name[SMIO_DEV_NAME_MAX_LEN] = {DEFAULT_VALUE};

    smio_media_intf_req_t *media_info = NULL;
    media_info = (smio_media_intf_req_t *)malloc(sizeof(smio_media_intf_req_t));
    if (media_info == NULL) {
        int errnum = errno;
        DSA_ERRNO_PRINT(errnum);
        LOG_ERROR("m2 flush check: malloc media_info failed");
        return DA_FAIL;
    }
    memset_s(media_info, sizeof(smio_media_intf_req_t), 0, sizeof(smio_media_intf_req_t));
    ret = ioctl_scan_media_new(media_info);
    if (ret != DA_OK) {
        LOG_ERROR("m2 flush check: scan media fail(%d)", ret);
        FREE_NO_JUDGE(media_info);
        return DA_FAIL;
    }
    
    (void)pthread_mutex_lock(&g_ds_m2_disk_info.ds_m2_disk_info_lock);
    for (int i = 0; i < SMIO_MEDIA_MAX_PER_ENCLOURSE; i++) {
        if (SMIO_MEDIA_TYPE_M2_SATA == media_info->p_media_info[i].type) {
            strncpy_s(dev_name, BUFSIZE_64, "/dev/", BUFSIZE_64 - 1);
            strncat_s(dev_name, BUFSIZE_64, media_info->p_media_info[i].name, BUFSIZE_64 - sizeof("/dev/"));

            g_ds_m2_disk_info.m2_disk_info[j].dev_slot = media_info->p_media_info[i].phy_slot;
            strncpy_s(g_ds_m2_disk_info.m2_disk_info[j].dev_esn, SMIO_DEV_ESN_MAX_LEN,
                      media_info->p_media_info[i].esn, SMIO_DEV_ESN_MAX_LEN - 1);
            strncpy_s(g_ds_m2_disk_info.m2_disk_info[j].dev_name, SMIO_DEV_NAME_MAX_LEN, dev_name,
                      SMIO_DEV_NAME_MAX_LEN - 1);
            j++;
            g_ds_m2_disk_info.disk_num = j;
        }
    }
    (void)pthread_mutex_unlock(&g_ds_m2_disk_info.ds_m2_disk_info_lock);
    FREE_NO_JUDGE(media_info);
    LOG_INFO("m2 flush check: m2 disk num:%d", g_ds_m2_disk_info.disk_num);
    // 没有扫到保电盘，不检测
    if (g_ds_m2_disk_info.disk_num <= 0) {
        LOG_INFO("m2 flush check: no m2 disk found!");
        return DA_FAIL;
    }
    return DA_OK;
}


/*************************************************
  函数: ds_get_rep_ccdb_vol
  描述: 对外部提供获取eds ccdb槽位号
  入参: no
  出参: result_vol
  返回: eds ccdb槽位号
  其它: no
*************************************************/
int ds_get_rep_ccdb_vol(process_vol *OUT result_vol)
{
    component_vol *p = NULL;
    list_head_t *component_node = NULL;
    process_vol *vol = NULL;
    list_head_t *vol_node = NULL;

    DSW_THREAD_MUTEX_LOCK(&g_component_vol.lock);
    list_for_each(component_node, &g_component_vol.component)
    {
        p = container_of(component_node, component_vol, component_chain);
        list_for_each(vol_node, &p->process)
        {
            vol = container_of(vol_node, process_vol, process_chain);
            strncpy_s(result_vol->key, KEY_LENGTH, vol->key, KEY_LENGTH - 1);
            strncpy_s(result_vol->value, BUFSIZE_256, vol->value, BUFSIZE_256 - 1);
            strncpy_s(result_vol->disk_name, BUFSIZE_64, vol->disk_name, BUFSIZE_64 - 1);
            result_vol->type = vol->type;
            result_vol->slot = vol->slot;
            DSW_THREAD_MUTEX_UNLOCK(&g_component_vol.lock);
            return DA_OK; // 目前复制元数据盘只有一个
        }
    }
    
    DSW_THREAD_MUTEX_UNLOCK(&g_component_vol.lock);
    return DA_FAIL;
}

bool IsNotifyResume(int process_type)
{
    return (process_type == DS_TYPE_ZK && g_ds_need_resume_zk) ||
           (process_type == DS_TYPE_EDS_CCDB && g_ds_need_resume_eds_ccdb) ||
           (process_type == DS_TYPE_REP_CCDB && g_ds_need_resume_rep_ccdb) ||
           (process_type == DS_TYPE_SYS && g_ds_need_resume_sys);
}
/*************************************************
  函数: ds_resume_check
  描述: 进程清除后通知恢复盘亚健康状态
  入参: process_type
  出参: notify_flag
  返回: void
  其它: c00473536 20190617
*************************************************/
void ds_resume_check(int process_type, int *IN OUT notify_flag)
{
    int ret = -1;
    bool resume_again = DSW_FALSE;
    dsw_u32 entry_num = 0;
    dsw_u32 i = 0;

    if (IsNotifyResume(process_type)) {
        entry_num = sizeof(g_ds_notify_table) / sizeof(ds_notify_table);
        for (i = 0; i < entry_num; i++) {
            if (*(notify_flag + g_ds_notify_table[i].notify_flag) != DS_NOTIFY_RESUME) {
                LOG_INFO("resume all metadisk subhealth alarm. notify_type=%d", g_ds_notify_table[i].disk_stat);
                ret = ds_notify(process_type, g_ds_notify_table[i].disk_stat, DS_NOTIFY_RESUME, -1, "unknown",
                                "unknown");
                if (ret == DA_OK) {
                    *(notify_flag + g_ds_notify_table[i].notify_flag) = DS_NOTIFY_RESUME;
                } else {
                    resume_again = DSW_TRUE;
                }
            }
        }

        if (!resume_again) {
            // 重置标识位
            if (process_type == DS_TYPE_ZK) {
                g_ds_need_resume_zk = DSW_FALSE;
            } else if (process_type  == DS_TYPE_EDS_CCDB) {
                g_ds_need_resume_eds_ccdb = DSW_FALSE;
            } else if (process_type == DS_TYPE_REP_CCDB) {
                g_ds_need_resume_rep_ccdb = DSW_FALSE;
            } else if (process_type == DS_TYPE_SYS) {
                g_ds_need_resume_sys = DSW_FALSE;
            } else {
                LOG_ERROR("process type is unknown, process_type=%d", process_type);
            }
        }

        // 更新元数据盘信息
        ds_update_metadisk_info();
        // 更新系统盘信息
        ds_update_sysdisk_info();
    }

    return;
}

/*************************************************
  函数: sdi_ep_check_init
  描述: sdi ep告警初始化
  入参: 无
  出参: 无
  返回: 无
  其它: 无
*************************************************/
void sdi_ep_check_init(void)
{
    DSW_THREAD_MUTEX_INIT(&(g_sdi_ep_alarm.alarm_lock), NULL);

    DSW_THREAD_MUTEX_LOCK(&(g_sdi_ep_alarm.alarm_lock));
    g_sdi_ep_alarm.alarm_send_flag = SDI_NO_SEND_ALARM;
    g_sdi_ep_alarm.alarm_send_status = SDI_EP_OK;
    g_sdi_ep_alarm.alarm_status = SDI_EP_OK;
    g_sdi_ep_alarm.normal_time = 0;
    DSW_THREAD_MUTEX_UNLOCK(&(g_sdi_ep_alarm.alarm_lock));
}

/*************************************************
  函数: update_metadisk_info_service
  描述: 定期更新元数据盘，线程超时时间20min
  入参: p_arg
  出参: null
  返回: NULL
  其它: no
*************************************************/
void *update_metadisk_info_service(void *p_arg)
{
    LOG_INFO("Starting timer for update metadisk info thread....");

    // 注册线程
    agent_regsiter_inner_thread(AGENT_METADISK_INFO_UPDATE_T, DEFAULT_THRID_34_SLEEP_TIME, NULL);

    while (DSW_TRUE) {
        // 初始化线程心跳
        agent_thread_set_hb(AGENT_METADISK_INFO_UPDATE_T);

        // 刷新sys disk缓存
        update_sys_disk_cache();
        
        // 循环检测，每次间隔10s
        sleep(DEFAULT_METADISK_UPDATE_SLEEP_TIME);
        
        // 更新系统盘信息
        ds_update_sysdisk_info();
        if (g_node_role_is_compute) {
            continue;
        }
        // 更新zk和eds ccdb的元数据盘信息
        ds_update_metadisk_info();
    }

    // 注销线程
    agent_unregsiter_inner_thread(AGENT_METADISK_INFO_UPDATE_T);

    return NULL;
}

int UpdateRepCCDBCheckFlag(void)
{
    shell_rsp cmd_rsp;
    char command[COMMAND_BUFSIZE] = {0};   
    memset_s(&cmd_rsp, sizeof(cmd_rsp), 0, sizeof(cmd_rsp));
    char path_name[DSA_DIR_PATH_MAX] = {0};
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s",
               path_name, 
               DSWARE_SHELL_NAME, 
               CHECK_DR_CCDB_SERVER_EXIST);
    shell_operate(command, &cmd_rsp, SHELL_TIME_OUT_10);
    if (cmd_rsp.status != DA_OK) {
        LOG_INFO("no dr ccdb process.");
        return DA_FAIL;
    }

    return DA_OK;
}

bool IsCheckCcdbDiskHealthCheck(int dev_slot)
{
    return dev_slot >= 0 && dev_slot < ISOMER_OR_RAID1_SLOT && dev_slot != SYS_DISK_SLOT && dev_slot != DIR_ZK_SLOT &&
           dev_slot != VIRTUAL_ZK_SLOT;
}
bool IsCheckDiskHealthCheck(int dev_slot)
{
    return dev_slot >= 0 && dev_slot < ISOMER_OR_RAID1_SLOT && dev_slot != SYS_DISK_SLOT && dev_slot != DIR_ZK_SLOT &&
           dev_slot != VIRTUAL_ZK_SLOT && g_ds_zk_subhealth_check;
}

void RaidPeriodCheck(int *raid1_check_counter, int sys_disk_num, int sys_raid_type, int *notify_flag_sys)
{
    // raid降级检测每五分钟一次
    if (*raid1_check_counter < RAID1_CHECK_PERIOD) {
        (*raid1_check_counter)++;
    } else if (sys_raid_type == SYS_DISK_HARD_RAID_TYPE && sys_disk_num == HARD_RAID_SYS_DISK_NUM) {
        sys_disk_raid_state_handle(DS_TYPE_SYS, notify_flag_sys);
        *raid1_check_counter = 0;
    }
}

void StartThirdServiceCheck(int *notify_flag_zk, int *notify_flag_eds_ccdb, int *notify_flag_rep_ccdb,
                            ds_slow_disk_count_t *slow_disk_count_sys,
                            ds_slow_disk_count_t *slow_disk_count_sys_soft, int *notify_flag_sys,
                            int *notify_flag_sys_soft, ds_io_block_count_t *io_block_count_sys_0,
                            ds_io_block_count_t *io_block_count_sys_1, ds_io_block_count_t
                            *io_block_count_zk,
                            ds_io_block_count_t *io_block_count_eds_ccdb,
                            ds_io_block_count_t
                            *io_block_count_rep_ccdb)
{
    g_ds_ccdb_ok = (UpdateRepCCDBCheckFlag() == DA_OK) ? DSW_TRUE : DSW_FALSE;
    dsw_u32 loop_count = 0;
    int raid1_check_counter = 0;
    int dev_slot = ZK_SLOT_ORIGINAL;
    int sys_disk_num = ZK_SLOT_ORIGINAL;
    int sys_raid_type = ZK_SLOT_ORIGINAL;
    process_vol rep_ccdb_vol;
    while (DSW_TRUE) {
        agent_thread_set_hb(AGENT_THIRD_T);

        loop_count++;

        // 循环检测，每次间隔1s
        sleep(DEFAULT_THRID_SLEEP_TIME);

        if (g_node_role_is_compute) {
            // SDI环境下检查EP通道   后面的亚健康不处理
            check_and_alarm_ep_status(loop_count);
            continue;
        }

        zk_cleanup(loop_count);

        // 进程删除后恢复盘亚健康告警
        ds_resume_check(DS_TYPE_ZK, notify_flag_zk);
        ds_resume_check(DS_TYPE_EDS_CCDB, notify_flag_eds_ccdb);
        ds_resume_check(DS_TYPE_REP_CCDB, notify_flag_rep_ccdb);

        // 扫盘获取盘的状态信息
        ds_dm_dev_lis_t *p_tmp_dev_list = (ds_dm_dev_lis_t *)malloc(sizeof(ds_dm_dev_lis_t));
        if (NULL == p_tmp_dev_list) {
            LOG_ERROR("malloc p_tmp_dev_list error");
            continue;
        }

        memset_s(p_tmp_dev_list, sizeof(ds_dm_dev_lis_t), 0, sizeof(ds_dm_dev_lis_t));
        if (DA_OK != ds_get_disk_info_from_smio(p_tmp_dev_list, DS_DISK_TYPE_ALL)) {
            LOG_ERROR("get disk info failed");
            FREE_NO_JUDGE(p_tmp_dev_list);
            continue;
        }

        // 系统盘亚健康
        pthread_mutex_lock(&g_ds_sys_disk_info.ds_sys_disk_info_lock);
        sys_disk_num = g_ds_sys_disk_info.disk_num;
        sys_raid_type = g_ds_sys_disk_info.raid_type;
        pthread_mutex_unlock(&g_ds_sys_disk_info.ds_sys_disk_info_lock);
        if (sys_disk_num > 0) {
            if (sys_disk_num == HARD_RAID_SYS_DISK_NUM) {
                ds_sys_slow_disk_check(loop_count, DSW_FALSE, slow_disk_count_sys, notify_flag_sys);
                ds_sysdisk_io_block_check(loop_count, DSW_FALSE, DS_TYPE_SYS, io_block_count_sys_0, notify_flag_sys);
                ds_sys_smio_check(loop_count, DSW_FALSE, notify_flag_sys, p_tmp_dev_list);
            } else if (sys_disk_num == SOFT_RAID_SYS_DISK_NUM) {
                ds_sys_slow_disk_check(loop_count, DSW_FALSE, slow_disk_count_sys, notify_flag_sys);
                ds_sys_slow_disk_check(loop_count, DSW_TRUE, slow_disk_count_sys_soft, notify_flag_sys_soft);
                ds_sysdisk_io_block_check(loop_count, DSW_FALSE, DS_TYPE_SYS, io_block_count_sys_0, notify_flag_sys);
                ds_sysdisk_io_block_check(loop_count, DSW_TRUE, DS_TYPE_SYS, io_block_count_sys_1, notify_flag_sys_soft);
                ds_sys_smio_check(loop_count, DSW_FALSE, notify_flag_sys, p_tmp_dev_list);
                ds_sys_smio_check(loop_count, DSW_TRUE, notify_flag_sys_soft, p_tmp_dev_list);
            }

            RaidPeriodCheck(&raid1_check_counter, sys_disk_num, sys_raid_type, notify_flag_sys);
        }

        // zk 盘亚健康
        pthread_mutex_lock(&g_ds_metadisk_info_zk.ds_disk_info_lock);
        dev_slot = g_ds_metadisk_info_zk.dev_slot;
        pthread_mutex_unlock(&g_ds_metadisk_info_zk.ds_disk_info_lock);
        if (IsCheckDiskHealthCheck(dev_slot)) {
            LOG_DEBUG("start zk disk health check.");
            ds_smio_check(loop_count, DS_TYPE_ZK, notify_flag_zk, p_tmp_dev_list);
        }

        // eds ccdb 盘亚健康
        pthread_mutex_lock(&g_ds_metadisk_info_eds_ccdb.ds_disk_info_lock);
        dev_slot = g_ds_metadisk_info_eds_ccdb.dev_slot;
        pthread_mutex_unlock(&g_ds_metadisk_info_eds_ccdb.ds_disk_info_lock);
        if (IsCheckCcdbDiskHealthCheck(dev_slot)) {
            ds_smio_check(loop_count, DS_TYPE_EDS_CCDB, notify_flag_eds_ccdb, p_tmp_dev_list);
        }

        // rep ccdb 盘亚健康
        if (ds_get_rep_ccdb_vol(&rep_ccdb_vol) == DA_OK && g_ds_ccdb_ok) {
            LOG_DEBUG("start rep ccdb disk health check.");
            if (rep_ccdb_vol.slot != SYS_DISK_SLOT) {
                ds_smio_check(loop_count, DS_TYPE_REP_CCDB, notify_flag_rep_ccdb, p_tmp_dev_list);
            }
        }

        FREE_NO_JUDGE(p_tmp_dev_list);
    }
}
/*************************************************
  函数: agent_third_service
  描述: no
  入参: p_arg
  出参: no
  返回: NULL
  其它: no
*************************************************/
void *agent_third_service(void *p_arg)
{
    int notify_flag_zk[DSIK_STATE_CHECK_LONG];
    int notify_flag_eds_ccdb[DSIK_STATE_CHECK_LONG];
    int notify_flag_rep_ccdb[DSIK_STATE_CHECK_LONG];
    int notify_flag_sys[DSIK_STATE_CHECK_LONG];
    int notify_flag_sys_soft[DSIK_STATE_CHECK_LONG];
    ds_slow_disk_count_t slow_disk_count_zk;
    ds_slow_disk_count_t slow_disk_count_eds_ccdb;
    ds_slow_disk_count_t slow_disk_count_rep_ccdb;
    ds_slow_disk_count_t slow_disk_count_sys;
    ds_slow_disk_count_t slow_disk_count_sys_soft;
    ds_io_block_count_t io_block_count_zk;
    ds_io_block_count_t io_block_count_eds_ccdb;
    ds_io_block_count_t io_block_count_rep_ccdb;
    ds_io_block_count_t io_block_count_sys_0;
    ds_io_block_count_t io_block_count_sys_1;
    LOG_INFO("Starting timer for zk server thread....");

    agent_regsiter_inner_thread(AGENT_THIRD_T, DEV_MON_THREAD_CHECK_TIME_60, NULL);
    if (!g_node_role_is_compute) {        
    // 停止复制ccdb慢盘检测
        int ret = stop_slow_component_disk_check();
        if (ret != DA_OK) {
            LOG_ERROR("stop component slow disk error");
        } else {
            // 启动复制ccdb慢盘检测(脚本阻塞)
            if (start_slow_component_disk_check() != DA_OK) {
                LOG_ERROR("start component slow disk error");
            }
        }
    
        // 初始化通知标识
        ds_init_notify_flag(notify_flag_zk);
        ds_init_notify_flag(notify_flag_eds_ccdb);
        ds_init_notify_flag(notify_flag_rep_ccdb);
        ds_init_notify_flag(notify_flag_sys);
        ds_init_notify_flag(notify_flag_sys_soft);
    
        // 初始化慢盘计数
        ds_init_slow_disk_count(&slow_disk_count_zk);
        ds_init_slow_disk_count(&slow_disk_count_eds_ccdb);
        ds_init_slow_disk_count(&slow_disk_count_rep_ccdb);
        ds_init_slow_disk_count(&slow_disk_count_sys);
        ds_init_slow_disk_count(&slow_disk_count_sys_soft);
    
        // 初始化block计数
        ds_init_io_block_count(&io_block_count_zk);
        ds_init_io_block_count(&io_block_count_eds_ccdb);
        ds_init_io_block_count(&io_block_count_rep_ccdb);
        ds_init_io_block_count(&io_block_count_sys_0);
        ds_init_io_block_count(&io_block_count_sys_1);
    
        // 更新元数据盘信息
        ds_update_metadisk_info();
        // 更新系统盘信息
        ds_update_sysdisk_info();
    }

    StartThirdServiceCheck(notify_flag_zk, notify_flag_eds_ccdb, notify_flag_rep_ccdb, &slow_disk_count_sys,
                           &slow_disk_count_sys_soft, notify_flag_sys, notify_flag_sys_soft, &io_block_count_sys_0,
                           &io_block_count_sys_1, &io_block_count_zk, &io_block_count_eds_ccdb,
                           &io_block_count_rep_ccdb);
    agent_unregsiter_inner_thread(AGENT_THIRD_T);
    if (DA_OK != stop_slow_component_disk_check()) {
        LOG_ERROR("stop component slow disk error");
    }

    return NULL;
}

/*************************************************
  函数: ds_init_check_sys_raid_env
  描述: 初始化获取环境信息，检查运行环境是否是arm 软raid环境
  入参: 无
  出参: 无
*************************************************/
void ds_init_check_sys_raid_env(void)
{
    char path_name[DSA_DIR_PATH_MAX] = { 0 };
    char command[COMMAND_BUFSIZE];
    shell_rsp cmd_rsp;
    int ret_value = DA_FAIL;
    dsw_s32 ret = 0;

    // 执行判断脚本
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    memset_s(command, COMMAND_BUFSIZE, 0, COMMAND_BUFSIZE);
    memset_s(&cmd_rsp, sizeof(cmd_rsp), 0, sizeof(cmd_rsp));
    ret = snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s",
                     path_name,
                     DSWARE_SHELL_NAME,
                     DA_OP_SYS_RAID_ENV_CHECK);
    if (ret == -1) {
        LOG_ERROR("ds_init_check_sys_raid_envsnprintf_s error!");
        return;
    }
    shell_operate(command, &cmd_rsp, SHELL_TIME_OUT_10);
    if (DA_OK != cmd_rsp.status) {
        LOG_ERROR("software_raid_status_check failed!. command=%s cmd_rsp.status:%d", command, cmd_rsp.status);
        return;
    } else {
        if (1 != sscanf_s(cmd_rsp.value, "%d", &ret_value)) {
            SUBHEALTH_LOG_ERROR("analyze shell command rsp failed,rsp=%s", cmd_rsp.value);
            return;
        }
        LOG_INFO("ds_init_check_sys_raid_env success. cmd_rsp.value=%d", cmd_rsp.value);
        g_sys_raid_flag = (ret_value == 0) ? DSW_FALSE : DSW_TRUE;
    }
    return;
}


/*************************************************
  函数: agent_sysdisk_subhealth_service
  描述: 系统盘亚检查处理线程函数
        保电盘刷盘能力检测
  入参: p_arg
  出参: no
  返回: NULL
  其它: no
*************************************************/
void * agent_sysdisk_subhealth_service(void *p_arg)
{
    dsw_u32 loop_count = 0;
    int notify_flag_downspeed = DS_NOTIFY_INIT;
    int notify_flag_ata1 = DS_NOTIFY_INIT;
    int notify_flag_ata2 = DS_NOTIFY_INIT;
    LOG_INFO("Starting timer for sysdisk subhealth thread....");
    // 初始化
    ds_init_m2_disk_notify_flag();
    // 初始化检查运行环境，如果非arm 软raid节点，不做软raid降级检测
    ds_init_check_sys_raid_env();
    // 注册线程
    agent_regsiter_inner_thread(AGENT_SYSDISK_SUBHEALTH_T, DEFAULT_SYSDISK_RAID_CHECK_TIME, NULL);

    while (g_dsware_agent_loop_flag) {
        // 初始化线程心跳
        agent_thread_set_hb(AGENT_SYSDISK_SUBHEALTH_T);
        
        loop_count++;
        
        // 循环检测，每次间隔5s
        sleep(DEFAULT_SYSDISK_RAID_CHECK_TIME);

        // 系统盘软raid状态检测，非arm 软raid节点，不做软raid降级检测
        if (g_sys_raid_flag) {
            software_raid_status_check(loop_count);
        }

        // 保电盘刷盘能力检测
        ds_m2_disk_flush_capability_check(loop_count);
        // 保电盘链路亚健康检测
        ds_m2_disk_link_downspeed_check(loop_count, &notify_flag_downspeed, &notify_flag_ata1, &notify_flag_ata2);
    }

    // 注销线程
    agent_unregsiter_inner_thread(AGENT_SYSDISK_SUBHEALTH_T);

    return NULL;
}

static void handle_result_when_no_ibmc_alarm_state(int ret)
{
    if (ret == DA_ERR_IBMC_ACCOUNT && agent_handle_bmc_alarm(IBMC_AUTH_FAIL_ALARM, SEND_ALARM, ret) == DA_OK) {
        g_ibmc_alarm_flag = IBMC_AUTH_FAIL_ALARM_STATE;
        LOG_INFO("send IBMC_AUTH_FAIL_ALARM successfully!");
    } else if (ret != DA_OK && agent_handle_bmc_alarm(HT_CHECK_EXCEP_ALARM, SEND_ALARM, ret) == DA_OK) {
        g_ibmc_alarm_flag = HT_CHECK_EXCEP_ALARM_STATE;
        g_lastExCheckResult = ret;
        LOG_INFO("send HIGH_TEMP_CHECK_EXCEP successfully[alarm ret:%d]!", ret);
    } else {
        LOG_DEBUG("NO_IBMC_ALARM_STATE: the alarm status hasn't been changed!");
    }
}

static void handle_result_when_ht_check_excep_alarm_state(int ret)
{
    if (ret == DA_ERR_IBMC_ACCOUNT &&
        agent_handle_bmc_alarm(HT_CHECK_EXCEP_ALARM, RESUME_ALARM, ret) == DA_OK &&
        agent_handle_bmc_alarm(IBMC_AUTH_FAIL_ALARM, SEND_ALARM, ret) == DA_OK) {
        g_ibmc_alarm_flag = IBMC_AUTH_FAIL_ALARM_STATE;
        LOG_INFO("resume HT_CHECK_EXCEP_ALARM and send iBMC_AUTH_FAIL_ALARM successfully!");
    } else if (ret == DA_OK && agent_handle_bmc_alarm(HT_CHECK_EXCEP_ALARM, RESUME_ALARM, ret) == DA_OK) {
        g_ibmc_alarm_flag = NO_IBMC_ALARM_STATE;
        LOG_INFO("resume HT_CHECK_EXCEP_ALARM successfully!");
    } else if (ret != g_lastExCheckResult &&
        agent_handle_bmc_alarm(HT_CHECK_EXCEP_ALARM, RESUME_ALARM, ret) == DA_OK &&
        agent_handle_bmc_alarm(HT_CHECK_EXCEP_ALARM, SEND_ALARM, ret) == DA_OK) {
        LOG_INFO("update HT_CHECK_EXCEP_ALARM desc successfully[lastRet:%d,curRet:%d]!", g_lastExCheckResult, ret);
        g_lastExCheckResult = ret;
    } else {
        LOG_DEBUG("HT_CHECK_EXCEP_ALARM_STATE: the alarm status hasn't been changed!");
    }
}

static void handle_result_when_ibmc_auth_fail_alarm_state(int ret)
{
    if (ret == DA_OK && agent_handle_bmc_alarm(IBMC_AUTH_FAIL_ALARM, RESUME_ALARM, ret) == DA_OK) {
        g_ibmc_alarm_flag = NO_IBMC_ALARM_STATE;
        LOG_INFO("resume IBMC_AUTH_FAIL_ALARM successfully!");
    } else if (ret != DA_ERR_IBMC_ACCOUNT &&
        agent_handle_bmc_alarm(IBMC_AUTH_FAIL_ALARM, RESUME_ALARM, ret) == DA_OK &&
        agent_handle_bmc_alarm(HT_CHECK_EXCEP_ALARM, SEND_ALARM, ret) == DA_OK) {
        g_ibmc_alarm_flag = HT_CHECK_EXCEP_ALARM_STATE;
        g_lastExCheckResult = ret;
        LOG_INFO("resume IBMC_AUTH_FAIL_ALARM and send HT_CHECK_EXCEP_ALARM successfully[exRet:%d]!", ret);
    } else {
        LOG_DEBUG("IBMC_AUTH_FAIL_ALARM_STATE: the alarm status hasn't been changed!");
    }
}

static void handle_result_when_other_state(int ret)
{
    if (agent_handle_bmc_alarm(IBMC_AUTH_FAIL_ALARM, RESUME_ALARM, ret) == DA_OK &&
        agent_handle_bmc_alarm(HT_CHECK_EXCEP_ALARM, RESUME_ALARM, ret) == DA_OK) {
        g_ibmc_alarm_flag = NO_IBMC_ALARM_STATE;
        LOG_INFO("resume IBMC_AUTH_FAIL_ALARM and HT_CHECK_EXCEP_ALARM successfully!");
        return;
    }
    LOG_ERROR("fail to resume iBMC alarm!!!");
}

void handle_check_result(int check_result)
{
    if (IsUpgrading() == 1) {
        LOG_WARNING("On upgrading, stop sending iBMC fault or password alarm.");
        return;
    }

    LOG_INFO("check_result=%d, g_ibmc_alarm_flag=%d.", check_result, g_ibmc_alarm_flag);
    // 无虚拟网卡驱动时，只打印警告日志，不发送告警
    if (check_result == DA_ERR_VETH_DRIVER) {
        LOG_WARNING("no veth driver, can not connect to iBMC!");
        return;
    }

    if (g_ibmc_alarm_flag == NO_IBMC_ALARM_STATE) {
        handle_result_when_no_ibmc_alarm_state(check_result);
    } else if (g_ibmc_alarm_flag == HT_CHECK_EXCEP_ALARM_STATE) {
        handle_result_when_ht_check_excep_alarm_state(check_result);
    } else if (g_ibmc_alarm_flag == IBMC_AUTH_FAIL_ALARM_STATE) {
        handle_result_when_ibmc_auth_fail_alarm_state(check_result);
    } else {
        handle_result_when_other_state(check_result);
    }
}

void *agent_cpu_tuyere_temp_mon_service(void *p_arg)
{
    LOG_INFO("Starting timer for cpu and inlet tem mon thread....");
    // 设定超时时间为30分钟
    int timeout = 1800;

    int ret = GetTempAlarmThreshold(GetCtrlBoardType());
    if (ret != DA_OK) {
        LOG_ERROR("get temperature alarm threshold failed %d, terminal thread.", ret);
        return NULL;
    }

    // 注册线程
    agent_regsiter_inner_thread(AGENT_CPU_TUYEYE_TEMP_MON_T, timeout, NULL);

    int check_result = DA_OK;
    while (g_dsware_agent_loop_flag) {
        // 初始化线程心跳
        agent_thread_set_hb(AGENT_CPU_TUYEYE_TEMP_MON_T);
        
        // 循环检测，每次间隔10秒钟
        sleep(DEFAULT_CPU_TUYEYE_TEMP_CHECK_TIME);

        //  agent 10s 检测cpu 和 进风口温度
        check_result = agent_check_cpu_tuyeye_tem();

        // 前后两次检查的返回值不同时，进行告警 或 恢复告警
        handle_check_result(check_result);
    }

    // 注销线程
    agent_unregsiter_inner_thread(AGENT_CPU_TUYEYE_TEMP_MON_T);

    return NULL;
}

static int GetStorageMediaType()
{
    char cmd[BUFSIZE_256] = {0};
    char path[DSA_DIR_PATH_MAX] = {0};
    (void)DumpDsaScriptDirPath(path, sizeof(path));
    shell_rsp cmd_rsp = {0};

    int len = sprintf_s(cmd, sizeof(cmd), "%s%s %s", path, DSWARE_SHELL_NAME, GET_MEDIA_TYPE);
    if (len < NUM0) {
        LOG_ERROR("snprintf_s failed!!!");
        return DA_FAIL;
    }

    shell_operate_with_return(cmd, &cmd_rsp, SHELL_TIME_OUT_10);
    if (cmd_rsp.status != DA_OK) {
        LOG_ERROR("fail to get media type by %s!!", cmd);
        return DA_FAIL;
    }

    return atoi(cmd_rsp.value);
}

void *agent_disk_temp_check_service(void *p_arg)
{
    LOG_INFO("Starting timer for disk tem mon thread....");

    char mediaName[DISK_NAME_LEN_MAX] = {0};
    int threshold = 0;
    int last_media_type = -1;

    int timeout = 1800;
    // 注册线程
    agent_regsiter_inner_thread(AGENT_DISK_TEMP_MON_T, timeout, NULL);

    while (g_dsware_agent_loop_flag) {
        // 初始化线程心跳
        agent_thread_set_hb(AGENT_DISK_TEMP_MON_T);
        int storage_media_type = GetStorageMediaType();
        if (storage_media_type < SATA_HDD_TYPE || storage_media_type > NVME_SSD_TYPE) {
            LOG_WARNING("Media type[%d] is not right! Maybe not create storage pool.", storage_media_type);
            sleep(DEFAULT_GET_MEDIA_TYPE_SLEEP_TIME);
            continue;
        }

        // get disk temperature threshold if the media type has been changed
        if (last_media_type != storage_media_type) {
            int ret = GetDiskTempThreshold(GetCtrlBoardType(), storage_media_type, mediaName, &threshold);
            if (ret != DA_OK) {
                LOG_ERROR("get disk temp threshold failed %d", ret);
                memset_s(mediaName, sizeof(mediaName), 0, sizeof(mediaName));
                sleep(DEFAULT_GET_MEDIA_TYPE_SLEEP_TIME);
                continue;
            }
            last_media_type = storage_media_type;
        }

        if (storage_media_type == SATA_HDD_TYPE || storage_media_type == SAS_HDD_TYPE) {
            agent_check_disk_temp(storage_media_type, mediaName, threshold);
            // HDD 检测周期为 10 分钟
            sleep(DEFAULT_HDD_DISK_TEMP_CHECK_TIME);
        } else {
            agent_check_disk_temp(storage_media_type, mediaName, threshold);
            // SSD 检测周期为 20 秒
            sleep(DEFAULT_SSD_DISK_TEMP_CHECK_TIME);
        }
    }

    // 注销线程
    agent_unregsiter_inner_thread(AGENT_DISK_TEMP_MON_T);

    return NULL;
}


/*************************************************
  Function:         start_third_thread_service
  Description:     start timer for zkrestart thread service.
  Input: void
  Output:           start timer for zkrestart thread service exeucte result
  Return: 0 1
                       0:sucess
                       1:fail
  Others: no
*************************************************/
int StartThirdThreadService(void)
{
    int ret = DA_FAIL;
    pthread_mutex_init(&g_ntp_check_mutex, NULL);
    if (!g_node_role_is_compute) {
        ret = pthread_create(&g_update_metadisk_info_thread, NULL, update_metadisk_info_service, NULL);
        if (ret != DA_OK) {
            DSA_ERRNO_PRINT(ret);
            LOG_ERROR("failed to create timer for update metadisk info thread");
            return DSWARE_AGENT_ERR;
        }
    }
    ret = pthread_create(&g_timer_zk_thread, NULL, agent_third_service, NULL);
    if (ret != DA_OK) {
        DSA_ERRNO_PRINT(ret);
        LOG_ERROR("failed to create timer for zkrestart thread");
        return DSWARE_AGENT_ERR;
    }

    dsw_int type = GetCtrlBoardType();
    LOG_INFO("dsware_cluster_status_info.baseboard_type is %d", type);
    if ((type == BASEBOARD_PACIFIC_9550 || type == BASEBOARD_PACIFIC_9950 ||
        type == BASEBOARD_COMMON_HW_2U || type == BASEBOARD_COMMON_HW_4U ||
        type == BASEBOARD_ARCTIC_16510_FAILOVER ||
        (type >= BASEBOARD_COMMON_HW_2U && type <= BASEBOARD_HG_CS_4U)) &&
        g_agent_sys_val.is_storage_euler && g_nodeRoleIsStorage) {
        ret = pthread_create(&g_cpuTuyeyeTemMonThread, NULL, agent_cpu_tuyere_temp_mon_service, NULL);
        if (ret != DA_OK) {
            DSA_ERRNO_PRINT(ret);
            LOG_ERROR("failed to create timer for cpu and inlet tem mon thread");
            return DSWARE_AGENT_ERR;
        }

        ret = pthread_create(&g_diskTemMonThread, NULL, agent_disk_temp_check_service, NULL);
        if (ret != DA_OK) {
            DSA_ERRNO_PRINT(ret);
            LOG_ERROR("failed to create timer for disk tem mon thread");
            return DSWARE_AGENT_ERR;
        }
    }
    if (g_node_role_is_compute) {
        LOG_INFO("The node is compute ,no need disk subhealth detect");
        return DSWARE_AGENT_OK;
    }
    ret = pthread_create(&g_timer_sysdisk_subhealth_thread, NULL, agent_sysdisk_subhealth_service, NULL);
    if (ret != DA_OK) {
        DSA_ERRNO_PRINT(ret);
        LOG_ERROR("failed to create timer for sysdisk subhealth thread");
        return DSWARE_AGENT_ERR;
    }
    return DSWARE_AGENT_OK;
}

void SetZkSubhealthCheckSwitch(bool switchValue)
{
    g_ds_zk_subhealth_check = switchValue;
}


