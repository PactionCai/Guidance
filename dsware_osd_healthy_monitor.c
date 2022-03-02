/************************************************************
  Copyright (c) Huawei Technologies Co., Ltd. 2015-2020. All rights reserved.
  FileName: agent_process_monitor.c
  Author:  
  Version :
  Date: 2015-08-28
  Description: 亚健康
  Version:
  Function List:
  History:
      <author>  <time>   <version >   <desc>
 ***********************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <limits.h>

#include "../config/agent_op_config.h"
#include "../utility/agent_op_log.h"
#include "agent_process_monitor.h"
#include "../interface/dsware_agent_disk_monitor.h"
#include "dsware_osd_healthy_monitor.h"
#include "../interface/dsware_agent_oper_osd.h"
#include "../interface/dsa_get_disk_info.h"
#include "../interface/dsa_manager_handle.h"
#include "../interface/fsa_utils.h"
#include "../config/dsware_agent_conf.h"
#include "../interface/dswareAgent_interface.h"
#include "FML.h"
#include "core_agent_msg.h"
#include "../interface/smio_agent_recover.h"
#include "../net_module/network_subhealth/net_sub_health_enter.h"
#include "dsw_error_def.h"
#include "../interface/agent_stat.h"

extern pool_info_list_t g_pool_info_list;
extern void check_chang_disk_status(void);

/*************************************************
  Function:        osd_power_on_and_turn_up
  Description:    磁盘起转
  Input:     dev_name:      设备名
                slot_id:         槽位号
  Output
  Return
                     
  Others
*************************************************/
int osd_power_on_and_turn_up(const char *dev_name, dsw_u32 slot_id)
{
    shell_rsp cmd_rsp;
    char command[COMMAND_BUFSIZE];

    memset_s(&cmd_rsp, sizeof(cmd_rsp), DEFAULT_VALUE, sizeof(cmd_rsp));
    memset_s(command, sizeof(command), DEFAULT_VALUE, sizeof(command));

    if (NULL == dev_name) {
        LOG_INFO("dm_disk_info is NULL.");
        return DA_FAIL;
    }
    char path_name[DSA_DIR_PATH_MAX] = { 0 };
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s %s %d",
               path_name,
               DSWARE_SHELL_NAME,
               "power_on_and_turn_up",
               dev_name,
               slot_id);

    shell_operate(command, &cmd_rsp, SHELL_TIME_OUT_3);

    LOG_DEBUG("osd_power_on_and_turn_up, value=%s cmd=%s", cmd_rsp.value, command);
    if (DA_OK != cmd_rsp.status) {
        LOG_ERROR("osd_power_on_and_turn_up failed, result=%s cmd=%s", cmd_rsp.value, command);
        return DA_FAIL;
    }

    return DA_OK;
}

/*************************************************
  Function:        get_monitor_process_info_from_file
  Description:    get info from agentMonitor
  Input:     is_monitro:     monitor info from agentMonitor
                out_reason:    monitor info from agentMonitor
                auto_in_times:monitor info from agentMonitor
                avoid_shake_time:  monitor info from agentMonitor
                file:    file name
  Output:
  Return:          RUN_ERR:  failed
                      RUN_OK:  success
  Others:
*************************************************/
int get_osd_monitor_process_info_from_file(int id, const char *type, dsw_u16 pool_id, int *OUT value)
{
    char buf[MAX_LINE_SIZE] = { DEFAULT_VALUE };
    char key[MAX_LINE_SIZE] = { DEFAULT_VALUE };
    char file_name[DSA_DIR_PATH_MAX] = { 0 };

    LOG_INFO("get_monitor_process_info_from_file start,id=%d,type=%s.", id, type);

    if (NULL == type || NULL == value) {
        LOG_ERROR("para is NULL.");
        return RUN_ERR;
    }

    if (INVALID_POOL_ID == pool_id) {
        snprintf_s(key, sizeof(key), sizeof(key) - 1, "osd_%d_%s", id, type);
    } else {
        snprintf_s(key, sizeof(key), sizeof(key) - 1, "osd_%hu_%d_%s", pool_id, id, type);
    }

    PROCESS_MONITOR_FILE(file_name);
    if (RUN_OK != read_profile_string(OSD_PROCESS_SECTION, key,
                                      buf, MAX_LINE_SIZE, "0", file_name)) {
        LOG_INFO("read_profile_string failed, key=%s. get default value.", key);
        /* 文件中读不到的参数 设置默认值为0 */
        *value = 0;
        // 设备默认值
        if (0 ==
            strncmp(type, MONITOR_INFO_SYS_RESOURCE, strnlen(MONITOR_INFO_SYS_RESOURCE, 32))) {
            *value = SYS_RESOURCE_NO_EXCEED;
        }
        return RUN_OK;
    }
    if (0 == strncmp(type, MONITOR_INFO_IS_MONITOR, sizeof(MONITOR_INFO_IS_MONITOR))) {
        if (0 == strncmp(buf, MONITOR, sizeof(MONITOR))) {
            *value = 0;
        } else {
            // process_operation_osd中有out_reason不为0的判断，不会走到将is_monitor改为True的分支
            *value = MEM_NOT_MONITOR;
        }
    } else {
        *value = atoi(buf);
    }

    LOG_INFO("get_monitor_process_info_from_file end,id=%d,type=%s,and value=%d.", id, type, *value);
    return RUN_OK;
}

/*************************************************
  Function:        get_offset
  Description:  获取各成员在结构体中的偏移位置
  Input:     p_process:      the process name

  Output
  Return:          RUN_ERR:  failed
                      RUN_OK:  success
*************************************************/
int get_offset(const char *type)
{
    if (0 == strncmp(type, MONITOR_INFO_IS_MONITOR, strnlen(MONITOR_INFO_IS_MONITOR, BUFSIZE_64))) {
        return offsetof(struct process_s, is_monitor);
    } else if (0 == strncmp(type, MONITOR_INFO_OUT, strnlen(MONITOR_INFO_OUT, BUFSIZE_64))) {
        return offsetof(struct process_s, out_reason);
    } else if (0 == strncmp(type, MONITOR_INFO_AUTOIN, strnlen(MONITOR_INFO_AUTOIN, BUFSIZE_64))) {
        return offsetof(struct process_s, auto_in_times);
    } else if (0 == strncmp(type, MONITOR_INFO_REASON_LAST_TIME, strnlen(MONITOR_INFO_REASON_LAST_TIME, BUFSIZE_64))) {
        return offsetof(struct process_s, auto_in_reason_last_time);
    } else if (0 == strncmp(type, MONITOR_INFO_CHECK, strnlen(MONITOR_INFO_CHECK, BUFSIZE_64))) {
        return offsetof(struct process_s, auto_in_check_times);
    } else if (0 == strncmp(type, MONITOR_INFO_AVOID_SHAKE, strnlen(MONITOR_INFO_AVOID_SHAKE, BUFSIZE_64))) {
        return offsetof(struct process_s, avoid_shake_time);
    } else if (0 == strncmp(type, MONITOR_INFO_SYS_RESOURCE, strnlen(MONITOR_INFO_SYS_RESOURCE, BUFSIZE_64))) {
        return offsetof(struct process_s, out_sys_resource);
    } else if (0 == strncmp(type, MONITOR_INFO_VNODE_ID, strnlen(MONITOR_INFO_VNODE_ID, BUFSIZE_64))) {
        return offsetof(struct process_s, vnode_id);
    } else if (0 == strncmp(type, MONITOR_INFO_ADD_FLAG, strnlen(MONITOR_INFO_ADD_FLAG, BUFSIZE_64))) {
        return offsetof(struct process_s, add_flag);
    } else {
        return -1;
    }
}

/*************************************************
  Function: get_osd_pool_id
  Description: 根据磁盘esn获取所在池的pool_id，获取不到说明该磁盘不在存储池中
  Input:    disk_serial:   osd_esn
  Output:   pool_id
  Return: int;
  Others: 
*************************************************/
int get_osd_pool_id(const char *disk_serial, dsw_u16 *OUT pool_id)
{
    process_node *p_tmp_process = NULL;
    list_head_t *p_tmp_node = NULL;
    process_monitor_t *monitor = NULL;
    pthread_mutex_t *monitor_lock = NULL;

    if (NULL == disk_serial || NULL == pool_id) {
        LOG_ERROR("parameter is NULL.");
        return RUN_ERR;
    }

    /* 内存中是否有进程 */
    if (process_monitor_lists_is_empty()) {
        return NO_PROCESS;
    }

    get_process_monitor(OSD_PROCESS_NAME, &monitor);
    if (NULL == monitor) {
        return NO_PROCESS;
    }
    monitor_lock = &monitor->process_monitor_lock;

    (void)pthread_mutex_lock(monitor_lock);
    list_for_each(p_tmp_node, &monitor->process_monitor_list)
    {
        p_tmp_process = list_entry(p_tmp_node, process_node, head);
        // 以hdd盘或ssd卡的真实esn长度与内存中esn匹配
        if (0 == strncmp(p_tmp_process->process.para, disk_serial, strnlen(disk_serial, BUFSIZE_64))) {
            *pool_id = p_tmp_process->poolId;
            LOG_DEBUG("get osd pool_id[%d] success", *pool_id);
            (void)pthread_mutex_unlock(monitor_lock);
            return DA_OK;
        }
    }
    (void)pthread_mutex_unlock(monitor_lock);

    LOG_DEBUG("failed to get_osd_pool_id:%s", disk_serial);
    return RUN_ERR;
}

/*************************************************
  Function:        update_fault_recover_info
  Description:    更新内存和配置文件中进程相关信息
  Input:    p_process: 进程信息   
  Output
  Return:      RUN_ERR:  failed
               RUN_OK:  success
  Others
*************************************************/
int update_fault_recover_info(process_node *p_process)
{
    int auto_in_times = DEFAULT_VALUE;
    int out_reason = DEFAULT_VALUE;
    int ret = DA_FAIL;

    if (NULL == p_process) {
        LOG_ERROR("input parameter null.");
        return DA_FAIL;
    }

    auto_in_times = p_process->process.auto_in_times;
    out_reason = p_process->process.out_reason;

    auto_in_times++;

    LOG_INFO("start to update_fault_recover_info, save last out_reason=%d", out_reason);

    ret = update_monitor_process(p_process, MONITOR_INFO_AUTOIN, auto_in_times);
    if (DA_OK != ret) {
        /* 修改auto_in_times失败不影响磁盘自动加入成功 */
        LOG_ERROR("update_monitor_process failed, disk_sn is %s, type is auto_in_times",
                  p_process->process.para);
    }
    ret = update_monitor_process(p_process, MONITOR_INFO_OUT, 0);
    if (DA_OK != ret) {
        /* 修改out_reason 失败不影响磁盘自动加入成功 */
        LOG_ERROR("update_monitor_process failed, disk_sn is %s,type is out_reason",
                  p_process->process.para);
    }
    // 取到的out_reason 赋值为auto_in_reason_last_time ( 上次因此原因踢出后自动加入)
    ret = update_monitor_process(p_process, MONITOR_INFO_REASON_LAST_TIME, out_reason);
    if (DA_OK != ret) {
        /* 修改auto_in_reason_last_time失败不影响磁盘自动加入成功 */
        LOG_ERROR("update_monitor_process failed, disk_sn is %s,type is auto_in_reason_last_time",
                  p_process->process.para);
    }

    // 网络亚健康增加流程
    if (SYS_RESOURCE_EXCEED == p_process->process.out_sys_resource) {
        ret = update_monitor_process(p_process, MONITOR_INFO_SYS_RESOURCE,
                                     SYS_RESOURCE_NO_EXCEED);
        if (DA_OK != ret) {
            /* 修改auto_in_reason_last_time失败不影响磁盘自动加入成功 */
            LOG_ERROR("update_monitor_process failed, disk_sn is %s,type is \
SYS_RESOURCE_NO_EXCEED",
                      p_process->process.para);
        }
    }

    // auto_in_check_times 清0
    p_process->process.auto_in_check_times = 0;

    return DA_OK;
}

/*************************************************
  Function:        check_and_save_detail_retcode
  Description:   Agent对于拉不起来的进程，需要判断错误原因，是否需保存错误码
                     用于触发后续能否自动恢复
  Input:          p_process:        进程信息
                     detail_retcode: 进程退出详细错误码
  Output
  Return:          RUN_ERR:  failed
                      RUN_OK:  success
  Others
*************************************************/
int check_and_save_detail_retcode(process_node *p_process, int detail_retcode)
{
    int ret = DA_FAIL;

    if (NULL == p_process) {
        LOG_ERROR("p_process input para is null");
        return DA_FAIL;
    }

    LOG_DEBUG("check process[%s] start heartbeat, detail_retcode=%d", p_process->process.para, detail_retcode);

    if (DSW_ERROR_AIO_DM_AIO_MAX_NR_SMALL == detail_retcode) {
        LOG_INFO("process[%s] start detail_retcode=%d, need to save out_reason",
                 p_process->process.para, detail_retcode);
        ret = update_monitor_process(p_process, MONITOR_INFO_OUT, detail_retcode);
        if (DA_OK != ret) {
            LOG_ERROR("modify_process_monitor_value failed.para=[%s]", p_process->process.para);
            return DA_FAIL;
        }
    }
    return DA_OK;
}

/*************************************************
  Function:        da_set_osd_out_reason
  Description:    将进程退出信息记录到内存和配置文件
  Input:    p_hb_req: 心跳信息   
  Output
  Return:      RUN_ERR:  failed
               RUN_OK:  success
  Others
*************************************************/
int da_set_osd_out_reason(core_agent_msg_t *p_hb_req)
{
    int ret = RUN_ERR;
    char file_name[DSA_DIR_PATH_MAX] = { 0 };
    if (NULL == p_hb_req) {
        LOG_ERROR("error, p_hb_req is null pointer");
        return DA_FAIL;
    }
    if (0 == strnlen(p_hb_req->name, BUFSIZE_32)) {
        LOG_ERROR("invalid start heartbeat message");
        return DA_FAIL;
    }
    if (0 != strncmp(p_hb_req->name, OSD_PROCESS_NAME, sizeof(OSD_PROCESS_NAME))) {
        LOG_ERROR("invalid message, p_hb_req->name(%s)", p_hb_req->name);
        return DA_FAIL;
    }

    LOG_INFO("revice %s process(para=%s) out_reason retcode=%d",
             p_hb_req->name, p_hb_req->para, p_hb_req->detail_retcode);

    // 亚健康流程，此时记录缺省退出原因，用于自动恢复流程
    ret = modify_monitor_process(OSD_PROCESS_NAME, p_hb_req->para, MONITOR_INFO_OUT, p_hb_req->detail_retcode);
    if (DA_OK != ret) {
        LOG_ERROR("modify_monitor_process failed.para=[%s]", p_hb_req->para);
        return DA_FAIL;
    }

    // 函数内部会处理非hight temp level2的情况
    modify_process_for_out_specail(OSD_PROCESS_NAME, p_hb_req->para, MONITOR_INFO_OUT,
                                   p_hb_req->detail_retcode);

    // 如果是网络亚健康原因被out，需要记录资源使用情况
    int resource_stat = SYS_RESOURCE_NO_EXCEED;
    if (DSW_ERROR_AIO_DM_NET_SUBHEALTH_2 == p_hb_req->detail_retcode ||
        DSW_ERROR_AIO_DM_NET_SUBHEALTH == p_hb_req->detail_retcode) {
        resource_stat = net_sub_health_query_sys_resource_stat();
        // 记录资源告警
        if (SYS_RESOURCE_EXCEED == resource_stat) {
            LOG_ERROR("OSD(%s)out reason sys resource exceed", p_hb_req->para);
            (void)modify_monitor_process(OSD_PROCESS_NAME, p_hb_req->para, MONITOR_INFO_SYS_RESOURCE,
                                         SYS_RESOURCE_EXCEED);
        }
    }

    LOG_INFO("da_set_osd_out_reason ok.");
    (void)DumpDsaConfMonitorFilePath(file_name, sizeof(file_name));
    (void)refresh_file_to_usb(file_name);
    return DA_OK;
}

/*************************************************
  Function: get_cache_esn_info
  Description: 获取cache_esn(只有ssd_card才有esn)
  Input:    media_type:   主存类型(ssd、hdd)
            dev_name:     设备名(/dev/sda)
			start_lba:    起始位置
  Output:   cache_esn
  Return: int;
  Others:
*************************************************/
int get_cache_esn_info(const char *media_type, const char *dev_name,
                       dsw_u64 start_lba, char *OUT cache_esn)
{
    shell_rsp cmd_rsp;
    char command[COMMAND_BUFSIZE] = { 0 };

    if (NULL == media_type || NULL == dev_name || NULL == cache_esn) {
        LOG_ERROR("input parameter null.");
        return DA_FAIL;
    }

    LOG_DEBUG("get_cache_esn_info: media_type[%s], dev_name[%s], start_lba[%llu]",
              media_type, dev_name, start_lba);
    char path_name[DSA_DIR_PATH_MAX] = { 0 };
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s %s %s %lu",
               path_name,
               DSWARE_SHELL_NAME,
               "get_cache_esn",
               media_type,
               dev_name,
               start_lba);
    memset_s(&cmd_rsp, sizeof(shell_rsp), 0, sizeof(shell_rsp));
    shell_operate(command, &cmd_rsp, SHELL_TIME_OUT_3);
    if (DA_OK != cmd_rsp.status) {
        return DA_FAIL;
    }
    strncpy_s(cache_esn, BUFSIZE_64, cmd_rsp.value, BUFSIZE_64 - 1);
    LOG_DEBUG("success to get cache_esn:%s", cache_esn);

    return DA_OK;
}

/*************************************************
  Function: get_pool_media_cache_type
  Description: 根据pool_id获取cache类型(nvdimm、ssd_card)
  Input:    disk_serial:   osd_esn
  Output:   cache_type
  Return: int;
  Others: 
*************************************************/
int get_pool_media_cache_type(dsw_u16 pool_id, char *OUT cache_type)
{
    shell_rsp cmd_rsp;
    char command[COMMAND_BUFSIZE] = { 0 };
    char osd_conf[BUFSIZE_128] = { 0 };

    if (NULL == cache_type) {
        LOG_ERROR("input parameter null.");
        return DA_FAIL;
    }

    if (INVALID_POOL_ID == pool_id) {
        snprintf_s(osd_conf, BUFSIZE_128, BUFSIZE_128 - 1, "%s/osd/conf/osd_conf.cfg", g_fsa_p_dir);
    } else {
        snprintf_s(osd_conf, BUFSIZE_128, BUFSIZE_128 - 1, "%s/osd/conf/osd_%hu_conf.cfg", g_fsa_p_dir, pool_id);
    }
    char path_name[DSA_DIR_PATH_MAX] = { 0 };
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s %s",
               path_name,
               DSWARE_SHELL_NAME,
               "get_cache_type",
               osd_conf);
    memset_s(&cmd_rsp, sizeof(shell_rsp), 0, sizeof(shell_rsp));
    shell_operate(command, &cmd_rsp, SHELL_TIME_OUT);
    if (DA_OK != cmd_rsp.status) {
        return DA_FAIL;
    }
    strncpy_s(cache_type, BUFSIZE_64, cmd_rsp.value, BUFSIZE_64 - 1);
    LOG_DEBUG("success to get cache_type:%s", cache_type);

    return DA_OK;
}

/*************************************************
  Function: auto_in_Callback
  Description: 回调函数，用于定期更新osd进程中亚健康相关参数值
  Input
  Return
  Others
*************************************************/
void auto_in_Callback(void *p_arg)
{
    process_node *p_tmp_process = NULL;
    list_head_t *p_tmp_node = NULL;
    process_monitor_t *monitor = NULL;
    list_head_t *monitor_list = NULL;
    pthread_mutex_t *monitor_lock = NULL;

    get_process_monitor(OSD_PROCESS_NAME, &monitor);
    monitor_lock = &monitor->process_monitor_lock;
    monitor_list = &monitor->process_monitor_list;

    (void)pthread_mutex_lock(monitor_lock);
    list_for_each(p_tmp_node, monitor_list)
    {
        p_tmp_process = list_entry(p_tmp_node, process_node, head);
        if (p_tmp_process->process.auto_in_times > 0) {
            update_monitor_process(p_tmp_process, MONITOR_INFO_AVOID_SHAKE,
                                   p_tmp_process->process.avoid_shake_time + 10);  // 10此处时间计算，单位为分钟
        }
        switch (p_tmp_process->process.auto_in_reason_last_time) {
            case DSW_ERROR_AIO_DM_LOST_HB:
                if (p_tmp_process->process.avoid_shake_time >= g_agent_sys_val.lost_heartbeat_recover_anti_shock_period * 60) { // 60表示时间转化
                    update_monitor_process(p_tmp_process, MONITOR_INFO_AVOID_SHAKE, 0);
                    update_monitor_process(p_tmp_process, MONITOR_INFO_AUTOIN, 0);
                    update_monitor_process(p_tmp_process, MONITOR_INFO_REASON_LAST_TIME, 0);
                }
                break;
            case DSW_ERROR_AIO_DM_NVDIMM_MAJOR:
                if (p_tmp_process->process.avoid_shake_time >= g_agent_sys_val.nvdimm_unhealth_recover_anti_shock_period * 60) { // 60表示时间转化
                    update_monitor_process(p_tmp_process, MONITOR_INFO_AVOID_SHAKE, 0);
                    update_monitor_process(p_tmp_process, MONITOR_INFO_AUTOIN, 0);
                    update_monitor_process(p_tmp_process, MONITOR_INFO_REASON_LAST_TIME, 0);
                }
                break;
            case DSW_ERROR_AIO_DM_NODE_UNHEALTH:
                if (p_tmp_process->process.avoid_shake_time >= g_agent_sys_val.cross_node_unhealth_recover_anti_shock_period *
                    60) { // 60表示时间转化
                    update_monitor_process(p_tmp_process, MONITOR_INFO_AVOID_SHAKE, 0);
                    update_monitor_process(p_tmp_process, MONITOR_INFO_AUTOIN, 0);
                    update_monitor_process(p_tmp_process, MONITOR_INFO_REASON_LAST_TIME, 0);
                }
                break;
            default:
                if (p_tmp_process->process.avoid_shake_time >= g_agent_sys_val.default_fault_recover_anti_shock_period * 60) { // 60表示时间转化
                    update_monitor_process(p_tmp_process, MONITOR_INFO_AVOID_SHAKE, 0);
                    update_monitor_process(p_tmp_process, MONITOR_INFO_AUTOIN, 0);
                    update_monitor_process(p_tmp_process, MONITOR_INFO_REASON_LAST_TIME, 0);
                }
        }
    }
    (void)pthread_mutex_unlock(monitor_lock);

    check_chang_disk_status();
}

/*************************************************
  函数: high_temperature_shutdown_handle
  描述
  入参
  出参
  返回: 0:  sucess

  其它
*************************************************/
int high_temperature_shutdown_handle(void)
{
    // 查询获得磁盘信息
    dm_dev_lis_t hdd_disk_info;
    dm_dev_lis_t ssd_disk_info;

    memset_s(&hdd_disk_info, sizeof(dm_dev_lis_t), 0, sizeof(dm_dev_lis_t));
    memset_s(&ssd_disk_info, sizeof(dm_dev_lis_t), 0, sizeof(dm_dev_lis_t));

    // 获取HDD磁盘信息
    if (DA_OK != aio_dm_get_hdd_disk_info(&hdd_disk_info)) {
        LOG_ERROR("get_hdd_disk_info failed");
        return DA_FAIL;
    }

    // 获取当前ssd卡信息
    if (DA_OK != aio_dm_query_ssd_card_and_nvme_info(&ssd_disk_info)) {
        LOG_ERROR("check_node_disk get ssd disk_info failed");
        return DA_FAIL;
    }

    return DA_OK;
}



