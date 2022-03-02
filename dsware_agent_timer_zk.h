/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 *
 * Description: dsware_agent_timer_zk.h
 *
 * @author: 
 * @create: 2012-11-2
 *
 */

#ifndef DSWARE_AGENT_TIMER_ZK_H_
#define DSWARE_AGENT_TIMER_ZK_H_

#include "./interface/fsa_op_media.h"
#include "./interface/dsa_disk_monitor.h"

#define GET_TIME_FAILED        (-1)
#define ZK_UTI_INTREVAL        120
#define ZK_DISK_CHECK_INTREVAL 20
#define ZK_IO_BLOCK_PERIOD     20

#define ZK_DISK_CHK_NULL      (-1)
#define ZK_DISK_CHK_GOOD      0
#define ZK_DISK_CHK_SLOW_DISK 1

#define DS_TYPE_ZK                   1
#define DS_TYPE_EDS_CCDB             2
#define DS_TYPE_REP_CCDB             3
#define DS_TYPE_SYS                  4
#define DS_NOTIFY_INIT               (-1)
#define DS_NOTIFY_ERROR              0
#define DS_NOTIFY_RESUME             1
#define DS_IO_STAT_BLOCK             0
#define DS_IO_STAT_NOBLOCK           1
#define DS_DISK_STAT_NORMAL          0
#define DS_DISK_STAT_SLOW            1
#define DS_DISK_STAT_SMART_EXCEED    2
#define DS_DISK_STAT_HIGH_TEMP       3
#define DS_DISK_STAT_FAULT           4
#define DS_DISK_STAT_NOT_EXIST       5
#define DS_DISK_STAT_IO_BLOCK        6
#define DS_DISK_STAT_RAID_DOWN_GRADE 7
#define DS_DISK_TYPE_HDD             1
#define DS_DISK_TYPE_SSD             2
#define DEFAULT_SYS_DISK_NUM         0
#define HARD_RAID_SYS_DISK_NUM       1
#define SOFT_RAID_SYS_DISK_NUM       2
#define SYS_IO_BLOCK_CHECK_NUM  12   // 系统盘io block上报告警校验次数
#define SYS_IO_BLOCK_CHECK_TIME 5
#define NUM_10 10
#define NUM_4 4
#define NUM_3 3
#define NUM_2 2
#define NUM_1 1
#define NUM_0 0
#define NUM_24 24
#define PACIFIC  "_pacific"
#define ATLANTIC "_atlantic"
#define BMC_ACCOUNT "accout"
#define BMC_PWD "password"
#define BMC_ACCOUNT_NORMAL_STATUS 0
#define GENERAL_SERVER 0
#define DEDICATED_HARDWARE_SERVER 1

// 杩涢�庡彛name cpu name
#define GET_TEMP_INFO_URL "\"[fe80::9e7d:a3ff:fe28:6ffa%veth]\""
#define PACIFIC_RECOVERY_TUYEYE_TEMP 34
#define PACIFIC_LEVEL_ONE_CPU_HIGH_TEMP 105
#define PACIFIC_LEVEL_ONE_TUYEYE_HIGH_TEMP 37
#define PACIFIC_LEVEL_TWO_CPU_HIGH_TEMP 110
#define PACIFIC_LEVEL_TWO_TUYEYE_HIGH_TEMP 40
#define ATLANTIC_RECOVERY_TUYEYE_TEMP 39
#define ATLANTIC_LEVEL_ONE_CPU_HIGH_TEMP 105
#define ATLANTIC_LEVEL_ONE_TUYEYE_HIGH_TEMP 42
#define ATLANTIC_LEVEL_TWO_CPU_HIGH_TEMP 110
#define ATLANTIC_LEVEL_TWO_TUYEYE_HIGH_TEMP 55
#define IBMC_AUTH_FAIL_ALARM 0x1001EA63100C
#define HT_CHECK_EXCEP_ALARM 0x1001EA63100D
#define TEM_CHECK_FIRST_ALARM 0x2001EA670001
#define TEM_CHECK_SECOND_ALARM 0x1001EA670001

#define DA_ERR_GET_BMC_ACCOUNT  1
#define DA_ERR_ACCESS_IBMC      2
#define DA_ERR_INLET_TEMP       3
#define DA_ERR_CPU_TEMP         4
#define DA_ERR_HTC_INNER_ERROR  5

#define DISK_NAME_LEN_MAX 64

extern ds_m2_disk_info_t g_ds_m2_disk_info;

typedef struct {
    dsw_u32 health_mask_1;
    dsw_u32 health_mask_2;
    int disk_stat;
    int notify_flag;
} ds_notify_table;

typedef struct {
    int cpu_temp;
    int tuyeye_temp; 
} cpu_tuyeye_temp;

typedef enum _KILL_ZK_RESULT_ {
    ZK_IOBLOCK_KILL = 0,
    ZK_IOBLOCK_NO_KILL
} KILL_ZK_RESULT;

int restart_zk(void);
int zk_cleanup(dsw_u32 count);
int smio_health_check_zk(dsw_u32 count);
int dsware_agent_get_zk_status(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp);
void software_raid_status_check(dsw_u32 count);
extern int get_virtual_zk_dev_name(char *p_zk_disk_path, int *drift_flag);
int GetZkDiskPath(int zk_slot, char *OUT p_zk_disk_path, dsw_u32 path_length, char *p_zk_disk_esn);
int ds_get_metadisk_info(int process_type, int *OUT dev_slot, char *OUT dev_esn, char *OUT dev_name,
                         int *OUT disk_type);
int ds_get_sysdisk_info(int *OUT dev_slot, char *OUT dev_esn, char *OUT dev_name,
                        int *OUT disk_type, int check_flag);
int ds_get_disk_type_by_slot_from_smio(int slot);
void ds_sysdisk_io_block_check(dsw_u32 count, int check_flag, int process_type, ds_io_block_count_t *IN OUT io_block_count,
                               int *IN OUT notify_flag);
void ds_sys_slow_disk_check(dsw_u32 count, int check_flag, ds_slow_disk_count_t *IN OUT slow_disk_count, int *IN OUT notify_flag);
void ds_smio_check(dsw_u32 count, int process_type, int *IN OUT notify_flag, ds_dm_dev_lis_t *p_dev_list);
void ds_m2_disk_flush_capability_check(dsw_u32 count);
void ds_m2_disk_link_downspeed_check(dsw_u32 count, int *IN OUT notify_flag, int *IN OUT notify_flag_ata1, int *IN OUT notify_flag_ata2);
int ds_get_m2_memory_size(void);
int GetTempAlarmThreshold(int serverType);
int agent_check_cpu_tuyeye_tem();
void agent_check_disk_temp(int mediaType, const char *mediaName, int threshold);
void ds_sys_smio_check(dsw_u32 count, int process_type, int *IN OUT notify_flag, ds_dm_dev_lis_t *p_dev_list);
int agent_get_bmc_accout_and_pwd(char **bmcAct, int actLen);
int agent_handle_bmc_alarm(dsw_u64 alarm_id, int alarm_type, int ret);
void set_sys_disk_status(int sys_disk_alarm, int send_or_resume, int index_flag);
void init_sys_disk_status(void);
void shut_down_node();
int dsware_agent_switch_zk_master(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp);

// Description:   get the threshold of disk high temperature
// Input:   serverType  :   server type
//          diskType    :   disk type
//          name        :   pre-allocated buffer to save the temperature item name
//          threshold   :   pre-allocated buffer to save the temperature threshold
// Output:  name        :   obtained temperature item name
//          threshold   :   obtained temperature threshold
// Return:  DA_OK   :   success
//          *       :   failure
int GetDiskTempThreshold(int serverType, int diskType, char name[DISK_NAME_LEN_MAX], int *threshold);

#endif /* DSWARE_AGENT_TIMER_ZK_H_ */
