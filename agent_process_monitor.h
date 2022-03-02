/*************************************************
  Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
  File name:    agent_op_config.h
  Author: l00130209
  Version:
  Date: 2012-07-17
  Description:  Configuration file read and write capabilities
*************************************************/
#ifndef AGENT_PROESS_MONITOR_H_
#define AGENT_PROESS_MONITOR_H_

#include "../utility/agent_op_list.h"
#include "../interface/dswareAgent_interface.h"
#include "../interface/dsa_disk_monitor.h"
#include "FML.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */
#define MONITOR_START_SLEEP_TIME 10
#define PROCESS_START_WAIT_TIMES 12

#define START 1
#define NSTART 0
#define RUN_OK 0
#define RUN_ERR (-1)
#define PROCESS_OK 0
#define PROCESS_ERR 1
#define MON_ERR (-3)
#define CREATE_FIFO_ERR (-4)

// zk无角色状态
#define ZK_NO_ROLE_STATUS 2
#define ZK_NO_MASTER_STATUS 3

#define SEND_ALARM_OK 0
#define SEND_ALARM_ERR 1
#define PARA_SIZE_16 16
#define PARA_SIZE_32 32
#define PARA_SIZE_64 64
#define PARA_SIZE_256 256
#define DECIMAL 10
#define STR_ONE "1"
#define NO_PROCESS (-2)
#define HAVE_PROCESS 1
#define ALARM 1
#define NO_ALARM 0
#define VBS_RUN_OK 0
#define VBS_RUN_FAIL 1
// 无效的SSD物理槽位号
#define INVALID_PYH_SLOT (-1)

#define PROCESS_MAX_NUM 128
#define ONE_PROCESS 1
#define MONITOR "True"
#define NO_MONITOR "False"

#define MEM_MONITOR 0
#define MEM_NOT_MONITOR 1
// 此状态表示agent不再拉此进程，但不从监控中删除该进程，也不在agentMonitor置进程标记为False
#define MEM_NOT_MONITOR_AND_ALARM 3

#define PROCESS_START_FLAG 1
#define PROCESS_MONITOR_FLAG 0

#define READONLY_FLAG 1
#define READWRITE_FLAG 0

#define PROCESS_MONITOR_FILE(file) do { \
    snprintf_s(file, sizeof(file), sizeof(file) - 1, "%s/conf/agentMonitor", g_fsm_agent_dir); \
} while (0)

#define FIFO_NAME "dsw_agent_listen_fifo"
#define CHOWN_DSW_AGENT_FIFO "chown persistence:storage %s"
#define CHMOD_DSW_AGENT_FIFO "chmod 660 %s"

#define MDC_PROCESS_SECTION "MDC_PROCESS"
#define VFS_PROCESS_SECTION "VFS_PROCESS"
#define KVS_PROCESS_SECTION "KVS_PROCESS"

#define OSD_PROCESS_SECTION "OSD_PROCESS"
#define OPPOSITE_OSD_PROCESS_SECTION "OPPOSITE_OSD_PROCESS"

#define ZK_PROCESS_SECTION "ZK_PROCESS"
#define OPENSM_PROCESS_SECTION "OPENSM_PROCESS"

// EXESHELL_PROCESS和JBODMNG_PROCESS属于SMIO的两个进程
#define EXESHELL_PROCESS_SECTION "EXESHELL_PROCESS"
#define JBODMNG_PROCESS_SECTION "JBODMNG_PROCESS"
#define PROCESS_SECTION_DEFAULT "\0"

#define MDC_PROCESS_NAME "MDC"
#define VBS_PROCESS_NAME "VBS"
#define VFS_PROCESS_NAME "VFS"
#define OSD_PROCESS_NAME "OSD"
#define ZK_PROCESS_NAME "ZK"
#define KVS_PROCESS_NAME "KVS"
#define OPENSM_PROCESS_NAME "OPENSM"

#define ALL_PROCESS_NAME "ALL"

#define OSD_PROCESS_TYPE "osd"
#define KVS_PROCESS_TYPE "kvs"
#define VFS_PROCESS_TYPE "vfs"
#define VBS_PROCESS_TYPE "vbs"
// EXESHELL和JBODMNG属于SMIO的两个进程
#define JBODMNG_PROCESS_NAME "JBODMNG"

#define MDC_ALARM_ID 0xFEA63000A
#define OSD_ALARM_ID 0xFEA63000F
#define ZK_ALARM_ID 0xFEA63000B
#define VFS_ALARM_ID 0xFEA63000C
#define SYS_DISK_ALARM_ID 0xF000A0233
#define SYS_DISK_RAID_DOWN_GRADE_ALARM_ID 0xF000A0133
#define KVS_ALARM_ID 1630
#define ZK_DISK_ALARM_ID 1806
#define DISK_ALARM_ID 1807
#define EXESHELL_ALARM_ID 1835
#define JBODMNG_ALARM_ID 8227454981L
#define NTP_ALARM_ID 1822
#define OPENSM_ALARM_ID 8227454979L
#define COMPONENT_ALARM_ID 3018

#define PROCESS_ALARM 1
#define ZK_DISK_ALARM 14
#define DISK_ALARM 15

#define ALARM_SEND_OK 1
#define ALARM_SEND_ERR 2
#define ALARM_RESUME_OK 3
#define ALARM_RESUME_ERR 4

#define ALARM_MOC "Process"
#define ALARM_MOC_DISK "Disk"
#define FLUSH_NVDIMM "flush_nvdimm"

#define SYS_DISK_IO_BLOCK "io block"
#define SYS_DISK_SLOW_DISK "slow disk"
#define SYS_DISK_SMART_EXCEED "smart exceed"
#define SYS_DISK_HIGH_TEMP "high temperature"
#define SYS_DISK_FAULT "disk fault"
#define SYS_DISK_RAID_DOWN_GRADE "RAID degradation"

#define SEND_ALARM_COUNT (600 / g_agent_sys_val.progress_monitor_time)
#define INIT_REFRESH_TIME 100
#define FIFO_PATH_SIZE 255

#define GET_EVENTS_ONE_TIME PROCESS_MAX_NUM
#define DEFAULT_TIMEOUTS 1
#define TIMEOUT_LAST 5
#define KILL_TIMES 2  // kill -6 两次
#define KILL_PROCESS_OP "kill_process_op"
#define KILL_PROCESS_OP_BY_PARA "kill_process_op_by_para"
#define NORMAL_KILL 6  // kill -6 PID, 正常杀，先生成黑匣子再推迟
#define FORCE_KILL 9   // kill -9 PID， 直接强制退出

#define PROCESS_START_OK 0
#define PROCESS_START_UNOK 1

#define PROCESS_RET_NO (-1)
#define PROCESS_RET_OK 0
#define PROCESS_RET_NOT_TO_PULL 1
#define PROCESS_RET_PULL_AGAIN 2
#define PROCESS_RET_NOT_TO_PULL_AND_ALARM 3
#define PROCESS_RET_UNKNOWN 4  // mdc不知道自己是否在集群中，需要fsa通过insight查询

#define LINUX_PROCESS_NOT_EXIST 5

// 强制删除内存中的监控标记位
#define FORCE_DEL_FLAG 1
// 只有在pool_id不同时才需要删除
#define NO_DEL_SAME_POOL 0

#define QUERY_NODE_ENV_NO_PROCESS 0
#define QUERY_NODE_ENV_HAVE_PROCESS 1

#define AIO_DM_OK 0
#define AIO_DM_UNOK 1
#define AIO_DM_CAN_RECOVER 1
#define MAX_CHECK_AIO_READY_STATE_TIME 300 /* 秒 */

#define NO_NEED_START 0  // 表示内存状态没有被更新
#define NEED_START 1     // 表示fsa监控的内存状态已经被更新，需要重新拉起
#define REFMONITOR_ACT_NOTHING "no_action"
#define REFMONITOR_ACT_DELETE "delete_host"   // 缩容节点或删除节点的场景，需要置jbod监控为false
#define REFMONITOR_ACT_ADD "add_host" 

#define CLEAR_OSD_RUNNING 1
#define MDC_MAP_CHECK_RUNNING 2
#define CLEAR_OSD_DEFAULT 0

typedef enum {
    PROCESS_NOT_EXIST = 0,  // 0表示进程没有出现
    PROCESS_IS_EXIST = 1,   // 1表示进程出现
} e_process_exist;

typedef enum {
    ALARM_FLAGE_FALSE = 0,  // 0表示未做告警
    ALARM_FLAGE_TRUE = 1,   // 1表示已做告警
} e_process_alarm;

enum E_PROCESS_PARA {
    PROCESS_NEED_PARA = 2,     // 2表示进程需要参数
    PROCESS_NO_NEED_PARA = 3,  // 3表示进程不需要参数
};

typedef enum {
    ZK_PROCESS_MOUNT_ERROR = 101,
    ZK_PROCESS_DISK_FAULT_ERROR = 102,
} e_zk_process_error;

// for out_reason specail
typedef struct {
    int stat;                 // 设备状态AIO_DM_OK，AIO_DM_UNOK
    int previous_check_time;  // 上次检测的时间
    int recover_time;         // 设备恢复的时间
} hight_temp_level2_t;

typedef struct {
    int previous_check_time;  // 上次检测的时间
} block_io_level1_t;

typedef struct {
    union {
        hight_temp_level2_t higth_level2_specail;
        block_io_level1_t block_io_level1_specail;
    } out_specail;
} out_reason_specail_t;
// END:for out_reason specail

struct process_s {
    char name[PARA_SIZE_32];
    int pid;
    int fifo_fd;
    int status;          // fsm查询的进程状态
    int monitor_status;  // 业务进程心跳状态
    int is_monitor;
    char running_status[PARA_SIZE_16];  // S ,D,T,Z状态
    char para[PARA_SIZE_64];
    char path[PARA_SIZE_256];
    int slot;
    int fault_times;                 /* 进程持续异常计数,用于进程告警. */
    dsw_u32 continuous_fault_times;  // 目前仅适用于vbs，记录进程持续出错的周期
    int alarm_threshold;
    int is_alarm;
    int send_alarm_status;
    int alarm_happen_time;
    int timeouts;  // useless for zk.由业务进程心跳消息中的timeouts更新,如果没有心跳则递减,减到低于阈值后杀进程.
    int deadline;
    int times; /* 进程状态正常计数,用于进程告警恢复. */
    int kill_times;
    int start_flag;        // record process starting or not
    int start_wait_times;  // wait process times count
    int update_flag;
    int need_start_flag;         // DTS2017071812623 标识fsa状态更新后是否需要拉起
    int detail_retcode;          // 启动错误小码w00173375
    int not_ready_start_time;    // 检测aio not ready第一次时间
    e_process_alarm alarm_flag;  // used for judge if need alarm
    dsw_u64 alarm_or_recover_tick;
    int status_flag;
    // spc303
    int out_reason;                    // 记录进程退出原因
    int auto_in_times;                 // 记录被自动加入的次数
    int auto_in_reason_last_time;      // 上一次因此原因被踢出后被自动加入，用于防震荡
    int auto_in_check_times;           // 记录检查次数，满足条件才能自动加入
    int avoid_shake_time;              // 防震荡计时信息
    int auto_in_flag;                  // 标志位，用于osd 成功加入后处理更新进程监控中autoin 相关信息
    int out_sys_resource;              // 记录网络亚健康时的系统资源  (CPU/网口带宽是否有告警)
    int write_conf_flag;               // 记录修改配置文件是否成功，避免每个周期都去修改配置文件
    out_reason_specail_t out_specail;  // 针对out_reason 的特殊数据结构
    unsigned int lock_keep_flag;       // 锁维持标记
    dsw_u16 vnode_id; // 太平洋专有硬件ID，只针对osd有效，默认为0
    enum ASYNC_ADD_OSD_FLAG add_flag; // 0表示本控osd，1表示对控osd
};

typedef struct osd_process_healthy {
    int is_monitor;        // 记录进程监控字段
    int out_reason;        // 记录进程退出原因
    int out_sys_resource;  // 记录进程退出的资源情况
    dsw_u16 vnode_id; // 太平洋服务器osd所属vnode_id，通用服务器默认为0
    dsw_u16 add_flag; // 正常拉起为0，太平洋服务器接管拉起对控osd为1 
} osd_process_healthy_t;

struct process_node_s {
    list_head_t head;
    dsw_u16 poolId;  // multi pool
    struct process_s process;
};

typedef struct process_node_s process_node;

// for specail out reason
// hight_temp_level2  sepecail
#define HIGHT_TEMP_LEVEL2_CHECK_INTERVAL (1 * 60)          // 高温检测的间隔
#define HIGHT_TEMP_LEVEL2_RECOVER_DURATION_TIME (20 * 60)  // 高温恢复持续的时间

// 针对out_reason 的特殊数据结构
// 目前看为了保证业务的可用性，agent会针对out_reason 做特殊处理
// out_reason_specail_t 特殊处理的数据结构，后续可以根据特殊的reason 扩展out_specail
typedef struct out_reason_callback_f {
    int out_reason;
    void (*func)(process_node *);
} out_reason_callback_f_t;
// for specail out reason

typedef struct wait_osd_process {
    char proc_name[BUFSIZE_16];
    char proc_para[BUFSIZE_64];
    dsw_u16 poolId;
    struct osd_process_healthy osd_healthy;
} wait_osd_process_t;

typedef struct refresh_osd_process {
    wait_osd_process_t proc_refresh_list[MAX_SSD_OSD_NUM];
    int refresh_num;
} refresh_osd_process_t;

typedef struct process_monitor {
    list_head_t process_monitor_list;
    pthread_mutex_t process_monitor_lock;
} process_monitor_t;

typedef struct process_monitor_list {
    process_monitor_t zk_process_monitor;
    process_monitor_t osd_process_monitor;
    process_monitor_t vfs_process_monitor;
    process_monitor_t kvs_process_monitor;
    process_monitor_t mdc_process_monitor;
    process_monitor_t opensm_process_monitor;
    process_monitor_t other_process_monitor;
} process_monitor_list_t;

typedef struct osd_process_info {
    char conf_file[BUFSIZE_128];
    char osd_esn[DISK_SN_LENGTH];
    char disk_name[BUFSIZE_128];
    int slot_id;
    int host_id;
    int process_status;
    dsw_u16 poolId;
    long long unsigned int osd_size;
    long long unsigned int start_pos;
    dsw_u16 vnode_id;
} osd_process_info_t;

typedef struct start_process_status_ret {
    char process_name[BUFSIZE_32];
    char process_para[BUFSIZE_64];
    int cur_status;
    int retcode;         // 大码，用于FSA逻辑判断
    int detail_retcode;  // 小码，即对大码retcode的细化码，用于给FSM透传
} start_process_status_ret_t;

typedef struct start_process_status_tbl {
    start_process_status_ret_t proc_start_list[PROCESS_MAX_NUM];
    int proc_start_num;
    pthread_mutex_t proc_start_list_lock;
} start_process_status_tbl_t;

typedef struct {
    int process_flag;
    int need_start_flag;
    int start_flag;
} monitor_flag_t;

typedef struct g_osd_ip_info_list {
    list_head_t g_osd_ip_info_list_head;
    pthread_mutex_t g_osd_ip_info_list_lock;
} g_osd_ip_info_list_t;

typedef struct fast_add_osd_service_params {
    char path_name[PARA_SIZE_256];
    char osd_sn[DISK_SN_LENGTH];
    char disk_name[BUFSIZE_128];               // 磁盘盘符sdx
    dsw_s32 disk_slot_id;                      // 对应的槽位号
    char osd_conf[BUFSIZE_128];
    dsw_u8 stoarge_type;                        // 存储池类型
    int add_flag;
    dsw_u8 disk_vnode_id;                      // 对应的vnode id
    dsw_s32 server_id;                         // 节点ID
    char cluster_ip_list[PARA_SIZE_256];       // 存储前端IP列表
    char storage_ip_list[PARA_SIZE_256];       // 存储后端IP列表
    dsw_u32 pool_id;
    dsw_u16 osd_slot_list[BUFSIZE_128];        // 池上的槽位号
    dsw_u32 osd_min_slot;                      // 最小槽位
    dsw_u32 osd_max_slot;                      // 最大槽位
} fast_add_osd_service_params_t;

typedef struct fast_stop_osd_service_params {
    char path_name[PARA_SIZE_256];
    char osd_sn[DISK_SN_LENGTH];
} fast_stop_osd_service_params_t;

// process name
typedef struct process_name_manager_tag {
    char process_name[PARA_SIZE_32]; // 进程名
} process_name_manager;

extern bool is_process_monitor_exited;
extern time_t g_check_add_osd_from_mdc_time_pre;
extern int g_delete_pool_flag;

int create_fifo_for_process(const char *process, const char *prap);
int delete_fifo_for_process_no_safe(const char *process, const char *prap);
process_node *find_process_by_name_and_para_no_safe(const char *process_name, const char *p_para);
extern int add_monitor_process_to_file(const char *p_process, const char *p_para, dsw_u16 poolId, 
    const char *process_section, dsw_u16 vnode_id, dsw_u8 own_side);
extern int del_monitor_process_from_file(const char *p_process, dsw_u16 poolId, const char *p_para, const char *p_process_section);
extern int add_monitor_process_to_memory(const char *p_process, const char *p_para, dsw_u16 poolId,
                                         monitor_flag_t *monitor_flag, const dsw_u16 vnode_id, const dsw_u16 add_flag);
extern int del_monitor_process_from_memory(const char *p_process, const char *p_para);
extern int add_monitor_process(const char *p_process, const char *p_para, dsw_u16 poolId, int process_flag,
                               int need_start_flag);
extern int refresh_multi_process_to_memory(const char *process_section, const char *process_name, char *p_type,
                                           dsw_u16 poolId, int need_start_flag);
int monitor_process_refresh(int need_start_flag, const char *is_del_host);
extern void *monitor_service(void *p_arg);
extern int stop_monitor(char *p_process, const char *p_ip, dsw_u16 poolId);
extern int stop_monitor_all(const char *p_process);

extern int init_monitor_process(void);
extern int clear_monitor(const char *ip, dsw_u8 own_side);
extern int find_vbs_id_by_manager_ip(const char *p_ip, int *id, int *vbs_id_num);
vbs_cluster_info *get_vbs_cluster_info_by_manager_ip(const char *p_ip);
extern int get_process_info_by_manager_ip(struct process_s **p_process_info_head, dsw_u32 *num, char *p_ip,
                                          char *process_name);
extern int get_all_process_info(struct process_s **p_process_info_head, dsw_u32 *num);
extern int stop_process(char init_letter);
extern int stop_server_by_type(dsware_server_req_t *server_req);
extern int update_monitor_process(process_node *p_tmp_process, const char *type, int value);
extern dsw_bool process_monitor_lists_is_empty(void);

// add by g00365424

extern int check_node_process_existence(dsw_u32 *mdc, dsw_u32 *zk, dsw_u32 *osd, dsw_u32 *vbs, dsw_u32 *kvs);
extern int modify_monitor_process_from_file(const char *p_process, const char *p_para, const char *type, int value,
                                            dsw_u16 pool_id);

extern process_monitor_list_t g_process_monitor_lists;

dsw_s32 check_process_status(char *process_name, const char *command_para, const char *p_ip, dsw_u16 poolId);
dsw_s32 check_process_monitor(char *process_name);
int start_dsware_service(void);
int start_service_by_type(dsware_server_req_t *server_req);
void process_operation(void);
void init_refresh_osd_process(dsw_u16 poolid);
void process_send_alarm(process_node *p_process, int category);
int get_process_start_return(char *proc_name, char *para, int *retcode, int *detail_retcode);
int da_get_process_start_heartbeat(char *process_name, char *para, int *retcode, int *detail_retcode);
int da_clean_process_start_heartbeat(char *process_name, char *para);
int delete_fifo_for_only(char *process, char *para, int fifo);
void stop_zk_disk_stat(void);
int restart_zk_disk_stat(void);
int del_monitor_process(const char *p_process, const char *p_para, dsw_u16 poolId, const char *p_process_section);
int clear_monitor_process_from_file(const char *p_process, const char *p_ip, dsw_u16 poolId, dsw_u8 own_side);
int get_process_monitor(const char *process_name, process_monitor_t **monitor);
int get_process_monitor_local(const char *process_name, process_monitor_t **monitor_out);
int free_process_monitor_local(process_monitor_t *monitor);
int check_process_in_memory_no_safe(const char *p_process, const char *p_para, process_node **result_process);
void modify_process_for_out_specail(const char *p_process, const char *p_para, const char *type, int value);
int modify_monitor_process(const char *p_process, const char *p_para, const char *type, int value);
int get_osd_pool_id(const char *disk_serial, dsw_u16 *OUT pool_id);
int start_vbs_by_manager_ip(char *p_ip, dsw_bool is_start_vbs);
int process_monitor_get_zk_disk_esn(char *esn_buff, dsw_u32 len);

int process_monitor_get_process(const char *p_process, const char *p_para, process_node OUT *result_process);
int check_process_in_memory(const char *p_process, const char *p_para, process_node **result_process);
int judge_pool_enable_nvdimm_back_up_flag(dsw_u16 pool_id);
int stop_one_osd_by_esn(char *osd_esn);
int check_vbs_all_start(char *p_ip);
int get_vbs_proc_count(char* p_ip, int* vbs_num_curr, int* vbs_num_total);
int del_same_esn_monitor_process(const char *p_process, const char *p_para, dsw_u16 pooId, int del_flag);
int dump_monitor_info_to_file(FILE *out);
int change_proccess_fifo_permission(const char *fifoPath);
int ReportSysDiskStatus(int process_type, dsw_s32 notify_type, int category, int disk_slot, const char *disk_serial,
                        char *disk_name);
int update_zk_cluster_conf(const char *new_manager_ip);

int add_all_monitor_osd_to_file(add_osd_req_v52 *p_osd_v52);
void del_all_monitor_osd_from_file(add_osd_req_v52 *p_osd_v52);
int add_monitor_process_for_osd_batch(const char *p_process, const char *p_para, dsw_u16 poolId, int process_flag,
                                      int need_start_flag, dm_dev_lis_t *dm_disk_info_local, 
                                      const char *process_section, dsw_u16 vnode_id, dsw_u16 add_flag);
int add_opposite_conf_to_own(const dsw_u16 poolId);
int del_opposite_memory_from_own(const dsw_u16 poolId);
int del_opposite_conf_from_own(const dsw_u16 poolId);
int pacific_start_osd_server_hdd_v51(const dsw_u16 poolId);
int pacific_start_osd_server_for_recover();
int pacific_stop_opposite_osd_server(const dsw_u16 poolId);
void send_jbod_resume_alarm();
extern int dsware_agent_refresh_monitor_process_list(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp);
void do_refresh_osd_process_to_mem(void);
int get_refresh_timer(void);

void close_cache_alarm_send(dm_disk_info_t *dm_disk_info, FML_INT alarm_type, int result_code);
void disk_faulty_alarm_send(dm_disk_info_t *dm_disk_info, FML_INT alarm_type, int pool_id,
                            int result_code, int disk_type);
int get_local_cluster_ip(char *OUT cluster_ip_list_str);
int get_local_storage_ip(char *OUT storage_ip_list_str);
int get_local_server_id(char *OUT server_id_str);
void judge_alarm_status(process_node *p_tmp_process);
void alarm_send(process_node *p_tmp_process, int alarm_status);
extern int is_node_deploy_vbs(const char *p_ip);
#ifdef __cplusplus
}
#endif /* __cpluscplus */
#endif /* AGENT_PROESS_MONITOR_H_ */
