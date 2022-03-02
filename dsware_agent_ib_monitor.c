/*************************************************
  Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
  File name:    dsware_agent_ib_monitor.c
  Author: x00369893
  Version:
  Date: 2019-07-11
  Description:  nvdimm detect
*************************************************/
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <net/if.h>

#include "../interface/dsware_agent_ib_monitor.h"
#include "../utility/agent_op_log.h"
#include "../interface/dsware_agent_shell_helper.h"
#include "../interface/dswareAgent_interface.h"
#include "../utility/agent_op_list.h"

#include "../utility/dsw_timer.h"
#include "../utility/util_common.h"
#include "../utility/mem_util.h"
#include "../config/dsware_agent_conf.h"
#include "../net_module/dev_mon/dev_mgr.h"
#include "../net_module/dev_mon/devmon_drop_jitter_ctrl.h"
#include "../interface/dswareAgent_interface.h"
#include "../net_module/network_subhealth/net_sub_health_device_mgnt.h"

#define DSA_IB_MONITOR_TIMEOUT    (4 * 60)  // FSM命令超时时间为5分钟，这里比FSM短
#define DSA_IB_BACKUP_LOG_TIMEOUT 50
#define DSA_IB_PORT_RANGE_LEN     12

#define DSA_IB_PARSE_PER_NUM 5  // 单次查询端口数量

#define DSA_IB_MONITOR_SHELL "ib_stat_check.sh"

#define DSA_IB_OP_Q_PORT_STAT       "qry_sw_port_stat"
#define DSA_IB_OP_Q_SW_PORT_NUM     "qry_sw_num"
#define DSA_IB_OP_Q_SW_RETRANS_RATE "query_retrans_rate"

#define DSA_JUMP_ONE_PLAG_RETURN(p_char, flag, p_last) \
    do { \
        p_char = strchr(p_char, flag);                     \
        if (NULL == (p_char)) {                              \
            LOG_ERROR("char is null");                     \
            free(p_sw_info);                               \
            p_sw_info = NULL;                              \
            return DA_FAIL;                                \
        }                                                  \
        (p_char)++;                                          \
        if ((p_char) >= (p_last)) {                          \
            LOG_ERROR("char is end");                     \
            p_char = NULL;                                 \
            free(p_sw_info);                               \
            p_sw_info = NULL;                              \
            return DA_FAIL;                                \
        } \
    } while (0);

#define DSA_JUMP_ONE_PLAG_RETURN_V2(p_char, flag, p_last) \
    do { \
        if (NULL == ((p_char) = strchr((p_char), flag))) {                              \
            return DA_FAIL;                                \
        }                                                  \
        (p_char)++;                                          \
        if ((p_char) >= (p_last)) {                          \
            return DA_FAIL;                                \
        } \
    } while (0);

// 交换机状态
// 永远不会上报异常状态，FSM采用两次比较法，没有收到的SW认为故障
enum SW_STAT {
    SW_STAT_NORMAL = 0,
    SW_STAT_UNNORAML = 1
};

#define DSA_SW_UNKNOWN 1

// 字段格式化最大长度
#define DSA_IB_FORMAT_MAX_LEN 20

typedef struct {
    char format[DSA_IB_FORMAT_MAX_LEN];  // 格式化必须和保存数据的缓存匹配
    dsw_u16 offset;
    dsw_u16 buff_len;  // 如果是字符串，必须填buff_len
} dsa_ib_port_stat_parse;


dsa_ib_port_stat_parse G_PORT_STAT_PARSES[] = {
    { "lid=%hu",       (dsw_u16)offsetof(port_stat, lid),                0 },
    { "port_no=%hu",       (dsw_u16)offsetof(port_stat, no),                 0 },
    { "stat=%hhu",       (dsw_u16)offsetof(port_stat, state),              0 },
    { "phy_stat=%hhu",      (dsw_u16)offsetof(port_stat, phy_state),          0 },
    { "rate=%hu",       (dsw_u16)offsetof(port_stat, rate),               0 },
    { "max_rate=%hu",       (dsw_u16)offsetof(port_stat, max_rate),           0 },
    { "to_guid=%19[^@]",    (dsw_u16)offsetof(port_stat, to_guid),            DSA_IB_GUID_LEN },
    { "to_lid=%hu",       (dsw_u16)offsetof(port_stat, to_lid),             0 },
    { "to_port=%hu",       (dsw_u16)offsetof(port_stat, to_port_no),         0 },
    { "xmit_pkts=%llu",     (dsw_u16)offsetof(port_stat, xmit_pkts),          0 },
    { "rcv_pkts=%llu",      (dsw_u16)offsetof(port_stat, rcv_pkts),           0 },
    { "xmit_discards=%llu", (dsw_u16)offsetof(port_stat, xmit_discards),      0 },
    { "rcv_errors=%llu",    (dsw_u16)offsetof(port_stat, rcv_errors),         0 },
    { "sym_err_cnt=%llu",   (dsw_u16)offsetof(port_stat, SymbolErrorCounter), 0 }
};

// /////////////BEGIN:ib port mon for flash fail/fault
pthread_t g_ip_mon_thread;
int g_ip_mon_loop_flag = 1;
dsw_u32 g_ip_mon_timer_id;

/*****************************************************************
Parameters    :  p_buff
                 len
                 p_port_stat
Return        :  int
Description   :  解析交换机端口状态，字符串eg:
guid=0x0000201302181314@type=1@lid=3@port_no=1@stat=1@phy_stat=2@rate=8@
max_rate=40@to_guid=0@to_lid=0@to_port=0@xmit_pkts=0@rcv_pkts=0@xmit_discards=
0@rcv_errors=0@sym_err_cnt=0@lid=3@port_no=2@stat=1@phy_stat=2@rate=8@max_rate
=40@to_guid=0@to_lid=0@to_port=0@xmit_pkts=0@rcv_pkts=0@xmit_discards=0@
rcv_errors=0@sym_err_cnt=0
*****************************************************************/
static int parse_sw_port_stat(const char *p_buff, int len, port_stat *OUT p_port_stat, dsw_u16 num)
{
    const char *p_char = p_buff;
    unsigned char *p_block_postion = NULL;
    unsigned char *p_fleid_postion = NULL;
    int ret = 0;

    DA_CHECK_NULL_RETURN_ERR_PARA(p_buff, "p_buff");
    DA_CHECK_NULL_RETURN_ERR_PARA(p_port_stat, "p_port_stat");

    LOG_INFO("parse_sw_port_stat enter,p_buff=%s", p_buff);

    // 跳过guid=0x0000201302200944@
    do {
        p_char = strchr(p_char, '@');
        if (NULL == p_char) {
            LOG_ERROR("char is null");
            return DA_FAIL;
        }
        p_char++;
        if (p_char >= (p_buff + len)) {
            LOG_ERROR("char is end");
            p_char = NULL;
            return DA_FAIL;
        }
    } while (0);

    if (NULL == p_char) {
        LOG_ERROR("p_buff is null");
        return DA_FAIL;
    }
    // END

    dsw_u16 flag_num = sizeof(G_PORT_STAT_PARSES) / sizeof(dsa_ib_port_stat_parse);
    const char *p_tmp = NULL;
    for (int index = 0; index < num; index++) {
        p_block_postion = (unsigned char *)&p_port_stat[index];
        for (int parseIndex = 0; parseIndex < flag_num; parseIndex++) {
            p_fleid_postion = p_block_postion + G_PORT_STAT_PARSES[parseIndex].offset;

            // 第一次执行时跳过了type=1@，type=1不需要在这里解析
            // 后续的正常解析
            p_tmp = strchr(p_char, '@');
            if (NULL == p_tmp) {
                LOG_ERROR("sscanf_s fail index=%d,parseIndex=%d,for parse buff:%s", index, parseIndex, p_char);
                return DA_FAIL;
            }

            p_tmp++;
            if (p_tmp >= ((p_buff + len))) {
                LOG_ERROR("sscanf_s fail index=%d,parseIndex=%d,for parse buff:%s", index, parseIndex, p_char);
                p_char = NULL;
                return DA_FAIL;
            }

            p_char = p_tmp;
            // END

            if (0 == G_PORT_STAT_PARSES[parseIndex].buff_len) {
                ret = sscanf_s(p_char, G_PORT_STAT_PARSES[parseIndex].format, p_fleid_postion);
            } else {
                ret = sscanf_s(p_char, G_PORT_STAT_PARSES[parseIndex].format,
                               p_fleid_postion, G_PORT_STAT_PARSES[parseIndex].buff_len);
            }

            if (1 != ret) {
                LOG_ERROR("sscanf_s fail index=%d,parseIndex=%d,for parse  buff:%s", index, parseIndex, p_char);
                return DA_FAIL;
            }
        }
    }

    for (int i = 0; i < num; i++) {
        LOG_INFO("lid=%hu;port_no=%hu;stat=%hhu;phy_stat=%hhu;rate=%hu;max_rate=%hu;to_guid=%s;to_lid=%hu;\
to_port=%hu;xmit_pkts=%llu;rcv_pkts=%llu;xmit_discards=%llu;rcv_errors=%llu;\
sym_err_cnt=%llu",
                 p_port_stat[i].lid, p_port_stat[i].no,
                 p_port_stat[i].state, p_port_stat[i].phy_state,
                 p_port_stat[i].rate, p_port_stat[i].max_rate,
                 p_port_stat[i].to_guid, p_port_stat[i].to_lid,
                 p_port_stat[i].to_port_no, p_port_stat[i].xmit_pkts,
                 p_port_stat[i].rcv_pkts, p_port_stat[i].xmit_discards,
                 p_port_stat[i].rcv_errors, p_port_stat[i].SymbolErrorCounter);
    }

    return DA_OK;
}

static int exec_shell_for_port_stat(const char *p_guid, const char *p_port_range, shell_rsp *p_shell_rsp)
{
    char command[COMMAND_BUFSIZE] = { 0 };
    char path_name[DSA_DIR_PATH_MAX] = { 0 };
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));

    int ret = snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s %s %s",
                         path_name,
                         DSA_IB_MONITOR_SHELL, DSA_IB_OP_Q_PORT_STAT, p_guid, p_port_range);
    if (ret <= 0) {
        LOG_ERROR("printf error");
        return -1;
    }
    shell_operate(command, p_shell_rsp, DSA_IB_MONITOR_TIMEOUT);
    if (DA_OK == p_shell_rsp->status) {
        LOG_INFO("cmd=%s exec success", command);
    } else {
        LOG_ERROR("cmd=%s exec fail", command);
    }

    return p_shell_rsp->status;
}
/*****************************************************************
Parameters    :  p_guid             
                 begin_port_num     
                 dsw_u16end_port_num
                 p_port_stat        
                 num                
Return        :    
Description   :  调用shell获取交换机端口状态
*****************************************************************/
static int fatch_few_sw_port_stat(const char *p_guid, dsw_u16 begin_port_num, dsw_u16 end_port_num,
                                  port_stat *OUT p_port_stat, dsw_u16 num)
{
    // static fucntion can't check param
    shell_rsp resp = { 0 };
    int ret = DA_OK;
    char port_range[DSA_IB_PORT_RANGE_LEN] = { 0 };

    snprintf_s(port_range, DSA_IB_PORT_RANGE_LEN, DSA_IB_PORT_RANGE_LEN - 1, "%d-%d", begin_port_num,
               end_port_num);

    ret = exec_shell_for_port_stat(p_guid, port_range, &resp);
    if (DA_OK != ret) {
        LOG_ERROR("iget_sw_port_range_stat fail");
        return DA_FAIL;
    }

    ret = parse_sw_port_stat(resp.value, sizeof(resp.value), p_port_stat, num);
    if (DA_OK != ret) {
        LOG_ERROR("parse_sw_port_stat fail");
        return DA_FAIL;
    }

    return DA_OK;
}

/*****************************************************************
Parameters    :  p_guid
                 port_num  交换机端口数量
                 p_rsp
Return
Description   :  获取指定guid的交换机端口状态
                      一般交换机36个口，一次查询的数量过大，经过验证36个port的
                      数据量大概为6-7k,因此改为分批次查询，每次5个
*****************************************************************/
static int fatch_sw_port_stat(const char *p_guid, dsw_u16 port_num, dsware_agent_rsp_hdr *p_rsp)
{
    ib_port_stat *p_port_stat_rsp = NULL;
    int ret = DA_OK;

    dsw_u32 for_malloc = (dsw_u32)(sizeof(ib_port_stat) + sizeof(port_stat) * port_num);
    p_port_stat_rsp = (ib_port_stat *)malloc(for_malloc);
    if (NULL == p_port_stat_rsp) {
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        LOG_ERROR("malloc fail,param=%d", for_malloc);
        return DA_FAIL;
    }
    memset_s(p_port_stat_rsp, for_malloc, 0, for_malloc);

    strncpy_s(p_port_stat_rsp->node_guid, DSA_IB_GUID_LEN, p_guid,
              DSA_IB_GUID_LEN - 1);
    p_port_stat_rsp->num = port_num;

    // BEGIN每次查询DSA_IB_PARSE_PER_NUM 个port状态eg:1-5,6-10
    dsw_u16 parse_times = port_num / DSA_IB_PARSE_PER_NUM;
    dsw_u16 parse_last = port_num % DSA_IB_PARSE_PER_NUM;
    dsw_u16 begin = 0;
    dsw_u16 end = 0;
    for (dsw_u16 i = 0; i < parse_times; i++) {
        begin = (dsw_u16)(1 + DSA_IB_PARSE_PER_NUM * i);
        end = (dsw_u16)(DSA_IB_PARSE_PER_NUM * (i + 1));
        ret = fatch_few_sw_port_stat(p_guid, begin, end,
                                     &p_port_stat_rsp->port_stats[i * DSA_IB_PARSE_PER_NUM],
                                     DSA_IB_PARSE_PER_NUM);

        if (DA_OK != ret) {
            p_rsp->status = DSA_SW_UNKNOWN;
            LOG_ERROR("get_sw_port_stat fail");
            FREE(p_port_stat_rsp);
            return DA_FAIL;
        }
    }

    if (0 != parse_last) {
        begin = port_num - parse_last + 1;
        end = port_num;
        ret = fatch_few_sw_port_stat(p_guid, begin, end,
                                     &p_port_stat_rsp->port_stats[port_num - parse_last], parse_last);

        if (DA_OK != ret) {
            p_rsp->status = DSA_SW_UNKNOWN;
            LOG_ERROR("get_sw_port_stat fail");
            FREE(p_port_stat_rsp);
            return DA_FAIL;
        }
    }

    p_rsp->length = for_malloc;
    p_rsp->status = DA_OK;
    p_rsp->value = p_port_stat_rsp;

    return DA_OK;
}

/*****************************************************************
Parameters    :  p_guid
                 p_result
Return
Description   :  调用shell，获取交换机信息的string
*****************************************************************/
static int exec_shell_4_sw_info(const char *p_guid, shell_rsp *p_result)
{
    LOG_INFO("enter");

    char command[COMMAND_BUFSIZE] = { 0 };
    char path_name[DSA_DIR_PATH_MAX] = { 0 };
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    int ret = snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s %s",
                         path_name,
                         DSA_IB_MONITOR_SHELL,
                         DSA_IB_OP_Q_SW_PORT_NUM, p_guid);
    if (ret <= 0) {
        LOG_ERROR("sprintf error");
        return -1;
    }
    
    shell_operate_ib_switch(command, p_result, DSA_IB_MONITOR_TIMEOUT);
    if (DA_OK == p_result->status) {
        LOG_INFO("cmd=%s exec success", command);
    } else {
        LOG_ERROR("cmd=%s exec fail", command);
    }

    return p_result->status;
}

/*****************************************************************
Parameters    :  p_guid
                 p_result
Return
Description   :  调用shell，获取交换机重传速率信息
*****************************************************************/
static int exec_shell_4_sw_restrans_rate(char *p_result)
{
    LOG_INFO("enter");

    char command[COMMAND_BUFSIZE] = { 0 };
    dsw_s32 status = 0;
    char path_name[DSA_DIR_PATH_MAX] = { 0 };
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));

    int ret = snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s",
                         path_name,
                         DSA_IB_MONITOR_SHELL,
                         DSA_IB_OP_Q_SW_RETRANS_RATE);
    if (ret <= 0) {
        LOG_ERROR("shell cmd =%s, error, status is not 0.", command);
        return AGENT_FAIL;
    }

    shell_operate_ib_switch_with_size(command, &status, p_result, BUFSIZE_8192, DSA_IB_MONITOR_TIMEOUT);
    if (DA_OK == status) {
        LOG_INFO("cmd=%s exec success", command);
    } else {
        LOG_ERROR("cmd=%s exec fail", command);
    }

    return status;
}

/*****************************************************************
Parameters    :  buff
                 len
                 p_sw
Return        :    p_sw
Description   :  从字符串中解析出交换机信息
sw_num=1@@@sw_guid=0x0000201302181314@@@sw_port_num=36@@@lid=3@@@sw_name=SwitchX - 
Mellanox Technologies
*****************************************************************/
static int parse_sw_info(char *buff, dsw_u16 len, sw_info **p_sw)
{
    LOG_INFO("parse_sw_info enter,for parse buff:%s", buff);

    dsw_u32 num = 0;
    sw_info *p_sw_info = NULL;

    int ret = sscanf_s(buff, "sw_num=%u", &num);
    if (1 != ret) {
        LOG_ERROR("get swm_num wrong,buff=%s", buff);
        return DA_FAIL;
    }

    if (DSA_SWITCH_MAX_NUM < num) {
        LOG_ERROR("swm_num too max,num=%d,buff=%s", num, buff);
        return DA_FAIL;
    }
    int need_len = (int)(sizeof(sw_info) + num * sizeof(sw_info_t));
    p_sw_info = (sw_info *)malloc(need_len);

    if (NULL == p_sw_info) {
        LOG_ERROR("malloc memory fail,len=%d", need_len);
        return DA_ERR_MALLOC_FAIL;
    }
    memset_s(p_sw_info, need_len, 0, need_len);

    char *p_char = buff;
    int index = 0;
    int j = 0;
    for (; index < num; index++) {
        p_sw_info->sw_infos[index].stat = SW_STAT_NORMAL;
        // 跳过3个@符号
        for (j = 0; j < 3; j++) {
            DSA_JUMP_ONE_PLAG_RETURN(p_char, '@', (buff + len));
        }
        ret =
            sscanf_s(p_char, "sw_guid=%18[^@]", p_sw_info->sw_infos[index].node_guid, DSA_IB_GUID_LEN);
        if (1 != ret) {
            LOG_ERROR("parse sw_guid fail,p_char=%s,index=%d", p_char, index);
            free(p_sw_info);
            p_sw_info = NULL;
            return DA_FAIL;
        }

        for (j = 0; j < 3; j++) { // 3表示当前循环次数
            DSA_JUMP_ONE_PLAG_RETURN(p_char, '@', (buff + len));
        }
        ret =
            sscanf_s(p_char, "sw_port_num=%hhu", &(p_sw_info->sw_infos[index].port_num));
        if (1 != ret) {
            LOG_ERROR("parse sw_port_num failed: %d, string: %s, index: %d", ret, p_char, index);
            free(p_sw_info);
            p_sw_info = NULL;
            return DA_FAIL;
        }

        for (j = 0; j < 3; j++) { // 3表示当前循环次数
            DSA_JUMP_ONE_PLAG_RETURN(p_char, '@', (buff + len));
        }
        ret =
            sscanf_s(p_char, "lid=%hu", &(p_sw_info->sw_infos[index].lid));
        if (1 != ret) {
            LOG_ERROR("parse lid failed: %d, string: %s, index: %d", ret, p_char, index);
            free(p_sw_info);
            p_sw_info = NULL;
            return DA_FAIL;
        }

        for (j = 0; j < 3; j++) { // 3表示当前循环次数
            DSA_JUMP_ONE_PLAG_RETURN(p_char, '@', (buff + len));
        }
        ret =
            sscanf_s(p_char, "sw_name=%127[^@]s",
                     p_sw_info->sw_infos[index].sw_name, DSA_SWITCH_NAME_LEN);
        if (1 != ret) {
            LOG_ERROR("parse sw_name failed: %d, string: %s, index: %d", ret, p_char, index);
            free(p_sw_info);
            p_sw_info = NULL;
            return DA_FAIL;
        }
    }
    p_sw_info->num = (dsw_u16)index;

    *p_sw = p_sw_info;

    for (int i = 0; i < index; i++) {
        LOG_INFO("INFO:guid=%s,port_num=%d,stat=%d,lid=%d,sw_name=%s", p_sw_info->sw_infos[i].node_guid,
                 p_sw_info->sw_infos[i].port_num,
                 p_sw_info->sw_infos[i].stat, p_sw_info->sw_infos[i].lid, p_sw_info->sw_infos[i].sw_name);
    }

    return DA_OK;
}

/*****************************************************************
Parameters    :  p_req
                 p_rsp
Return
Description   :  查询指定交换机的端口状态，参数:guid
*****************************************************************/
int dsware_agent_ib_query_sw_port(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    if (p_rsp == NULL) {
        LOG_ERROR("null buffer to save the response");
        return DA_ERR_PARA;
    }
    (void)memset_s(p_rsp, sizeof(dsware_agent_rsp_hdr), 0, sizeof(dsware_agent_rsp_hdr));
    
    if (p_req == NULL || p_req->value == NULL) {
        LOG_ERROR("input para error, p_req is null pointer");
        p_rsp->status = DA_ERR_PARA;
        return DA_FAIL;
    } else if (p_req->length < sizeof(sw_port_req)) {
        LOG_ERROR("invalid request length: %u/%u", sizeof(sw_port_req), p_req->length);
        p_rsp->status = DA_ERR_PARA;
        return DA_FAIL;
    }

    sw_port_req *p_param = (sw_port_req *)p_req->value;
    char sw_guid[DSA_IB_GUID_LEN + 1] = {0};
    errno_t rc = memcpy_s(sw_guid, sizeof(sw_guid), p_param->node_guid, sizeof(p_param->node_guid));
    if (rc != EOK) {
        LOG_ERROR("copy switch guid failed: %d", (int)rc);
        p_rsp->status = DA_ERR_PARA;
        return DA_ERR_PARA;
    }

    // BEGIN 获取交换机port数量
    shell_rsp sh_rsp = { 0 };
    int ret = exec_shell_4_sw_info(sw_guid, &sh_rsp);
    if (ret != DA_OK) {
        LOG_ERROR("get switch info failed: %d", ret);
        p_rsp->status = DSA_SW_UNKNOWN;
        return DA_FAIL;
    }

    sw_info *p_sw_info = NULL;
    ret = parse_sw_info(sh_rsp.value, sizeof(sh_rsp.value), &p_sw_info);
    if (ret != DA_OK || p_sw_info == NULL || p_sw_info->num != 1) {
        LOG_ERROR("parse switch info failed: %d, switch num: %d", ret, (p_sw_info == NULL) ? -1 : p_sw_info->num);
        p_rsp->status = DSA_SW_UNKNOWN;
        DSA_FREE(p_sw_info);
        return DA_FAIL;
    }

    // END     获取交换机port数量
    ret = fatch_sw_port_stat(sw_guid, p_sw_info->sw_infos[0].port_num, p_rsp);
    DSA_FREE(p_sw_info);
    if (ret != DA_OK) {
        LOG_ERROR("fatch switch port status failed: %d", ret);
        p_rsp->status = DSA_SW_UNKNOWN;
        return DA_FAIL;
    }
    return DA_OK;
}
/*****************************************************************
Parameters    :  p_req
                 p_rsp
Return
Description   :  查询交换机信息,无参数。
*****************************************************************/
int dsware_agent_query_sw_info(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    if (NULL == p_rsp) {
        LOG_ERROR("input para error, p_rsp is null pointer");
        return DA_FAIL;
    }

    shell_rsp cmd_rsp = { 0 };
    sw_info *psw_info = NULL;
    int ret = 0;

    ret = exec_shell_4_sw_info("", &cmd_rsp);
    if (DA_OK != ret) {
        LOG_ERROR("get_sw_info fail.");

        p_rsp->status = ret;
        return DA_FAIL;
    }

    ret = parse_sw_info(cmd_rsp.value, sizeof(cmd_rsp.value), &psw_info);
    if (DA_OK != ret) {
        LOG_ERROR("get_sw_info fail.");

        p_rsp->status = DSA_SW_UNKNOWN;
        return DA_FAIL;
    }

    if (NULL == psw_info) {
        LOG_ERROR("psw_info is null.");

        p_rsp->status = DSA_SW_UNKNOWN;
        return DA_FAIL;
    }

    p_rsp->status = DA_OK;
    p_rsp->length = (dsw_u32)(psw_info->num * sizeof(sw_info_t) + sizeof(sw_info));
    p_rsp->value = psw_info;

    return DA_OK;
}

static int parse_sw_port_info_to_arr(char *buff, dsw_u16 len, int sw_num,
    sw_retrans_rate_t sw_info[DSA_SWITCH_MAX_NUM],
    port_retrans_rate_t sw_port_info[DSA_SWITCH_MAX_NUM][IBPORT_INFO_MAX])
{
    dsw_u8 port_num = 0;
    char *p_char = buff;

    for (int sw_index = 0; sw_index < sw_num; sw_index++) {
        // 跳过@符号
        for (int j = 0; j < 3; j++) { // 3表示当前循环次数
            DSA_JUMP_ONE_PLAG_RETURN_V2(p_char, '@', (buff + len));
        }
        if (1 != sscanf_s(p_char, "sw_guid=%18[^@]", sw_info[sw_index].sw_guid, DSA_IB_GUID_LEN)) {
            LOG_ERROR("parse sw_guid fail,p_char=%s,sw_index=%d", p_char, sw_index);
            return DA_FAIL;
        }

        for (int j = 0; j < 3; j++) { // 3表示当前循环次数
            DSA_JUMP_ONE_PLAG_RETURN_V2(p_char, '@', (buff + len));
        }
        if (1 != sscanf_s(p_char, "sw_name=%127[^@]", sw_info[sw_index].sw_name, DSA_SWITCH_NAME_LEN)) {
            LOG_ERROR("parse sw_name fail,p_char=%s,sw_index=%d", p_char, sw_index);
            return DA_FAIL;
        }

        for (int j = 0; j < 3; j++) { // 3表示当前循环次数
            DSA_JUMP_ONE_PLAG_RETURN_V2(p_char, '@', (buff + len));
        }
        if (1 != sscanf_s(p_char, "sw_port_num=%hhu", &port_num)) {
            LOG_ERROR("parse sw_port_num fail,p_char=%s,sw_index=%d", p_char, sw_index);
            return DA_FAIL;
        }
        if (IBPORT_INFO_MAX < port_num) {
            LOG_ERROR("port_num too max,num=%d,p_char=%s,sw_index=%d", port_num, p_char, sw_index);
            return DA_FAIL;
        }

        for (int port_index = 0; port_index < port_num; port_index++) {
            for (int j = 0; j < 3; j++) { // 3表示当前循环次数
                DSA_JUMP_ONE_PLAG_RETURN_V2(p_char, '@', (buff + len));
            }
            if (1 != sscanf_s(p_char, "sw_port=%hu", &(sw_port_info[sw_index][port_index].sw_port))) {
                LOG_ERROR("parse sw_port fail,p_char=%s,sw_index=%d,port_index=%d", p_char, sw_index, port_index);
                return DA_FAIL;
            }

            for (int j = 0; j < 3; j++) { // 3表示当前循环次数
                DSA_JUMP_ONE_PLAG_RETURN_V2(p_char, '@', (buff + len));
            }
            if (1 != sscanf_s(p_char, "port_rate=%llu", &(sw_port_info[sw_index][port_index].retrans_rate))) {
                LOG_ERROR("parse port_rate fail,p_char=%s,sw_index=%d,port_index=%d", p_char, sw_index, port_index);
                return DA_FAIL;
            }
        }
        sw_info[sw_index].port_num = port_num;
    }

    return DA_OK;
}

static int parse_sw_retrans_rate_to_rsp(int sw_num,
    sw_retrans_rate_t sw_info[DSA_SWITCH_MAX_NUM],
    port_retrans_rate_t sw_port_info[DSA_SWITCH_MAX_NUM][IBPORT_INFO_MAX],
    ib_sw_retrans_rate_t **p_sw, dsw_u32 *sw_len)
{
    ib_sw_retrans_rate_t *p_sw_info = NULL;
    dsw_u8 port_num = 0;
    int sw_index = 0;
    int port_index = 0;
    int need_len = 0;

    need_len = (int)(sizeof(ib_sw_retrans_rate_t) + sw_num * sizeof(sw_retrans_rate_t));
    for (sw_index = 0; sw_index < sw_num; sw_index++) {
        need_len += sw_info[sw_index].port_num * sizeof(port_retrans_rate_t);
    }

    p_sw_info = (ib_sw_retrans_rate_t *)malloc(need_len);
    if (NULL == p_sw_info) {
        LOG_ERROR("malloc memory fail,len=%d", need_len);
        return DA_ERR_MALLOC_FAIL;
    }
    memset_s(p_sw_info, need_len, 0, need_len);

    char *start_pos = (char *)p_sw_info;
    p_sw_info->sw_num = sw_num;
    start_pos += sizeof(p_sw_info->sw_num);
    for (sw_index = 0; sw_index < p_sw_info->sw_num; sw_index++) {
        memcpy_s(start_pos, sizeof(sw_retrans_rate_t), &(sw_info[sw_index]), sizeof(sw_retrans_rate_t));
        LOG_INFO("sw_guid=%s,sw_name=%s,port_num=%hhu", sw_info[sw_index].sw_guid, sw_info[sw_index].sw_name,
            sw_info[sw_index].port_num);
        start_pos += sizeof(sw_retrans_rate_t);
       
        port_num = sw_info[sw_index].port_num;
        for (port_index = 0; port_index < port_num; port_index++) {
            memcpy_s(start_pos, sizeof(port_retrans_rate_t), &(sw_port_info[sw_index][port_index]),
                sizeof(port_retrans_rate_t));
            start_pos += sizeof(port_retrans_rate_t);
            LOG_INFO("sw_port=%hu,retrans_rate=%llu", sw_port_info[sw_index][port_index].sw_port,
                sw_port_info[sw_index][port_index].retrans_rate);
        }
    }

    *p_sw = p_sw_info;
    *sw_len = need_len;

    return DA_OK;
}

/*****************************************************************
Parameters    :  buff
                 len
                 p_sw
Return        :    p_sw
Description   :  从字符串中解析出交换机重传速率信息
sw_num=1@@@sw_guid=0xec0d9a0300f69990@@@sw_name=MF0;C14-a03:MSB7800/U1@@@sw_port_num=2@@@sw_port=1@@@port_rate=300@@@sw_port=2@@@port_rate=600
Mellanox Technologies
*****************************************************************/
static int parse_sw_retrans_rate(char *buff, dsw_u16 len, ib_sw_retrans_rate_t **p_sw, dsw_u32 *sw_len)
{
    LOG_DEBUG("parse_sw_info enter,for parse buff:%s", buff);

    sw_retrans_rate_t sw_info[DSA_SWITCH_MAX_NUM];
    port_retrans_rate_t sw_port_info[DSA_SWITCH_MAX_NUM][IBPORT_INFO_MAX];
    dsw_u16 sw_num = 0;

    if (1 != sscanf_s(buff, "sw_num=%hu", &sw_num)) {
        LOG_ERROR("get switch_num error,buff=%s", buff);
        return DA_FAIL;
    }

    if (DSA_SWITCH_MAX_NUM < sw_num) {
        LOG_ERROR("switch_num too max,num=%d,buff=%s", sw_num, buff);
        return DA_FAIL;
    }

    memset_s(sw_info, sizeof(sw_info), 0, sizeof(sw_info));
    memset_s(sw_port_info, sizeof(sw_port_info), 0, sizeof(sw_port_info));

    if (parse_sw_port_info_to_arr(buff, len, sw_num, sw_info, sw_port_info) != DA_OK) {
        return DA_FAIL;
    }

    return parse_sw_retrans_rate_to_rsp(sw_num, sw_info, sw_port_info, p_sw, sw_len);
}

/*****************************************************************
Parameters    :  p_req
                 p_rsp
Return
Description   :  查询交换机端口重传速率,无参数。
*****************************************************************/
int dsware_agent_ib_query_sw_retrans_rate(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    if (NULL == p_rsp) {
        LOG_ERROR("input para error, p_rsp is null pointer");
        return DA_FAIL;
    }

    LOG_INFO("dsware_agent_ib_query_sw_retrans_rate start");

    char value[BUFSIZE_8192] = { 0 };
    ib_sw_retrans_rate_t *psw_info = NULL;
    int ret = 0;
    dsw_u32 len = 0;

    ret = exec_shell_4_sw_restrans_rate(value);
    if (DA_OK != ret) {
        LOG_ERROR("get_sw_info fail.");

        p_rsp->status = ret;
        return DA_FAIL;
    }

    ret = parse_sw_retrans_rate(value, sizeof(value), &psw_info, &len);
    if (DA_OK != ret) {
        LOG_ERROR("get_sw_info fail.");
        p_rsp->status = DSA_SW_UNKNOWN;
        return DA_FAIL;
    }

    if (NULL == psw_info) {
        LOG_ERROR("psw_info is null.");
        p_rsp->status = DSA_SW_UNKNOWN;
        return DA_FAIL;
    }

    p_rsp->status = DA_OK;
    p_rsp->length = len;
    p_rsp->value = psw_info;

    return DA_OK;
}

void get_temp_errors_desc(struct ibnet_error *temp_errors)
{
    if (strstr(temp_errors->desc, "Node has wrong FW version") != NULL) {
        temp_errors->error_code = 1;
        LOG_WARNING("[query_ibnet] Node has wrong FW version");
    } else if (strstr(temp_errors->desc, "Bad link was found in DR") != NULL) {
        temp_errors->error_code = 2; // 2相应的错误码返回
        LOG_WARNING("[query_ibnet] Bad link was found in DR");
    } else if (strstr(temp_errors->desc, "Unexpected actual link speed") != NULL) {
        temp_errors->error_code = 3; // 3相应的错误码返回
        LOG_WARNING("[query_ibnet] Unexpected actual link speed");
    } else if (strstr(temp_errors->desc, "Credit loop found on the following path") != NULL) {
        temp_errors->error_code = 4; // 4相应的错误码返回
        LOG_WARNING("[query_ibnet] Credit loop found on the following path");
    } else {
        temp_errors->error_code = 0;
    }
}

int BackUpIbLog()
{
    char command[COMMAND_BUFSIZE] = { DEFAULT_VALUE };
    char path_name[DSA_DIR_PATH_MAX] = { DEFAULT_VALUE };
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    int ret = snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s",
                         path_name, DSWARE_IB_CHECK_SHELL_NAME, DA_OP_IBNET_LOG_BACKUP);
    if (ret <= 0) {
        LOG_ERROR("shell cmd =%s, error, status is not 0.", command);
        return AGENT_FAIL;
    }

    shell_rsp cmd_rsp_s = { DEFAULT_VALUE };
    shell_operate(command, &cmd_rsp_s, DSA_IB_BACKUP_LOG_TIMEOUT);
    if (DA_OK != cmd_rsp_s.status) {
        LOG_ERROR("ib_log_backup failed");
    }

    LOG_INFO("dsware_agent_query_ibnet_status success");
    return AGENT_SUCCESS;
}

int dsware_agent_query_ibnet_status(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    LOG_INFO("dsware agent start handle dsware_agent_query_ibnet_status request");
    char *inner_ptr = NULL;
    dsw_u8 error_num = DEFAULT_VALUE;
    struct ibnet_error ibnet_errors[IBNET_ERROR_MAX + 1];
    memset_s(ibnet_errors, sizeof(ibnet_errors), 0, sizeof(ibnet_errors));
    if (check_input_para(p_req, p_rsp)) {
        LOG_ERROR("dsware_agent_query_ibnet_status input pointer empty");
        return AGENT_FAIL;
    }

    char command[COMMAND_BUFSIZE] = { DEFAULT_VALUE };
    char path_name[DSA_DIR_PATH_MAX] = { DEFAULT_VALUE };
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    int ret = snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s",
                         path_name, DSWARE_IB_CHECK_SHELL_NAME, DA_OP_QUERY_IBNET_STATUS);
    if (ret <= 0) {
        LOG_ERROR("shell cmd =%s, error, status is not 0.", command);
        return AGENT_FAIL;
    }

    shell_rsp_size_4k cmd_rsp = { DEFAULT_VALUE };
    shell_operate_with_size(command, &cmd_rsp.status, cmd_rsp.value, SHELL_VALUE_LEN_4k, DSA_IB_MONITOR_TIMEOUT);
    if (DA_OK != cmd_rsp.status) {
        LOG_ERROR("dsware_agent_query_ibnet_status failed");
        p_rsp->status = cmd_rsp.status;
        p_rsp->length = 0;
        return AGENT_FAIL;
    }
    // 脚本执行结果格式：result=1;value=-E-
    // Ports counters value Check finished with errors-E-
    // lid=0x0008 dev=51000 Se468a303005527c3/Ne468a303005527c0/P27
    // Performance Monitor counter         : Value
    // port_rcv_switch_relay_errors        : 65535
    // (overflow)-E- lid=0x0008 dev=51000 Se468a303005527c3/Ne468a303005527c0/P31
    // Performance Monitor counter         : Value
    // port_xmit_discard                   : 65535
    // (overflow)@-E- FW Check finished with errors-E-
    // S200bc703001df4bc/U1 - Node has wrong FW version 2.11.1250.
    // Maximum available FW version for this device in the fabric is 2.11.1262@;
    // char testcmd_rsp[1023]="-E-Ports counters value Check finished with errors\n-E-
    // lid=0x0008 dev=51000 Se468a303005527c3/Ne468a303005527c0/P27\n        
    // Performance Monitor counter         : Value     \n        
    // port_rcv_switch_relay_errors        : 65535      
    // (overflow)\n-E-lid=0x0008 dev=51000 Se468a303005527c3/Ne468a303005527c0/P31\n        
    // Performance Monitor counter         : Value     \n        
    // port_xmit_discard                   : 65535      
    // (overflow)@-E-FW Check finished with errors\n-E-S200bc703001df4bc/U1 - Node has wrong FW version 2.11.1250. 
    // Maximum available FW version for this device in the fabric is 2.11.1262@";
    char *info_buf = strtok_r(cmd_rsp.value, "@", &inner_ptr);
    struct ibnet_error temp_errors;
    while (NULL != info_buf) {
        temp_errors.error_code = 0;
        memset_s(temp_errors.desc, BUFSIZE_256, 0, BUFSIZE_256);
        if (sscanf_s(info_buf, "%255[^@]", temp_errors.desc, sizeof(temp_errors.desc)) != 1) {
            LOG_ERROR("analyze shell command result failed");
            return DA_FAIL;
        }

        get_temp_errors_desc(&temp_errors);
        if (temp_errors.error_code != 0) {
            memcpy_s(&ibnet_errors[error_num], sizeof(ibnet_error), &temp_errors, sizeof(ibnet_error));
            error_num++;
        }
        if (IBNET_ERROR_MAX <= error_num) {
            LOG_ERROR("to many errors");
            break;
        }
        info_buf = strtok_r(NULL, "@", &inner_ptr);
    }

    dsw_u32 len = sizeof(struct ibnet_error_api) + sizeof(ibnet_error) * error_num;
    struct ibnet_error_api *ibnet_info = (struct ibnet_error_api *)malloc(len);
    if (NULL == ibnet_info) {
        int errnum = errno;
        DSA_ERRNO_PRINT(errnum);
        LOG_ERROR("malloc failed.");
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        p_rsp->length = DEFAULT_VALUE;
        return DA_ERR_MALLOC_FAIL;
    }
    memset_s(ibnet_info, len, 0, len);

    ibnet_info->error_code_num = error_num;
    p_rsp->length = (uint16_t)(sizeof(struct ibnet_error_api) + sizeof(ibnet_error) * error_num);
    if (error_num > 0) {
        for (int i = 0; i < error_num; i++) {
            ibnet_info->ibnet_errors[i].error_code = (dsw_u8)ibnet_errors[i].error_code;
            strncpy_s((ibnet_info->ibnet_errors[i]).desc, BUFSIZE_256, ibnet_errors[i].desc, BUFSIZE_256 - 1);
            LOG_INFO("IBNET_INFO:error_code is %llu, desc is %s",
                     ibnet_info->ibnet_errors[i].error_code,
                     ibnet_info->ibnet_errors[i].desc);
        }
    }
    /* 为rsp->value分配内存 */
    p_rsp->value = ibnet_info;
    p_rsp->status = DA_OK;

    /* ib日志收集 */
    return BackUpIbLog();
}

#define CHECK_REQ_PARAM_RETURN(p_req, p_rsp, status)      \
    {                                                     \
        if (NULL == (p_req)) {                              \
            LOG_ERROR("input para %s is null", #p_req);   \
            status = DA_ERR_PARA;                         \
            return DA_FAIL;                               \
        } else if (NULL == (p_rsp)) {                       \
            LOG_ERROR("input para (%s) is null", #p_rsp); \
            return DA_FAIL;                               \
        }                                                 \
    }

static void fill_ib_port_info(dsw_net_device_t *ib_net, ib_port_info_t *port_info,
                              ib_card_info_t *card_info, node_ib_info_t *node_info, dsw_u32 port_num)
{
    /* 填充port_info */
    dsw_u32 i = port_num;
    port_info[i].port_guid = ib_net->eth_net_device.port_guid;
    port_info[i].port_lid = atoi((const char *)(ib_net->eth_net_device.lid));
    port_info[i].port_no = ib_net->eth_net_device.port_no;
    port_info[i].storage_net_type = (dsw_u32)ib_net->eth_net_device.storage_net_type;
    memcpy_s(port_info[i].name, IB_MAX_DEV_NAME_LEN, ib_net->eth_net_device.name, IB_MAX_DEV_NAME_LEN);

    /* 填充card_info */
    int j = 0;
    for (; j < node_info->card_num; j++) {
        if (card_info[j].node_guid == ib_net->eth_net_device.node_guid) {
            break;
        }
    }
    if (j == node_info->card_num) { // 未找到，新增
        card_info[j].node_guid = ib_net->eth_net_device.node_guid;
        memcpy_s(card_info[j].ca_name, IB_MAX_CA_NAME_LEN, ib_net->eth_net_device.ca_name, IB_MAX_CA_NAME_LEN);
        node_info->card_num++;
    }
    card_info[j].port_num++;
    LOG_INFO("[IB_QUERY] fill info, port_name:%s, port_no:%u, lid:%u, guid:0x%llx, storage_net_type:%u, "
             "ca_name:%s, card_port_num:%u, card_guid: 0x%llx, port_total: %u, card_total: %u",
             port_info[i].name,
             port_info[i].port_no,
             port_info[i].port_lid,
             port_info[i].port_guid,
             port_info[i].storage_net_type,
             card_info[j].ca_name,
             card_info[j].port_num,
             card_info[j].node_guid,
             port_num + 1,
             node_info->card_num);
    return;
}

int parse_node_ibport_info(char *input_info, ib_port_info_t *port_info, ib_card_info_t *card_info,
    node_ib_info_t *ib_info, dsw_u32 *port_num, dsware_agent_rsp_hdr *p_rsp)
{
    char *info_buf = NULL;
    char *inner_ptr = NULL;
    dsw_u32 tmp_port_num = 0;

    info_buf = strtok_r(input_info, "@", &inner_ptr);
    while (NULL != info_buf) {
        char net_name[16] = {0};
        if (sscanf_s(info_buf, "netdev=%15s", net_name, sizeof(net_name)) != 1) {
            LOG_ERROR("[IB_QUERY] load ib dev info command rsp failed, string=%s", info_buf);
            p_rsp->status = DA_ERR_RUN_SHELL;
            p_rsp->length = DEFAULT_VALUE;
            return AGENT_FAIL;
        }
        int find_flag = 0;
        list_head_t *node = NULL;
        DSW_THREAD_MUTEX_LOCK(&g_eth_dev_chain_lock);
        list_for_each(node, &g_eth_dev_chain) {
            dsw_net_device_t *nd = list_entry(node, dsw_net_device_t, chain);
            if (dsw_strncmp_fsa(net_name, nd->eth_net_device.name, IFNAMSIZ)) {
                continue;
            }
            int lid_num = atoi((const char *)nd->eth_net_device.lid);
            if (IB_PORT_ILLEGAL_PORT == lid_num || 0 == lid_num) {
                LOG_ERROR("[IB_QUERY] ib port lid is illegal, link down, port name: %s", net_name);
                break;
            }
            fill_ib_port_info(nd, port_info, card_info, ib_info, tmp_port_num);
            tmp_port_num++;
            find_flag = 1;
            break;
        }
        DSW_THREAD_MUTEX_UNLOCK(&g_eth_dev_chain_lock);

        if (!find_flag) {
            // 以proc读取的为准,没找到直接打印错误信息即可.
            LOG_ERROR("[IB_QUERY] cannot find ib net dev name: %s", net_name);
        }

        info_buf = strtok_r(NULL, "@", &inner_ptr);
    }

    if (!tmp_port_num) {
        p_rsp->status = DA_ERR_IB_NIC_NOT_EXISTED;
        p_rsp->length = 0;
        LOG_ERROR("[IB_QUERY] query node_ibport_info failed, shell rsp info invalid or node not exist ib card! rsp");
        return AGENT_FAIL;
    }

    *port_num = tmp_port_num;
    return AGENT_SUCCESS;
}

int return_node_ibport_info(ib_port_info_t *port_info, ib_card_info_t *card_info,
    node_ib_info_t *ib_info, dsw_u32 port_num, dsware_agent_rsp_hdr *p_rsp)
{
    /* 构造返回信息 */
    size_t malloc_size = 0;
    malloc_size += sizeof(node_ib_info_t) + sizeof(ib_card_info_t) * ib_info->card_num
                   + port_num * sizeof(ib_port_info_t);
    char *node_info = (char *)DSA_ZMALLOC_SIZE_LIMITED(malloc_size);
    if (!node_info) {
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        p_rsp->length = DEFAULT_VALUE;
        return DA_ERR_MALLOC_FAIL;
    }
    char *start_pos = node_info;
    /* *填充 */
    memcpy_s(start_pos, sizeof(node_ib_info_t), ib_info, sizeof(node_ib_info_t));
    start_pos += sizeof(node_ib_info_t);
    char *port_start = (char *)port_info;
    for (int k = 0; k < ib_info->card_num; k++) {
        if (EOK != memcpy_s(start_pos, sizeof(ib_card_info_t), &card_info[k], sizeof(ib_card_info_t))) {
            LOG_ERROR("[IB_QUERY] memcpy_s failed");
            dsw_free(node_info);
            p_rsp->status = DA_ERR_INNER_ERROR;
            p_rsp->length = DEFAULT_VALUE;
            return AGENT_FAIL;
        }
        start_pos += sizeof(ib_card_info_t);
        size_t port_size = sizeof(ib_port_info_t) * card_info[k].port_num;
        if (memcpy_s(start_pos, port_size, port_start, port_size) != EOK) {
            LOG_ERROR("[IB_QUERY] memcpy_s failed");
            dsw_free(node_info);
            p_rsp->status = DA_ERR_INNER_ERROR;
            p_rsp->length = DEFAULT_VALUE;
            return AGENT_FAIL;
        }
        start_pos += port_size;
        port_start += port_size;
    }
    LOG_DEBUG_DUMP_MEM(node_info, (int)malloc_size);
    p_rsp->status = DA_OK;
    p_rsp->length = (uint32_t)malloc_size;
    p_rsp->value = node_info;
    return AGENT_SUCCESS;
}

/*
* 只查询存储平面的IB端口信息
 */
int dsware_agent_query_node_ibport_info(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    LOG_INFO("[IB_QUERY] dsware dsware_agent_query_node_ibport_info request");

    char command[COMMAND_BUFSIZE];
    shell_rsp cmd_rsp;
    char network_command_script_path[DSA_DIR_PATH_MAX] = { 0 };
    NETWORK_COMMAND_SHELL_FILE(network_command_script_path);
    // 首先重新加载一遍数据
    int change = 0;
    (void)load_ib_dev_info(&change);

    memset_s(command, sizeof(command), 0, sizeof(command));
    memset_s(&cmd_rsp, sizeof(cmd_rsp), 0, sizeof(cmd_rsp));
    int ret = get_shell_excute_script(command, sizeof(command), network_command_script_path, "%s %s",
                                      network_command_script_path, DA_OP_LOAD_IB_LID_INFO);
    if (ret != DA_OK) {
        SUBHEALTH_LOG_ERROR("shell cmd =%s, error, status is not 0.", command);
        return AGENT_FAIL;
    }

    shell_operate(command, &cmd_rsp, SHELL_TIME_OUT_2);
    if (DA_OK != cmd_rsp.status) {
        p_rsp->status = cmd_rsp.status;
        p_rsp->length = 0;
        LOG_ERROR("[IB_QUERY] dsware_agent_query_ibport_info failed, cmd_rsp status %d, value:%s",
                  cmd_rsp.status, cmd_rsp.value);
        return AGENT_FAIL;
    }

    LOG_INFO("[IB_QUERY] query node ib port info cmd rsp value: %s", cmd_rsp.value);
    ib_port_info_t port_info[MAX_LOCAL_IB_ID_NUM];
    ib_card_info_t card_info[MAX_IB_CARD_NUM];
    node_ib_info_t ib_info;
    dsw_u32 port_num = 0;

    memset_s(port_info, sizeof(port_info), 0, sizeof(port_info));
    memset_s(card_info, sizeof(card_info), 0, sizeof(card_info));
    memset_s(&ib_info, sizeof(ib_info), 0, sizeof(ib_info));

    if (parse_node_ibport_info(cmd_rsp.value, port_info, card_info, &ib_info, &port_num, p_rsp) != AGENT_SUCCESS) {
        return AGENT_FAIL;
    }

    return return_node_ibport_info(port_info, card_info, &ib_info, port_num, p_rsp);
}

void CopyIbPortInfo(struct port_stat *outer, struct port_stat *inner, const char *node_guid)
{
    strncpy_s(outer->to_guid, NODE_GUID_LENGTH, inner->to_guid, NODE_GUID_LENGTH - 1);
    outer->no = (dsw_u16) inner->no;
    outer->lid = (dsw_u16) inner->lid;
    outer->state = (dsw_u8) inner->state;
    outer->phy_state = (dsw_u8) inner->phy_state;
    outer->rate = (dsw_u16) inner->rate;
    outer->max_rate = (dsw_u16) inner->max_rate;
    outer->to_lid = (dsw_u32) inner->to_lid;
    outer->to_port_no = (dsw_u32) inner->to_port_no;
    outer->xmit_pkts = (dsw_u64) inner->xmit_pkts;
    outer->rcv_pkts = (dsw_u64) inner->rcv_pkts;
    outer->xmit_discards = (dsw_u64) inner->xmit_discards;
    outer->rcv_errors = (dsw_u64) inner->rcv_errors;
    outer->SymbolErrorCounter = (dsw_u64) inner->SymbolErrorCounter;

    LOG_INFO("IBPORT_INFO:guid is %s,to_guid is %s, no is %hu, lid is %hu, stat is %hhu, phy_stat is %hhu, rate %hu, "
             "max_rate is %hu to_lid is %hu, to_port_no is %hu, xmit_pkts is %llu, rcv_pkts is %llu, "
             "xmit_discards is %llu, rcv_errors is %llu, SymbolErrorCounter %llu",
             node_guid, outer->to_guid, outer->no, outer->lid, outer->state, outer->phy_state,
             outer->rate, outer->max_rate, outer->to_lid, outer->to_port_no, outer->xmit_pkts,
             outer->rcv_pkts, outer->xmit_discards, outer->rcv_errors, outer->SymbolErrorCounter);
}

int dsware_agent_query_ibport_status(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    LOG_INFO("dsware agent start handle dsware_agent_query_ibport_status request");
    char *inner_ptr = NULL;
    char this_node_guid[DSA_IB_GUID_LEN] = { 0 };
    dsw_u16 ibport_info_num = DEFAULT_VALUE;
    struct port_stat ibport_infos[IBPORT_INFO_MAX + 1];
    memset_s(ibport_infos, sizeof(ibport_infos), 0, sizeof(ibport_infos));
    if (check_input_para(p_req, p_rsp)) {
        LOG_ERROR("dsware_agent_query_ibport_status input pointer empty");
        return AGENT_FAIL;
    }

    char command[COMMAND_BUFSIZE] = { DEFAULT_VALUE };
    shell_rsp cmd_rsp = { DEFAULT_VALUE };
    char path_name[DSA_DIR_PATH_MAX] = { 0 };
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s",
               path_name, DSWARE_IB_CHECK_SHELL_NAME, DA_OP_QUERY_IBPORT_STATUS);
    shell_operate(command, &cmd_rsp, DSA_IB_MONITOR_TIMEOUT);
    if (DA_OK != cmd_rsp.status) {
        LOG_ERROR("dsware_agent_query_ibport_status failed");
        p_rsp->status = cmd_rsp.status;
        p_rsp->length = 0;
        return AGENT_FAIL;
    }

    char *info_buf = strtok_r(cmd_rsp.value, "@", &inner_ptr);
    struct port_stat temp_ibport_info;
    while (NULL != info_buf) {
        int ret = sscanf_s(info_buf,
                           "guid=%18[^,],port_no=%10hu,to_guid=%18[^,],Base_lid=%10hu,State=%10hhu,Physical_state=%10hhu,Rate=%10hu,Current_rate=%10hu,to_lid=%10hu,to_port=%10hu,PortXmitPkts=%31llu,PortRcvPkts=%31llu,PortXmitDiscards=%31llu,PortRcvErrors=%31llu,SymbolErrorCounter=%31llu",
                           this_node_guid, DSA_IB_GUID_LEN, &(temp_ibport_info.no),
                           temp_ibport_info.to_guid, DSA_IB_GUID_LEN, &(temp_ibport_info.lid),
                           &(temp_ibport_info.state),
                           &(temp_ibport_info.phy_state), &(temp_ibport_info.max_rate), &(temp_ibport_info.rate),
                           &(temp_ibport_info.to_lid),
                           &(temp_ibport_info.to_port_no), &(temp_ibport_info.xmit_pkts), &(temp_ibport_info.rcv_pkts),
                           &(temp_ibport_info.xmit_discards), &(temp_ibport_info.rcv_errors),
                           &(temp_ibport_info.SymbolErrorCounter));
        if (ret != BUFSIZE_15) { // 15表示当前有15个变量进行赋值
            LOG_ERROR("analyze shell command rsp failed return string=%s ret=%d", cmd_rsp.value, ret);
            return DA_ERR_INNER_ERROR;
        }
        memcpy_s(&ibport_infos[ibport_info_num], sizeof(port_stat), &temp_ibport_info, sizeof(port_stat));
        ibport_info_num++;
        if (IBPORT_INFO_MAX <= ibport_info_num) {
            LOG_ERROR("to many ports");
            break;
        }
        info_buf = strtok_r(NULL, "@", &inner_ptr);
    }

    struct ib_port_stat *ibport_info_apis = (struct ib_port_stat *)malloc(sizeof(struct ib_port_stat) + sizeof(struct port_stat) * ibport_info_num);
    if (NULL == ibport_info_apis) {
        int errnum = errno;
        DSA_ERRNO_PRINT(errnum);
        LOG_ERROR("malloc failed.");
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        p_rsp->length = DEFAULT_VALUE;
        return DA_ERR_MALLOC_FAIL;
    }
    strncpy_s(ibport_info_apis->node_guid, NODE_GUID_LENGTH, this_node_guid, NODE_GUID_LENGTH - 1);
    ibport_info_apis->num = (dsw_u16)ibport_info_num;
    if (ibport_info_num > 0) {
        for (int i = 0; i < ibport_info_num; i++) {
            CopyIbPortInfo(&(ibport_info_apis->port_stats[i]), &(ibport_infos[i]), ibport_info_apis->node_guid);
        }
    }
    p_rsp->length = (uint16_t)(sizeof(struct ib_port_stat) + sizeof(port_stat) * ibport_info_num);
    p_rsp->value = ibport_info_apis;
    p_rsp->status = DA_OK;
    LOG_INFO("dsware_agent_query_ibport_status success");
    return AGENT_SUCCESS;
}

int scanf_port_info_query_all_ibport_status(const char *port_info, port_stat *local_port_stat,
        char *adapter_guid, shell_rsp_size_8k *cmd_rsp)
{
    int ret = 0;
    ret = sscanf_s(port_info,
                   "guid=%18[^,],port_no=%10hu,to_guid=%18[^,],Base_lid=%10hu,State=%10hhu,Physical_state=%10hhu,"
                   "Rate=%10hu,Current_rate=%10hu,to_lid=%10hu,to_port=%10hu,PortXmitPkts=%31llu,PortRcvPkts=%31llu,"
                   "PortXmitDiscards=%31llu,PortRcvErrors=%31llu,SymbolErrorCounter=%31llu",
                   adapter_guid, DSA_IB_GUID_LEN, &(local_port_stat->no),
                   local_port_stat->to_guid, DSA_IB_GUID_LEN, &(local_port_stat->lid), &(local_port_stat->state),
                   &(local_port_stat->phy_state), &(local_port_stat->max_rate), &(local_port_stat->rate), &(local_port_stat->to_lid),
                   &(local_port_stat->to_port_no), &(local_port_stat->xmit_pkts), &(local_port_stat->rcv_pkts),
                   &(local_port_stat->xmit_discards), &(local_port_stat->rcv_errors), &(local_port_stat->SymbolErrorCounter));
    if (ret != 15) { // 15表示当前有15个变量进行赋值
        LOG_ERROR("analyze shell command rsp failed return string=%s ret=%d", cmd_rsp->value, ret);
        return DA_ERR_INNER_ERROR;
    }

    LOG_INFO("IBPORT_INFO:guid is %s,to_guid is %s, no is %hu, lid is %hu, stat is %hhu, phy_stat is %hhu, rate %hu, "
             "max_rate is %hu to_lid is %hu, to_port_no is %hu, xmit_pkts is %llu, rcv_pkts is %llu, "
             "xmit_discards is %llu, rcv_errors is %llu, SymbolErrorCounter %llu",
             adapter_guid,
             local_port_stat->to_guid,
             local_port_stat->no,
             local_port_stat->lid,
             local_port_stat->state,
             local_port_stat->phy_state,
             local_port_stat->rate,
             local_port_stat->max_rate,
             local_port_stat->to_lid,
             local_port_stat->to_port_no,
             local_port_stat->xmit_pkts,
             local_port_stat->rcv_pkts,
             local_port_stat->xmit_discards,
             local_port_stat->rcv_errors,
             local_port_stat->SymbolErrorCounter);
    return DA_OK;
}

static int sub_func_query_all_ipport_status(dsw_u16 *adapter_cnt, shell_rsp_size_8k *cmd_rsp,
        dsware_agent_rsp_hdr *p_rsp, char **port_info, dsw_u16 *port_cnt_array, dsw_u16 *total_port_cnt)
{
    if (1 != sscanf_s(cmd_rsp->value, "%hu", adapter_cnt) || 0 == *adapter_cnt) {
        LOG_ERROR("Invalid adatper cnt, value=%s", cmd_rsp->value);
        return DA_ERR_INNER_ERROR;
    }
    *adapter_cnt = (*adapter_cnt) > IB_ADAPTER_MAX ? IB_ADAPTER_MAX : (*adapter_cnt);
    LOG_INFO("total %u IB adapters", *adapter_cnt);

    dsw_u16 index = 0;
    char *port_cnt_pos = NULL;
    char *rest_pos = NULL;
    port_cnt_pos = strtok_r(cmd_rsp->value, "#", &rest_pos);
    if (NULL == port_cnt_pos) {
        p_rsp->status = DA_ERR_INNER_ERROR;
        LOG_ERROR("Invalid ib port info, value=%s", cmd_rsp->value);
        return DA_ERR_INNER_ERROR;
    }

    port_cnt_pos = strtok_r(rest_pos, "#", &rest_pos); /* 跳过adapter_cnt */
    while (NULL != port_cnt_pos && index < *adapter_cnt) {
        dsw_u16 port_cnt;
        if (1 != sscanf_s(port_cnt_pos, "%hu", &port_cnt)) {
            LOG_ERROR("get port_cnt for adapter %u fail", index);
            return DA_ERR_INNER_ERROR;
        }
        LOG_INFO("port of adapter %u is %u", index + 1, port_cnt);
        port_cnt_array[index] = port_cnt;
        (*total_port_cnt) += port_cnt;
        *port_info = port_cnt_pos; /* 保存下来给后面获取每个port信息使用 */
        port_cnt_pos = strtok_r(rest_pos, "#", &rest_pos);
        index++;
    }
    if (index != *adapter_cnt) {
        LOG_ERROR("port_cnt array size is not same with adapter count , index:%u adapter_cnt:%u", index, *adapter_cnt);
        return DA_ERR_INNER_ERROR;
    }
    return DA_OK;
}

int ConstructQueryIbStatusResp(dsware_agent_rsp_hdr *p_rsp, dsw_u16 port_index, dsw_u16 total_port_cnt,
                               port_stat_array *port_array, size_t sz)
{
    if (port_index != total_port_cnt) {
        LOG_ERROR("port info array size is not same with total_port_cnt, port_index:%u  total_port_cnt:%u", port_index,
                  total_port_cnt);
        return DA_ERR_INNER_ERROR;
    }

    p_rsp->length = (uint16_t) (sz);
    p_rsp->value = port_array;
    p_rsp->status = DA_OK;
    LOG_INFO("dsware_agent_query_ibport_status success");
    return AGENT_SUCCESS;
}

int dsware_agent_query_all_ibport_status(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    LOG_INFO("dsware agent start handle dsware_agent_query_all_ibport_status request");
    CHECK_REQ_PARAM_RETURN(p_req, p_rsp, p_rsp->status);

    char command[COMMAND_BUFSIZE] = { DEFAULT_VALUE };
    shell_rsp_size_8k cmd_rsp = { DEFAULT_VALUE };
    char path_name[DSA_DIR_PATH_MAX] = { DEFAULT_VALUE };
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s",
               path_name, DSWARE_IB_CHECK_SHELL_NAME, DA_OP_QUERY_ALL_IBPORT_STATUS);
    shell_operate_with_size(command, &cmd_rsp.status, cmd_rsp.value, BUFSIZE_8192, DSA_IB_MONITOR_TIMEOUT);
    if (DA_OK != cmd_rsp.status) {
        LOG_ERROR("dsware_agent_query_ibport_status failed");
        p_rsp->status = cmd_rsp.status;
        p_rsp->length = 0;
        return AGENT_FAIL;
    }

    dsw_u16 adapter_cnt = 0;
    char *port_info = NULL;
    dsw_u16 port_cnt_array[IB_ADAPTER_MAX] = { 0 };
    dsw_u16 total_port_cnt = 0;
    char *rest_pos = NULL;
    int ret = sub_func_query_all_ipport_status(&adapter_cnt, &cmd_rsp, p_rsp, &port_info,
        (dsw_u16*)&port_cnt_array, &total_port_cnt);
    if (ret != DA_OK) {
        return ret;
    }

    size_t sz = sizeof(port_stat_array) + total_port_cnt * sizeof(port_stat) + adapter_cnt * sizeof(ib_port_stat);
    port_stat_array *port_array = (port_stat_array *)DSA_ZMALLOC_SIZE_LIMITED(sz);
    if (NULL == port_array) {
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        p_rsp->length = DEFAULT_VALUE;
        return DA_ERR_MALLOC_FAIL;
    }
    port_array->num = adapter_cnt;
    port_array->type = IB_PORT;

    dsw_u16 adapter_index = 0;  // adapter_index
    dsw_u16 port_index = 0;
    dsw_u16 dealed_adapter_port_cnt = 0;
    dsw_u16 local_port_index = 0;  // 当前adatper的port编号
    char adapter_guid[DSA_IB_GUID_LEN] = { 0 };
    port_info = strtok_r(port_info, "@", &rest_pos);
    port_info = strtok_r(rest_pos, "@", &rest_pos);
    ib_port_stat *dealing_ib_port_stat = (ib_port_stat *)((unsigned char *)port_array + sizeof(port_stat_array));
    while (NULL != port_info && port_index < total_port_cnt) {
        port_stat *local_port_stat = dealing_ib_port_stat->port_stats + local_port_index;

        ret = scanf_port_info_query_all_ibport_status(port_info, local_port_stat, (char*)&adapter_guid, &cmd_rsp);
        if (ret != DA_OK) {
            free(port_array);
            return ret;
        }

        if ((port_cnt_array[adapter_index] - 1) == local_port_index) {
            local_port_index = 0;
            dealed_adapter_port_cnt += port_cnt_array[adapter_index];
            dealing_ib_port_stat->num = port_cnt_array[adapter_index];
            strncpy_s(dealing_ib_port_stat->node_guid, NODE_GUID_LENGTH, adapter_guid, NODE_GUID_LENGTH - 1);
            adapter_index++;
            dealing_ib_port_stat = (ib_port_stat *)((unsigned char *)port_array + sizeof(port_stat_array) + adapter_index *
                                                    sizeof(ib_port_stat)
                                                    + dealed_adapter_port_cnt * sizeof(port_stat));
        } else {
            local_port_index++;
        }
        port_index++;
        port_info = strtok_r(rest_pos, "@", &rest_pos);
    }

    if (ConstructQueryIbStatusResp(p_rsp, port_index, total_port_cnt, port_array, sz) != AGENT_SUCCESS) {
        free(port_array);
        return DA_ERR_INNER_ERROR;
    }
    return AGENT_SUCCESS;
}



