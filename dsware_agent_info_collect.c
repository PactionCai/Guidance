/*************************************************
  Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
  File name:    dsware_agent_info_collect.c
  Author: x00369893
  Version:
  Date: 2019-07-11
  Description:  nvdimm detect
*************************************************/
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "kmca.h"
#include "../utility/agent_op_log.h"
#include "../utility/str_util.h"
#include "../utility/mem_util.h"
#include "agent_process_monitor.h"
#include "../config/dsware_agent_conf.h"
#include "cJSON.h"
#include "osax/dpax_virtual.h"
#include "../interface/dswareAgent_interface.h"
#include "../interface/dsware_agent_info_collect.h"
#include "../interface/dsware_agent_analyze_req_hdr.h"
#include "../interface/dsware_agent_shell_helper.h"
#include "../interface/devmon_agent.h"
#include "../openssl/dsware_openssl_handle.h"
#include "dsware_kmc_api.h"
#include "../monitor/dsware_agent_timer_zk.h"
#include "util_common.h"

extern int g_log_print;
extern pthread_mutex_t g_log_print_lock;
extern ssize_t do_write(int fd, void *p_buf, size_t len);

#define DSA_MANAGER_TYPE_QUERY_LFTP_USER_PW 0x4001
typedef struct bakup_metadata_path {
    char *back_path;
}bakup_metadata_para_t;


int ReturnDumpMemoryResult(dsware_agent_rsp_hdr *rsp)
{
    dsw_u32 length = sizeof(dsw_memory_info_t);
    char *p_buff_rsp = malloc(length);
    if (NULL == p_buff_rsp) {
        int errnum = errno;
        DSA_ERRNO_PRINT(errnum);
        LOG_ERROR("malloc temp_disk_info failed.");
        rsp->status = DA_ERR_MALLOC_FAIL;
        return DA_ERR_MALLOC_FAIL;
    }
    memset_s(p_buff_rsp, length, DEFAULT_VALUE, length);
    strncpy_s(((dsw_memory_info_t *)p_buff_rsp)->filename, MAX_PATH_FILE_LEN, MEMORY_INFO_FSA_LOG,
              MAX_PATH_FILE_LEN - 1);

    rsp->length = length;
    rsp->value = p_buff_rsp;
    rsp->status = DA_OK;

    LOG_INFO("dsware_agent_dump_memory_info end");
    return DA_OK;
}

/*************************************************
  Function:         dsware_agent_dump_memory_info
  Description: Description
  Input:
        req:  client request
  Output:
        rsp:  client response
  Return:
         0:sucess
         1:failed
  Others: Others
*************************************************/
int dsware_agent_dump_memory_info(dsware_agent_req_hdr *req, dsware_agent_rsp_hdr *rsp)
{
    int errnum = 0;
    LOG_INFO("dsware_agent_dump_memory_info start");
    /* 参数合法性检查 */
    if (NULL == rsp) {
        LOG_ERROR("rsp is NULL, failed.");
        return DA_ERR_PARA;
    }

    // mkdir
    if (mkdir(MEMORY_INFO_FSA_LOG_PATH, 0750) == -1 && (errno != EEXIST)) { // 0750表示权限
        errnum = errno;
        DSA_ERRNO_PRINT(errnum);
        LOG_ERROR("Failed to create directory [ %s].", MEMORY_INFO_FSA_LOG_PATH);
        rsp->status = DA_ERR_WRITE_DSWARE_FILE;
        return DA_ERR_WRITE_DSWARE_FILE;
    }

    mode_t old_mask = umask(077); // 077表示权限
    FILE *out = fopen(MEMORY_INFO_FSA_LOG, "aw+");
    umask(old_mask);  // set old mask
    if (NULL == out) {
        errnum = errno;
        DSA_ERRNO_PRINT(errnum);
        LOG_ERROR("fopen file failed.");
        rsp->status = DA_ERR_OPEN_FILE;
        return DA_ERR_OPEN_FILE;
    }

    if (0 != fseek(out, 0L, SEEK_END)) {
        errnum = errno;
        DSA_ERRNO_PRINT(errnum);
        LOG_ERROR("fseek file failed.");
        fclose(out);
        out = NULL;
        rsp->status = DA_ERR_WRITE_DSWARE_FILE;
        return DA_ERR_WRITE_DSWARE_FILE;
    }

    int ret = dump_monitor_info_to_file(out);
    if (0 != ret) {
        fclose(out);
        out = NULL;
        LOG_ERROR("dump_monitor_info_to_buff failed. ret=%d", ret);
        rsp->status = ret;
        return ret;
    }

    if (DEFAULT_VALUE != fclose(out)) {
        out = NULL;
        errnum = errno;
        DSA_ERRNO_PRINT(errnum);
        LOG_ERROR("fclose file failed.");
        rsp->status = DA_ERR_WRITE_DSWARE_FILE;
        return DA_ERR_WRITE_DSWARE_FILE;
    }
    out = NULL;

    /* 构造响应消息 */
    return ReturnDumpMemoryResult(rsp);
}

/*************************************************
 Function:        get_rsa_switch

 Description:     获取公司要登陆开关
 Input: Input
 Output: Output
 Return: 开关值
 Others: Others
*************************************************/
int get_rsa_switch(void)
{
    char *buf = NULL;
    int rsa_status = 0;
    char pmi_file_name[DSA_DIR_PATH_MAX] = {0};
    PMI_CONFIG_FILE(pmi_file_name);
    // 从配置文件中读取信息收集公私钥登录开关
    // 如果使用公私钥登录，则获取私钥密密码，否则认为非公私钥登录
    if (DSWARE_AGENT_OK != get_conf_var(pmi_file_name, RSA_SWITCH, &buf)) {
        LOG_ERROR("Failed to get rsa switch from %s", pmi_file_name);
        // 获取公私钥开关失败，则认为是非公私钥登录
        rsa_status = 1;
    } else {
        // 设置公私钥开关
        rsa_status = atoi(buf);
        // 校验，如果配置文件开关被人为修改错误（非0或1），则默认走安全通道，及DSA通道
        if (rsa_status != 0) {
            rsa_status = 1;
        }
    }

    /* 释放buf空间 */
    FREE(buf);
    return rsa_status;
}

void CollectAgentFile(dsware_agent_rsp_hdr *p_rsp, const char *fsmIp, const char *dswareFtp, const char *reg,
                     const char *src, const char *dst, const char *ftpDswarePasswd, uint8_t version)
{
    int rsa_status;
    char *buf = NULL;
    int ret = 0;
    char pmi_file_name[DSA_DIR_PATH_MAX] = {0};
    PMI_CONFIG_FILE(pmi_file_name);
    // 从配置文件中读取信息收集公私钥登录开关
    // 如果使用公私钥登录，则获取私钥密密码，否则认为非公私钥登录
    if (DSWARE_AGENT_OK != get_conf_var(pmi_file_name, RSA_SWITCH, &buf)) {
        LOG_ERROR("Failed to get rsa switch from %s", pmi_file_name);
        // 获取公私钥开关失败，则认为是非公私钥登录
        rsa_status = 1;
    } else {
        // 设置公私钥开关
        rsa_status = atoi(buf);
        // 校验，如果配置文件开关被人为修改错误（非0或1），则默认走安全通道，及DSA通道
        if (rsa_status != 0) {
            rsa_status = 1;
        }
    }

    FREE(buf);
    char path_name[DSA_DIR_PATH_MAX] = {0};
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    char command[BUFSIZE_1024] = {0};
    char param[BUFSIZE_1024] = {0};
    // 如果rsa_status的值为1，则认为是公私钥登录，如果是0，则认为是账户密码登录
    if (1 == rsa_status) {
        shell_rsp temp_cmd_rsp = {0};
        if (DSWARE_AGENT_OK != agent_info_collect_way_analysis(&temp_cmd_rsp)) {
            LOG_ERROR("get rsa passwordphrase failed.");
            return;
        }

        ret = snprintf_s(command, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s%s %s %s %s '%s' '%s' '%s' %d", path_name,
                         DSWARE_SHELL_NAME, AGENT_FILE_COLLECT, fsmIp, dswareFtp, reg, src, dst, version);
        if (ret <= 0) {
            LOG_ERROR("snprintf_s failed.");
            return;
        }
        ret = snprintf_s(param, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s@@@%s", ftpDswarePasswd, temp_cmd_rsp.value);
        if (ret <= 0) {
            LOG_ERROR("snprintf_s failed.");
            return;
        }
        // 安全问题，变量赋值后需要memset清零
        memset_s(&temp_cmd_rsp, sizeof(shell_rsp), 0, sizeof(shell_rsp));
    } else {
        ret = snprintf_s(command, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s%s %s %s %s '%s' '%s' '%s' %d", path_name,
                         DSWARE_SHELL_NAME, AGENT_FILE_COLLECT, fsmIp, dswareFtp, reg, src, dst, version);
        if (ret <= 0) {
            LOG_ERROR("snprintf_s failed.");
            return;
        }
        ret = snprintf_s(param, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s", ftpDswarePasswd);
        if (ret <= 0) {
            LOG_ERROR("snprintf_s failed.");
            return;
        }
    }

    shell_rsp cmd_rsp = {0};
    shell_operate_with_private_param(command, &cmd_rsp, SHELL_TIME_OUT, param,
                                     strnlen(param, BUFSIZE_1024));

    // 安全问题，变量赋值后需要memset清零
    memset_s(param, sizeof(param), 0, sizeof(param));

    if (DA_OK != cmd_rsp.status) {
        p_rsp->status = cmd_rsp.status;
        p_rsp->length = 0;
        return;
    }
    p_rsp->status = DA_OK;
    p_rsp->length = 0;
}

/****************************************************************************
  Description   :   verify the register string which parse from collect file request
  Input         :   p_reg   -   the register string to be verified
  Output        :   none
  Return        :   DA_OK on success, others on failure
  Note          :   none
 ****************************************************************************/
static int verify_reg_in_collect_file_req(const char *p_reg)
{
    if (p_reg == NULL || strlen(p_reg) == 0) {
        LOG_ERROR("null reg to be verified");
        return DA_FAIL;
    }
    const char regex_strs[][BUFSIZE_128] = {"fs_manual_backup_metadata_", "dsware_autoback"};

    /* verify reg */
    for (int i = 0; i < sizeof(regex_strs) / sizeof(regex_strs[0]); ++i) {
        /* found the allowed reg */
        if (strstr(p_reg, regex_strs[i]) != NULL) {
            return DA_OK;
        }
    }
    LOG_ERROR("invalid reg %s not match allowed reg", p_reg);
    return DA_FAIL;
}

static struct bakup_metadata_path backup_metadata_paths[] = {
    {"/opt/fusionstorage/persistence_layer/agent/zk/data/mdcMetadataBackup/"},
    {"/opt/dsware/vbs/backup/"},
    {"/opt/dsware/vfs/vfs_metadata_backup/"},
    {"/opt/dsware/ccdb/ccdb_metadata_backup/"},
    {"/opt/dsware/zk/zk_metadata_backup/"},
    {"/opt/dsware/ccdbx/ccdbx_metadata_backup/"},
};

/****************************************************************************
  Description   :   verify the metadata path which parse from collect file request
  Input         :   p_reg   -   the metadata path to be verified
  Output        :   none
  Return        :   DA_OK on success, others on failure
  Note          :   none
 ****************************************************************************/
static int verify_metadata_path_in_collect_file_req(const char *p_metadata_path)
{
    if (p_metadata_path == NULL || strlen(p_metadata_path) == 0) {
        LOG_ERROR("null metadata path to be verified");
        return DA_FAIL;
    }

    char metadata_paths[6][DSA_DIR_PATH_MAX] = {{0}, {0}, {0}, {0}, {0}, {0}};
    for (int j = 0; j < sizeof(backup_metadata_paths) / sizeof(backup_metadata_paths[0]); ++j) {
        int ret = sprintf_s(metadata_paths[j], DSA_DIR_PATH_MAX, "%s", backup_metadata_paths[j].back_path);
        if (ret <= 0) {
            LOG_ERROR("snprintf_s failed");
            return DA_FAIL;
        }
    }

    /* verity src path */
    for (int i = 0; i < sizeof(metadata_paths) / sizeof(metadata_paths[0]); ++i) {
        /* found the allowed path */
        if (strcmp(p_metadata_path, metadata_paths[i]) == 0) {
            return DA_OK;
        }
    }
    LOG_ERROR("invalid src %s not match allowed path", p_metadata_path);
    return DA_FAIL;
}

/*************************************************
  Function:        agent_file_collect
  Description:    信息收集
  Input:
         dsware_agent_req_hdr:  manager request hdr
  Output:
         dsware_agent_rsp_hdr:  respond to manager
  Return:
         DA_OK:     sucess
         DA_FAIL:   failed
  Others: Others
*************************************************/
int agent_file_collect(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    DA_CHECK_NULL_RETURN_ERR_PARA(p_req, "p_req");
    DA_CHECK_NULL_RETURN_ERR_PARA(p_rsp, "p_rsp");
    LOG_INFO("agent_log_collect start");

    if (NULL == p_req->value) {
        LOG_ERROR("invalid req no msg");
        p_rsp->status = DA_ERR_PARA;
        return DA_FAIL;
    }

    cJSON *pJson = cJSON_Parse(p_req->value);
    if (NULL == pJson) {
        LOG_ERROR("malloc pJson failed");
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        p_rsp->length = 0;
        return DA_ERR_MALLOC_FAIL;
    }

    p_rsp->status = DA_ERR_PARA;
    p_rsp->length = 0;

    cJSON *fsmIp = cJSON_GetObjectItem(pJson, "fsmIp");
    CHECK_JSON_STRING(fsmIp, pJson);
    cJSON *ftpDswarePasswd = cJSON_GetObjectItem(pJson, "ftpDswarePasswd");
    CHECK_JSON_STRING(ftpDswarePasswd, pJson);
    size_t pwd_len = strlen(ftpDswarePasswd->valuestring);
    cJSON *ftp_dsware = cJSON_GetObjectItem(pJson, "ftp_dsware");
    CHECK_JSON_STRING(ftp_dsware, pJson);
    cJSON *reg = cJSON_GetObjectItem(pJson, "reg");
    CHECK_JSON_STRING(reg, pJson);
    cJSON *src = cJSON_GetObjectItem(pJson, "src");
    CHECK_JSON_STRING(src, pJson);
    cJSON *dst = cJSON_GetObjectItem(pJson, "dst");
    CHECK_JSON_STRING(dst, pJson);

    /* verity fsmIP */
    if (0 != strcmp(fsmIp->valuestring, g_agent_sys_val.manager_ip) &&
        NULL == get_vbs_cluster_info_by_manager_ip(fsmIp->valuestring)) {
        p_rsp->status = DA_ERR_PARA;
        LOG_ERROR("invalid fsmip %s", fsmIp->valuestring);
        MEM_ERASE(ftpDswarePasswd->valuestring, pwd_len, SAFE_ERASE_TIMES);
        cJSON_Delete(pJson);
        return DA_FAIL;
    }

    /* verify reg */
    if (verify_reg_in_collect_file_req(reg->valuestring) != DA_OK) {
        p_rsp->status = DA_ERR_PARA;
        LOG_ERROR("invalid reg %s not match allowed reg", reg->valuestring);
        MEM_ERASE(ftpDswarePasswd->valuestring, pwd_len, SAFE_ERASE_TIMES);
        cJSON_Delete(pJson);
        return DA_FAIL;
    }

    /* verity src path */
    if (verify_metadata_path_in_collect_file_req(src->valuestring) != DA_OK) {
        p_rsp->status = DA_ERR_PARA;
        LOG_ERROR("invalid src %s not match allowed path", src->valuestring);
        MEM_ERASE(ftpDswarePasswd->valuestring, pwd_len, SAFE_ERASE_TIMES);
        cJSON_Delete(pJson);
        return DA_FAIL;
    }

    CollectAgentFile(p_rsp, fsmIp->valuestring, ftp_dsware->valuestring, reg->valuestring, src->valuestring,
                     dst->valuestring, ftpDswarePasswd->valuestring, p_req->version);
    MEM_ERASE(ftpDswarePasswd->valuestring, pwd_len, SAFE_ERASE_TIMES);
    cJSON_Delete(pJson);
    LOG_INFO("agent_file_collect end,status=%d", p_rsp->status);
    return DA_OK;
}

/*************************************************
  Function:        agent_get_backup_from_fsm
  Description:    从fsm节点获取fsm的备份文件
  Input:
         dsware_agent_req_hdr:  manager request hdr
  Output:
         dsware_agent_rsp_hdr:  respond to manager
  Return:
         DA_OK:     sucess
         DA_FAIL:   failed
  Others: Others
*************************************************/
 
int agent_get_backup_from_fsm (dsware_agent_req_hdr * p_req, dsware_agent_rsp_hdr * p_rsp)
{
    LOG_INFO("agent_get_backup_from_fsm start");
    if (NULL == p_req || NULL == p_rsp || NULL == p_req->value) {
        LOG_ERROR("parameter is invalid");
        return DA_ERR_PARA;
    }
 
    char command[BUFSIZE_1024] = { 0 };
    char param[BUFSIZE_1024] = { 0 };
 
    char metadata_paths[2][DSA_DIR_PATH_MAX] = {{0}, {0}};
    snprintf_s(metadata_paths[0], DSA_DIR_PATH_MAX, DSA_DIR_PATH_MAX - 1, "%s", "/manager_metadata/");
    snprintf_s(metadata_paths[1], DSA_DIR_PATH_MAX, DSA_DIR_PATH_MAX - 1, "%s", "/");
    
    int metadata_paths_size = sizeof(metadata_paths) / PATH_LENGTH;
    int i = 0;
 
    if (NULL == p_req->value) {
        LOG_ERROR("invalid req no msg");
        p_rsp->status = DA_ERR_PARA;
        return DA_FAIL;
    }
 
    cJSON * pJson = cJSON_Parse(p_req->value);
    if (NULL == pJson) {
        LOG_ERROR("malloc pJson failed");
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        p_rsp->length = 0;
        return DA_ERR_MALLOC_FAIL;
    }
 
    p_rsp->status = DA_ERR_PARA;
    p_rsp->length = 0;
 
    cJSON * fsmIp = cJSON_GetObjectItem(pJson, "fsmIp");
    CHECK_JSON_STRING(fsmIp, pJson);
    cJSON * ftpDswarePasswd = cJSON_GetObjectItem(pJson, "ftpDswarePasswd");
    CHECK_JSON_STRING(ftpDswarePasswd, pJson);
    size_t pwd_len = strlen(ftpDswarePasswd->valuestring);
    cJSON * ftp_dsware = cJSON_GetObjectItem(pJson, "ftp_dsware");
    CHECK_JSON_STRING(ftp_dsware, pJson);
    cJSON * file_name = cJSON_GetObjectItem(pJson, "fileName");
    CHECK_JSON_STRING(file_name, pJson);
    cJSON * src = cJSON_GetObjectItem(pJson, "src");
    CHECK_JSON_STRING(src, pJson);
    cJSON * dst = cJSON_GetObjectItem(pJson, "dst");
    CHECK_JSON_STRING(dst, pJson);
 
    /* verity fsmIP */ 
    if (0 != strcmp(fsmIp->valuestring, g_agent_sys_val.manager_ip) &&
        NULL == get_vbs_cluster_info_by_manager_ip(fsmIp->valuestring)) {
        p_rsp->status = DA_ERR_PARA;
        LOG_ERROR("invalid fsmip %s", fsmIp->valuestring);
        MEM_ERASE(ftpDswarePasswd->valuestring, pwd_len, SAFE_ERASE_TIMES);
        cJSON_Delete(pJson);
        return DA_FAIL;
    }
 
    /* verity src path */ 
    for (i = 0; i < metadata_paths_size; i++) {
        /* found the allowed path */
        if (0 != strncmp(src->valuestring, metadata_paths[i], sizeof(metadata_paths[i]))) {
            break;
        }
    }
 
    /* not found the allowed path */
    if (i == metadata_paths_size) {
        p_rsp->status = DA_ERR_PARA;
        LOG_ERROR("invalid src %s not match allowed path", src->valuestring);
        MEM_ERASE(ftpDswarePasswd->valuestring, pwd_len, SAFE_ERASE_TIMES);
        cJSON_Delete(pJson);
        return DA_FAIL;
    }

    char path_name[DSA_DIR_PATH_MAX] = {0};
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));

    snprintf_s(command, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s%s %s %s %s '%s' '%s' '%s'",
               path_name, DSWARE_SHELL_NAME, GET_FSM_BACKUP_FILE, fsmIp->valuestring,
               ftp_dsware->valuestring, file_name->valuestring, src->valuestring, dst->valuestring);
    snprintf_s(param, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s", ftpDswarePasswd->valuestring);
    MEM_ERASE(ftpDswarePasswd->valuestring, pwd_len, SAFE_ERASE_TIMES);
    cJSON_Delete(pJson);
    shell_rsp cmd_rsp = {0};
    shell_operate_with_private_param(command, &cmd_rsp, SHELL_TIME_OUT, param,
                                     strnlen(param, BUFSIZE_1024));

    p_rsp->status = cmd_rsp.status;
    p_rsp->length = 0;
    LOG_INFO("agent_get_backup_from_fsm end,status=%d", p_rsp->status);
    return cmd_rsp.status;
}

/*************************************************
  Function:        agent_file_collect
  Description:    信息收集
  Input:
         dsware_agent_req_hdr:  manager request hdr
  Output:
         dsware_agent_rsp_hdr:  respond to manager
  Return:
         DA_OK:     sucess
         DA_FAIL:   failed
  Others: Others
*************************************************/
int agent_view_log_collect(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    LOG_DEBUG("agent_log_collect start");
    char command[BUFSIZE_1024] = {0};
    char param[BUFSIZE_1024] = {0};
    int rsa_status;

    if (NULL == p_req || NULL == p_rsp || NULL == p_req->value) {
        LOG_ERROR("parameter is invalid");
        return DA_ERR_PARA;
    }
    cJSON *pJson = cJSON_Parse(p_req->value);
    if (NULL == pJson) {
        LOG_ERROR("malloc pJson failed");
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        p_rsp->length = 0;
        return DA_ERR_MALLOC_FAIL;
    }

    p_rsp->status = DA_ERR_PARA;
    p_rsp->length = 0;
    cJSON *fsmIp = cJSON_GetObjectItem(pJson, "fsmIp");
    CHECK_JSON_STRING(fsmIp, pJson);
    cJSON *ftpDswarePasswd = cJSON_GetObjectItem(pJson, "ftpDswarePasswd");
    CHECK_JSON_STRING(ftpDswarePasswd, pJson);
    size_t pwd_len = strlen(ftpDswarePasswd->valuestring);
    cJSON *ftp_dsware = cJSON_GetObjectItem(pJson, "ftp_dsware");
    CHECK_JSON_STRING(ftp_dsware, pJson);
    cJSON *reg = cJSON_GetObjectItem(pJson, "reg");
    CHECK_JSON_STRING(reg, pJson);
    cJSON *src = cJSON_GetObjectItem(pJson, "src");
    CHECK_JSON_STRING(src, pJson);
    cJSON *dst = cJSON_GetObjectItem(pJson, "dst");
    CHECK_JSON_STRING(dst, pJson);
    
    rsa_status = get_rsa_switch();

    char path_name[DSA_DIR_PATH_MAX] = {0};
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    // 如果rsa_status的值为1，则认为是公私钥登录，如果是0，则认为是账户密码登录
    if (rsa_status == 1) {
        shell_rsp temp_cmd_rsp = {0};
        if (DSWARE_AGENT_OK != agent_info_collect_way_analysis(&temp_cmd_rsp)) {
            LOG_ERROR("get rsa passwordphrase failed.");
            MEM_ERASE(ftpDswarePasswd->valuestring, pwd_len, SAFE_ERASE_TIMES);
            cJSON_Delete(pJson);
            return DA_FAIL;
        }

        snprintf_s(command, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s%s %s %s %s '%s' '%s' '%s' %d", path_name,
                   DSWARE_SHELL_NAME, AGENT_VIEW_LOG_COLLECT, fsmIp->valuestring, ftp_dsware->valuestring,
                   reg->valuestring, src->valuestring, dst->valuestring, p_req->version);
        snprintf_s(param, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s@@@%s", ftpDswarePasswd->valuestring, temp_cmd_rsp.value);

        // 安全问题，变量赋值后需要memset清零
        memset_s(&temp_cmd_rsp, sizeof(shell_rsp), 0, sizeof(shell_rsp));
    } else {
        snprintf_s(command, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s%s %s %s %s '%s' '%s' '%s' %d", path_name,
                   DSWARE_SHELL_NAME, AGENT_VIEW_LOG_COLLECT, fsmIp->valuestring, ftp_dsware->valuestring,
                   reg->valuestring, src->valuestring, dst->valuestring, p_req->version);
        snprintf_s(param, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s", ftpDswarePasswd->valuestring);
    }

    MEM_ERASE(ftpDswarePasswd->valuestring, pwd_len, SAFE_ERASE_TIMES);
    cJSON_Delete(pJson);
    shell_rsp cmd_rsp = {0};
    
    shell_operate_with_private_param(command, &cmd_rsp, SHELL_TIME_OUT, param, strnlen(param, BUFSIZE_1024));
    MEM_ERASE(param, sizeof(param), SAFE_ERASE_TIMES);
    if (DA_OK != cmd_rsp.status) {
        p_rsp->status = cmd_rsp.status;
        p_rsp->length = 0;
        return cmd_rsp.status;
    }

    p_rsp->status = cmd_rsp.status;
    p_rsp->length = 0;
    LOG_DEBUG("agent_file_collect end,status=%d", p_rsp->status);
    return DA_OK;
}

/*****************************************************************
Parameters    :  p_req
                 p_rsp
Return        : Return
Description   :  FSM 传输文件到本节点
*****************************************************************/
int fsm_transfer_file_to_local(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    int file_fd = 0;
    char *pfile_name = NULL;
    dsw_u32 file_content_len = 0;
    dsw_u32 check_mesg_len = 0;
    fsm_transfer_file_req_t *transfer_file_req = NULL;

    /* tmpwwnfile文件用于传递集群system_wwn到agent节点 */

#define file_count_for_fsm_transfer 6
    char valid_path[file_count_for_fsm_transfer][DSA_DIR_PATH_MAX] = {{0}, {0}, {0}, {0}, {0}, {0}};

    int i = 0;
    snprintf_s(valid_path[i++], DSA_DIR_PATH_MAX, DSA_DIR_PATH_MAX - 1, "%s%s", g_fsm_agent_dir, "FsaCertInfo.zip");
    snprintf_s(valid_path[i++], DSA_DIR_PATH_MAX, DSA_DIR_PATH_MAX - 1, "%s%s", g_fsm_agent_dir, "CertInfo.zip");
    snprintf_s(valid_path[i++], DSA_DIR_PATH_MAX, DSA_DIR_PATH_MAX - 1, "%s%s", g_fsm_agent_dir,
               "replicationCertInfo.zip");
    snprintf_s(valid_path[i++], DSA_DIR_PATH_MAX, DSA_DIR_PATH_MAX - 1, "%s%s", g_fsm_agent_dir, "tool/ops_config");
    snprintf_s(valid_path[i++], DSA_DIR_PATH_MAX, DSA_DIR_PATH_MAX - 1, "%s", "/tmp/service/dr/update/tmpwwnfile");
    snprintf_s(valid_path[i++], DSA_DIR_PATH_MAX, DSA_DIR_PATH_MAX - 1, "%s", "/opt/dsware/service/dr/cloudbackup/tmp/CloudBackupCert.zip");
    i = 0;
    LOG_INFO("fsm_transfer_file_local begin");

    DA_CHECK_NULL_RETURN_ERR_PARA(p_req, "p_req");
    DA_CHECK_NULL_RETURN_ERR_PARA(p_rsp, "p_rsp");
    DA_CHECK_NULL_RETURN_ERR_PARA(p_req->value, "p_req->value");

    check_mesg_len = sizeof(fsm_transfer_file_req_t);

    if (p_req->length < check_mesg_len) {
        LOG_ERROR("req mesg len too small,mesg len=%u,check_mesg_len=%u", p_req->length, check_mesg_len);
        p_rsp->status = DA_ERR_PARA;
        return DA_ERR_PARA;
    }

    transfer_file_req = (fsm_transfer_file_req_t *)(p_req->value);
    transfer_file_req->file_name[sizeof(transfer_file_req->file_name) - 1] = '\0';
    pfile_name = transfer_file_req->file_name;
    for (i = 0; i < file_count_for_fsm_transfer; i++) {
        if (0 ==
            strncmp(pfile_name, valid_path[i],
                    strlen(valid_path[i]) > strlen(pfile_name) ? strlen(pfile_name) + 1 : strlen(valid_path[i]) + 1)) {
            break;
        }
    }

    if (i >= file_count_for_fsm_transfer) {
        LOG_ERROR("invalid file path:%s", pfile_name);
        p_rsp->status = DA_ERR_PARA;
        return DA_ERR_PARA;
    }

    file_content_len = transfer_file_req->file_content_len;
    if (p_req->length - check_mesg_len < file_content_len) {
        LOG_ERROR("req mesg len too small,mesg len=%u,file_content_len=%u", p_req->length, file_content_len);
        p_rsp->status = DA_ERR_PARA;
        return DA_ERR_PARA;
    }

    /* 证书文件通常在1MB以内,这里只是为了防止文件长度过大,定义上限为10MB(约等于). */
    if (file_content_len > 10000000) { // 10000000表示文件上限大小约等于
        LOG_ERROR("file content len(%u) too large!", file_content_len);
        p_rsp->status = DA_ERR_PARA;
        return DA_ERR_PARA;
    }
    
    char path[BUFSIZE_128 * 2] = {0};  
    if (realpath(pfile_name, path) == NULL) {
        LOG_INFO("realpath %s error!", pfile_name);
    }
    /* 打开文件，文件不存在则新建文件 */
    file_fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (file_fd < 0) {
        int errnum = errno;
        DSA_ERRNO_PRINT(errnum); 
        LOG_ERROR("open file %s failed", path);
        p_rsp->status = DA_ERR_OPEN_FILE;  
        return DA_ERR_OPEN_FILE;
    }

    /* 把文件内容写入到配置文件中 */
    if (file_content_len != do_write(file_fd, (void *)transfer_file_req->file_content, file_content_len)) {
        LOG_ERROR(" write file error");
        DsaClose(file_fd);
        p_rsp->status = DA_ERR_TRANSFER_FILE_LOCAL_FAIL;
        return DA_ERR_TRANSFER_FILE_LOCAL_FAIL;
    }

    DsaClose(file_fd);

    p_rsp->status = DA_OK;
    LOG_INFO("fsm_transfer_file_local end");

    return DA_OK;
}


/*************************************************
 Function:        agent_info_collect_way_analysis
 Description:     the way to transfer file to fsm(public and private key or password), if public and private key is
used, get the key pasword 
 Input: cmd_rsp
 Output: no
 Return: 0:sucessful 1:failed 
 Others: no
*************************************************/
int agent_info_collect_way_analysis(shell_rsp *cmd_rsp)
{
    LOG_INFO("agent_info_collect_way_analysis start");
    unsigned char *plain_text = NULL;  // 解密后的明文
    uint32_t plain_text_len = 0;        // 解密后的明文长度
    unsigned char cipher_text[BUFSIZE_128] = {0};
    dsw_u32 old_domain_id = 150;                      // 老版本DswareTool/FSM/DSwareAPI/FSA使用的工作密钥,域id为150
    dsw_u32 old_key_id = 0;                           // 老版本DswareTool/FSM/DSwareAPI/FSA使用的工作密钥,key id为0
    unsigned char key_plain_text[BUFSIZE_128] = {0};  // MK密钥
    dsw_u32 key_len = 128;
    FS_MK_INFO_STRU pstMkInfo = {0};

    char command[COMMAND_BUFSIZE] = {0};
    shell_rsp tmp_cmd_rsp = {0, {0}};
    char path_name[DSA_DIR_PATH_MAX] = {0};
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    /* 调用脚本获取文件中KMC  的密文 */
    snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s", path_name, DSWARE_SHELL_NAME,
               GET_INFO_COLLECT_KEY_PASSWD);
    // 密文，错误异常也不要打印出来
    (void)pthread_mutex_lock(&g_log_print_lock);
    g_log_print = DSW_FALSE;
    shell_operate(command, &tmp_cmd_rsp, SHELL_TIME_OUT);
    g_log_print = DSW_TRUE;
    (void)pthread_mutex_unlock(&g_log_print_lock);
    if (DA_OK != tmp_cmd_rsp.status) {
        LOG_ERROR("fail to run shell operate");
        MEM_ERASE(&tmp_cmd_rsp, sizeof(tmp_cmd_rsp), SAFE_ERASE_TIMES);
        return DA_FAIL;
    }

    strncpy_s((char*)cipher_text, BUFSIZE_128, tmp_cmd_rsp.value, BUFSIZE_128 - 1);
    MEM_ERASE(&tmp_cmd_rsp, sizeof(tmp_cmd_rsp), SAFE_ERASE_TIMES);
    uint32_t cipher_text_len = strnlen((char*)cipher_text, BUFSIZE_128);
    if (0 == cipher_text_len) {
        LOG_ERROR("invalid shell return value");
        return DA_FAIL;
    }

    /* 先使用DSware_KMC的解密接口进行解密，
       如果解密失败则从DSware_KMC中获取老版本的密钥使用老方法进行解密 */
    int32_t kmca_ret = KMCA_Decrypt(KMCA_DOMAIN_ID_FSA_ENCRYPT, cipher_text, cipher_text_len,
                                    &plain_text, &plain_text_len);
    MEM_ERASE(cipher_text, sizeof(cipher_text), SAFE_ERASE_TIMES);
    if (kmca_ret == KMCA_SUCCESS) {
        strncpy_s(cmd_rsp->value, BUFSIZE_1024, (char *)plain_text, BUFSIZE_1024 - 1);
        /* 敏感信息在可用资源中保存应该遵循存储时间最短原则，对存储口令和秘钥的
           变量使用完毕后必须显示覆盖或清空 */
        MEM_ZFREE(plain_text, plain_text_len);
    } else {
        MEM_ZFREE(plain_text, plain_text_len);
        LOG_WARNING("kmc agent decrypt failed %d, try to use the old version of the key decryption", kmca_ret);
        /* 调用KMC 接口获取老版本的密钥，然后用老版本的openssl解密 */
        FS_KMC_ERR_T ret = DSWARE_KMC_GetMkInfo(old_domain_id, old_key_id, &pstMkInfo, key_plain_text, &key_len);
        if (ret != FS_KMC_SUCCESS) {
            LOG_ERROR("dsware kmc get mk info failed %llu", ret);
            MEM_ERASE(key_plain_text, sizeof(key_plain_text), SAFE_ERASE_TIMES);
            return DA_FAIL;
        }

        if (0 == strnlen((char *)key_plain_text, BUFSIZE_128)) {
            LOG_ERROR("invalid shell return value");
            MEM_ERASE(key_plain_text, sizeof(key_plain_text), SAFE_ERASE_TIMES);
            return DA_FAIL;
        }

        /* 调用脚本获取文件中用openssl加密的密码 */
        memset_s(command, sizeof(command), 0, sizeof(command));
        snprintf_s(command, COMMAND_BUFSIZE, COMMAND_BUFSIZE - 1, "%s%s %s %s", path_name, DSWARE_SHELL_NAME,
                   GET_INFO_COLLECT_KEY_PASSWD, key_plain_text);
        MEM_ERASE(key_plain_text, sizeof(key_plain_text), SAFE_ERASE_TIMES);

        // 密码，错误异常也不要打印出来
        (void)pthread_mutex_lock(&g_log_print_lock);
        g_log_print = DSW_FALSE;
        shell_operate(command, &tmp_cmd_rsp, SHELL_TIME_OUT);
        g_log_print = DSW_TRUE;
        (void)pthread_mutex_unlock(&g_log_print_lock);
        memset_s(command, sizeof(command), 0, sizeof(command));
        if (DA_OK != tmp_cmd_rsp.status) {
            MEM_ERASE(&tmp_cmd_rsp, sizeof(tmp_cmd_rsp), SAFE_ERASE_TIMES);
            LOG_ERROR("fail to run shell operate");
            return DA_FAIL;
        }

        strncpy_s(cmd_rsp->value, BUFSIZE_1024, tmp_cmd_rsp.value, BUFSIZE_1024 - 1);
        
        /* 敏感信息在可用资源中保存应该遵循存储时间最短原则，对存储口令和秘钥的
      变量使用完毕后必须显示覆盖或清空 */
        MEM_ERASE(&tmp_cmd_rsp, sizeof(tmp_cmd_rsp), SAFE_ERASE_TIMES);

        if (0 == strnlen(cmd_rsp->value, BUFSIZE_1024)) {
            LOG_ERROR("invalid shell return value");
            return DA_FAIL;
        }
    }
    LOG_INFO("agent_info_collect_way_analysis end");
    return DA_OK;
}

/*************************************************
 Function:        meminfo_check
 Description:     get meminfo_check result shell script
 Input: dsware_agent_req_hdr dsware_agent_rsp_hdr
 Output: Output
 Return:
       0:sucessful 1:failed
 Others: Others
*************************************************/
int meminfo_check(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    LOG_INFO("meminfo_check start");

    if (NULL == p_req || NULL == p_rsp) {
        LOG_ERROR("meminfo_check input pointer empty");
        return DA_FAIL;
    }

    int ret = 0;
    char command[BUFSIZE_1024] = {0};
    dsw_u64 free_mem = 0;
    shell_rsp cmd_rsp = {0};
    struct shell_rsp_parser_body MEMINFO_CHECK_PARSES[] = {
        { "%llu", DEFAULT_VALUE, 0 }
    };
    char path_name[DSA_DIR_PATH_MAX] = {0};
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    snprintf_s(command, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s%s %s", path_name, DSWARE_SHELL_NAME, MEMINFO_CHECK);

    // execute shell command
    shell_operate(command, &cmd_rsp, SHELL_TIME_OUT);
    if (DA_OK != cmd_rsp.status) {
        LOG_ERROR("Parse shell failed, rsp status [%d]", cmd_rsp.status);
        p_rsp->status = cmd_rsp.status;
        p_rsp->length = 0;
        return cmd_rsp.status;
    }
    ret = parser_shell_rsp(&cmd_rsp, &free_mem, sizeof(free_mem), 1, MEMINFO_CHECK_PARSES,
                           sizeof(MEMINFO_CHECK_PARSES) / PARSER_BODY_LEN);
    if (0 == ret) {
        LOG_ERROR("analyze shell command rsp failed return string=%s ", cmd_rsp.value);
        p_rsp->status = cmd_rsp.status;
        p_rsp->length = 0;
        return DA_ERR_INNER_ERROR;
    } else {
        p_rsp->status = cmd_rsp.status;
        cJSON *pJsonRoot = cJSON_CreateObject();
        if (NULL == pJsonRoot) {
            LOG_ERROR("malloc pJson failed");
            p_rsp->status = DA_ERR_MALLOC_FAIL;
            p_rsp->length = 0;
            return DA_ERR_MALLOC_FAIL;
        }
        cJSON_AddNumberToObject(pJsonRoot, "free_mem", (double)free_mem);
        p_rsp->status = cmd_rsp.status;
        p_rsp->value = cJSON_PrintUnformatted(pJsonRoot);
        if (NULL == p_rsp->value) {
            LOG_ERROR("malloc p_rsp->value failed");
            p_rsp->status = DA_ERR_MALLOC_FAIL;
            p_rsp->length = 0;
            cJSON_Delete(pJsonRoot);
            return DA_ERR_MALLOC_FAIL;
        }
        p_rsp->length = strlen(p_rsp->value) + 1;
        cJSON_Delete(pJsonRoot);
    }
    LOG_INFO("meminfo_check end");
    return DA_OK;
}

void record_responce(dsware_agent_rsp_hdr* p_rsp)
{
    p_rsp->status = DA_ERR_MALLOC_FAIL;
    p_rsp->length = 0;
    LOG_ERROR("malloc failed");
    return;
}

/*************************************************
 Function:        total_meminfo_check
 Description:     get query_mem_total result shell script
 Input: Input
 Output: Output
 Return:
       0:sucessful 1:failed
 Others: Others
*************************************************/
int total_meminfo_check(dsware_agent_req_hdr* p_req, dsware_agent_rsp_hdr* p_rsp)
{
    if (p_req == NULL || p_rsp == NULL) {
        LOG_ERROR("meminfo_check input pointer empty");
        return DA_FAIL;
    }

    char command[BUFSIZE_1024] = {0};
    dsw_u64 totalMem = 0;
    shell_rsp cmd_rsp = {0};
    struct shell_rsp_parser_body MEMINFO_CHECK_PARSES[] = {
        {"%llu", DEFAULT_VALUE, 0}
    };
    char path_name[DSA_DIR_PATH_MAX] = {0};
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    int ret = snprintf_s(command, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s%s %s",
        path_name, DSWARE_SHELL_NAME, TOTAL_MEMINFO_CHECK);
    if (ret < 0) {
        record_responce(p_rsp);
        return DA_ERR_INNER_ERROR;
    } 
    shell_operate(command, &cmd_rsp, SHELL_TIME_OUT);
    if (cmd_rsp.status != DA_OK) {
        record_responce(p_rsp);
        return cmd_rsp.status;
    }
    ret = parser_shell_rsp(&cmd_rsp, &totalMem, sizeof(totalMem), 1,
        MEMINFO_CHECK_PARSES, sizeof(MEMINFO_CHECK_PARSES) / PARSER_BODY_LEN);
    if (ret == 0) {
        record_responce(p_rsp);
        return DA_ERR_INNER_ERROR;
    } else {
        p_rsp->status = cmd_rsp.status;
        cJSON* pJsonRoot = cJSON_CreateObject();
        if (pJsonRoot == NULL) {    
            record_responce(p_rsp);
            return DA_ERR_MALLOC_FAIL;
        }
        cJSON_AddNumberToObject(pJsonRoot, "total_mem", (double) totalMem);
        p_rsp->status = cmd_rsp.status;
        p_rsp->value = cJSON_PrintUnformatted(pJsonRoot);
        if (p_rsp->value == NULL) {
            record_responce(p_rsp);
            cJSON_Delete(pJsonRoot);
            return DA_ERR_MALLOC_FAIL;
        }
        p_rsp->length = strlen(p_rsp->value) + 1;
        cJSON_Delete(pJsonRoot);
    }
    return DA_OK;
}

/*************************************************
 Function:        environment_type_check
 Description:     get environment_type_check result
 Input: dsware_agent_req_hdr dsware_agent_rsp_hdr
 Output: Output
 Return:
       0:sucessful 1:failed
 Others: Others
*************************************************/
int environment_type_check(dsware_agent_req_hdr* p_req, dsware_agent_rsp_hdr* p_rsp)
{
    LOG_INFO("environment_type_check start");

    if (p_req == NULL || p_rsp == NULL) {
        LOG_ERROR("meminfo_check input pointer empty");
        return DA_FAIL;
    }

    int env_type = 0;
    cJSON* pJsonRoot = cJSON_CreateObject();
    if (pJsonRoot == NULL) {
        LOG_ERROR("malloc pJson failed");
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        p_rsp->length = 0;
        return DA_ERR_MALLOC_FAIL;
    }
    env_type = dpax_get_machine_type();
    LOG_INFO("env type is %d", env_type);
    cJSON_AddNumberToObject(pJsonRoot, "env_type", (int) env_type);
    p_rsp->status = 0;
    p_rsp->value = cJSON_PrintUnformatted(pJsonRoot);
    if (p_rsp->value == NULL) {
        LOG_ERROR("malloc p_rsp->value failed");
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        p_rsp->length = 0;
        cJSON_Delete(pJsonRoot);
        return DA_ERR_MALLOC_FAIL;
    }
    p_rsp->length = strlen(p_rsp->value) + 1;
    cJSON_Delete(pJsonRoot);
    LOG_INFO("environment_type_check end");
    return DA_OK;
}

void batch_storage_ip(char *ip_list, char *port, cJSON *storage_ip_list, cJSON *dst_port, int *ip_list_length)
{
    if (NULL == storage_ip_list || NULL == storage_ip_list->string || cJSON_GetArraySize(storage_ip_list) == 0) {
        return;
    }

    cJSON *port_list = cJSON_GetObjectItem(dst_port, storage_ip_list->string);
    if (NULL == port_list || 0 == cJSON_GetArraySize(port_list)) {
        return;
    }

    char buffer[BUFSIZE_16];
    for (int j = 0; j <= 1; j++) {
        // 双平面 j=0时是第一个平面，如果j=1不为空，则拥有双平面
        if (NULL == cJSON_GetArrayItem(storage_ip_list, j) ||
            NULL == cJSON_GetArrayItem(storage_ip_list, j)->string) {
            continue;
        }

        strncat_s(ip_list, BUFSIZE_1024, cJSON_GetArrayItem(storage_ip_list, j)->string,
                  strnlen(cJSON_GetArrayItem(storage_ip_list, j)->string, BUFSIZE_1024 - 1));
        strncat_s(ip_list, BUFSIZE_1024, ",", strlen(","));
        ip_list[BUFSIZE_1024 - 1] = '\0';

        // CCB结论，取第一个每个IP对应的第一个端口做网络探测
        if (NULL != cJSON_GetArrayItem(port_list, 0)) {
            snprintf_s(buffer, BUFSIZE_16, BUFSIZE_16 - 1, "%.0f", cJSON_GetArrayItem(port_list, 0)->valuedouble);
            strncat_s(port, BUFSIZE_128, buffer, BUFSIZE_16);
            strncat_s(port, BUFSIZE_128, ",", strlen(","));
            port[BUFSIZE_128 - 1] = '\0';
        }
        (*ip_list_length)++;
    }
}

int parser_traceroute_result(char *rsp_value, cJSON *pJsonRoot, t_traceroute_check *check_batch, int maxNum)
{
    struct shell_rsp_parser_body traceroute_check_parse[] = {
        {"%s", (dsw_u16) offsetof(t_traceroute_check, storage_ip), IPV6_BUF_LEN},
        {"%s", (dsw_u16) offsetof(t_traceroute_check, src_ip), IPV6_BUF_LEN},
        {"%d", (dsw_u16) offsetof(t_traceroute_check, result), 0},
    };
    const int parser_size = sizeof(traceroute_check_parse) / sizeof(struct shell_rsp_parser_body);
    int ret = parser_shell_rsp_with_size(rsp_value, check_batch, sizeof(t_traceroute_check),
                                         maxNum, traceroute_check_parse, parser_size);
    if (ret == 0) {
        LOG_ERROR("analyze shell command response failed return string=%s ret=%d", rsp_value, ret);
        return DA_ERR_RUN_SHELL;
    }
    for (int i = 0; i < ret; i++) {
        if (0 != check_batch[i].result) {
            LOG_ERROR("Some traceroute check failed,to ip: %s,result: %d", check_batch[i].storage_ip,
                      check_batch[i].result);
            cJSON_AddStringToObject(pJsonRoot, check_batch[i].storage_ip, check_batch[i].src_ip);
        }
    }
    return DA_OK;
}

void CjsonDeleteObject(cJSON *pJson, cJSON *pJsonRoot)
{
    cJSON_Delete(pJson);
    cJSON_Delete(pJsonRoot);
}

bool IsParameterNull(cJSON *dst_port, cJSON *dst_addr, cJSON *protocol, cJSON *addr_type)
{
    return dst_port == NULL || dst_addr == NULL || protocol == NULL || addr_type == NULL;
}
/*************************************************
 Function:        traceroute_check
 Description:     get traceroute_check result shell script
 Input: dsware_agent_req_hdr dsware_agent_rsp_hdr
 Output: Output
 Return:
       0:sucessful 1:failed
 Others: Others
*************************************************/
int traceroute_check(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    LOG_INFO("traceroute_check start");
    if (NULL == p_req || NULL == p_rsp || NULL == p_req->value) {
        LOG_ERROR("traceroute_check input pointer empty");
        return DA_FAIL;
    }
    p_rsp->status = DA_ERR_PARA;
    p_rsp->length = 0;

    t_traceroute_check traceroute_check_batch[TRACEROUTE_PARA_NUM + 1];
    memset_s(traceroute_check_batch, sizeof(traceroute_check_batch), 0, sizeof(traceroute_check_batch));
    cJSON *pJson = cJSON_Parse(p_req->value);
    if (NULL == pJson) {
        LOG_ERROR("malloc pJson failed");
        return DA_ERR_MALLOC_FAIL;
    }

    cJSON *pJsonRoot = cJSON_CreateObject();
    if (NULL == pJsonRoot) {
        LOG_ERROR("malloc pJson failed");
        cJSON_Delete(pJson);
        return DA_ERR_MALLOC_FAIL;
    }

    cJSON *dst_port = cJSON_GetObjectItem(pJson, "dst_port");
    cJSON *dst_addr = cJSON_GetObjectItem(pJson, "dst_addr");
    cJSON *protocol = cJSON_GetObjectItem(pJson, "protocol");
    cJSON *addr_type = cJSON_GetObjectItem(pJson, "addr_type");
    if (IsParameterNull(dst_port, dst_addr, protocol, addr_type)) {
        LOG_ERROR("dst_port or dst_addr or protocol or addr_type is NULL");
        CjsonDeleteObject(pJson, pJsonRoot);
        return DA_FAIL;
    }
    
    char ip_list[BUFSIZE_1024] = {0};
    char port_list[BUFSIZE_128] = {0};
    int ip_list_length = 0;
    char path_name[DSA_DIR_PATH_MAX] = {0};
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    for (int i = 0; i < cJSON_GetArraySize(dst_addr); i++) {
        cJSON *storage_ip_list = cJSON_GetArrayItem(dst_addr, i);
        batch_storage_ip(ip_list, port_list, storage_ip_list, dst_port, &ip_list_length);

        if ((i == cJSON_GetArraySize(dst_addr) - 1 && ip_list_length > 0) || ip_list_length >= TRACEROUTE_PARA_NUM) {
            char command[BUFSIZE_1024] = {0};
            snprintf_s(command, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s%s %s %s %s %s %s", path_name, NETWORK_COMMAND_SHELL,
                       TRACEROUTE_CHECK, port_list, ip_list, protocol->valuestring, addr_type->valuestring);
            shell_rsp_size2048 cmd_rsp = {0};
            shell_operate_with_size(command, &cmd_rsp.status, cmd_rsp.value, BUFSIZE_2048, SHELL_TIME_OUT);
            if (DA_OK != cmd_rsp.status) {
                p_rsp->status = DA_ERR_RUN_SHELL;
                CjsonDeleteObject(pJson, pJsonRoot);
                return DA_ERR_RUN_SHELL;
            }

            int ret = parser_traceroute_result(cmd_rsp.value, pJsonRoot, traceroute_check_batch,
                                               TRACEROUTE_PARA_NUM + 1);
            if (0 != ret) {
                LOG_ERROR("analyze shell command response failed return string=%s ret=%d", cmd_rsp.value, ret);
                p_rsp->status = ret;
                CjsonDeleteObject(pJson, pJsonRoot);
                return ret;
            }

            memset_s(ip_list, BUFSIZE_1024, 0, BUFSIZE_1024);
            memset_s(port_list, BUFSIZE_128, 0, BUFSIZE_128);
            memset_s(traceroute_check_batch, sizeof(traceroute_check_batch), 0, sizeof(traceroute_check_batch));
            ip_list_length = 0;
        }
    }

    // execute shell command
    p_rsp->status = DA_OK;
    p_rsp->value = cJSON_PrintUnformatted(pJsonRoot);
    if (NULL == p_rsp->value) {
        LOG_ERROR("malloc p_rsp->value failed");
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        CjsonDeleteObject(pJson, pJsonRoot);
        return DA_ERR_MALLOC_FAIL;
    }
    p_rsp->length = strlen(p_rsp->value) + 1;
    CjsonDeleteObject(pJson, pJsonRoot);

    LOG_INFO("traceroute_check end");
    return DA_OK;
}

/******************************************************
  Function:        dsware_agent_query_electronic_label
  Description:     query electronic info
  Input:
         dsware_agent_req_hdr:  request struct
         dsware_agent_rsp_hdr:  response struct
  Output: Output
  Return:
         0:sucess
         1:failed
******************************************************/
int dsware_agent_query_electronic_label(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    LOG_INFO("dsware_agent_query_electronic_label start...");

    p_rsp->status = DA_OK;
    p_rsp->length = 0;
    p_rsp->value = NULL;

    FILE *pf = popen("python /opt/fusionstorage/agent/script/modify_electronic_label.py \"get_label_from_broad\"", "r");

    if (pf == NULL) {
        LOG_ERROR("get label from broad failed.");
        return DA_FAIL;
    }

    char res[BUFSIZE_128] = {0};
    fgets(res, sizeof(res), pf);
    pclose(pf);

    p_rsp->length = sizeof(res);
    p_rsp->value = malloc(p_rsp->length);

    if (p_rsp->value == NULL) {
        LOG_ERROR("malloc p_rsp->value failed error.");
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        return DA_FAIL;
    }

    memset_s(p_rsp->value, p_rsp->length, 0, p_rsp->length);
    if (EOK != memcpy_s(p_rsp->value, p_rsp->length, res, sizeof(res))) {
        LOG_ERROR("dsware_agent_query_electronic_label.c: memcpy_s failed.");
        p_rsp->status = DA_ERR_INNER_ERROR;
        return DA_FAIL;
    }

    LOG_INFO("dsware_agent_query_electronic_label end,value(%s)", (char *)p_rsp->value);
    return DA_OK;
}

/******************************************************
  Function:        dsware_agent_query_bios_info
  Description:     query bios info
  Input:
         dsware_agent_req_hdr:  request struct
         dsware_agent_rsp_hdr:  response struct
  Output: Output
  Return:
         0:sucess
         1:failed
******************************************************/
int dsware_agent_query_bios_info(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    shell_rsp cmd_rsp;

    LOG_INFO("dsware_agent_query_bios_info start...");
    if (NULL == p_req || NULL == p_rsp) {
        LOG_ERROR("query bios parameter is null.");
        return DA_FAIL;
    }

    p_rsp->status = DA_OK;
    p_rsp->length = 0;
    p_rsp->value = NULL;

    char command[BUFSIZE_1024] = {0};
    char path_name[DSA_DIR_PATH_MAX] = {0};
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    snprintf_s(command, BUFSIZE_1024, BUFSIZE_1024 - 1,
               "%s%s %s",
               path_name,
               DSWARE_SHELL_NAME,
               QUERY_BIOS_TYPE);
    shell_operate(command, &cmd_rsp, SHELL_TIME_OUT_10);

    dsw_u32 process = 0;
    if (sscanf_s(cmd_rsp.value, "%d", &process) != 1) {
        char err[ERROR_SIZE] = {0};
        strerror_r(errno, err, ERROR_SIZE);
        LOG_ERROR("analyze shell command rsp failed errno=%d (%s),rsp=%s",
                  errno, err, cmd_rsp.value);
        p_rsp->status = DA_ERR_ANALYZE_REQ_HDR;
        return DA_FAIL;
    }

    /* 拼接返回值 */
    p_rsp->length = sizeof(unsigned int);
    p_rsp->value = (char *)malloc(p_rsp->length);
    if (NULL == p_rsp->value) {
        char err[ERROR_SIZE] = {0};
        strerror_r(errno, err, ERROR_SIZE);
        LOG_ERROR("malloc p_rsp->value failed errno=%d (%s)", errno, err);
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        return DA_FAIL;
    }
    if (EOK != memcpy_s(p_rsp->value, p_rsp->length, &process, sizeof(process))) {
        char err[ERROR_SIZE] = {0};
        strerror_r(errno, err, ERROR_SIZE);
        LOG_ERROR("memcpy_s failed errno=%d (%s)", errno, err);
        p_rsp->status = DA_ERR_INNER_ERROR;
        return DA_FAIL;
    }
    return DA_OK;
}

extern int send_req_to_manage(dsware_agent_req_hdr *req, dsware_agent_rsp_hdr *rsp);
int dsware_agent_upload_file_to_manager(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    upload_file_info op_req;
    dsware_agent_req_hdr req = {0};
    dsware_agent_rsp_hdr rsp = {0};
    int ret = DA_OK;
    char command[BUFSIZE_1024] = {0};
    char param[BUFSIZE_256] = {0};
    
    LOG_INFO("dsware agent start handle upload_file_to_manager start");

    if (NULL == p_req || NULL == p_rsp || NULL == p_req->value) {
        LOG_ERROR("dsware_agent_upload_file_to_manager input pointer empty");
        return DA_FAIL;
    }

    /* initial rsp */
    p_rsp->status = DA_OK;
    p_rsp->length = 0;
    p_rsp->value = NULL;

    if (p_req->length != (sizeof(op_req.user) + sizeof(op_req.filepath))) {
        LOG_ERROR("dsware_agent_upload_file_to_manager input para error");
        p_rsp->status = DA_ERR_PARA;
        return DA_FAIL;
    }

    memset_s(&op_req, sizeof(op_req), DEFAULT_VALUE, sizeof(op_req));

    memcpy_s(op_req.user, sizeof(op_req.user), p_req->value, sizeof(op_req.user));
    op_req.user[sizeof(op_req.user) - 1] = '\0';
    if (EOK != memcpy_s(op_req.filepath, sizeof(op_req.filepath), (char*)p_req->value + sizeof(op_req.user),
        sizeof(op_req.filepath))) {
        LOG_ERROR("memcpy_s error");
        p_rsp->status = DA_ERR_INNER_ERROR;
        return DA_FAIL;
    }
    op_req.filepath[sizeof(op_req.filepath) - 1] = 0;

    LOG_INFO("user=%s,filepath=%s\n", op_req.user, op_req.filepath);

    if (DA_FAIL == command_parameter_check(op_req.user)) {
        LOG_ERROR("user %s parameter error,may leads to cmd intrusion", op_req.user);
        p_rsp->status = DA_ERR_PARA;
        return DA_FAIL;
    }
    if (DA_FAIL == command_parameter_check(op_req.filepath)) {
        LOG_ERROR("filepath %s parameter error,may leads to cmd intrusion", op_req.filepath);
        p_rsp->status = DA_ERR_PARA;
        return DA_FAIL;
    }

    req.type = DSA_MANAGER_TYPE_QUERY_LFTP_USER_PW;
    req.length = sizeof(op_req.user);
    req.value = op_req.user;

    ret = send_req_to_manage(&req, &rsp);

    if (DA_OK != ret) {
        LOG_ERROR("send req to fsm fail(%d)", ret);
        p_rsp->status = ret;
        return ret;
    }

    if (DA_OK != rsp.status || NULL == rsp.value) {
        LOG_ERROR("fsm response result(%d)", ret);
        p_rsp->status = rsp.status;
        return rsp.status;
    }
    LOG_INFO("send to fsm success");
    char path_name[DSA_DIR_PATH_MAX] = {0};
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    snprintf_s(command, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s%s %s '%s' '%s' %s", path_name, DSWARE_SHELL_NAME,
               UPLOAD_FILE_TO_MANAGER, op_req.user, op_req.filepath, g_agent_sys_val.manager_ip);
    // FSM返回结构为passwd[BUFSIZE_32+1] + dsw_u8 reserved[8]
    memcpy_s(param, sizeof(param), (char *)rsp.value, strnlen((char *)rsp.value, BUFSIZE_32));

    shell_rsp cmd_rsp = {0};
    shell_operate_with_private_param(command, &cmd_rsp, SHELL_TIME_OUT, param, strnlen(param, BUFSIZE_256));

    if (DA_OK != cmd_rsp.status) {
        p_rsp->status = cmd_rsp.status;
        p_rsp->length = 0;
        return cmd_rsp.status;
    }
    // 安全问题，变量赋值后需要memset清零
    memset_s(param, sizeof(param), 0, sizeof(param));

    p_rsp->status = cmd_rsp.status;
    p_rsp->length = 0;
    LOG_INFO("dsware_agent_upload_file_to_manager end,status=%d", p_rsp->status);

    return DA_OK;
}

/******************************************************
  Function:        dsware_agent_query_bbu_memory_size
  Description:     query bbu memeory size
  Input:
         dsware_agent_req_hdr:  request struct
         dsware_agent_rsp_hdr:  response struct
  Output: Output
  Return:
         0:sucess
         1:failed
******************************************************/
int dsware_agent_query_bbu_memory_size(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    LOG_INFO("dsware_agent_query_bbu_memory_size start...");

    p_rsp->status = DA_OK;
    p_rsp->length = 0;
    p_rsp->value = NULL;

    // 获取保电内存大小
    int memory_size = ds_get_m2_memory_size();
    if (memory_size <= 0) {
        LOG_ERROR("get m2 memory size faild, memory_size:%d", memory_size);
        p_rsp->status = DA_FAIL;
        return DA_FAIL;
    }
    p_rsp->length = sizeof(unsigned int);
    p_rsp->value = (char *)malloc(p_rsp->length);
    if (NULL == p_rsp->value) {
        char err[ERROR_SIZE] = {0};
        strerror_r(errno, err, ERROR_SIZE);
        LOG_ERROR("malloc p_rsp->value failed errno=%d (%s)", errno, err);
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        return DA_FAIL;
    }
    if (EOK != memcpy_s(p_rsp->value, p_rsp->length, &memory_size, sizeof(memory_size))) {
        char err[ERROR_SIZE] = {0};
        strerror_r(errno, err, ERROR_SIZE);
        LOG_ERROR("memcpy_s failed errno=%d (%s)", errno, err);
        p_rsp->status = DA_ERR_INNER_ERROR;
        return DA_FAIL;
    }
    return DA_OK;
}

int query_driver_support_dsm(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    p_rsp->status = DA_OK;
    p_rsp->length = 0;
    shell_rsp cmd_rsp = { 0 };
    char command[BUFSIZE_1024] = { 0 };
    char path_name[DSA_DIR_PATH_MAX] = { 0 };
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    memset_s(command, sizeof(command), 0, sizeof(command));
    int ret = snprintf_s(command, BUFSIZE_1024, BUFSIZE_1024 - 1, "%s%s %s %s", path_name, NETWORK_COMMAND_SHELL,
                         "net_op", "query_driver_support_dsm");
    if (ret == -1) {
        LOG_ERROR("generate command failed");
        p_rsp->status = DA_FAIL;
        return DA_FAIL;
    }
    shell_operate(command, &cmd_rsp, SHELL_TIME_OUT_5);

    if (cmd_rsp.status != DA_OK) {
        p_rsp->status = DA_FAIL;
        LOG_ERROR("query_driver_support_dsm fail, cmd=%s status=%d.", command, cmd_rsp.status);
        return cmd_rsp.status;
    }

    LOG_DEBUG("query driver support dsm success");

    return DA_OK;
}

int CheckCgroupConfig(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    if (p_req == NULL || p_rsp == NULL) {
        LOG_ERROR("CheckCgroupConfig input pointer empty");
        return DA_FAIL;
    }
    p_rsp->status = DA_OK;
    p_rsp->length = 0;
    shell_rsp cmd_rsp = { 0 };
    char command[BUFSIZE_1024] = { 0 };
    char path_name[DSA_DIR_PATH_MAX] = { 0 };
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));
    int ret = sprintf_s(command, BUFSIZE_1024, "%s%s %s", path_name, DSWARE_SHELL_NAME, CHECK_CGROUP_CONFIG);
    if (ret < 0) {
        LOG_ERROR("snprintf fail,ret:%d", ret);
        p_rsp->status = DA_FAIL;
        return DA_FAIL;
    }
    shell_operate(command, &cmd_rsp, SHELL_TIME_OUT_10);
    dsw_s32 cgroup_config = 0;
    if (sscanf_s(cmd_rsp.value, "%d", &cgroup_config) != 1) {
        LOG_ERROR("sscanf_s cmd_rsp.value failed");
        p_rsp->status = DA_FAIL;
        return DA_FAIL;
    }

    p_rsp->length = sizeof(unsigned int);
    p_rsp->value = (char *)malloc(p_rsp->length);
    if (p_rsp->value == NULL) {
        LOG_ERROR("malloc p_rsp->value failed");
        p_rsp->status = DA_FAIL;
        p_rsp->length = 0;
        return DA_FAIL;
    }
    if (memcpy_s(p_rsp->value, p_rsp->length, &cgroup_config, sizeof(cgroup_config)) != EOK) {
        LOG_ERROR("memcpy_s failed");
        p_rsp->status = DA_FAIL;
        p_rsp->length = 0;
        return DA_FAIL;
    }
    return DA_OK;
}

int CheckJsonWithoutFree(cJSON *obj)
{
    if (((obj) == NULL) || (obj)->type != cJSON_String || ((obj)->valuestring == NULL)) {
        LOG_ERROR("invalid string json object %p", obj);
        return DA_FAIL;
    }
    return DA_OK;
}

static int GetCollectionFtpParam(cJSON *ftpDswarePasswd, size_t pwdLen, char *param, int paramLen)
{
    int rsa_status = get_rsa_switch();
    int ret;
    // 如果rsa_status的值为1，则认为是公私钥登录，如果是0，则认为是账户密码登录
    if (1 == rsa_status) {
        shell_rsp temp_cmd_rsp = {0};
        if (DSWARE_AGENT_OK != agent_info_collect_way_analysis(&temp_cmd_rsp)) {
            LOG_ERROR("get rsa passwordphrase failed.");
            return DA_FAIL;
        }
        ret = sprintf_s(param, paramLen, "%s@@@%s", ftpDswarePasswd->valuestring, temp_cmd_rsp.value);

        // 安全问题，变量赋值后需要memset清零
        memset_s(&temp_cmd_rsp, sizeof(shell_rsp), 0, sizeof(shell_rsp));
    } else {
        ret = sprintf_s(param, paramLen, "%s", ftpDswarePasswd->valuestring);
    }
    
    if (ret <= 0) {
        LOG_ERROR("sprintf_s param failed(%d).", ret);
        return DA_FAIL;
    }

    return DA_OK;
}

static int CollectPrivateLog(cJSON *pJson, uint8_t version)
{
    cJSON *fsmIp = cJSON_GetObjectItem(pJson, "fsmIp");
    cJSON *ftpDswarePasswd = cJSON_GetObjectItem(pJson, "ftpDswarePasswd");
    cJSON *ftp_dsware = cJSON_GetObjectItem(pJson, "ftp_dsware");
    cJSON *serviceType = cJSON_GetObjectItem(pJson, "serviceType");
    cJSON *moduleName = cJSON_GetObjectItem(pJson, "moduleName");
    cJSON *label = cJSON_GetObjectItem(pJson, "label");
    cJSON *dst = cJSON_GetObjectItem(pJson, "dst");
    if (cJSON_GetStringValue(ftpDswarePasswd) == NULL) {
        LOG_ERROR("get ftp password from json object failed");
        return DA_ERR_PARA;
    }
    
    size_t pwdLen = strlen(ftpDswarePasswd->valuestring);
    bool validParam = (cJSON_GetStringValue(fsmIp) != NULL && cJSON_GetStringValue(ftp_dsware) != NULL &&
                       cJSON_GetStringValue(serviceType) != NULL && cJSON_GetStringValue(moduleName) != NULL &&
                       cJSON_GetStringValue(label) != NULL && cJSON_GetStringValue(dst) != NULL);
    if (!validParam) {
        MEM_ERASE(ftpDswarePasswd->valuestring, pwdLen, SAFE_ERASE_TIMES);
        LOG_ERROR("get string items from json object failed");
        return DA_ERR_PARA;
    }
    
    char path_name[DSA_DIR_PATH_MAX] = {0};
    (void)DumpDsaScriptDirPath(path_name, sizeof(path_name));    
    char command[BUFSIZE_1024] = {0};
    int ret = sprintf_s(command, BUFSIZE_1024, "%s%s %s %s %s '%s' '%s' '%s' '%s' %d", path_name,
        DSWARE_SHELL_NAME, AGENT_PRIVATE_LOG_COLLECT, fsmIp->valuestring, ftp_dsware->valuestring,
        serviceType->valuestring, moduleName->valuestring, label->valuestring, dst->valuestring,
        version);
    if (ret <= 0) {
        LOG_ERROR("sprintf_s command failed(%d).", ret);
        MEM_ERASE(ftpDswarePasswd->valuestring, pwdLen, SAFE_ERASE_TIMES);
        return DA_FAIL;
    }
    
    char param[BUFSIZE_1024] = {0};
    ret = GetCollectionFtpParam(ftpDswarePasswd, pwdLen, param, BUFSIZE_1024);
    MEM_ERASE(ftpDswarePasswd->valuestring, pwdLen, SAFE_ERASE_TIMES);
    if (ret != DA_OK) {
        LOG_ERROR("get private log ftp param failed(%d).", ret);
        MEM_ERASE(param, BUFSIZE_1024, SAFE_ERASE_TIMES);
        return ret;
    }

    shell_rsp cmd_rsp = {0};
    shell_operate_with_private_param(command, &cmd_rsp, SHELL_TIME_OUT, param, strnlen(param, BUFSIZE_1024));
    MEM_ERASE(param, BUFSIZE_1024, SAFE_ERASE_TIMES);
    if (cmd_rsp.status != DA_OK) {
        LOG_ERROR("excute script(%s) failed(%d).", AGENT_PRIVATE_LOG_COLLECT, cmd_rsp.status);
        return cmd_rsp.status;
    }
    return DA_OK;
}

/*************************************************
  Function:      agent_private_log_collect
  Description:   私有日志收集
  Input:
         dsware_agent_req_hdr:  manager request hdr
  Output:
         dsware_agent_rsp_hdr:  respond to manager
  Return:
         DA_OK:     sucess
         DA_FAIL:   failed
  Others: Others
*************************************************/
int agent_private_log_collect(dsware_agent_req_hdr *p_req, dsware_agent_rsp_hdr *p_rsp)
{
    LOG_DEBUG("agent_private_log_collect start");

    if (NULL == p_req || NULL == p_rsp || NULL == p_req->value) {
        LOG_ERROR("parameter is invalid");
        return DA_ERR_PARA;
    }
    cJSON *pJson = cJSON_Parse(p_req->value);
    if (NULL == pJson) {
        LOG_ERROR("malloc pJson failed");
        p_rsp->status = DA_ERR_MALLOC_FAIL;
        p_rsp->length = 0;
        return DA_ERR_MALLOC_FAIL;
    }

    int ret = CollectPrivateLog(pJson, p_req->version);
    cJSON_Delete(pJson);
    if (ret != DA_OK) {
        p_rsp->status = ret;
        p_rsp->length = 0;
        return ret;
    }

    p_rsp->status = DA_OK;
    p_rsp->length = 0;
    LOG_DEBUG("agent_private_log_collect end,status=%d", p_rsp->status);
    return DA_OK;
}

