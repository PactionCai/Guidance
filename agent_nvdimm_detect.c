/************************************************************
  Copyright (c) Huawei Technologies Co., Ltd. 2013-2020. All rights reserved.
  FileName: agent_op_net.c
  Author:  w00222163
  Version :
  Date: 2013-02-02
  Description: agent_op_net.c
  Version:
  Function List:
  History:
      <author>  <time>   <version >   <desc>
 ***********************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../interface/dswareAgent_interface.h"
#include "agent_nvdimm_detect.h"
#include "../config/dsware_agent_conf.h"
#include "../utility/agent_op_log.h"
#include "smio.h"
#include "../interface/fsa_op_smio.h"

#ifdef __cplusplus
extern "C" {
#endif

static dsw_int agent_nvdimm_query_dev(smio_media_intf_t *OUT nvdimm_info)
{
    smio_media_intf_req_t *media_info = NULL;
    int ret = DA_OK;

    if (NULL == nvdimm_info) {
        LOG_ERROR("input param is null");
        return DA_FAIL;
    }

    media_info = (smio_media_intf_req_t *)malloc(sizeof(smio_media_intf_req_t));
    if (NULL == media_info) {
        int errnum = errno;
        DSA_ERRNO_PRINT(errnum);
        LOG_ERROR("malloc media_info failed");
        return DA_FAIL;
    }
    memset_s(media_info, sizeof(smio_media_intf_req_t), 0, sizeof(smio_media_intf_req_t));

    ret = ioctl_scan_media_new(media_info);
    if (DA_OK != ret) {
        LOG_ERROR("scan media fail(%d)", ret);
        FREE_NO_JUDGE(media_info);
        return ret;
    }

    for (int i = 0; i < SMIO_MEDIA_MAX_PER_ENCLOURSE; i++) {
        // print info
        LOG_DEBUG("dev name=%s,esn=%s,model=%s,phy_slot=%d,capacity=%llu",
                  media_info->p_media_info[i].name, media_info->p_media_info[i].esn,
                  media_info->p_media_info[i].model, media_info->p_media_info[i].phy_slot,
                  media_info->p_media_info[i].capacity);

        if (SMIO_MEDIA_TYPE_NVDIMM == media_info->p_media_info[i].type) {
            memcpy_s(nvdimm_info, sizeof(*nvdimm_info), &media_info->p_media_info[i],
                     sizeof(*nvdimm_info));
            FREE_NO_JUDGE(media_info);
            return DA_OK;
        }
    }

    FREE_NO_JUDGE(media_info);
    LOG_ERROR("can'n found nvdimm");
    return DA_FAIL;
}

dsw_int agent_ioctl_nvdimm_info(nvdimm_alarm_info_t *nvdimm)
{
    dsw_int ret = DSWARE_AGENT_OK;
    smio_media_intf_t nvdimm_info;

    if (NULL == nvdimm) {
        LOG_ERROR("parameter dimms cannot be NULL");
        return DSWARE_AGENT_ERR;
    }

    memset_s(nvdimm, sizeof(nvdimm_alarm_info_t), 0, sizeof(nvdimm_alarm_info_t));

    memset_s(&nvdimm_info, sizeof(nvdimm_info), 0, sizeof(nvdimm_info));

    ret = agent_nvdimm_query_dev(&nvdimm_info);
    if (DA_OK != ret) {
        LOG_ERROR("query nvdimm fail");
        return ret;
    }
    nvdimm->health = nvdimm_info.hw_status;
    return DA_OK;
}

/*************************************************
  Function:         agent_check_nvdimm_invalid_unfill_alarm
  Description:     检测nvdimm的invalid和unfill告警信息
  Input: poolId
  Output: no
  Return:
         0:sucess
         1:检测到告警
  Others: no
*************************************************/
dsw_int agent_check_nvdimm_invalid_unfill_alarm(dsw_u16 poolId)
{
    nvdimm_alarm_info_t nvdimm;
    dsw_u8 nvdimm_switch = AGENT_NVDIMM_SWITCH_ON;

    memset_s(&nvdimm, sizeof(nvdimm_alarm_info_t), 0, sizeof(nvdimm_alarm_info_t));

    if (DSWARE_AGENT_OK != get_val_nvdimm_switch(&nvdimm_switch, poolId)) {
        LOG_ERROR("get nvdimm switch val failed!");
        return DA_FAIL;
    }

    if (nvdimm_switch == AGENT_NVDIMM_SWITCH_OFF) {
        return DA_OK;
    }

    if (DSWARE_AGENT_OK != agent_ioctl_nvdimm_info(&nvdimm)) {
        LOG_ERROR("agent check nvdimm info failed!");
        return DA_FAIL;
    }

    if (SMIO_MEDIA_RESPAWN == nvdimm.health) {
        LOG_ERROR("check nvdimm status alarm! health =%d ", nvdimm.health);
        return DA_ERR_NVDIMM_NOT_READY;
    }
    return DA_OK;
}

/*************************************************
  Function:         agent_check_nvdimm_not_invalid_unfill_alarms
  Description:     检测nvdimm的除了invalid和unfill之外的所有告警信息
  Input: poolId
  Output: no
  Return:
         0:sucess
         1:检测到告警
  Others: no
*************************************************/
dsw_int agent_check_nvdimm_not_invalid_unfill_alarms(dsw_u16 poolId)
{
    nvdimm_alarm_info_t nvdimm;
    dsw_u8 nvdimm_switch = AGENT_NVDIMM_SWITCH_ON;

    memset_s(&nvdimm, sizeof(nvdimm_alarm_info_t), 0, sizeof(nvdimm_alarm_info_t));

    if (DSWARE_AGENT_OK != get_val_nvdimm_switch(&nvdimm_switch, poolId)) {
        LOG_ERROR("get nvdimm switch val failed!");
        return DA_ERR_NVDIMM_CHK_FAIL;
    }

    if (nvdimm_switch == AGENT_NVDIMM_SWITCH_OFF) {
        return DA_OK;
    }

    if (DSWARE_AGENT_OK != agent_ioctl_nvdimm_info(&nvdimm)) {
        LOG_ERROR("agent check nvdimm info failed!");
        return DA_ERR_NVDIMM_CHK_FAIL;
    }

    if (SMIO_MEDIA_HEALTH_OK != nvdimm.health && SMIO_MEDIA_RESPAWN != nvdimm.health) {
        LOG_ERROR("check nvdimm status alarm! health=%d", nvdimm.health);
        return DA_ERR_NVDIMM_ALARM;
    }

    return DA_OK;
}

/*************************************************
  Function:         agent_check_nvdimm_all_status
  Description:     检测nvdimm的所有告警信息
  Input: poolId
  Output: no
  Return:
         0:sucess
         1:检测到告警
  Others: no
*************************************************/
dsw_int agent_check_nvdimm_all_alarms(dsw_u16 poolId)
{
    nvdimm_alarm_info_t nvdimm;
    dsw_u8 nvdimm_switch = AGENT_NVDIMM_SWITCH_ON;

    memset_s(&nvdimm, sizeof(nvdimm_alarm_info_t), 0, sizeof(nvdimm_alarm_info_t));

    if (DSWARE_AGENT_OK != get_val_nvdimm_switch(&nvdimm_switch, poolId)) {
        LOG_ERROR("get nvdimm switch val failed!");
        return DA_ERR_NVDIMM_CHK_FAIL;
    }

    if (nvdimm_switch == AGENT_NVDIMM_SWITCH_OFF) {
        return DA_OK;
    }

    if (DSWARE_AGENT_OK != agent_ioctl_nvdimm_info(&nvdimm)) {
        LOG_ERROR("agent check nvdimm info failed!");
        return DA_ERR_NVDIMM_CHK_FAIL;
    }

    if (SMIO_MEDIA_HEALTH_OK != nvdimm.health) {
        LOG_ERROR("check nvdimm status alarm! health =%d", nvdimm.health);

        return DA_ERR_NVDIMM_ALARM;
    }

    return DA_OK;
}

dsw_int agent_start_osd_check_nvdimm(dsw_u16 poolId)
{
    static dsw_u32 retry_count = 0;
    dsw_int ret = DA_OK;

    if (DA_OK != (ret = agent_check_nvdimm_invalid_unfill_alarm(poolId))) {
        LOG_DEBUG("agent nvdimm retval=%d", ret);
        if (DA_FAIL == ret) {
            return ret;
        }

        while (DA_ERR_NVDIMM_NOT_READY == ret) {
            retry_count++;

            if (retry_count > AGENT_NVDIMM_RETRY_COUNT) {
                retry_count = 0;
                return DA_ERR_NVDIMM_NOT_READY;
            }
            LOG_ERROR("nvdimm detect not ready, retry count=%d", retry_count);
            sleep(AGENT_NVDIMM_RETRY_TIME);
            ret = agent_check_nvdimm_invalid_unfill_alarm(poolId);
        }
    }

    return DA_OK;
}
