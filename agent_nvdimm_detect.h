/*************************************************
  Copyright (c) Huawei Technologies Co., Ltd. 2013-2020. All rights reserved.
  File name:    agent_op_log.h
  Author: w00222163
  Version:
  Date: 2013-02-2
  Description:  nvdimm detect
*************************************************/

#ifndef _AGENT_NVDIMM_DETECT_H_
#define _AGENT_NVDIMM_DETECT_H_
#include "../dsw_typedef.h"

#pragma pack(1)

typedef struct nvdimm_alarm_info {
    unsigned int health; /* µçÈÝÎ´³äÂú¸æ¾¯¡£ */
} nvdimm_alarm_info_t;

#define AGENT_MANAGER_IOCTL_DIMM_NAME "/dev/dsw"

#define AGENT_IOCTL_GET_DSW_DIMM 0x10016

#define AGENT_NVDIMM_ALARM_VALUE   1
#define AGENT_NVDIMM_NORMAL_VALUE  0
#define AGENT_NVDIMM_INVALID_VALUE (-1)
#define AGENT_NVDIMM_RETRY_TIME    30
#define AGENT_NVDIMM_RETRY_COUNT   10

#define agent_nvdimm_alarm(alarm_type)   (AGENT_NVDIMM_ALARM_VALUE == (alarm_type))
#define agent_nvdimm_normal(alarm_type)  (AGENT_NVDIMM_NORMAL_VALUE == (alarm_type))
#define agent_nvdimm_invalid(alarm_type) (AGENT_NVDIMM_INVALID_VALUE == (alarm_type))

dsw_int agent_ioctl_nvdimm_info(nvdimm_alarm_info_t *nvdimm);
dsw_int agent_check_nvdimm_all_alarms(dsw_u16 poolId);
dsw_int agent_check_nvdimm_not_invalid_unfill_alarms(dsw_u16 poolId);
dsw_int agent_start_osd_check_nvdimm(dsw_u16 poolId);
dsw_int agent_check_nvdimm_invalid_unfill_alarm(dsw_u16 poolId);
#pragma pack()
#endif

