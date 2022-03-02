/*************************************************
   Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
  File name:    agent_op_config.h
  Author: l00130209
  Version:
  Date: 2012-07-17
  Description:  Configuration file read and write capabilities
*************************************************/

#ifndef __DSWARE_OSD_HEARLTHY_MONITOR_H__
#define __DSWARE_OSD_HEARLTHY_MONITOR_H__

#include "../interface/dswareAgent_interface.h"
#include "agent_process_monitor.h"
#include "core_agent_msg.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define MONITOR_INFO_IS_MONITOR       "is_monitor"
#define MONITOR_INFO_OUT              "out_reason"
#define MONITOR_INFO_AUTOIN           "auto_in_times"
#define MONITOR_INFO_REASON_LAST_TIME "auto_in_reason_last_time"
#define MONITOR_INFO_CHECK            "auto_in_check_times"
#define MONITOR_INFO_AVOID_SHAKE      "avoid_shake_time"
#define MONITOR_INFO_SYS_RESOURCE     "out_sys_resource"

#define MONITOR_INFO_VNODE_ID     "vnode_id"
#define MONITOR_INFO_ADD_FLAG     "add_flag"

extern int get_offset(const char *type);
extern int get_osd_monitor_process_info_from_file(int id, const char *type, dsw_u16 pool_id, int *OUT value);
extern int update_fault_recover_info(process_node *p_process);
extern int check_and_save_detail_retcode(process_node *p_process, int detail_retcode);
extern int da_set_osd_out_reason(core_agent_msg_t *p_hb_req);
extern int osd_power_on_and_turn_up(const char *dev_name, dsw_u32 slot_id);
extern int high_temperature_shutdown_handle(void);
extern void auto_in_Callback(void *p_arg);
extern int get_pool_media_cache_type(dsw_u16 pool_id, char *OUT cache_type);
extern int get_cache_esn_info(const char *media_type, const char *dev_name,
                              dsw_u64 start_lba, char *OUT cache_esn);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* __DSWARE_OSD_HEARLTHY_MONITOR_H__ */


