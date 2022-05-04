/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: Transport Module Source File
 * Author: c00654545
 * Create: 2022-4-30
 *
 */

#include "dsa_transport.h"
#include <string.h>
#include <stdint.h>
#include "../config/dsware_agent_conf.h"
#include "../utility/agent_op_log.h"
#include "../utility/mem_util.h"
#include "../interface/msg_obj.h"



// Description:   get the component working status
// Input:   status_buf  :   pre-allocated buffer to save the status
//          buf_size    :   the size of pre-allocated buffer
// Output:  status_buf  :   working status
// Return:  DA_OK   :   success
//          *       :   failure
// Note:    private function
int DsaTransportCliCmdHandler(const void *msg, size_t msgLen)
{
    return DA_OK;
}

// Description:   get the component working status
// Input:   status_buf  :   pre-allocated buffer to save the status
//          buf_size    :   the size of pre-allocated buffer
// Output:  status_buf  :   working status
// Return:  DA_OK   :   success
//          *       :   failure
// Note:    private function
int DsaParseTransportMsg(const void *msg, size_t msgLen)
{
    return DA_OK;
}

// Description:   get the component working status
// Input:   status_buf  :   pre-allocated buffer to save the status
//          buf_size    :   the size of pre-allocated buffer
// Output:  status_buf  :   working status
// Return:  DA_OK   :   success
//          *       :   failure
// Note:    private function
int DsaAsyncSendTransportMsgToDest(void *header, const void *msg, size_t msgLen)
{
    return DA_OK;
}

typedef struct {
    uint32_t serviceId;
    char msgType[32];
    uint16_t pid;
    uint16_t subPid;
    uint16_t msgPeriod;
    uint16_t port;
    uint32_t opCode;
} DsaUcChannelParam;

typedef struct {
    uint16_t port;
} DsaDatanetChannelParam;

typedef struct {
    uint64_t sessionId;
    uint32_t timeoutMs;
    char destProcess[64];
    char channelType[64];
    DsaUcChannelParam ucParam;
    DsaDatanetChannelParam datanetParam;
    size_t payloadLen;
    char payload[0];
} DsaTransportMsg;


extern int ParseCliMsg(const dsware_agent_req_hdr *req, DsaTransportMsg **msg);
extern int HandleTransportMsg(const DsaTransportMsg *msg, int fd, ev_user_data_t *userData);

// Description:   handle the message from cli to fsa
// Input:   msg         :   the parsed request message received from external client
//          fd          :   the file description of the communation socket
//          userData    :   user context
// Return:  DA_OK   :   success
//          *       :   failure
int HandleDsaChannelMsg(const DsaTransportMsg *msg, int fd, ev_user_data_t *userData)
{
    void *payload = MSGOBJ_Decode(msg->payload, msg->payloadLen);
    if (payload == NULL) {
        LOG_ERROR("parse the cli request payload as tlv format failed %d");
        return DA_ERR_PARA;
    }

    dsw_u64 opCode = 0;
    MSGOBJ_GetRecordOpcode(payload, 0, &opCode);

    return DA_OK;
}

// Description:   transport message entrance handler
// Input:   req         :   the request received from external client
//          fd          :   the file description of the communation socket
//          userData    :   user context
// Return:  DA_OK   :   success
//          *       :   failure
int DsaAsyncTransportMsgHandler(dsware_agent_req_hdr *req, int fd, ev_user_data_t *userData)
{
    // check input parameter(s)
    if (req == NULL || fd < 0 || userData == NULL) {
        LOG_ERROR("invalid input param");
        return DA_ERR_PARA;
    }

    // parse the cli request message
    DsaTransportMsg *msg = NULL;
    int ret = ParseCliMsg(req, &msg);
    if (ret != DA_OK) {
        LOG_ERROR("parse the cli request message failed %d", ret);
        return DA_ERR_PARA;
    }

    // handle the cli request message
    ret = HandleTransportMsg(msg, fd, userData);
    DSA_FREE(msg);
    if (ret != DA_OK) {
        LOG_ERROR("handle the cli request message failed %d", ret);
        return ret;
    }
    return DA_OK;
}


static pthread_t g_TesterThreadId = 0;
// Description:   cli transport tester main function
// Return:  NULL
// Note:    private function
static void *DsaCliTransportTester(void *arg)
{
    while (1) {

    }
    return NULL;
}

int DsaStartCliTransportTester(void)
{
    int ret = pthread_create(&g_TesterThreadId, NULL, DsaCliTransportTester, NULL);
    if (ret != 0) {
        LOG_ERROR("create cli transport tester thread failed %d", ret);
        return DA_FAIL;
    }
    LOG_INFO("create cli transport tester success.");
    return DA_OK;
}
