/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: Transport Module Source File
 * Author: c00654545
 * Create: 2022-4-30
 *
 */

#include "dsa_cli_cmd.h"
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

typedef int (*CliMsgParser)(const void *msg, size_t msgLen, void **parsedMsg, size_t *parsedMsgLen);
typedef int (*CliMsgHandler)(void *parsedMsg, size_t parsedMsgLen);
typedef void (*CliMsgDestroyer)(void *parsedMsg);

typedef struct {
    int itemId;
    int memberOffset;
    int memberSize;
} DsaCliMsgMap;

typedef struct {
    dsw_u64 opCode;
    DsaCliMsgMap map;
    CliMsgParser parser;
    CliMsgHandler handler;
    CliMsgDestroyer destroyer;
} DsaCliHandlerMap;



static const DsaCliMsgMap g_CliMsgMap[] = {
    {64, 8}
};

int DsaCliMsgDefaultParser(const void *msgObj, void **parsedMsg, size_t *parsedMsgLen, DsaCliMsgMap *map, size_t mapSize)
{
    *parsedMsgLen = 0;
    for (int i = 0; i < mapSize; ++i) {
        if (map[i].itemId < 0 || map[i].memberSize < 0) {
            break;
        }
        *parsedMsgLen += map[i].memberSize;
    }
    *parsedMsg = DSA_ZMALLOC(*parsedMsgLen);
    for (int i = 0; i < mapSize; ++i) {
        if (map[i].itemId < 0 || map[i].memberSize < 0) {
            break;
        }

        dsw_u8 *data = NULL;
        dsw_u32 dataLen = 0;
        dsw_u16 type = MSGOBJ_GetItemType(msgObj, 0, map[i].itemId);
        if (type == MSGOBJ_ITEM_TYPE_BLOB) {
            MSGOBJ_GetItemBlob(msgObj, 0, map[i].itemId, &data, &dataLen);
        } else if (type == MSGOBJ_ITEM_TYPE_STRING) {

        } else if (type == MSGOBJ_ITEM_TYPE_STRING) {
            
        }

        memcpy_s();
        *parsedMsgLen += map[i].memberSize;
    }
    return DA_OK;
}

int DsaCliMsgDefaultHandler(void *parsedMsg, size_t parsedMsgLen)
{
    return DA_OK;
}

void DsaCliMsgDefaultDestroyer(void *parsedMsg)
{
    return;
}

int DsaCliGetLogInfoReqParser(const void *msg, size_t msgLen, void **parsedMsg, size_t *parsedMsgLen)
{
    return DA_OK;
}

int DsaCliMsgDefaultHandler(void *parsedMsg, size_t parsedMsgLen)
{
    return DA_OK;
}

void DsaCliMsgDefaultDestroyer(void *parsedMsg)
{
    return;
}

static const DsaCliHandlerMap g_cliHandlerTable[] = {
    {0x00000001, {{64, 0, 8}, {-1, -1, -1}}, DsaCliMsgDefaultParser, DsaCliMsgDefaultHandler, DsaCliMsgDefaultDestroyer}
};

int DsaSendDataOverNetSocket(int fd, const void *data, size_t len, bool openssl, SSL *sslCtx)
{
    if (openssl) {
        int ret = do_write(fd, data, len);
        if (ret != len) {
            LOG_ERROR("send socket data failed: %d/%zu", ret, len);
            return DA_ERR_NET_SEND;
        }
    } else {
        int ret = openssl_write(sslCtx, data, len);
        if (ret != len) {
            LOG_ERROR("send ssl data failed: %d/%zu", ret, len);
            return DA_ERR_NET_SEND;
        }
    }
    return DA_OK;
}

/*****************************************************************
Parameters    :  session
                 rsp
Return        :  void
Description   :  向fsm发送response
*****************************************************************/
int DsaSendRespToClient(int fd, ev_user_data_t *userData, const dsware_agent_rsp_hdr *rsp)
{
    // check input parameter(s)
    if (fd < 0 || userData == NULL || rsp == NULL) {
        LOG_ERROR("invalid input param");
        return DA_ERR_PARA;
    }

    // write audit log
    response_write_aduit_log(fd, req, rsp->status);

    // send response header over net socket
    int ret = DsaSendDataOverNetSocket(fd, rsp, sizeof(rsp->status) + sizeof(rsp->length),
                                       userData->openssl_flag, userData->p_ssl);
    if (ret != DA_OK) {
        LOG_ERROR("send response header over net socket failed: %d", ret);
        return ret;
    }

    // send response payload over net socket
    if (rsp->length > 0) {
        ret = DsaSendDataOverNetSocket(fd, rsp->value, rsp->length, userData->openssl_flag, userData->p_ssl);
        if (ret != DA_OK) {
            LOG_ERROR("send response payload over net socket failed: %d", ret);
            return ret;
        }
    }
    return DA_OK;
}

int DsaSendRespStatusToClient(int fd, ev_user_data_t *userData, int status)
{
    dsware_agent_rsp_hdr resp = {0};
    resp.status = status;
    return DsaSendRespToClient(fd, userData, &resp)
}

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
        LOG_ERROR("parse the cli request payload as tlv format failed: %d");
        return DA_ERR_PARA;
    }

    dsw_u64 opCode = 0;
    MSGOBJ_GetRecordOpcode(payload, 0, &opCode);
    dsw_s32 tlvErr = MSGOBJ_GetLastError(payload);
    if (tlvErr != RETURN_OK) {
        LOG_ERROR("get op code from tlv message failed: %d", tlvErr);
        MSGOBJ_Destroy(payload);
        return DA_ERR_PARA;
    }

    for (int i = 0; i < ARRAY_LEN(g_cliHandlerTable); ++i) {
        if (opCode != g_cliHandlerTable[i].opCode) {
            continue;
        }
        char *parsedMsg = NULL;
        size_t parsedMsgLen = 0;
        int ret = g_cliHandlerTable[i].parser(msg->payload, msg->payloadLen, &parsedMsg, &parsedMsgLen);
        if (ret != DA_OK) {
            LOG_ERROR("parse the cli request payload by parser failed: %d, op code: 0x%llx", ret, opCode);
            (void)DsaSendRespStatusToClient(fd, userData, ret);
            return ret;
        }
        ret = g_cliHandlerTable[i].handler(parsedMsg, parsedMsgLen);
        g_cliHandlerTable[i].destroyer(parsedMsg);
        if (ret != DA_OK) {
            LOG_ERROR("handle the cli request failed: %d, op code: 0x%llx", ret, opCode);
            (void)DsaSendRespStatusToClient(fd, userData, ret);
            return ret;
        }
        return DA_OK;
    }
    LOG_ERROR("cannot find the op code: 0x%llx from the table: %d", opCode);
    (void)DsaSendRespStatusToClient(fd, userData, DA_ERR_TYPE);
    return DA_ERR_TYPE;
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
