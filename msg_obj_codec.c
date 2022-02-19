/*******************************************************************
Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.

Filename      : msg_obj_codec.c
Author        : z00337844
Creation time : 2016/8/1
Description   : 提供tlv消息的编解码
                原始代码来自于omm,fsa做了部分适配
                1.日志使用fsa日志模块打印
                2.数据类型使用dsw_typedef.h中的定义
                3.删除部分接口中不需要的参数
                


Version       : 1.0
********************************************************************/
#include "../utility/agent_op_log.h"
#include "securec.h"
#include "../interface/msg_obj.h"
#include "msg_obj_codec.inc"

#define LVOS_Malloc(byte) malloc(byte)
#define LVOS_MallocSub(byte, func) malloc(byte)
#define LVOS_Free(ptr) free(ptr)

#define RETURN_PARAM_ERROR 0x3000003  // 参数错误。
#define RETURN_SSP(code) (0x01000000 + (code))
#define RETURN_MSG_CODE_ITEM_ERROR RETURN_SSP(0x300) /* 消息通信编解码获取元素类型不匹配 */

/*****************************************************************************
 函 数 名  : MSGOBJ_CreateSub
 功能描述  : 创建一个Obj
 输入参数  : dsw_u32 uiMaxRecord
             dsw_u32 uiMaxItemId
             const char *v_pFunction
             dsw_u32 v_uiLine
 输出参数  : 无
 返 回 值  : void *
 调用函数  : void
 被调函数  : void

 修改历史      :
  1.日    期   : 2008年12月6日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
void *MSGOBJ_CreateSub(dsw_u32 uiMaxRecord, dsw_u32 uiMaxItemId, const char *v_pFunction, dsw_u32 v_uiLine,
                       dsw_u64 v_ullCallerAddr)
{
    dsw_u32 uiObjSize;
    MSGOBJ_S *pObjMem = NULL;
    void *pObjTmp = NULL; /* 为了处理pclint误报，定义临时变量 */

    if ((0 == uiMaxRecord) || (uiMaxRecord > MSGOBJ_MAX_RECORD_NUM) || (uiMaxItemId >= MSGOBJ_MAX_ITEM_NUM)) {
        LOG_ERROR(
            "The input param(max-record-num %u, max-item-num %u) is invalid when create obj at line (%d) of function (%s).",
            uiMaxRecord, uiMaxItemId, v_uiLine, v_pFunction);
        return NULL;
    }

    /* 内存 = obj头 + ((rec头 + (item * 数量)) * 数量) */
    uiObjSize = sizeof(MSGOBJ_S) +
                ((sizeof(MSGOBJ_RECORD_S) + (sizeof(MSGOBJ_ITEM_S) * MSGOBJ_ITEM_NUM(uiMaxItemId))) * uiMaxRecord);

    pObjTmp = LVOS_MallocSub(uiObjSize, v_ullCallerAddr);

    if (NULL == pObjTmp) {
        LOG_ERROR("The (%d)'th line of (%s) allocate buffer for message object failed.", v_uiLine, v_pFunction);
        return NULL;
    }

    /* 初始化 */
    memset_s(pObjTmp, uiObjSize, 0, uiObjSize);

    pObjMem = pObjTmp;
    pObjMem->uiMagic = MSG_OBJ_MAGIC;
    pObjMem->uiRecordNum = uiMaxRecord;
    pObjMem->uiItemNum = MSGOBJ_ITEM_NUM(uiMaxItemId);

    return pObjMem;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_GetObjInfoSub
 功能描述  : 取对象的基本信息
 输入参数  : void *pMsgObj
             dsw_u32 *puiMsgLength
             dsw_u32 *puiMaxRecord
             dsw_u32 *puiMaxItemId
             dsw_u64 *pullFirstOpCode
 输出参数  : 无
 返 回 值  : dsw_s32
 调用函数  : void
 被调函数  : void

 修改历史      :
  1.日    期   : 2008年12月9日
    作    者   : renshifei 00001615 gaoyong 00002868
    修改内容   : 新生成函数

*****************************************************************************/
dsw_s32 MSGOBJ_GetObjInfoSub(void *pMsgObj, dsw_u32 *puiMsgLength, dsw_u32 *puiMaxRecord, dsw_u64 *pullFirstOpCode,
                             const char *v_pFunction, dsw_u32 v_uiLine)
{
    dsw_u32 uiRecIndex;
    dsw_u32 uiMsgLength = 0;
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_RECORD_S *pRecord = NULL;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR(
            "The object is invalid which is input at (%d)'th line of function (%s) when getting object information.",
            v_uiLine, v_pFunction);
        return RETURN_ERROR;
    }

    if (NULL != puiMsgLength) {
        /* 遍历Record计算编码后长度 */
        for (uiRecIndex = 0; uiRecIndex < pObj->uiRecordNum; uiRecIndex++) {
            pRecord = GET_RECORD_BY_ID(pMsgObj, uiRecIndex);
            /* 如果长度不为0，则认为有Item使用，Record内容 + 头长度 */
            if (0 != pRecord->usLength) {
                uiMsgLength += (pRecord->usLength + sizeof(MSGOBJ_RECORD_S));
            } else if (0 != pRecord->ullOpCode) { /* 仅Opcode有效，则只计算头长度 */
                uiMsgLength += sizeof(MSGOBJ_RECORD_S);
            }
        }

        /* 输出参数并更新Obj有效长度 */
        *puiMsgLength = uiMsgLength;
        pObj->uiMsgLength = uiMsgLength;
    }

    if (NULL != puiMaxRecord) {
        *puiMaxRecord = pObj->uiRecordNum;
    }

    /* 第一个Record的地址 */
    pRecord = (void *)(pObj->aucRecords); /* 数组转为void指针 */
    if (NULL != pullFirstOpCode) {
        *pullFirstOpCode = pRecord->ullOpCode;
    }

    return RETURN_OK;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_FillDataInMsg
 功能描述  : 从Obj填充数据到Msg
 输入参数  : void *pMsgObj
             void *pMsg
 输出参数  : 无
 返 回 值  : void
 调用函数  : void
 被调函数  : void

 修改历史      :
  1.日    期   : 2008年12月13日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_FillDataInMsg(void *pMsgObj, void *pMsg)
{
    dsw_u32 uiRecIndex, uiItemIndex;
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_RECORD_S *pRecord = NULL;
    MSGOBJ_ITEM_S *pItem = NULL;
    void *pMsgTmp = pMsg;

    /* 本函数为MSGOBJ_Encode的子函数，参数合法性有保证，不再检查 */
    /* 遍历obj，拷贝内容到msg */
    for (uiRecIndex = 0; uiRecIndex < pObj->uiRecordNum; uiRecIndex++) {
        pRecord = GET_RECORD_BY_ID(pMsgObj, uiRecIndex);

        /* 没有Opcode，也没有Item */
        if ((0 == pRecord->ullOpCode) && (0 == pRecord->usLength)) {
            continue;
        }

        ((MSGOBJ_RECORD_S *)pMsgTmp)->ullOpCode = pRecord->ullOpCode;
        ((MSGOBJ_RECORD_S *)pMsgTmp)->usLength = pRecord->usLength;

        /* 偏移到数据区，转换为char *进行偏移 */
        pMsgTmp = (char *)pMsgTmp + sizeof(MSGOBJ_RECORD_S);

        /* 没有填 */
        if (0 == pRecord->usLength) {
            continue;
        }

        /* 填写了Item */
        for (uiItemIndex = 0; uiItemIndex < pObj->uiItemNum; uiItemIndex++) {
            pItem = GET_ITEM_BY_ID(pMsgObj, uiRecIndex, uiItemIndex);
            if (0 == pItem->usLength) { /* Item有效长度为0，继续下一个 */
                continue;
            }

            /* 数据块和字符串处理方法一致 */
            if ((MSGOBJ_ITEM_TYPE_BLOB == pItem->usType) || IS_STRING_ITEM_TYPE(pItem->usType)) {
                memcpy_s(&(((MSGOBJ_ITEM_S *)pMsgTmp)->Value.ullLong), pItem->usLength, pItem->Value.pData,
                         pItem->usLength);
            } else if (IS_UNSIGNED_ITEM_TYPE(pItem->usType)
                || (MSGOBJ_ITEM_TYPE_SIGNED == pItem->usType)) { /* 有符号数和无符号数处理方法一致 */
                memcpy_s(&(((MSGOBJ_ITEM_S *)pMsgTmp)->Value.ullLong), pItem->usLength, &(pItem->Value.ullLong),
                         pItem->usLength);
            } else { /* 类型错误，忽略该ITEM，继续处理下一个Item */
                LOG_ERROR("Data type (%d) is invalid.", pItem->usType);
                continue;
            }

            /* 类型正确，填入类型、ID、长度到消息体中 */
            ((MSGOBJ_ITEM_S *)pMsgTmp)->usType = pItem->usType;
            ((MSGOBJ_ITEM_S *)pMsgTmp)->usCmo = pItem->usCmo;
            ((MSGOBJ_ITEM_S *)pMsgTmp)->usLength = pItem->usLength;

            /* 移动指针到未填充区域，转换为char *偏移 */
            pMsgTmp = (void *)((char *)pMsgTmp + (pItem->usLength + MSGOBJ_ITEM_HEAD_LEN));
        }
    }
}

/*****************************************************************************
 函 数 名  : MSGOBJ_SetError
 功能描述  : 设置Item操作失败标志
 输入参数  : void *pMsgObj
             dsw_u32 uiRecordId
             dsw_u32 uiItemId
             dsw_s32 iErrorCode
 输出参数  : 无
 返 回 值  : void
 调用函数  : no void
 被调函数  : no void

 修改历史      :
  1.日    期   : 2009年2月10日
    作    者   : zhouzhengjuan90001778
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_SetError(void *pMsgObj, dsw_s32 iErrorCode)
{
    MSGOBJ_S *pObj = pMsgObj;

    pObj->iErrFlag = iErrorCode;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_ClearErrorSub
 功能描述  : 清除设置的错误标志
 输入参数  : void *pMsgObj
 输出参数  : 无
 返 回 值  : void
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2009年2月10日
    作    者   : zhouzhengjuan90001778
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_ClearErrorSub(void *pMsgObj, const char *v_pFunction, dsw_u32 v_uiLine)
{
    MSGOBJ_S *pObj = pMsgObj;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when clearing error.",
                  v_uiLine, v_pFunction);
        return;
    }

    LOG_DEBUG("MsgObj Error Cleared!");
    pObj->iErrFlag = 0;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_GetLastErrorSub
 功能描述  : 获取最后一个错误标志
 输入参数  : void *pMsgObj
 输出参数  : 无
 返 回 值  : dsw_s32
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2009年2月10日
    作    者   : zhouzhengjuan90001778
    修改内容   : 新生成函数

*****************************************************************************/
dsw_s32 MSGOBJ_GetLastErrorSub(void *pMsgObj, const char *v_pFunction, dsw_u32 v_uiLine)
{
    MSGOBJ_S *pObj = pMsgObj;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when getting last error.",
                  v_uiLine, v_pFunction);
        return RETURN_ERROR;
    }

    if ((RETURN_OK != pObj->iErrFlag)) {
        LOG_ERROR("There is error when getting object at (%d)'th line of function (%s)", v_uiLine, v_pFunction);
    }

    return pObj->iErrFlag;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_CopyObjData
 功能描述  : 扩展Reocrd时copy数据的子函数
 输入参数  : MSGOBJ_S *pOldObj
             MSGOBJ_S *pNewObj
 输出参数  : 无
 返 回 值  : dsw_s32
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2009年2月10日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
dsw_s32 MSGOBJ_CopyObjData(MSGOBJ_S *pOldObj, MSGOBJ_S *pNewObj)
{
    dsw_u32 iLoop;
    dsw_u32 len = 0;
    /* 每个record单独copy */
    for (iLoop = 0; iLoop < pOldObj->uiRecordNum; iLoop++) {
        len = sizeof(MSGOBJ_RECORD_S) + sizeof(MSGOBJ_ITEM_S) * pOldObj->uiItemNum;

        memcpy_s(GET_RECORD_BY_ID(pNewObj, iLoop), len, GET_RECORD_BY_ID(pOldObj, iLoop), len);
    }

    return RETURN_OK;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_ExtendSub
 功能描述  : 扩展Obj的Record数或Item数
 输入参数  : void *pMsgObj
             dsw_u32 uiMaxRecord
             dsw_u32 uiMaxItemId
 输出参数  : 无
 返 回 值  : void *
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2009年2月10日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
void *MSGOBJ_ExtendSub(void *pMsgObj, dsw_u32 uiMaxRecord, dsw_u32 uiMaxItemId, const char *v_pFunction,
                       dsw_u32 v_uiLine)
{
    dsw_s32 iRet;
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_S *pNewObj = NULL;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when extending object.",
                  v_uiLine, v_pFunction);
        return NULL;
    }

    if ((uiMaxRecord < pObj->uiRecordNum) || (MSGOBJ_ITEM_NUM(uiMaxItemId) < pObj->uiItemNum)) {
        LOG_ERROR(
            "The input param(max-record-num %u, max-item-num %u) is invalid when extending object at line (%d) of function (%s).",
            uiMaxRecord, uiMaxItemId, v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return NULL;
    }

    /* 根据参数创建新obj */
    pNewObj = MSGOBJ_Create(uiMaxRecord, uiMaxItemId);
    if (NULL == pNewObj) {
        return pNewObj;
    }

    /* copy头并重设 record,item 数量 */
    memcpy_s(pNewObj, sizeof(MSGOBJ_S), pObj, sizeof(MSGOBJ_S));
    pNewObj->uiRecordNum = uiMaxRecord;
    pNewObj->uiItemNum = MSGOBJ_ITEM_NUM(uiMaxItemId);

    /* copy原数据到新obj */
    iRet = MSGOBJ_CopyObjData(pObj, pNewObj);
    if (RETURN_OK != iRet) {
        LOG_ERROR("Fail to copy date to object when extending object, the caller function is (%s).", v_pFunction);
        MSGOBJ_Destroy(pNewObj);
        return NULL;
    }

    /* 清内存使用记录，释放原obj */
    pObj->usMemIndex = 0;
    memset_s(pObj->apMem, sizeof(void *) * MSGOBJ_MAX_MEM_NUM, 0, sizeof(void *) * MSGOBJ_MAX_MEM_NUM);
    MSGOBJ_Destroy(pObj);

    return pNewObj;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_EncodeSub
 功能描述  : 消息对象编码
 输入参数  : void *pMsgObj
 输出参数  : void *pMsg
             dsw_u32 uiMsgMaxLen
 返 回 值  : dsw_s32
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月10日
    作    者   : renshifei 00001615 gaoyong 00002868
    修改内容   : 新生成函数

*****************************************************************************/
dsw_s32 MSGOBJ_EncodeSub(void *pMsgObj, void *pMsg, dsw_u32 uiMsgMaxLen, const char *v_pFunction, dsw_u32 v_uiLine)
{
    dsw_s32 iRet;
    MSGOBJ_S *pObj = pMsgObj;
    dsw_u32 uiMsgLength = 0;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when encoding object.",
                  v_uiLine, v_pFunction);
        return RETURN_ERROR;
    }

    if ((NULL == pMsg) || (0 == uiMsgMaxLen)) {
        LOG_ERROR(
            "The input message is invalid or the message length (%u) is invalid which is input at (%d)'th line of function (%s) when encoding object.",
            uiMsgMaxLen, v_uiLine, v_pFunction);
        return RETURN_PARAM_ERROR;
    }

    /* 检查设置过程中是否有错误 */
    if (0 != pObj->iErrFlag) {
        LOG_ERROR("There have errors when set item for function (%s).", v_pFunction);
        return RETURN_ERROR;
    }

    /* 获取Obj编码后长度 */
    iRet = MSGOBJ_GetObjInfo(pMsgObj, &uiMsgLength, NULL, NULL);
    if (RETURN_OK != iRet) {
        LOG_ERROR("Fail to get object information for function (%s).", v_pFunction);
        return RETURN_ERROR;
    }

    if (uiMsgLength > uiMsgMaxLen) {
        LOG_ERROR("The input object's length (%u) is larger than object's real length (%u) from function (%s).",
                  uiMsgMaxLen, uiMsgLength, v_pFunction);
        return RETURN_ERROR;
    }

    /* 填充数据到Msg */
    MSGOBJ_FillDataInMsg(pMsgObj, pMsg);

    return RETURN_OK;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_SetRecordOpcodeSub
 功能描述  : 设置各记录的Opcode
 输入参数  : void *pMsgObj
             dsw_u32 uiRecordId
             dsw_u64 ullOpcode
 输出参数  : 无
 返 回 值  : void
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月9日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_SetRecordOpcodeSub(void *pMsgObj, dsw_u32 uiRecordId, dsw_u64 ullOpcode, const char *v_pFunction,
                               dsw_u32 v_uiLine)
{
    dsw_u32 uiRecIndex;
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_RECORD_S *pRecord = NULL;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when setting record opcode.",
                  v_uiLine, v_pFunction);
        return;
    }

    if ((MSGOBJ_INVALID_RECORD_ID != uiRecordId) && (uiRecordId >= pObj->uiRecordNum)) {
        LOG_ERROR(
            "The record id (%d) is larger than the max-record-num (%u) when setting object record at line (%d) of function (%s).",
            uiRecordId, pObj->uiRecordNum, v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    /* 设置所有还是单个Record */
    if (MSGOBJ_INVALID_RECORD_ID == uiRecordId) {
        /* 遍历Record设置Opcode */
        for (uiRecIndex = 0; uiRecIndex < ((MSGOBJ_S *)pMsgObj)->uiRecordNum; uiRecIndex++) {
            pRecord = GET_RECORD_BY_ID(pMsgObj, uiRecIndex);

            pRecord->ullOpCode = ullOpcode;
        }
    } else {
        pRecord = GET_RECORD_BY_ID(pMsgObj, uiRecordId);

        pRecord->ullOpCode = ullOpcode;
    }

    return;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_GetMem
 功能描述  : 为String和Blob类型申请空间
 输入参数  : MSGOBJ_S *pObj
             dsw_u32 uiMemSize
 输出参数  : 无
 返 回 值  : void *
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月11日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
void *MSGOBJ_GetMem(MSGOBJ_S *pObj, dsw_u16 usMemSize)
{
    void *pObjMem = NULL;

    if (NULL == pObj || usMemSize <= 0) {
        LOG_ERROR("param is wrong");
        return NULL;
    }

    /* 检查已有的内存是否够用，初次使用则在下面分配 */
    if (usMemSize < pObj->usMemFree) {
        /* 找到未用的起始内存地址 */
        pObjMem = (char *)pObj->apMem[pObj->usMemIndex] + MSGOBJ_MIN_MEM_SIZE - pObj->usMemFree;

        /* 更新剩余字节数 */
        pObj->usMemFree -= usMemSize;

        return pObjMem;
    } else if ((pObj->usMemIndex + 1) == MSGOBJ_MAX_MEM_NUM) { /* 内存已用完 */
        LOG_ERROR("There does not have enough memory when getting memory, it already used (%d) blocks.",
                  MSGOBJ_MAX_MEM_NUM);
        return NULL;
    }

    if (usMemSize > MSGOBJ_MIN_MEM_SIZE) { /* 大于8k小于30k的独立申请 */
        pObjMem = LVOS_Malloc(usMemSize);
    } else { /* 小于8k的统一申请后共享 */
        pObjMem = LVOS_Malloc(MSGOBJ_MIN_MEM_SIZE);
    }

    if (NULL == pObjMem) {
        LOG_ERROR("Fail to allocate fail memory.");
        return NULL;
    }

    /* 如果第一块内存为NULL，认为是首次分配 */
    if (NULL == pObj->apMem[0]) {
        pObj->usMemIndex = 0;
    } else {
        pObj->usMemIndex += 1;
    }

    /* 记录已申请内存信息 */
    pObj->apMem[pObj->usMemIndex] = pObjMem;

    /* 更新剩余内存信息 */
    if (usMemSize > MSGOBJ_MIN_MEM_SIZE) {
        pObj->usMemFree = 0;
    } else {
        pObj->usMemFree = MSGOBJ_MIN_MEM_SIZE - usMemSize;
    }

    return pObjMem;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_SetItemStringSub
 功能描述  : 设置字符串类型数据
 输入参数  : void *pMsgObj
             dsw_u32 uiRecordId
             dsw_u32 uiItemId
             char *szString
 输出参数  : 无
 返 回 值  : void
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月9日
    作    者   : renshifei 00001615 gaoyong 00002868
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_SetItemStringSub(void *pMsgObj, dsw_u32 uiRecordId, dsw_u32 uiItemId, const char *szString, dsw_u16 usType,
                             const char *v_pFunction, dsw_u32 v_uiLine)
{
    dsw_u16 usStrLength;
    void *pObjMem = NULL;
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_ITEM_S *pItem = NULL;
    MSGOBJ_RECORD_S *pRecord = NULL;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when setting item string.",
                  v_uiLine, v_pFunction);
        return;
    }

    if (NULL == szString) {
        LOG_ERROR("The input string is NULL at (%d)'th line of function (%s) when setting item string.", v_uiLine,
                  v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    if ((uiRecordId >= pObj->uiRecordNum) || (MSGOBJ_ITEM_NUM(uiItemId) > pObj->uiItemNum) ||
        (strlen(szString) >= MSGOBJ_MAX_MEM_SIZE)) {
        LOG_ERROR(
            "Parameter(input-record-id %d, input-item-id %d, obj-record-num %d, obj-item-num %d, string-length %d, line %d, FUNC %s) is invalid.",
            uiRecordId, uiItemId, pObj->uiRecordNum, pObj->uiItemNum, strlen(szString), v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    /* 字符串长度 + 结束符，strlen返回int类型，内部记录为U16 */
    usStrLength = (dsw_u16)strlen(szString) + 1;
    pRecord = GET_RECORD_BY_ID(pMsgObj, uiRecordId);

    pObjMem = MSGOBJ_GetMem(pObj, usStrLength);
    if (NULL == pObjMem) {
        LOG_ERROR("Fail to get memory at (%d)'th line of function (%s).", v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_ERROR);
        return;
    }

    /* 最后一个字节放'\0'结束符 */
    strncpy_s(pObjMem, usStrLength, szString, usStrLength);

    /* 在item中记录 */
    pItem = GET_ITEM_BY_ID(pMsgObj, uiRecordId, MSGOBJ_ITEM_ID_TO_INDEX(uiItemId));
    pItem->usType = usType;
    pItem->usCmo = uiItemId & 0xFFF;
    pItem->Value.pData = pObjMem;

    /* 如果该字段被重复设置，那么record长度要减去原来的长度 */
    if (0 != pItem->usLength) {
        pRecord->usLength -= (pItem->usLength + MSGOBJ_ITEM_HEAD_LEN);
    }
    pItem->usLength = usStrLength;

    /* 更新Record的长度，有效参数 + Item头长度 */
    pRecord->usLength += (usStrLength + MSGOBJ_ITEM_HEAD_LEN);

    return;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_JudgeUnsignedLength
 功能描述  : 检测无符号数的真实长度以最大限度利用空间
 输入参数  : dsw_u64 ullVal
 输出参数  : 无
 返 回 值  : dsw_u16
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2009年1月21日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
dsw_u16 MSGOBJ_JudgeUnsignedLength(dsw_u64 ullVal)
{
    /* MSGOBJ_SetItemUnsigned 子函数，参数合法性有保证，不再检查 */
    if (ullVal <= 0xFF) {
        return sizeof(dsw_u8);
    } else if (ullVal <= 0xFFFF) {
        return sizeof(dsw_u16);
    } else if (ullVal <= 0xFFFFFFFFULL) {
        return sizeof(dsw_u32);
    }

    return sizeof(dsw_u64);
}

/*****************************************************************************
 函 数 名  : MSGOBJ_SetItemUnsignedSub
 功能描述  : 设置无符号类型数据
 输入参数  : void *pMsgObj
             dsw_u32 uiRecordId
             dsw_u32 uiItemId
             dsw_u64 ullVal
             dsw_u32 uiValLen
 输出参数  : 无
 返 回 值  : void
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月9日
    作    者   : renshifei 00001615 gaoyong 00002868
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_SetItemUnsignedSub(void *pMsgObj, dsw_u32 uiRecordId, dsw_u32 uiItemId, dsw_u64 ullVal, dsw_u32 uiValLen,
                               dsw_u16 usType, const char *v_pFunction, dsw_u32 v_uiLine)
{
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_ITEM_S *pItem = NULL;
    MSGOBJ_RECORD_S *pRecord = NULL;
    dsw_u16 usValLen = (dsw_u16)uiValLen;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when setting item unsigned.",
                  v_uiLine, v_pFunction);
        return;
    }

    if ((uiRecordId >= pObj->uiRecordNum) || (MSGOBJ_ITEM_NUM(uiItemId) > pObj->uiItemNum)) {
        LOG_ERROR(
            "Parameter(input-record-id %d, input-item-id %d, obj-record-num %d, obj-item-num %d) at (%d)'th line of function (%s) is invalid.",
            uiRecordId, uiItemId, pObj->uiRecordNum, pObj->uiItemNum, v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    /* 找到对应的item */
    pItem = GET_ITEM_BY_ID(pMsgObj, uiRecordId, MSGOBJ_ITEM_ID_TO_INDEX(uiItemId));
    switch (uiValLen) {
        /* 根据目标类型进行转换 */
        case sizeof(dsw_u8): {
            pItem->Value.ullLong = (dsw_u8)ullVal;
            break;
        }
        case sizeof(dsw_u16): {
            pItem->Value.ullLong = (dsw_u16)ullVal;
            break;
        }
        case sizeof(dsw_u32): {
            pItem->Value.ullLong = (dsw_u32)ullVal;
            break;
        }
        case sizeof(dsw_u64): {
            pItem->Value.ullLong = ullVal;
            break;
        }
        default:
            LOG_ERROR(
                "Parameter that the input length (%d) is not legal when setting item unsigned at (%d)'th line of function (%s).",
                uiValLen, v_uiLine, v_pFunction);
            MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
            return;
    }

    /* 填写Item信息，长度为U16类型 */
    pItem->usType = usType;
    pItem->usCmo = uiItemId & 0xFFF;

    /* 更新Record的长度，有效参数 + Item头长度 */
    pRecord = GET_RECORD_BY_ID(pMsgObj, uiRecordId);

    /* 如果该字段被重复设置，那么record长度要减去原来的长度 */
    if (0 != pItem->usLength) {
        pRecord->usLength -= (pItem->usLength + MSGOBJ_ITEM_HEAD_LEN);
    }

    pItem->usLength = usValLen;
    pRecord->usLength += (usValLen + MSGOBJ_ITEM_HEAD_LEN);

    return;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_JudgeSignedLength
 功能描述  : 检测无符号数的真实长度以最大限度利用空间
 输入参数  : dsw_s64 llVal

 输出参数  : 无
 返 回 值  : dsw_u16
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2009年3月19日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
dsw_u16 MSGOBJ_JudgeSignedLength(dsw_s64 llVal)
{
    /* MSGOBJ_SetItemSigned 子函数，参数合法性有保证，不再检查 */
    if (IS_RANGE_OF_1_BYTE(llVal)) {
        return sizeof(dsw_s8);
    } else if (IS_RANGE_OF_2_BYTE(llVal)) {
        return sizeof(dsw_s16);
    } else if (IS_RANGE_OF_4_BYTE(llVal)) {
        return sizeof(dsw_s32);
    }

    return sizeof(dsw_s64);
}

/*****************************************************************************
 函 数 名  : MSGOBJ_SetItemSignedSub
 功能描述  : 设置有符号类型数据
 输入参数  : void *pMsgObj
             dsw_u32 uiRecordId
             dsw_u32 uiItemId
             dsw_s64 llVal
             dsw_u32 uiValLen
 输出参数  : 无
 返 回 值  : void
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2009年3月19日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_SetItemSignedSub(void *pMsgObj, dsw_u32 uiRecordId, dsw_u32 uiItemId, dsw_s64 llVal, dsw_u32 uiValLen,
                             const char *v_pFunction, dsw_u32 v_uiLine)
{
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_ITEM_S *pItem = NULL;
    MSGOBJ_RECORD_S *pRecord = NULL;
    dsw_u16 usValLen = (dsw_u16)uiValLen;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when setting item signed.",
                  v_uiLine, v_pFunction);
        return;
    }

    if ((uiRecordId >= pObj->uiRecordNum) || (MSGOBJ_ITEM_NUM(uiItemId) > pObj->uiItemNum)) {
        LOG_ERROR(
            "Parameter(input-record-id %d, input-item-id %d, obj-record-num %d, obj-item-num %d) at (%d)'th line of function (%s) is invalid.",
            uiRecordId, uiItemId, pObj->uiRecordNum, pObj->uiItemNum, v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }
    /* 找到对应的item */
    pItem = GET_ITEM_BY_ID(pMsgObj, uiRecordId, MSGOBJ_ITEM_ID_TO_INDEX(uiItemId));
    switch (uiValLen) {
        /* 根据目标类型进行转换 */
        case sizeof(dsw_s8): {
            pItem->Value.llLong = (dsw_s8)llVal;
            break;
        }
        case sizeof(dsw_s16): {
            pItem->Value.llLong = (dsw_s16)llVal;
            break;
        }
        case sizeof(dsw_s32): {
            pItem->Value.llLong = (dsw_s32)llVal;
            break;
        }
        case sizeof(dsw_s64): {
            pItem->Value.llLong = llVal;
            break;
        }
        default:
            LOG_ERROR(
                "Parameter that the input length (%d) is not legal when setting item signed at (%d)'th line of function (%s).",
                uiValLen, v_uiLine, v_pFunction);
            MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
            return;
    }

    /* 填写Item信息，长度为U16类型 */
    pItem->usType = MSGOBJ_ITEM_TYPE_SIGNED;
    pItem->usCmo = uiItemId & 0xFFF;

    /* 更新Record的长度，有效参数 + Item头长度 */
    pRecord = GET_RECORD_BY_ID(pMsgObj, uiRecordId);

    /* 如果该字段被重复设置，那么record长度要减去原来的长度 */
    if (0 != pItem->usLength) {
        pRecord->usLength -= (pItem->usLength + MSGOBJ_ITEM_HEAD_LEN);
    }

    pItem->usLength = usValLen;
    pRecord->usLength += (usValLen + MSGOBJ_ITEM_HEAD_LEN);

    return;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_SetItemBlobSub
 功能描述  : 设置数据块
 输入参数  : void *pMsgObj
             dsw_u32 uiRecordId
             dsw_u32 uiItemId
             dsw_u8 *pData
             dsw_u32 uiDataLen
 输出参数  : 无
 返 回 值  : void
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月9日
    作    者   : renshifei 00001615 gaoyong 00002868
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_SetItemBlobSub(void *pMsgObj, dsw_u32 uiRecordId, dsw_u32 uiItemId, const dsw_u8 *pData, dsw_u32 uiDataLen,
                           const char *v_pFunction, dsw_u32 v_uiLine)
{
    dsw_u16 usDataLen = (dsw_u16)uiDataLen;
    void *pObjMem = NULL;
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_ITEM_S *pItem = NULL;
    MSGOBJ_RECORD_S *pRecord = NULL;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when setting item blob.",
                  v_uiLine, v_pFunction);
        return;
    }

    if ((NULL == pData) || (0 == uiDataLen)) {
        LOG_ERROR("The input data is NULL or blob len is 0 when setting item blob at (%d)'th line of function (%s).",
                  v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    if ((uiRecordId >= pObj->uiRecordNum) || (MSGOBJ_ITEM_NUM(uiItemId) > pObj->uiItemNum) ||
        (uiDataLen >= MSGOBJ_MAX_MEM_SIZE)) {
        LOG_ERROR(
            "Parameter(input-record-id %d, input-item-id %d, obj-record-num %d, obj-item-num %d, blob-len %u) at (%d)'th line of function (%s) is invalid.",
            uiRecordId, uiItemId, pObj->uiRecordNum, pObj->uiItemNum, uiDataLen, v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    pRecord = GET_RECORD_BY_ID(pMsgObj, uiRecordId);

    pObjMem = MSGOBJ_GetMem(pObj, usDataLen);
    if (NULL == pObjMem) {
        LOG_ERROR("Fail to get memory when setting item blob at (%d)'th line of function (%s).", v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_ERROR);
        return;
    }

    /* 拷贝到空闲内存 */
    memcpy_s(pObjMem, usDataLen, pData, usDataLen);
    /* 在item中记录 */
    pItem = GET_ITEM_BY_ID(pMsgObj, uiRecordId, MSGOBJ_ITEM_ID_TO_INDEX(uiItemId));
    pItem->usType = MSGOBJ_ITEM_TYPE_BLOB;
    pItem->usCmo = uiItemId & 0xFFF;

    /* 如果该字段被重复设置，那么record长度要减去原来的长度 */
    if (0 != pItem->usLength) {
        pRecord->usLength -= (pItem->usLength + MSGOBJ_ITEM_HEAD_LEN);
    }

    pItem->usLength = usDataLen;
    pItem->Value.pData = pObjMem;

    /* 更新Record的长度，有效参数 + Item头长度 */
    pRecord->usLength += (usDataLen + MSGOBJ_ITEM_HEAD_LEN);

    return;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_GetRecordOpcodeSub
 功能描述  : 取指定记录的Opcode
 输入参数  : void *pMsgObj
             dsw_u32 uiRecordId
 输出参数  : dsw_u64 *pullOpcode
 返 回 值  : void
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月9日
    作    者   : renshifei 00001615 gaoyong 00002868
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_GetRecordOpcodeSub(void *pMsgObj, dsw_u32 uiRecordId, dsw_u64 *pullOpcode, const char *v_pFunction,
                               dsw_u32 v_uiLine)
{
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_RECORD_S *pRecord = NULL;
    /* HVSC99 DTS2012112809551 modified by c00214937 2012/11/28 end */

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when getting record opcode.",
                  v_uiLine, v_pFunction);
        return;
    }

    if (NULL == pullOpcode) {
        LOG_ERROR("Opcode pointer is NULL input at (%d)'th line of function (%s) when getting record opcode.", v_uiLine,
                  v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    if (uiRecordId >= pObj->uiRecordNum) {
        LOG_ERROR(
            "Parameter is invalid at (%d)'th line of function (%s), record id is (%d) but object record number is (%d).",
            v_uiLine, v_pFunction, uiRecordId, pObj->uiRecordNum);

        /* HVSC99 DTS2012112809551 modified by c00214937 2012/11/28 end */
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    pRecord = GET_RECORD_BY_ID(pMsgObj, uiRecordId);

    *pullOpcode = pRecord->ullOpCode;

    return;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_GetItemStringSub
 功能描述  : 取字符串类型数据
 输入参数  : void *pMsgObj
             dsw_u32 uiRecordId
             dsw_u32 uiItemId
 输出参数  : char *szString
 返 回 值  : void
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月9日
    作    者   : renshifei 00001615 gaoyong 00002868
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_GetItemStringSub(void *pMsgObj, dsw_u32 uiRecordId, dsw_u32 uiItemId, char **szString,
                             const char *v_pFunction, dsw_u32 v_uiLine)
{
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_ITEM_S *pItem = NULL;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when getting item string.",
                  v_uiLine, v_pFunction);
        return;
    }

    if (NULL == szString) {
        LOG_ERROR("The input string is NULL which is input at (%d)'th line of function (%s) when getting item string.",
                  v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    if ((uiRecordId >= pObj->uiRecordNum) || (MSGOBJ_ITEM_NUM(uiItemId) > pObj->uiItemNum)) {
        LOG_ERROR(
            "Parameter(input-record-id %d, input-item-id %d, obj-record-num %d, obj-item-num %d) at (%d)'th line of function (%s) is invalid.",
            uiRecordId, uiItemId, pObj->uiRecordNum, pObj->uiItemNum, v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    pItem = GET_ITEM_BY_ID(pMsgObj, uiRecordId, MSGOBJ_ITEM_ID_TO_INDEX(uiItemId));
    if (!IS_STRING_ITEM_TYPE(pItem->usType)) {
        LOG_ERROR(
            "Item(record %d, item %d) type (%d) is not right when getting item string at (%d)'th line of function (%s).",
            uiRecordId, uiItemId, pItem->usType, v_uiLine, v_pFunction);
        /* HVSC99 DTS2012112809551 modified by c00214937 2012/11/28 end */
        MSGOBJ_SetError(pObj, RETURN_MSG_CODE_ITEM_ERROR);
        return;
    }

    *szString = (char *)pItem->Value.pData;

    return;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_GetItemUnsignedSub
 功能描述  : 取无符号整数类型数据
 输入参数  : void *pMsgObj
             dsw_u32 uiRecordId
             dsw_u32 uiItemId
             dsw_u32 uiValLen
 输出参数  : void *pvVal
 返 回 值  : void
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月9日
    作    者   : renshifei 00001615 gaoyong 00002868
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_GetItemUnsignedSub(void *pMsgObj, dsw_u32 uiRecordId, dsw_u32 uiItemId, void *pvVal, dsw_u32 uiValLen,
                               const char *v_pFunction, dsw_u32 v_uiLine)
{
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_ITEM_S *pItem = NULL;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when getting item unsigned.",
                  v_uiLine, v_pFunction);
        return;
    }

    if (NULL == pvVal) {
        LOG_ERROR(
            "The input value pointer is NULL which is input at (%d)'th line of function (%s) when getting item unsigned.",
            v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    if ((uiRecordId >= pObj->uiRecordNum) || (MSGOBJ_ITEM_NUM(uiItemId) > pObj->uiItemNum)) {
        LOG_ERROR(
            "Parameter(input-record-id %d, input-item-id %d, obj-record-num %d, obj-item-num %d) at (%d)'th line of function (%s) is invalid.",
            uiRecordId, uiItemId, pObj->uiRecordNum, pObj->uiItemNum, v_uiLine, v_pFunction);
        /* HVSC99 DTS2012112809551 modified by c00214937 2012/11/28 end */
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    pItem = GET_ITEM_BY_ID(pMsgObj, uiRecordId, MSGOBJ_ITEM_ID_TO_INDEX(uiItemId));
    if (!(IS_UNSIGNED_ITEM_TYPE(pItem->usType))) {
        LOG_ERROR("Item(record %d, item %d) type (%d) at (%d)'th line of function (%s) is wrong.", uiRecordId, uiItemId,
                  pItem->usType, v_uiLine, v_pFunction);
        /* HVSC99 DTS2012112809551 modified by c00214937 2012/11/28 end */
        MSGOBJ_SetError(pObj, RETURN_MSG_CODE_ITEM_ERROR);
        return;
    }

    switch (uiValLen) {
        /* 转换为目标类型并写入数据 */
        case sizeof(dsw_u8): {
            *(dsw_u8 *)pvVal = (dsw_u8)(pItem->Value.ullLong);
            break;
        }
        case sizeof(dsw_u16): {
            *(dsw_u16 *)pvVal = (dsw_u16)(pItem->Value.ullLong);
            break;
        }
        case sizeof(dsw_u32): {
            *(dsw_u32 *)pvVal = (dsw_u32)(pItem->Value.ullLong);
            break;
        }
        case sizeof(dsw_u64): {
            *(dsw_u64 *)pvVal = pItem->Value.ullLong;
            break;
        }
        default:
            LOG_ERROR("Parameter that value length (%u) at (%d)'th line of function (%s) is not legal.", uiValLen,
                      v_uiLine, v_pFunction);
            MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
            return;
    }

    return;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_GetItemSignedSub
 功能描述  : 取有符号整数类型数据
 输入参数  : void *pMsgObj
             dsw_u32 uiRecordId
             dsw_u32 uiItemId
             dsw_u32 uiValLen
 输出参数  : void *pvVal
 返 回 值  : void
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2009年3月19日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/

void MSGOBJ_GetItemSignedSub(void *pMsgObj, dsw_u32 uiRecordId, dsw_u32 uiItemId, void *pvVal, dsw_u32 uiValLen,
                             const char *v_pFunction, dsw_u32 v_uiLine)
{
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_ITEM_S *pItem = NULL;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when getting item signed.",
                  v_uiLine, v_pFunction);
        return;
    }

    if (NULL == pvVal) {
        LOG_ERROR("The input value pointer is NULL when getting item signed at (%d)'th line of function (%s).",
                  v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    if ((uiRecordId >= pObj->uiRecordNum) || (MSGOBJ_ITEM_NUM(uiItemId) > pObj->uiItemNum)) {
        LOG_ERROR(
            "Parameter(input-record-id %d, input-item-id %d, obj-record-num %d, obj-item-num %d) at (%d)'th line of function (%s) is invalid.",
            uiRecordId, uiItemId, pObj->uiRecordNum, pObj->uiItemNum, v_uiLine, v_pFunction);
        /* HVSC99 DTS2012112809551 modified by c00214937 2012/11/28 end */
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    pItem = GET_ITEM_BY_ID(pMsgObj, uiRecordId, MSGOBJ_ITEM_ID_TO_INDEX(uiItemId));
    if (MSGOBJ_ITEM_TYPE_SIGNED != pItem->usType) {
        LOG_ERROR(
            "Item(record %d, item %d) type (%d) is wrong when getting item signed at (%d)'th line of function (%s).",
            uiRecordId, uiItemId, pItem->usType, v_uiLine, v_pFunction);
        /* HVSC99 DTS2012112809551 modified by c00214937 2012/11/28 end */
        MSGOBJ_SetError(pObj, RETURN_MSG_CODE_ITEM_ERROR);
        return;
    }

    switch (uiValLen) {
        /* 转换为目标类型并写入数据 */
        case sizeof(dsw_s8): {
            *(dsw_s8 *)pvVal = (dsw_s8)(pItem->Value.llLong);
            break;
        }
        case sizeof(dsw_s16): {
            *(dsw_s16 *)pvVal = (dsw_s16)(pItem->Value.llLong);
            break;
        }
        case sizeof(dsw_s32): {
            *(dsw_s32 *)pvVal = (dsw_s32)(pItem->Value.llLong);
            break;
        }
        case sizeof(dsw_s64): {
            *(dsw_s64 *)pvVal = pItem->Value.llLong;
            break;
        }
        default:
            LOG_ERROR(
                "Parameter that value length (%u) is not legal when getting item signed at (%d)'th line of function (%s).",
                uiValLen, v_uiLine, v_pFunction);
            MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
            return;
    }

    return;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_GetItemBlobSub
 功能描述  : 取指定数据块
 输入参数  : void *pMsgObj
             dsw_u32 uiRecordId
             dsw_u32 uiItemId
 输出参数  : dsw_u8 *pData
             dsw_u32 uiDataLen
 返 回 值  : void
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月9日
    作    者   : renshifei 00001615 gaoyong 00002868
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_GetItemBlobSub(void *pMsgObj, dsw_u32 uiRecordId, dsw_u32 uiItemId, dsw_u8 **pData, dsw_u32 *puiDataLen,
                           const char *v_pFunction, dsw_u32 v_uiLine)
{
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_ITEM_S *pItem = NULL;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when getting item blob.",
                  v_uiLine, v_pFunction);
        return;
    }

    if ((NULL == pData) || (NULL == puiDataLen)) {
        LOG_ERROR(
            "The input data pointer or data-len pointer at (%d)'th line of function (%s) when getting item blob is NULL.",
            v_uiLine, v_pFunction);
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    if ((uiRecordId >= pObj->uiRecordNum) || (MSGOBJ_ITEM_NUM(uiItemId) > pObj->uiItemNum)) {
        LOG_ERROR(
            "Parameter(input-record-id %d, input-item-id %d, obj-record-num %d, obj-item-num %d) at (%d)'th line of function (%s) is invalid.",
            uiRecordId, uiItemId, pObj->uiRecordNum, pObj->uiItemNum, v_uiLine, v_pFunction);
        /* HVSC99 DTS2012112809551 modified by c00214937 2012/11/28 end */
        MSGOBJ_SetError(pObj, RETURN_PARAM_ERROR);
        return;
    }

    pItem = GET_ITEM_BY_ID(pMsgObj, uiRecordId, MSGOBJ_ITEM_ID_TO_INDEX(uiItemId));
    if (MSGOBJ_ITEM_TYPE_BLOB != pItem->usType) {
        LOG_ERROR("Item(record %d, item %d) type (%d) is wrong when getting item blob at (%d)'th line of function (%s).",
                  uiRecordId, uiItemId, pItem->usType, v_uiLine, v_pFunction);
        /* HVSC99 DTS2012112809551 modified by c00214937 2012/11/28 end */
        MSGOBJ_SetError(pObj, RETURN_MSG_CODE_ITEM_ERROR);
        return;
    }

    /* 内部记录为U16，输出参数为int */
    *puiDataLen = (dsw_u32)pItem->usLength;
    *pData = pItem->Value.pData;

    return;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_GetItemTypeSub
 功能描述  : 获取指定Item类型
 输入参数  : void *pMsgObj
             dsw_u32 uiRecordId
             dsw_u32 uiItemId
 输出参数  : 无
 返 回 值  : dsw_u16
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2009年2月10日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
dsw_u16 MSGOBJ_GetItemTypeSub(void *pMsgObj, dsw_u32 uiRecordId, dsw_u32 uiItemId, const char *v_pFunction,
                              dsw_u32 v_uiLine)
{
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_ITEM_S *pItem = NULL;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when getting item type.",
                  v_uiLine, v_pFunction);
        return MSGOBJ_ITEM_TYPE_INVALID;
    }

    if ((uiRecordId >= pObj->uiRecordNum) || (MSGOBJ_ITEM_NUM(uiItemId) > pObj->uiItemNum)) {
        LOG_ERROR("Param is error, record id:(%d), Obj record num:(%d), item id:(%d), Obj item num:(%d).", uiRecordId,
                  pObj->uiRecordNum, uiItemId, pObj->uiItemNum);
        return MSGOBJ_ITEM_TYPE_INVALID;
    }

    pItem = GET_ITEM_BY_ID(pMsgObj, uiRecordId, MSGOBJ_ITEM_ID_TO_INDEX(uiItemId));

    return pItem->usType;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_GetItemNumSub
 功能描述  : 获取ObjItem数量
 输入参数  : void *pMsgObj
 输出参数  : 无
 返 回 值  : dsw_u32
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2009年3月4日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
dsw_u32 MSGOBJ_GetItemNumSub(void *pMsgObj, const char *v_pFunction, dsw_u32 v_uiLine)
{
    MSGOBJ_S *pObj = pMsgObj;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when getting item number.",
                  v_uiLine, v_pFunction);
        return MSGOBJ_INVALID_ITEM_NUM;
    }

    return pObj->uiItemNum - MSGOBJ_SPECIAL_ITEM_NUM;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_CountAndCreatObj
 功能描述  : 遍历Msg并根据结果申请Obj
 输入参数  : void *pMsg
             dsw_u32 uiMsgLen
 输出参数  : 无
 返 回 值  : void *
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月13日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
void *MSGOBJ_CountAndCreatObj(const void *pMsg, dsw_u32 uiMsgLen, const char *pstrFunc, dsw_u32 uiLine,
                              dsw_u64 v_ullCallerAddr)
{
    dsw_u32 uiCurRecIndex = 0;
    dsw_u32 uiCurItemIndex = 0;
    dsw_u32 uiRecNum = 0;
    dsw_u32 uiMaxItemIndex = MSGOBJ_SPECIAL_ITEM_NUM; /* 索引应从特殊Item数量开始 */
    void *pObj = NULL;
    MSGOBJ_RECORD_S *pRecord = (MSGOBJ_RECORD_S *)pMsg;
    MSGOBJ_ITEM_S *pItem = (void *)(pRecord->aucItems);

    /* 本函数为MSGOBJ_Decode的子函数，参数合法性有保证，不再检查 */
    /* 解码msg取得obj的Recordnum和MaxItemId */
    while (uiCurRecIndex < uiMsgLen) {
        /* Record 的OpCode和Length不能均为0 */
        if (uiMsgLen < uiCurRecIndex + sizeof(MSGOBJ_RECORD_S)) {
            LOG_ERROR("param error");
            return NULL;
        }

        if (uiMsgLen < uiCurRecIndex + sizeof(MSGOBJ_RECORD_S) + pRecord->usLength) {
            LOG_ERROR("param error");
            return NULL;
        }

        if ((0 == pRecord->ullOpCode) && (0 == pRecord->usLength)) {
            LOG_ERROR("The input opcode or record length is 0 when count and create object.");
            return NULL;
        }

        while (uiCurItemIndex < pRecord->usLength) {
            if (pRecord->usLength < uiCurItemIndex + MSGOBJ_ITEM_HEAD_LEN) {
                LOG_ERROR("param error");
                return NULL;
            }

            if (MSGOBJ_ITEM_ID_TO_INDEX((dsw_u32)(pItem->usCmo)) > uiMaxItemIndex) {
                uiMaxItemIndex = MSGOBJ_ITEM_ID_TO_INDEX((dsw_u32)(pItem->usCmo));
            }
            uiCurItemIndex += (MSGOBJ_ITEM_HEAD_LEN + pItem->usLength);

            /* Item的长度大于Record */
            if (uiCurItemIndex > pRecord->usLength) {
                LOG_ERROR("Item (%d)'s length (%d) is lager than record length (%d) when count and create object.",
                          pItem->usCmo, uiCurItemIndex, pRecord->usLength);
                return NULL;
            }

            pItem = (void *)((char *)pItem + MSGOBJ_ITEM_HEAD_LEN + pItem->usLength);
        }
        /* 记录数增加 */
        uiRecNum++;

        uiCurRecIndex += pRecord->usLength + sizeof(MSGOBJ_RECORD_S);

        /* Record的长度大于消息 */
        if (uiCurRecIndex > uiMsgLen) {
            LOG_ERROR("Record length (%d) is lager than message length (%d) when count and create object.",
                      uiCurRecIndex, uiMsgLen);
            return NULL;
        }

        pRecord = (void *)((char *)pRecord + sizeof(MSGOBJ_RECORD_S) + pRecord->usLength);

        /* 清零从下一个Record继续 */
        uiCurItemIndex = 0;
        pItem = (void *)(pRecord->aucItems);
    }

    /* 根据RecordNum和MaxItemID创建Obj */
    pObj = MSGOBJ_CreateSub(uiRecNum, MSGOBJ_ITEM_INDEX_TO_ID(uiMaxItemIndex), pstrFunc, uiLine, v_ullCallerAddr);

    return pObj;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_GetUnsignedData
 功能描述  : 获取unsigned类型的数据
 输入参数  : void *pMsg
             dsw_u32 uiMsgLen
 输出参数  : 无
 返 回 值  : void *
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月13日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
dsw_u64 MSGOBJ_GetUnsignedData(MSGOBJ_ITEM_S *pItem, dsw_u32 uiLen)
{
    switch (uiLen) {
        /* 根据目标类型进行转换 */
        case sizeof(dsw_u8): {
            return *(dsw_u8 *)&(pItem->Value);
        }
        case sizeof(dsw_u16): {
            return *(dsw_u16 *)&(pItem->Value);
        }
        case sizeof(dsw_u32): {
            return *(dsw_u32 *)&(pItem->Value);
        }
        case sizeof(dsw_u64): {
            return pItem->Value.ullLong;
        }
        default:
            LOG_ERROR("Parameter that value length (%u) is not legal when getting unsigned data.", uiLen);
            return 0;
    }
}

/*****************************************************************************
 函 数 名  : MSGOBJ_GetSignedData
 功能描述  : 获取signed类型的数据
 输入参数  : void *pMsg
             dsw_u32 uiMsgLen
 输出参数  : 无
 返 回 值  : void *
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月13日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
dsw_s64 MSGOBJ_GetSignedData(MSGOBJ_ITEM_S *pItem, dsw_u32 uiLen)
{
    switch (uiLen) {
        /* 根据目标类型进行转换 */
        case sizeof(dsw_s8): {
            return *(dsw_s8 *)&(pItem->Value);
        }
        case sizeof(dsw_s16): {
            return *(dsw_s16 *)&(pItem->Value);
        }
        case sizeof(dsw_s32): {
            return *(dsw_s32 *)&(pItem->Value);
        }
        case sizeof(dsw_s64): {
            return pItem->Value.llLong;
        }
        default:
            LOG_ERROR("Parameter that value length (%u) is not legal when getting signed data.", uiLen);
            return 0;
    }
}

/*****************************************************************************
 函 数 名  : MSGOBJ_RestoreDataToObj
 功能描述  : 恢复数据到Obj
 输入参数  : void *pMsg
             dsw_u32 uiRecNum
             void *pMsgObj
 输出参数  : 无
 返 回 值  : void
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月13日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_RestoreDataToObj(const void *pMsg, dsw_u32 uiMsgLen, void *pMsgObj)
{
    dsw_u32 uiCurRecIndex = 0;
    dsw_u32 uiCurItemIndex = 0;
    dsw_u32 uiRecordId = 0;
    MSGOBJ_RECORD_S *pRecord = (MSGOBJ_RECORD_S *)pMsg;
    MSGOBJ_ITEM_S *pItem = (void *)(pRecord->aucItems);
    char *tmp_string = NULL;

    /* 本函数为MSGOBJ_Decode的子函数，参数合法性有保证，不再检查 */
    /* 设置Obj，从消息中取第一个Record和Item */
    while (uiCurRecIndex < uiMsgLen) {
        while (uiCurItemIndex < pRecord->usLength) {
            /* 根据Item类型进行设置，并转换参数为目标类型 */
            if (MSGOBJ_ITEM_TYPE_BLOB == pItem->usType) {
                MSGOBJ_SetItemBlob(pMsgObj, uiRecordId, pItem->usCmo, (dsw_u8 *)&(pItem->Value.ullLong),
                                   (dsw_u32)pItem->usLength);
            } else if (IS_STRING_ITEM_TYPE(pItem->usType)) {
                tmp_string = (char *)&(pItem->Value.ullLong);
                tmp_string[pItem->usLength - 1] = 0;
                MSGOBJ_SetItemStringSub(pMsgObj, uiRecordId, pItem->usCmo, (char *)&(pItem->Value.ullLong),
                                        pItem->usType, __FUNCTION__, __LINE__);
            } else if (IS_UNSIGNED_ITEM_TYPE(pItem->usType)) {
                MSGOBJ_SetItemUnsignedSub(pMsgObj, uiRecordId, pItem->usCmo,
                                          MSGOBJ_GetUnsignedData(pItem, pItem->usLength), (dsw_u32)pItem->usLength,
                                          pItem->usType, __FUNCTION__, __LINE__);
            } else if (MSGOBJ_ITEM_TYPE_SIGNED == pItem->usType) {
                MSGOBJ_SetItemSigned(pMsgObj, uiRecordId, pItem->usCmo, MSGOBJ_GetSignedData(pItem, pItem->usLength),
                                     (dsw_u32)pItem->usLength);
            } else {
                LOG_ERROR("Item type (%d) is wrong when restore data to object.", pItem->usType);
            }

            uiCurItemIndex += (MSGOBJ_ITEM_HEAD_LEN + pItem->usLength);
            pItem = (void *)((char *)pItem + MSGOBJ_ITEM_HEAD_LEN + pItem->usLength);
        }

        /* 填充Opcode */
        MSGOBJ_SetRecordOpcode(pMsgObj, uiRecordId, pRecord->ullOpCode);

        /* 记录数增加，恢复下一个记录数据 */
        uiRecordId++;
        uiCurRecIndex += pRecord->usLength + sizeof(MSGOBJ_RECORD_S);
        pRecord = (void *)((char *)pRecord + sizeof(MSGOBJ_RECORD_S) + pRecord->usLength);

        /* Item索引清零从下一个Record继续 */
        uiCurItemIndex = 0;
        pItem = (void *)(pRecord->aucItems); /* item数组地址转换为结构指针 */
    }
    /* 记录Obj编码后长度 */
    ((MSGOBJ_S *)pMsgObj)->uiMsgLength = uiCurRecIndex;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_DecodeSub
 功能描述  : 消息对象解码
 输入参数  : void *pMsg
             dsw_u32 uiMsgLen
 输出参数  : 无
 返 回 值  : void *
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月10日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
void *MSGOBJ_DecodeSub(const void *pMsg, dsw_u32 uiMsgLen, const char *v_pFunction, dsw_u32 v_uiLine)
{
    void *pObj = NULL;

    if ((NULL == pMsg) || (0 == uiMsgLen)) {
        LOG_ERROR(
            "The message is invalid or message length is invalid which is input at (%d)'th line of function (%s) when decoding message.",
            v_uiLine, v_pFunction);
        return NULL;
    }

    /* 计算RecordNum和ItemID，创建Obj */
    pObj = MSGOBJ_CountAndCreatObj(pMsg, uiMsgLen, v_pFunction, v_uiLine, (dsw_u64)0);
    if (NULL == pObj) {
        LOG_ERROR("Fail to create object which is input at (%d)'th line of function (%s) when decoding message.",
                  v_uiLine, v_pFunction);
        return NULL;
    }

    /* 恢复数据到Obj */
    MSGOBJ_RestoreDataToObj(pMsg, uiMsgLen, pObj);

    return pObj;
}

/*****************************************************************************
 函 数 名  : MSGOBJ_DestroySub
 功能描述  : 释放一个Obj
 输入参数  : void *pMsgObj
 输出参数  : 无
 返 回 值  : void
 调用函数
 被调函数

 修改历史      :
  1.日    期   : 2008年12月6日
    作    者   : renshifei 00001615
    修改内容   : 新生成函数

*****************************************************************************/
void MSGOBJ_DestroySub(void *pMsgObj, const char *v_pFunction, dsw_u32 v_uiLine)
{
    dsw_u32 uiMemIndex;
    MSGOBJ_S *pObj = pMsgObj;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when destroying message.",
                  v_uiLine, v_pFunction);
        return;
    }

    /* 遍历数组释放内存块 */
    for (uiMemIndex = 0; uiMemIndex <= pObj->usMemIndex; uiMemIndex++) {
        if (NULL != pObj->apMem[uiMemIndex]) {
            free(pObj->apMem[uiMemIndex]);
            pObj->apMem[uiMemIndex] = NULL;
        }
    }

    free(pMsgObj);
    pMsgObj = NULL;
}
static void print_item(MSGOBJ_ITEM_S *pItem)
{
    dsw_s64 item_svalue = 0;
    dsw_u64 item_value = 0;

    /* 有符号数和无符号数处理方法一致 */
    if (IS_UNSIGNED_ITEM_TYPE(pItem->usType)) {
        switch (pItem->usLength) {
            case sizeof(dsw_u8):
                item_value = (dsw_u8)pItem->Value.ullLong;
                break;
            case sizeof(dsw_u16):
                item_value = (dsw_u16)pItem->Value.ullLong;
                break;
            case sizeof(dsw_u32):
                item_value = (dsw_u32)pItem->Value.ullLong;
                break;
            case sizeof(dsw_u64):
                item_value = (dsw_u64)pItem->Value.ullLong;
                break;
            default:
                LOG_ERROR("Data usleng (%d) is invalid.", pItem->usLength);
                break;
        }

        LOG_DEBUG("value=%llu", item_value);

    } else if (MSGOBJ_ITEM_TYPE_SIGNED == pItem->usType) {
        switch (pItem->usLength) {
            case sizeof(dsw_s8):
                item_svalue = (dsw_u8)pItem->Value.llLong;
                break;
            case sizeof(dsw_s16):
                item_svalue = (dsw_u16)pItem->Value.llLong;
                break;
            case sizeof(dsw_s32):
                item_svalue = (dsw_u32)pItem->Value.llLong;
                break;
            case sizeof(dsw_s64):
                item_svalue = (dsw_u64)pItem->Value.llLong;
                break;
            default:
                LOG_ERROR("Data usleng (%d) is invalid.", pItem->usLength);
                break;
        }

        LOG_DEBUG("value=%lld", item_svalue);
    } else { /* 类型错误，忽略该ITEM，继续处理下一个Item */
        LOG_ERROR("Data type (%d) is can't print.", pItem->usType);
    }
}

/*****************************************************************
Parameters    :  pMsgObj
                 v_pFunction
                 v_uiLine
Return        : void
Description   :  打印obj中的数据
*****************************************************************/
void MSGOBJ_PrintObjSub(void *pMsgObj, const char *v_pFunction, dsw_u32 v_uiLine)
{
    dsw_u32 uiRecIndex, uiItemIndex;
    MSGOBJ_S *pObj = pMsgObj;
    MSGOBJ_RECORD_S *pRecord = NULL;
    MSGOBJ_ITEM_S *pItem = NULL;
    dsw_u32 item_id = 0;
    dsw_u32 item_type = 0;

    if (!OBJ_IS_VALID(pObj)) {
        LOG_ERROR("The object is invalid which is input at (%d)'th line of function (%s) when encoding object.",
                  v_uiLine, v_pFunction);
        return;
    }

    for (uiRecIndex = 0; uiRecIndex < pObj->uiRecordNum; uiRecIndex++) {
        pRecord = GET_RECORD_BY_ID(pMsgObj, uiRecIndex);

        /* 没有Opcode，也没有Item */
        if ((0 == pRecord->ullOpCode) && (0 == pRecord->usLength)) {
            continue;
        }

        LOG_DEBUG("record_index=%u opcode=%llu,record_len=%d", uiRecIndex, pRecord->ullOpCode, pRecord->usLength);

        /* 填写了Item */
        for (uiItemIndex = 0; uiItemIndex < pObj->uiItemNum; uiItemIndex++) {
            pItem = GET_ITEM_BY_ID(pMsgObj, uiRecIndex, uiItemIndex);
            if (0 == pItem->usLength) { /* Item有效长度为0，继续下一个 */
                continue;
            }
            item_id = pItem->usCmo;
            item_type = pItem->usType;

            LOG_DEBUG("itemid=%d type=%d length=%hu", item_id, item_type, pItem->usLength);

            /* 数据块和字符串处理方法一致 */
            if (MSGOBJ_ITEM_TYPE_STRING == pItem->usType || MSGOBJ_ITEM_TYPE_ARRAY == pItem->usType) {
                LOG_DEBUG("value=%s", (char *)pItem->Value.pData);
            } else {
                print_item(pItem);
            }
        }
    }
}
