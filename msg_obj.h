/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2018. All rights reserved.
 * Description: msg_obj.h
 * Author: l00113568
 * Create: 2016-10-11
 *
 */
/** \addtogroup MSG
    消息对象处理模块
    \image html msg_format.jpg
<table align="center" width="500" border=0><tr><td>一个消息由消息头和消息体组成<br>
消息体由1到多个Record组成，每个Record由消息码和若干个Item组成<br>
如果把Record看作一个结构，那么Item可以认为是结构的一个成员<br></tr></td></table>

 */
/** @{ */
/**
    \brief 消息编解码模块对外接口文件
    \author r00001615 任仕飞 g90002868 高勇
    \date 2008-12-11
*/


#ifndef __MSG_OBJ_H__
#define __MSG_OBJ_H__

#include "../dsw_typedef.h"

#undef RETURN_ERROR
#define RETURN_ERROR 1

#undef RETURN_OK
#define RETURN_OK 0

#define MSGOBJ_SINGLE_RECORD_NUM 1
#define MSGOBJ_SINGLE_RECORD_ID  0

/** \brief 定义无效记录号, 使用\ref MSGOBJ_SetRecordOpcode函数时表示所有的记录 */
#define MSGOBJ_INVALID_RECORD_ID ((dsw_u32)(-1))

/** \brief 定义返回值标志, 使用\ref MSGOBJ_SetItemUnsigned 函数设置返回值, 使用\ref MSGOBJ_GetItemUnsigned 函数获取返回值 */
#define MSGOBJ_RET_VALUE_CMO 0xFFF

/** \brief 定义非法的Item数量 */
#define MSGOBJ_INVALID_ITEM_NUM 0

/** \brief 定义Item类型 */
typedef enum tagMsgObjItemType {
    MSGOBJ_ITEM_TYPE_INVALID = 0,  /**< 无效 */
    MSGOBJ_ITEM_TYPE_BLOB = 1,     /**< 内存块 */
    MSGOBJ_ITEM_TYPE_STRING = 2,   /**< 字符串 */
    MSGOBJ_ITEM_TYPE_UNSIGNED = 3, /**< 无符号整数 */
    MSGOBJ_ITEM_TYPE_SIGNED = 4,   /**< 有符号整数 */
    MSGOBJ_ITEM_TYPE_BOOL = 5,     /**< bool类型 */
    MSGOBJ_ITEM_TYPE_ENUM = 6,     /**< 枚举类型 */
    MSGOBJ_ITEM_TYPE_ARRAY = 7,    /**< 数组 */
    MSGOBJ_ITEM_TYPE_JSON = 8,     /**< 以JSON表示的复杂类型 */
    MSGOBJ_ITEM_TYPE_BUTT
} MSGOBJ_ITEM_TYPE_E;

/**
    \brief 将设备内的消息对象编码为传输的消息格式
    \param[in]  pMsgObj     输入的设备内部消息格式
    \param[out] pMsg        存放编码后的消息缓冲区地址
    \param[in]  uiMsgMaxLen 输入的消息缓冲区长度(消息最大长度)
    \retval     RETURN_OK    成功
    \retval     RETURN_ERROR 失败
    \retval     RETURN_PARAM_ERROR  参数错误
    \sa MSGOBJ_Decode
 */
dsw_s32 MSGOBJ_EncodeSub(void *pMsgObj,
                         void *pMsg,
                         dsw_u32 uiMsgMaxLen,
                         const char *v_pFunction,
                         dsw_u32 v_uiLine);
#define MSGOBJ_Encode(pMsgObj, pMsg, uiMsgMaxLen) MSGOBJ_EncodeSub(pMsgObj, pMsg, uiMsgMaxLen, __FUNCTION__, __LINE__)

/**
    \brief 将收到的消息解码为用于设备内部的消息对象
    \param[in]  pMsg      接收到的消息
    \param[in]  uiMsgLen  接收到的消息长度
    \return     解码成功则返回一个创建的消息对象，失败返回NULL
    \attention  使用完成后请使用\ref MSGOBJ_Destroy释放返回的Obj资源
    \sa MSGOBJ_Encode
 */
void *MSGOBJ_DecodeSub(const void *pMsg,
                       dsw_u32 uiMsgLen,
                       const char *v_pFunction,
                       dsw_u32 v_uiLine);
#define MSGOBJ_Decode(pMsg, uiMsgLen) MSGOBJ_DecodeSub(pMsg, uiMsgLen, __FUNCTION__, __LINE__)

/**
    \brief 创建一个消息对象
    \param[in] uiMaxRecord   消息对象最大记录数
    \param[in] uiMaxItemId   每个消息对象最大记录ID值(注意是ID值不是数量)
    \return    返回消息对象指针, 失败则返回NULL
    \attention 使用完成后请使用\ref MSGOBJ_Destroy释放资源
    \see MSGOBJ_Destroy
 */
void *MSGOBJ_CreateSub(dsw_u32 uiMaxRecord,
                       dsw_u32 uiMaxItemId,
                       const char *v_pFunction,
                       dsw_u32 v_uiLine,
                       dsw_u64 v_ullCallerAddr);
#define MSGOBJ_Create(uiMaxRecord, uiMaxItemId) MSGOBJ_CreateSub(uiMaxRecord, uiMaxItemId, __FUNCTION__, __LINE__, 0ULL)

/**
    \brief 设置记录的操作码
    \param[in,out] pMsgObj 需要设置的消息对象
    \param[in] uiRecordId  需要设置的记录号，如果是\ref MSGOBJ_INVALID_RECORD_ID则设置所有的Record为相同的Opcode
    \param[in] ullOpcode   需要设置的操作码
    \attention  使用\ref MSGOBJ_GetLastError 获取错误码,成功:RETURN_OK,失败:RETURN_ERROR,参数错误:RETURN_PARAM_ERROR
    \sa MSGOBJ_GetRecordOpcode
 */
void MSGOBJ_SetRecordOpcodeSub(void *pMsgObj,
                               dsw_u32 uiRecordId,
                               dsw_u64 ullOpcode,
                               const char *v_pFunction,
                               dsw_u32 v_uiLine);
#define MSGOBJ_SetRecordOpcode(pMsgObj, uiRecordId, ullOpcode) \
    MSGOBJ_SetRecordOpcodeSub(pMsgObj, uiRecordId, ullOpcode, __FUNCTION__, __LINE__)

/**
    \brief 设置一个字符串类型的消息记录的一个字段的值
    \param[in,out]  pMsgObj     需要设置的消息对象
    \param[in]      uiRecordId  需要设置的记录号
    \param[in]      uiItemId   需要设置的字段ID
    \param[in]      szString    需要设置的值
    \attention  使用\ref MSGOBJ_GetLastError 获取错误码,成功:RETURN_OK,失败:RETURN_ERROR,参数错误:RETURN_PARAM_ERROR
    \sa MSGOBJ_SetItemUnsigned, MSGOBJ_SetItemBlob, MSGOBJ_SetItemSigned, MSGOBJ_GetItemString
 */
void MSGOBJ_SetItemStringSub(void *pMsgObj, dsw_u32 uiRecordId,
                             dsw_u32 uiItemId, const char *szString, dsw_u16 usType,
                             const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_SetItemString(pMsgObj, uiRecordId, uiItemId, szString) \
    MSGOBJ_SetItemStringSub(pMsgObj, uiRecordId, uiItemId, szString, MSGOBJ_ITEM_TYPE_STRING, __FUNCTION__, __LINE__)
#define MSGOBJ_SetItemArray(pMsgObj, uiRecordId, uiItemId, szString) \
    MSGOBJ_SetItemStringSub(pMsgObj, uiRecordId, uiItemId, szString, MSGOBJ_ITEM_TYPE_ARRAY, __FUNCTION__, __LINE__)

/**
    \brief 设置一个无符号整数类型的消息记录的一个字段的值
    \param[in,out]  pMsgObj     需要设置的消息对象
    \param[in]      uiRecordId  需要设置的记录号
    \param[in]      uiItemId   需要设置的字段ID
    \param[in]      ullVal      需要设置的值
    \param[in]      uiValLen    值的长度(1:U8, 2:U16, 4:U32, 8:U64)
    \attention  使用\ref MSGOBJ_GetLastError 获取错误码,成功:RETURN_OK,失败:RETURN_ERROR,参数错误:RETURN_PARAM_ERROR
    \attention  当ItemID 为\ref MSGOBJ_RET_VALUE_CMO 时，函数功能为设置消息返回值
    \sa MSGOBJ_SetItemString, MSGOBJ_SetItemBlob, MSGOBJ_SetItemSigned, MSGOBJ_GetItemUnsigned
 */
void MSGOBJ_SetItemUnsignedSub(void *pMsgObj, dsw_u32 uiRecordId,
                               dsw_u32 uiItemId, dsw_u64 ullVal, dsw_u32 uiValLen, dsw_u16 usType,
                               const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_SetItemUnsigned(pMsgObj, uiRecordId, uiItemId, ullVal, uiValLen) \
    MSGOBJ_SetItemUnsignedSub(pMsgObj, uiRecordId, uiItemId, ullVal, uiValLen, MSGOBJ_ITEM_TYPE_UNSIGNED, __FUNCTION__, __LINE__)
#define MSGOBJ_SetItemEnum(pMsgObj, uiRecordId, uiItemId, ullVal, uiValLen) \
    MSGOBJ_SetItemUnsignedSub(pMsgObj, uiRecordId, uiItemId, ullVal, uiValLen, MSGOBJ_ITEM_TYPE_ENUM, __FUNCTION__, __LINE__)
#define MSGOBJ_SetItemBool(pMsgObj, uiRecordId, uiItemId, ullVal, uiValLen) \
    MSGOBJ_SetItemUnsignedSub(pMsgObj, uiRecordId, uiItemId, ullVal, uiValLen, MSGOBJ_ITEM_TYPE_BOOL, __FUNCTION__, __LINE__)

/**
    \brief 设置一个有符号整数类型的消息记录的一个字段的值
    \param[in,out]  pMsgObj     需要设置的消息对象
    \param[in]      uiRecordId  需要设置的记录号
    \param[in]      uiItemId   需要设置的字段ID
    \param[in]      llVal      需要设置的值
    \param[in]      uiValLen    值的长度(1:S8, 2:S16, 4:S32, 8:S64)
    \attention  使用\ref MSGOBJ_GetLastError 获取错误码,成功:RETURN_OK,失败:RETURN_ERROR,参数错误:RETURN_PARAM_ERROR
    \attention  当ItemID 为\ref MSGOBJ_RET_VALUE_CMO 时，函数功能为设置消息返回值
    \sa MSGOBJ_SetItemString, MSGOBJ_SetItemBlob, MSGOBJ_SetItemUnsigned, MSGOBJ_GetItemSigned
 */
void MSGOBJ_SetItemSignedSub(void *pMsgObj, dsw_u32 uiRecordId,
                             dsw_u32 uiItemId, dsw_s64 llVal, dsw_u32 uiValLen,
                             const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_SetItemSigned(pMsgObj, uiRecordId, uiItemId, llVal, uiValLen) \
    MSGOBJ_SetItemSignedSub(pMsgObj, uiRecordId, uiItemId, llVal, uiValLen, __FUNCTION__, __LINE__)

/**
    \brief 设置一个内存块类型的消息记录的一个字段的值
    \param[in,out]  pMsgObj     需要设置的消息对象
    \param[in]      uiRecordId  需要设置的记录号
    \param[in]      uiItemId   需要设置的字段ID
    \param[in]      pData       内存块值得指针
    \param[in]      uiDataLen   内存块的长度
    \attention  使用\ref MSGOBJ_GetLastError 获取错误码,成功:RETURN_OK,失败:RETURN_ERROR,参数错误:RETURN_PARAM_ERROR
    \sa MSGOBJ_SetItemString, MSGOBJ_SetItemUnsigned, MSGOBJ_SetItemSigned, MSGOBJ_GetItemBlob
 */
void MSGOBJ_SetItemBlobSub(void *pMsgObj, dsw_u32 uiRecordId,
                           dsw_u32 uiItemId, const dsw_u8 *pData, dsw_u32 uiDataLen,
                           const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_SetItemBlob(pMsgObj, uiRecordId, uiItemId, pData, uiDataLen) \
    MSGOBJ_SetItemBlobSub(pMsgObj, uiRecordId, uiItemId, pData, uiDataLen, __FUNCTION__, __LINE__)

/**
    \brief 获取记录的操作码
    \param[in]  pMsgObj     需要获取的消息对象
    \param[in]  uiRecordId  需要获取的记录号
    \param[out] pullOpcode  输出获取到的操作码
    \attention  使用\ref MSGOBJ_GetLastError 获取错误码,成功:RETURN_OK,失败:RETURN_ERROR,参数错误:RETURN_PARAM_ERROR
    \note   输出参数的空间由使用者提供
    \sa MSGOBJ_SetRecordOpcode
 */
void MSGOBJ_GetRecordOpcodeSub(void *pMsgObj,
                               dsw_u32 uiRecordId, dsw_u64 *pullOpcode,
                               const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_GetRecordOpcode(pMsgObj, uiRecordId, pullOpcode) \
    MSGOBJ_GetRecordOpcodeSub(pMsgObj, uiRecordId, pullOpcode, __FUNCTION__, __LINE__)

/**
    \brief 获取一个字符串类型的消息记录的一个字段的值
    \param[in,out]  pMsgObj     需要获取的消息对象
    \param[in]      uiRecordId  需要获取的记录号
    \param[in]      uiItemId   需要获取的字段ID
    \param[out]     szString    需要获取的值
    \attention  使用\ref MSGOBJ_GetLastError 获取错误码,成功:RETURN_OK,失败:RETURN_ERROR,
                参数错误:RETURN_PARAM_ERROR, Item类型错误:RETURN_MSG_CODE_ITEM_ERROR
    \sa MSGOBJ_GetItemUnsigned, MSGOBJ_GetItemBlob, MSGOBJ_GetItemSigned, MSGOBJ_SetItemString
    \note  字符串的存放空间由Obj分配，销毁Obj时自动释放
 */
void MSGOBJ_GetItemStringSub(void *pMsgObj, dsw_u32 uiRecordId,
                             dsw_u32 uiItemId, char **szString,
                             const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_GetItemString(pMsgObj, uiRecordId, uiItemId, szString) \
    MSGOBJ_GetItemStringSub(pMsgObj, uiRecordId, uiItemId, szString, __FUNCTION__, __LINE__)
#define MSGOBJ_GetItemArray(pMsgObj, uiRecordId, uiItemId, szString) \
    MSGOBJ_GetItemStringSub(pMsgObj, uiRecordId, uiItemId, szString, __FUNCTION__, __LINE__)

/**
    \brief 获取一个无符号整数类型的消息记录的一个字段的值
    \param[in,out]  pMsgObj     需要获取的消息对象
    \param[in]      uiRecordId  需要获取的记录号
    \param[in]      uiItemId   需要获取的字段ID
    \param[out]     pvVal       需要获取的值
    \param[in]      uiValLen    值的长度(1:U8, 2:U16, 4:U32, 8:U64)
    \attention  使用\ref MSGOBJ_GetLastError 获取错误码,成功:RETURN_OK,失败:RETURN_ERROR,
                参数错误:RETURN_PARAM_ERROR, Item类型错误:RETURN_MSG_CODE_ITEM_ERROR
    \attention  当ItemID 为\ref MSGOBJ_RET_VALUE_CMO 时，函数功能为获取消息返回值
    \note   输出参数的空间由使用者提供
    \sa MSGOBJ_GetItemUnsigned, MSGOBJ_GetItemBlob, MSGOBJ_GetItemSigned, MSGOBJ_SetItemUnsigned
 */
void MSGOBJ_GetItemUnsignedSub(void *pMsgObj, dsw_u32 uiRecordId,
                               dsw_u32 uiItemId, void *pvVal, dsw_u32 uiValLen,
                               const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_GetItemUnsigned(pMsgObj, uiRecordId, uiItemId, pvVal, uiValLen) \
    MSGOBJ_GetItemUnsignedSub(pMsgObj, uiRecordId, uiItemId, pvVal, uiValLen, __FUNCTION__, __LINE__)
#define MSGOBJ_GetItemEnum(pMsgObj, uiRecordId, uiItemId, pvVal, uiValLen) \
    MSGOBJ_GetItemUnsignedSub(pMsgObj, uiRecordId, uiItemId, pvVal, uiValLen, __FUNCTION__, __LINE__)
#define MSGOBJ_GetItemBool(pMsgObj, uiRecordId, uiItemId, pvVal, uiValLen) \
    MSGOBJ_GetItemUnsignedSub(pMsgObj, uiRecordId, uiItemId, pvVal, uiValLen, __FUNCTION__, __LINE__)

/**
    \brief 获取一个有符号整数类型的消息记录的一个字段的值
    \param[in,out]  pMsgObj     需要获取的消息对象
    \param[in]      uiRecordId  需要获取的记录号
    \param[in]      uiItemId   需要获取的字段ID
    \param[out]     pvVal       需要获取的值
    \param[in]      uiValLen    值的长度(1:S8, 2:S16, 4:S32, 8:S64)
    \attention  使用\ref MSGOBJ_GetLastError 获取错误码,成功:RETURN_OK,失败:RETURN_ERROR,
                参数错误:RETURN_PARAM_ERROR, Item类型错误:RETURN_MSG_CODE_ITEM_ERROR
    \attention  当ItemID 为\ref MSGOBJ_RET_VALUE_CMO 时，函数功能为获取消息返回值
    \note   输出参数的空间由使用者提供
    \sa MSGOBJ_GetItemString, MSGOBJ_GetItemBlob, MSGOBJ_GetItemUnsigned, MSGOBJ_GetItemSigned, MSGOBJ_SetItemSigned
 */
void MSGOBJ_GetItemSignedSub(void *pMsgObj, dsw_u32 uiRecordId,
                             dsw_u32 uiItemId, void *pvVal, dsw_u32 uiValLen,
                             const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_GetItemSigned(pMsgObj, uiRecordId, uiItemId, pvVal, uiValLen) \
    MSGOBJ_GetItemSignedSub(pMsgObj, uiRecordId, uiItemId, pvVal, uiValLen, __FUNCTION__, __LINE__)

/**
    \brief 获取一个内存块类型的消息记录的一个字段的值
    \param[in,out]  pMsgObj     需要获取的消息对象
    \param[in]      uiRecordId  需要获取的记录号
    \param[in]      uiItemId   需要获取的字段ID
    \param[out]     pData       内存块值得指针
    \param[out]     puiDataLen  内存块的长度指针
    \attention  使用\ref MSGOBJ_GetLastError 获取错误码,成功:RETURN_OK,失败:RETURN_ERROR,
                参数错误:RETURN_PARAM_ERROR, Item类型错误:RETURN_MSG_CODE_ITEM_ERROR
    \note   输出参数内存块的长度的空间由使用者提供
    \sa MSGOBJ_GetItemBlob, MSGOBJ_GetItemUnsigned, MSGOBJ_GetItemSigned, MSGOBJ_SetItemBlob
    \note  内存块的存放空间由Obj分配，销毁Obj时自动释放
 */
void MSGOBJ_GetItemBlobSub(void *pMsgObj, dsw_u32 uiRecordId,
                           dsw_u32 uiItemId, dsw_u8 **pData, dsw_u32 *puiDataLen,
                           const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_GetItemBlob(pMsgObj, uiRecordId, uiItemId, pData, puiDataLen) \
    MSGOBJ_GetItemBlobSub(pMsgObj, uiRecordId, uiItemId, pData, puiDataLen, __FUNCTION__, __LINE__)

/**
    \brief 获取一个字段的类型
    \param[in]      pMsgObj     需要获取的消息对象
    \param[in]      uiRecordId  需要获取的记录号
    \param[in]      uiItemId    需要获取的字段ID
    \retval     MSGOBJ_ITEM_TYPE_INVALID   无效
    \retval     MSGOBJ_ITEM_TYPE_BLOB      内存块
    \retval     MSGOBJ_ITEM_TYPE_STRING    字符串 
    \retval     MSGOBJ_ITEM_TYPE_UNSIGNED  无符号整数  
 */
dsw_u16 MSGOBJ_GetItemTypeSub(void *pMsgObj,
                              dsw_u32 uiRecordId, dsw_u32 uiItemId,
                              const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_GetItemType(pMsgObj, uiRecordId, uiItemId) \
    MSGOBJ_GetItemTypeSub(pMsgObj, uiRecordId, uiItemId, __FUNCTION__, __LINE__)

/**
    \brief 获取一个Obj的Item数量
    \param[in]      pMsgObj     需要获取的消息对象
    \retval     MSGOBJ_INVALID_ITEM_NUM    无效的数量
    \retval     成功则返回正确的Item数量
    \note  Obj中有多个Record时，返回最大的Item数量
 */
dsw_u32 MSGOBJ_GetItemNumSub(void *pMsgObj, const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_GetItemNum(pMsgObj) MSGOBJ_GetItemNumSub(pMsgObj, __FUNCTION__, __LINE__)

/**
    \brief 清除使用Obj过程中的错误
    \param[in]      pMsgObj     需要获取的消息对象
    \attention      清除前请确认错误是可以忽略的
    \sa MSGOBJ_GetLastError
 */
void MSGOBJ_ClearErrorSub(void *pMsgObj, const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_ClearError(pMsgObj) MSGOBJ_ClearErrorSub(pMsgObj, __FUNCTION__, __LINE__)

/**
    \brief 获取使用Obj过程中的最后一个错误
    \param[in]  pMsgObj      需要获取的消息对象
    \retval     RETURN_OK    正确
    \retval     RETURN_ERROR 错误
    \retval     RETURN_PARAM_ERROR 参数错误
    \attention  用户需要关心的是否出错，错误码本身携带的信息供调试使用，
                如果发生了错误没有清除，编码时会返回失败
    \sa MSGOBJ_ClearError
 */
dsw_s32 MSGOBJ_GetLastErrorSub(void *pMsgObj, const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_GetLastError(pMsgObj) MSGOBJ_GetLastErrorSub(pMsgObj, __FUNCTION__, __LINE__)

/**
    \brief 扩展Obj的 RecordNum 和 ItemNum
    \param[in]      pMsgObj     需要扩展的消息对象
    \param[in]      uiMaxRecord 新的记录数量
    \param[in]      uiMaxItemId 新的最大字段ID
    \retval         成功返回新的Obj指针，失败则原Obj不会释放
    \attention      1.Obj只能增大，不能缩小。
                    2.新的Obj与原Obj重复部分定义应是一致的
                    3.原有的Obj将被删除，不能再使用，无需用户释放
                    4.新的Obj使用完后需要用户自行释放
 */
void *MSGOBJ_ExtendSub(void *pMsgObj,
                       dsw_u32 uiMaxRecord, dsw_u32 uiMaxItemId,
                       const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_Extend(pMsgObj, uiMaxRecord, uiMaxItemId) \
    MSGOBJ_ExtendSub(pMsgObj, uiMaxRecord, uiMaxItemId, __FUNCTION__, __LINE__)

/**
    \brief 获取消息对象的简要信息
    \param[in]   pMsgObj 消息对象
    \param[out]  puiMsgLength       输出该对象的编码后消息长度, 如果该项为NULL则不输出该项
    \param[out]  puiMaxRecord       输出该对象的最大记录数量, 如果该项为NULL则不输出该项
    \param[out]  pullFirstOpCode    输出该对象第一个记录的Opcode, 如果该项为NULL则不输出该项
    \note 在编码前，主要用于取得需要的消息长度，在解码后，获取最大记录数和OpCode，输出参数的空间由使用者提供
    \retval     RETURN_OK    成功
    \retval     RETURN_ERROR 失败
    \retval     RETURN_PARAM_ERROR  参数错误
 */
dsw_s32 MSGOBJ_GetObjInfoSub(void *pMsgObj, dsw_u32 *puiMsgLength,
                             dsw_u32 *puiMaxRecord, dsw_u64 *pullFirstOpCode,
                             const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_GetObjInfo(pMsgObj, puiMsgLength, puiMaxRecord, pullFirstOpCode) \
    MSGOBJ_GetObjInfoSub(pMsgObj, puiMsgLength, puiMaxRecord, pullFirstOpCode, __FUNCTION__, __LINE__)

void MSGOBJ_DestroySub(void *pMsgObj, const char *v_pFunction, dsw_u32 v_uiLine);

/**
    \brief 销毁一个消息对象
    \param[in] pMsgObj 需要销毁的对象标识
    \note pMsgObj必须是使用MSGOBJ_Decode或者MSGOBJ_Create返回的对象
    \sa MSGOBJ_Create, MSGOBJ_Decode
 */
#define MSGOBJ_Destroy(pMsgObj)                             \
    do {                                                    \
        MSGOBJ_DestroySub(pMsgObj, __FUNCTION__, __LINE__); \
        (pMsgObj) = NULL;                                   \
    } while (0)

/*****************************************************************
Parameters    :  pMsgObj    
                 v_pFunction
                 v_uiLine   
Return        :  void
Description   :  no
*****************************************************************/
void MSGOBJ_PrintObjSub(void *pMsgObj, const char *v_pFunction, dsw_u32 v_uiLine);
#define MSGOBJ_PrintObj(pMsgObj) \
    MSGOBJ_PrintObjSub(pMsgObj, __FUNCTION__, __LINE__)


#endif /* __MSG_OBJ_H__ */


