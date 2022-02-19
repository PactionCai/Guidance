/******************************************************************************

  Copyright (c) Huawei Technologies Co., Ltd. 2008-2018. All rights reserved.

 * *****************************************************************************
  文 件 名   : msg_obj_codec.inc
  版 本 号   : 初稿
  作    者   : renshifei 00001615
  生成日期   : 2008年12月5日
  最近修改   :
  功能描述   : 消息编解码模块的私有头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2008年12月5日
    作    者   : renshifei 00001615
    修改内容   : 创建文件

******************************************************************************/

#ifndef __MSG_OBJ_CODEC_INC__
#define __MSG_OBJ_CODEC_INC__

/* type/CMO + Length的长度 */
#define MSGOBJ_ITEM_HEAD_LEN 4

/* 允许的最大Record和Item数量，ItemID为0 ~ 1023 */
#define MSGOBJ_MAX_RECORD_NUM 1024
#define MSGOBJ_MAX_ITEM_NUM   4096

#define IS_UNSIGNED_ITEM_TYPE(type) ((MSGOBJ_ITEM_TYPE_UNSIGNED == (type)) \
                                     || (MSGOBJ_ITEM_TYPE_BOOL == (type)) \
                                     || (MSGOBJ_ITEM_TYPE_ENUM == (type)))

#define IS_STRING_ITEM_TYPE(type) ((MSGOBJ_ITEM_TYPE_STRING == (type)) \
                                     || (MSGOBJ_ITEM_TYPE_ARRAY == (type)) \
                                     || (MSGOBJ_ITEM_TYPE_JSON == (type)))

/* ITEM相关定义 */
#define MSGOBJ_ITEM_ID_MASK     0xFFF /* 有效ITEM_ID掩码 */
#define MSGOBJ_SPECIAL_ITEM_NUM 1     /* 特殊ITEM, 目前只有一个返回码 */

/* ITEM_ID转换 */
#define MSGOBJ_ITEM_ID_TO_INDEX(ItemId)    (((ItemId) + MSGOBJ_SPECIAL_ITEM_NUM) & MSGOBJ_ITEM_ID_MASK)
#define MSGOBJ_ITEM_INDEX_TO_ID(ItemIndex) (((ItemIndex) - MSGOBJ_SPECIAL_ITEM_NUM) & MSGOBJ_ITEM_ID_MASK)
#define MSGOBJ_ITEM_NUM(ItemId)            (MSGOBJ_ITEM_ID_TO_INDEX(ItemId) + 1)

/* 每个OBJ最多占用8块内存，每块8K--30K，编码时如果编码后长度超过消息则编码失败 */
#define MSGOBJ_MAX_MEM_NUM 8

/* 每块内存的长度 */
#define MSGOBJ_MIN_MEM_SIZE 8000 /* 系统页为8K，留部分给操作系统使用 */
#define MSGOBJ_MAX_MEM_SIZE (30 * 1024)

/* 根据记录ID找到地址 */
#define GET_RECORD_BY_ID(pMsgObj, uiRecordId) \
    ((void *)((char *)(pMsgObj) + sizeof(MSGOBJ_S) + ((sizeof(MSGOBJ_RECORD_S) \
    + sizeof(MSGOBJ_ITEM_S) * ((MSGOBJ_S *)(pMsgObj))->uiItemNum) * (uiRecordId))))

/* 根据ItemID找到地址 */
#define GET_ITEM_BY_ID(pMsgObj, uiRecordId, uiItemIndex) \
    ((void *)((char *)GET_RECORD_BY_ID(pMsgObj, uiRecordId)    \
    + sizeof(MSGOBJ_RECORD_S) + (sizeof(MSGOBJ_ITEM_S) * (uiItemIndex))))

/* obj魔术字 */
#define MSG_OBJ_MAGIC 0x20090202

/* obj合法性校验 */
#define OBJ_IS_VALID(obj) ((NULL != (obj)) && (MSG_OBJ_MAGIC == (obj)->uiMagic))

/* 有符号数的范围 */
#define IS_RANGE_OF_1_BYTE(llVal) (((llVal) >= -128) && ((llVal) <= 127))
#define IS_RANGE_OF_2_BYTE(llVal) (((llVal) >= -32768) && ((llVal) <= 32767))
#define IS_RANGE_OF_4_BYTE(llVal) (((llVal) >= -2147483648LL) && ((llVal) <= 2147483647))

#pragma pack(1)
/* Item的结构 */
typedef struct tagMsgObjItem {
    dsw_u16 usType : 4; /* 字段类型 */
    dsw_u16 usCmo : 12; /* 字段cmo */
    dsw_u16 usLength; /* 字段长度 */
    union {             /* 字段值的联合 */
        dsw_s64 llLong;
        dsw_u64 ullLong;
        void *pData;
    } Value;
} MSGOBJ_ITEM_S;

/* RECORD的结构 */
typedef struct tagMsgObjRecord {
    dsw_u64 ullOpCode;  /* 操作码 */
    dsw_u16 usLength;   /* Record的长度 */
    dsw_u8 aucItems[0]; /* item数组 */
} MSGOBJ_RECORD_S;

/* OBJ的结构 */
typedef struct tagMsgObj {
    dsw_u32 uiMagic;                 /* obj的魔术字 */
    dsw_s32 iErrFlag;                /* obj的错误标志 */
    dsw_u32 uiRecordNum;             /* obj内的record数量 */
    dsw_u32 uiItemNum;               /* obj内最大item的数量 */
    dsw_u32 uiMsgLength;             /* obj的实际长度 */
    dsw_u16 usMemIndex;              /* 当前使用的Mem索引 */
    dsw_u16 usMemFree;               /* 当前内存剩余字节数 */
    void *apMem[MSGOBJ_MAX_MEM_NUM]; /* 内存指针数组 */
    dsw_u8 aucRecords[0];            /* record数组 */
} MSGOBJ_S;
#pragma pack()

#endif /* __MSG_OBJ_CODEC_INC__ */


