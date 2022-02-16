/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef TEE_CLIENT_TYPE_H
#define TEE_CLIENT_TYPE_H
/**
 * @addtogroup TeeClient
 * @{
 *
 * @brief TEEC_API 客户端(非安全侧)接口。
 *
 * 提供非安全侧(正常模式)下客户端程序访问安全模式下安全应用相关接口。
 *
 * @since 8
 */

/**
 * @file tee_client_type.h
 *
 * @brief 基本数据类型和数据结构定义。
 *
 * @since 8
 */

#include <semaphore.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "tee_client_constants.h"

/**
 * @brief 链表类型定义
 *
 * @since 8
 */
struct ListNode {
    struct ListNode *next;  /* point to next node  */
    struct ListNode *prev;  /* point to prev node */
};

/**
 * @brief 函数返回值类型定义。
 *
 * @since 8
 */
typedef enum TEEC_ReturnCode TEEC_Result;

/**
 * @brief UID类型类型定义，遵循RFC4122 [2]，用于标识安全应用。
 *
 * @since 8
 */
typedef struct {
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqAndNode[8];
} TEEC_UUID;

/**
 * @brief 描述客户端应用与安全世界之间建立的连接环境。
 *
 * @since 8
 */
typedef struct {
    int32_t fd;
    uint8_t *ta_path;
    struct ListNode session_list;
    struct ListNode shrd_mem_list;
    union {
        struct {
            void *buffer;
            sem_t buffer_barrier;
        } share_buffer;
        uint64_t imp;
    };
} TEEC_Context;

/**
 * @brief 描述客户端应用与安全世界之间建立的会话。
 *
 * @since 8
 */
typedef struct {
    uint32_t session_id;
    TEEC_UUID service_id;
    uint32_t ops_cnt;
    union {
        struct ListNode head;
        uint64_t imp;
    };
    TEEC_Context *context;
} TEEC_Session;

/**
 * @brief 描述一块共享内存，可以注册，也可以分配。
 *
 * @since 8
 */
typedef struct {
    void *buffer;
    uint32_t size;
    uint32_t flags;         /* TEEC_SharedMemCtl */
    uint32_t ops_cnt;
    bool is_allocated;
    union {
        struct ListNode head;
        void* imp;
    };
    TEEC_Context *context;
} TEEC_SharedMemory;

/**
 * @brief 描述一块临时缓冲区指针。
 *
 * @since 8
 */
typedef struct {
    void *buffer;
    uint32_t size;
} TEEC_TempMemoryReference;

/**
 * @brief 描述共享内存指针，指向事先注册或分配好的共享内存。
 *
 * @since 8
 */
typedef struct {
    TEEC_SharedMemory *parent;
    uint32_t size;
    uint32_t offset;
} TEEC_RegisteredMemoryReference;

/**
 * @brief 描述少量数据。
 *
 * @since 8
 */
typedef struct {
    uint32_t a;
    uint32_t b;
} TEEC_Value;

/**
 * @brief 描述#TEEC_Operation所对应的参数类型。
 *
 * @since 8
 */
typedef union {
    TEEC_TempMemoryReference tmpref;
    TEEC_RegisteredMemoryReference memref;
    TEEC_Value value;
} TEEC_Parameter;

/**
 * @brief 打开会话或发送命令时的参数。
 *
 * @since 8
 */
typedef struct {
    uint32_t started;     /* 0 代表取消该命令，其他表示执行该命令 */
    uint32_t paramTypes;  /* 使用 TEEC_PARAM_TYPES 来创建该参数 */
    TEEC_Parameter params[TEEC_PARAM_NUM];
    TEEC_Session *session;
    bool cancel_flag;
} TEEC_Operation;

/** @} */
#endif
