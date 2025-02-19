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

#ifndef _TEE_CLIENT_INNER_H_
#define _TEE_CLIENT_INNER_H_

#include <pthread.h>
#include <unistd.h>
#include "tee_client_constants.h"
#include "tee_client_list.h"
#include "tee_client_type.h"
#include "tee_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IS_TEMP_MEM(paramType)                                                              \
    (((paramType) == TEEC_MEMREF_TEMP_INPUT) || ((paramType) == TEEC_MEMREF_TEMP_OUTPUT) || \
     ((paramType) == TEEC_MEMREF_TEMP_INOUT))

#define IS_PARTIAL_MEM(paramType)                                                        \
    (((paramType) == TEEC_MEMREF_WHOLE) || ((paramType) == TEEC_MEMREF_PARTIAL_INPUT) || \
     ((paramType) == TEEC_MEMREF_PARTIAL_OUTPUT) || ((paramType) == TEEC_MEMREF_PARTIAL_INOUT))

#define IS_VALUE_MEM(paramType) \
    (((paramType) == TEEC_VALUE_INPUT) || ((paramType) == TEEC_VALUE_OUTPUT) || ((paramType) == TEEC_VALUE_INOUT))

#define IS_SHARED_MEM(paramType) \
    ((paramType) == TEEC_MEMREF_SHARED_INOUT)

#define MAX_SHAREDMEM_LEN 0x10000000

#define CHECK_ERR_RETURN(val, ref, ret)                                                        \
    do {                                                                                       \
        if ((val) != (ref)) {                                                                  \
            tloge("%" PUBLIC "d: error: %" PUBLIC "d\n", __LINE__, (int)(val)); \
            return ret;                                                                        \
        }                                                                                      \
    } while (0)

#define CHECK_ERR_NO_RETURN(val, ref)                                                          \
    do {                                                                                       \
        if ((val) != (ref)) {                                                                  \
            tloge("%" PUBLIC "d: error: %" PUBLIC "d\n", __LINE__, (int)(val)); \
            return;                                                                            \
        }                                                                                      \
    } while (0)

#define CHECK_ERR_GOTO(val, ref, label)                                                        \
    do {                                                                                       \
        if ((val) != (ref)) {                                                                  \
            tloge("%" PUBLIC "d: error: %" PUBLIC "d\n", __LINE__, (int)(val)); \
            goto label;                                                                        \
        }                                                                                      \
    } while (0)


#define MAX_CXTCNT_ONECA 16                 /* one ca only can get 16 contexts */
#define MAX_TA_PATH_LEN 256
#define PARAM_SIZE_LIMIT (0x400000 + 0x100) /* 0x100 is for share mem flag etc */
#define NUM_OF_SHAREMEM_BITMAP 8

#ifndef ZERO_SIZE_PTR
#define ZERO_SIZE_PTR   ((void *)16)
#endif

#define BUFF_LEN_MAX 4096

#ifndef PAGE_SIZE
#define PAGE_SIZE getpagesize()
#endif

typedef struct {
    int32_t fd;                    /* file descriptor */
    struct ListNode session_list;  /* session list  */
    struct ListNode shrd_mem_list; /* share memory list */
    struct {
        void *buffer;
        sem_t buffer_barrier;
    } share_buffer;
    uint8_t shm_bitmap[NUM_OF_SHAREMEM_BITMAP];
    struct ListNode c_node; /* context list node  */
    uint32_t ops_cnt;
    pthread_mutex_t sessionLock;
    pthread_mutex_t shrMemLock;
    pthread_mutex_t shrMemBitMapLock;
    bool callFromService; /* true:from Service, false:from native */
} TEEC_ContextInner;

typedef struct {
    void *buffer;              /* memory pointer */
    uint32_t size;             /* memory size */
    uint32_t flags;            /* memory flag, distinguish between input and output, range in #TEEC_SharedMemCtl */
    uint32_t ops_cnt;          /* memoty operation cnt */
    bool is_allocated;         /* memory allocated flag, distinguish between registered or distributed */
    struct ListNode head;      /* head of shared memory list */
    TEEC_ContextInner *context; /* point to its own TEE environment */
    uint32_t offset;
} TEEC_SharedMemoryInner;

typedef struct {
    const uint8_t *taPath;
    FILE *taFp;
} TaFileInfo;

typedef TEEC_Result (*InitializeContextFunc)(const char *name, TEEC_Context *context);
typedef void (*FinalizeContextFunc)(TEEC_Context *context);
typedef TEEC_Result (*OpenSessionFunc)(TEEC_Context *context, TEEC_Session *session, const TEEC_UUID *destination,
    uint32_t connectionMethod, const void *connectionData, TEEC_Operation *operation, uint32_t *returnOrigin);
typedef void (*CloseSessionFunc)(TEEC_Session *session);
typedef TEEC_Result (*InvokeCommandFunc)(TEEC_Session *session, uint32_t commandID,
    TEEC_Operation *operation, uint32_t *returnOrigin);

typedef struct {
    InitializeContextFunc initializeContext;
    FinalizeContextFunc finalizeContext;
    OpenSessionFunc openSession;
    CloseSessionFunc closeSession;
    InvokeCommandFunc invokeCommand;
} TEEC_FuncMap;

#ifdef __cplusplus
}
#endif
#endif
