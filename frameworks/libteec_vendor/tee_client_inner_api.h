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

#ifndef TEE_CLIENT_INNER_API_H
#define TEE_CLIENT_INNER_API_H

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "tee_auth_common.h"
#include "tee_client_constants.h"
#include "tee_client_inner.h"
#include "tee_client_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TEE GLOBAL CMD */
enum SVC_GLOBAL_CMD_ID {
    GLOBAL_CMD_ID_INVALID                   = 0x0,  /* Global Task invalid cmd ID */
    GLOBAL_CMD_ID_BOOT_ACK                  = 0x1,  /* Global Task boot ack */
    GLOBAL_CMD_ID_OPEN_SESSION              = 0x2,  /* Global Task open Session */
    GLOBAL_CMD_ID_CLOSE_SESSION             = 0x3,  /* Global Task close Session */
    GLOBAL_CMD_ID_LOAD_SECURE_APP           = 0x4,  /* Global Task load dyn ta */
    GLOBAL_CMD_ID_NEED_LOAD_APP             = 0x5,  /* Global Task judge if need load ta */
    GLOBAL_CMD_ID_REGISTER_AGENT            = 0x6,  /* Global Task register agent */
    GLOBAL_CMD_ID_UNREGISTER_AGENT          = 0x7,  /* Global Task unregister agent */
    GLOBAL_CMD_ID_REGISTER_NOTIFY_MEMORY    = 0x8,  /* Global Task register notify memory */
    GLOBAL_CMD_ID_UNREGISTER_NOTIFY_MEMORY  = 0x9,  /* Global Task unregister notify memory */
    GLOBAL_CMD_ID_INIT_CONTENT_PATH         = 0xa,  /* Global Task init content path */
    GLOBAL_CMD_ID_TERMINATE_CONTENT_PATH    = 0xb,  /* Global Task terminate content path */
    GLOBAL_CMD_ID_ALLOC_EXCEPTION_MEM       = 0xc,  /* Global Task alloc exception memory */
    GLOBAL_CMD_ID_TEE_TIME                  = 0xd,  /* Global Task get tee secure time */
    GLOBAL_CMD_ID_TEE_INFO                  = 0xe,  /* Global Task tlogcat get tee info */
    GLOBAL_CMD_ID_MAX,
};

void SetBit(uint32_t i, uint32_t byteMax, uint8_t *bitMap);
void ClearBit(uint32_t i, uint32_t byteMax, uint8_t *bitMap);
int32_t GetAndSetBit(uint8_t *bitMap, uint32_t byteMax);
int32_t GetAndCleartBit(uint8_t *bitMap, uint32_t byteMax);
TEEC_Result TEEC_InitializeContextInner(TEEC_ContextInner *context, const CaAuthInfo *caInfo);
TEEC_Result TEEC_OpenSessionInner(int callingPid, const TaFileInfo *taFile, TEEC_ContextInner *context,
    TEEC_Session *session, const TEEC_UUID *destination, uint32_t connectionMethod,
    const void *connectionData, TEEC_Operation *operation, uint32_t *returnOrigin);
TEEC_Result TEEC_InvokeCommandInner(TEEC_ContextInner *context, const TEEC_Session *session,
    uint32_t commandID, const TEEC_Operation *operation, uint32_t *returnOrigin);
void TEEC_CloseSessionInner(TEEC_Session *session, const TEEC_ContextInner *context);
void TEEC_FinalizeContextInner(TEEC_ContextInner *context);
TEEC_Result TEEC_RegisterSharedMemoryInner(TEEC_ContextInner *context, TEEC_SharedMemoryInner *sharedMem);
TEEC_Result TEEC_AllocateSharedMemoryInner(TEEC_ContextInner *context, TEEC_SharedMemoryInner *sharedMem);
void TEEC_ReleaseSharedMemoryInner(TEEC_SharedMemoryInner *sharedMem);
TEEC_ContextInner *GetBnContext(const TEEC_Context *context);
bool PutBnContext(TEEC_ContextInner *context);
TEEC_ContextInner *FindAndRemoveBnContext(const TEEC_Context *context);
TEEC_Session *GetBnSession(const TEEC_Session *session, TEEC_ContextInner *context);
void PutBnSession(TEEC_Session *session);
TEEC_Session *FindAndRemoveSession(const TEEC_Session *session, TEEC_ContextInner *context);
TEEC_SharedMemoryInner *GetBnShmByOffset(uint32_t shmOffset, TEEC_ContextInner *context);
void PutBnShrMem(TEEC_SharedMemoryInner *shrMem);
TEEC_Result TEEC_SendSecfileInner(const char *path, int tzFd, FILE *fp);

#ifdef __cplusplus
}
#endif
#endif
