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

#include "tee_client_api.h"
#include <errno.h>     /* for errno */
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <securec.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h> /* for ioctl */
#include <sys/mman.h>  /* for mmap */
#include <sys/stat.h>
#include <sys/types.h> /* for open close */
#include "tc_ns_client.h"
#include "tee_client_app_load.h"
#include "tee_client_inner_api.h"
#include "tee_client_list.h"
#include "tee_get_native_cert.h"
#include "tee_log.h"

#define TEE_ERROR_CA_AUTH_FAIL 0xFFFFCFE5

#define AGENT_BUFF_SIZE           0x1000
#define CA_AUTH_RETRY_TIMES       30
#define H_OFFSET                  32

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "libteec_vendor"

#define SHIFT    3
#define MASK     0x7
#define BYTE_BIT 8

void SetBit(uint32_t i, uint32_t byteMax, uint8_t *bitMap)
{
    if ((i >> SHIFT) >= byteMax) {
        return;
    }
    if (bitMap == NULL) {
        return;
    }
    bitMap[i >> SHIFT] |= (1U << (i & MASK));
}

void ClearBit(uint32_t i, uint32_t byteMax, uint8_t *bitMap)
{
    if ((i >> SHIFT) >= byteMax) {
        return;
    }
    if (bitMap == NULL) {
        return;
    }
    bitMap[i >> SHIFT] &= ~(1U << (i & MASK));
}

static void ClearBitWithLock(pthread_mutex_t *mutex, uint32_t i, uint32_t byteMax, uint8_t *bitMap)
{
    if (pthread_mutex_lock(mutex) != 0) {
        tloge("get share mem bit lock failed\n");
        return;
    }
    ClearBit(i, byteMax, bitMap);
    (void)pthread_mutex_unlock(mutex);
}

enum BitmapOps {
    SET,
    CLEAR
};

static int32_t IterateBitmap(uint8_t *bitMap, uint32_t byteMax, enum BitmapOps ops)
{
    uint32_t i, j;
    int32_t validBit = -1;
    uint8_t refByte = ((ops == SET) ? 0xff : 0);
    bool refBit = ((ops == SET) ? true : false);

    for (i = 0; i < byteMax; i++) {
        if (bitMap[i] == refByte) {
            continue;
        }
        for (j = 0; j < BYTE_BIT; j++) {
            bool bitZero = (bitMap[i] & (0x1 << j)) == 0;
            if (bitZero == refBit) {
                validBit = (int32_t)i * BYTE_BIT + (int32_t)j;
                break;
            }
        }

        if (validBit != -1) {
            break;
        }
    }

    if (validBit == -1) {
        return validBit;
    }

    if (ops == SET) {
        SetBit(validBit, byteMax, bitMap);
    } else {
        ClearBit(validBit, byteMax, bitMap);
    }
    return validBit;
}

int32_t GetAndSetBit(uint8_t *bitMap, uint32_t byteMax)
{
    if (bitMap == NULL) {
        return -1;
    }
    return IterateBitmap(bitMap, byteMax, SET);
}

static int32_t GetAndSetBitWithLock(pthread_mutex_t *mutex, uint8_t *bitMap, uint32_t byteMax)
{
    if (pthread_mutex_lock(mutex) != 0) {
        tloge("get share mem bit lock failed\n");
        return -1;
    }
    int32_t validBit = GetAndSetBit(bitMap, byteMax);
    (void)pthread_mutex_unlock(mutex);
    return validBit;
}

int32_t GetAndCleartBit(uint8_t *bitMap, uint32_t byteMax)
{
    if (bitMap == NULL) {
        return -1;
    }
    return IterateBitmap(bitMap, byteMax, CLEAR);
}

static pthread_mutex_t g_mutexAtom = PTHREAD_MUTEX_INITIALIZER;
static void AtomInc(volatile uint32_t *cnt)
{
    /*
     * The use of g_mutexAtom has been rigorously checked
     * and there is no risk of failure, we do not care the return value
     * of pthread_mutex_lock here
     */
    (void)pthread_mutex_lock(&g_mutexAtom);
    (*cnt)++;
    (void)pthread_mutex_unlock(&g_mutexAtom);
}

static bool AtomDecAndCompareWithZero(volatile uint32_t *cnt)
{
    bool result = false;

    /*
     * The use of g_mutexAtom has been rigorously checked
     * and there is no risk of failure, we do not care the return value
     * of pthread_mutex_lock here
     */
    (void)pthread_mutex_lock(&g_mutexAtom);
    (*cnt)--;
    if ((*cnt) == 0) {
        result = true;
    }
    (void)pthread_mutex_unlock(&g_mutexAtom);
    return result;
}

static LIST_DECLARE(g_teecContextList);
static pthread_mutex_t g_mutexTeecContext = PTHREAD_MUTEX_INITIALIZER;
TEEC_Result TEEC_CheckOperation(TEEC_ContextInner *context, const TEEC_Operation *operation);

static int32_t MutexLockContext(void)
{
    int lockRet = pthread_mutex_lock(&g_mutexTeecContext);
    return lockRet;
}

static void MutexUnlockContext(int lockRet)
{
    if (lockRet) {
        tloge("unlock mutex: not exe, mutex not in lock state. lockRet = %d\n", lockRet);
        return;
    }
    (void)pthread_mutex_unlock(&g_mutexTeecContext);
}

static TEEC_Result AddSessionList(uint32_t sessionId, const TEEC_UUID *destination, TEEC_ContextInner *context,
                                  TEEC_Session *session)
{
    struct ListNode *node      = NULL;
    struct ListNode *n         = NULL;
    TEEC_Session *sessionEntry = NULL;

    session->session_id = sessionId;
    session->service_id = *destination;
    session->ops_cnt    = 1; /* only for libteec hidl, not for vendor ca */

    int lockRet = pthread_mutex_lock(&context->sessionLock);
    if (lockRet != 0) {
        tloge("get session lock failed.\n");
        return TEEC_ERROR_GENERIC;
    }
    /* if session is still in list,  remove it */
    LIST_FOR_EACH_SAFE(node, n, &context->session_list)
    {
        sessionEntry = CONTAINER_OF(node, TEEC_Session, head);
        if (sessionEntry == session) {
            ListRemoveEntry(node);
        }
    }
    ListInit(&session->head);
    ListInsertTail(&context->session_list, &session->head);
    AtomInc(&session->ops_cnt); /* only for libteec hidl, not for vendor ca */
    (void)pthread_mutex_unlock(&context->sessionLock);
    return TEEC_SUCCESS;
}

static TEEC_ContextInner *FindBnContext(const TEEC_Context *context)
{
    TEEC_ContextInner *sContext = NULL;

    if (context == NULL) {
        tloge("find context: context is NULL!\n");
        return NULL;
    }

    struct ListNode *ptr = NULL;
    if (!LIST_EMPTY(&g_teecContextList)) {
        LIST_FOR_EACH(ptr, &g_teecContextList)
        {
            TEEC_ContextInner *tmp = CONTAINER_OF(ptr, TEEC_ContextInner, c_node);
            if (tmp->fd == context->fd) {
                sContext = tmp;
                break;
            }
        }
    }
    return sContext;
}

TEEC_ContextInner *GetBnContext(const TEEC_Context *context)
{
    TEEC_ContextInner *sContext = NULL;

    int retMutexLock = MutexLockContext();
    if (retMutexLock != 0) {
        tloge("get context lock failed.\n");
        return NULL;
    }
    sContext = FindBnContext(context);
    if (sContext != NULL) {
        AtomInc(&sContext->ops_cnt);
    }
    MutexUnlockContext(retMutexLock);
    return sContext;
}

bool PutBnContext(TEEC_ContextInner *context)
{
    if (context == NULL) {
        tloge("put context: context is NULL!\n");
        return false;
    }

    if (AtomDecAndCompareWithZero(&context->ops_cnt)) {
        TEEC_FinalizeContextInner(context);
        return true;
    }

    return false;
}

TEEC_ContextInner *FindAndRemoveBnContext(const TEEC_Context *context)
{
    TEEC_ContextInner *sContext = NULL;

    int retMutexLock = MutexLockContext();
    if (retMutexLock != 0) {
        tloge("get context lock failed.\n");
        return NULL;
    }
    sContext = FindBnContext(context);
    if (sContext != NULL) {
        ListRemoveEntry(&sContext->c_node);
    }
    MutexUnlockContext(retMutexLock);
    return sContext;
}

static TEEC_Session *FindBnSession(const TEEC_Session *session, const TEEC_ContextInner *context)
{
    TEEC_Session *sSession = NULL;

    struct ListNode *ptr = NULL;
    if (!LIST_EMPTY(&context->session_list)) {
        LIST_FOR_EACH(ptr, &context->session_list)
        {
            TEEC_Session *tmp = CONTAINER_OF(ptr, TEEC_Session, head);
            if (tmp->session_id == session->session_id) {
                sSession = tmp;
                break;
            }
        }
    }
    return sSession;
}

/* only for libteec hidl, not for vendor ca */
TEEC_Session *GetBnSession(const TEEC_Session *session, TEEC_ContextInner *context)
{
    TEEC_Session *sSession = NULL;

    if (session == NULL || context == NULL) {
        tloge("get session: context or session is NULL!\n");
        return NULL;
    }

    int lockRet = pthread_mutex_lock(&context->sessionLock);
    if (lockRet != 0) {
        tloge("get session lock failed.\n");
        return NULL;
    }
    sSession = FindBnSession(session, context);
    if (sSession != NULL) {
        AtomInc(&sSession->ops_cnt);
    }
    (void)pthread_mutex_unlock(&context->sessionLock);
    return sSession;
}

/* only for libteec hidl, not for vendor ca */
void PutBnSession(TEEC_Session *session)
{
    if (session == NULL) {
        tloge("put session: session is NULL!\n");
        return;
    }

    if (AtomDecAndCompareWithZero(&session->ops_cnt)) {
        free(session);
    }
    return;
}

TEEC_Session *FindAndRemoveSession(const TEEC_Session *session, TEEC_ContextInner *context)
{
    TEEC_Session *sSession = NULL;

    if (session == NULL || context == NULL) {
        tloge("find and remove session: context or session is NULL!\n");
        return NULL;
    }

    int lockRet = pthread_mutex_lock(&context->sessionLock);
    if (lockRet != 0) {
        tloge("get session lock failed.\n");
        return NULL;
    }
    sSession = FindBnSession(session, context);
    if (sSession != NULL) {
        ListRemoveEntry(&sSession->head);
    }
    (void)pthread_mutex_unlock(&context->sessionLock);
    return sSession;
}

static void ReleaseSharedMemory(TEEC_SharedMemoryInner *sharedMem)
{
    bool condition = (sharedMem->is_allocated) && (sharedMem->buffer != NULL) && (sharedMem->buffer != ZERO_SIZE_PTR) &&
                     (sharedMem->size != 0);
    if (condition) {
        int32_t ret = ioctl(sharedMem->context->fd, (int)TC_NS_CLIENT_IOCTL_UNMAP_SHARED_MEM, sharedMem->buffer);
        if (ret) {
            tlogd("Release SharedMemory ioctl failed, maybe linux not support\n");
        }

        ret = munmap(sharedMem->buffer, sharedMem->size);
        if (ret) {
            tloge("Release SharedMemory failed, munmap error\n");
        }
        ClearBitWithLock(&sharedMem->context->shrMemBitMapLock, sharedMem->offset,
                         sizeof(sharedMem->context->shm_bitmap), sharedMem->context->shm_bitmap);
    }

    sharedMem->buffer  = NULL;
    sharedMem->size    = 0;
    sharedMem->flags   = 0;
    sharedMem->ops_cnt = 0;
    sharedMem->context = NULL;
    free(sharedMem);
}

void PutBnShrMem(TEEC_SharedMemoryInner *shrMem)
{
    if (shrMem == NULL) {
        return;
    }

    if (AtomDecAndCompareWithZero(&shrMem->ops_cnt)) {
        ReleaseSharedMemory(shrMem);
    }
    return;
}

TEEC_SharedMemoryInner *GetBnShmByOffset(uint32_t shmOffset, TEEC_ContextInner *context)
{
    TEEC_SharedMemoryInner *tempShardMem = NULL;

    if (context == NULL) {
        tloge("get shrmem offset: context is NULL!\n");
        return NULL;
    }

    int lockRet = pthread_mutex_lock(&context->shrMemLock);
    if (lockRet != 0) {
        tloge("get shrmem lock failed.\n");
        return NULL;
    }

    /* found server shardmem */
    struct ListNode *ptr = NULL;
    if (!LIST_EMPTY(&context->shrd_mem_list)) {
        LIST_FOR_EACH(ptr, &context->shrd_mem_list)
        {
            tempShardMem = CONTAINER_OF(ptr, TEEC_SharedMemoryInner, head);
            if (tempShardMem->offset == shmOffset) {
                AtomInc(&tempShardMem->ops_cnt);
                (void)pthread_mutex_unlock(&context->shrMemLock);
                return tempShardMem;
            }
        }
    }
    (void)pthread_mutex_unlock(&context->shrMemLock);
    return NULL;
}

static TEEC_Result MallocShrMemInner(TEEC_SharedMemoryInner **shareMemInner)
{
    errno_t nRet;

    TEEC_SharedMemoryInner *shmInner = (TEEC_SharedMemoryInner *)malloc(sizeof(*shmInner));
    if (shmInner == NULL) {
        tloge("malloc shrmem: shmInner malloc failed\n");
        return TEEC_FAIL;
    }
    nRet = memset_s(shmInner, sizeof(*shmInner), 0x00, sizeof(*shmInner));
    if (nRet != EOK) {
        tloge("malloc shrmem: shmInner memset failed : %d\n", (int)nRet);
        free(shmInner);
        return TEEC_FAIL;
    }
    *shareMemInner = shmInner;
    return TEEC_SUCCESS;
}

static TEEC_Result TranslateRetValue(int32_t ret)
{
    TEEC_Result teeRet;

    switch (ret) {
        case -EFAULT:
            teeRet = TEEC_ERROR_ACCESS_DENIED;
            break;
        case -ENOMEM:
            teeRet = TEEC_ERROR_OUT_OF_MEMORY;
            break;
        case -EINVAL:
            teeRet = TEEC_ERROR_BAD_PARAMETERS;
            break;
        default:
            teeRet = TEEC_ERROR_GENERIC;
            break;
    }
    return teeRet;
}

static uint32_t TranslateParamType(uint32_t flag)
{
    uint32_t paramType;

    switch (flag) {
        case TEEC_MEM_INPUT:
            paramType = TEEC_MEMREF_PARTIAL_INPUT;
            break;
        case TEEC_MEM_OUTPUT:
            paramType = TEEC_MEMREF_PARTIAL_OUTPUT;
            break;
        case TEEC_MEM_INOUT:
            paramType = TEEC_MEMREF_PARTIAL_INOUT;
            break;
        default:
            paramType = TEEC_MEMREF_PARTIAL_INOUT;
            break;
    }

    return paramType;
}

static void TEEC_EncodeTempParam(const TEEC_TempMemoryReference *tempRef, TC_NS_ClientParam *param)
{
    param->memref.buffer        = (unsigned int)(uintptr_t)tempRef->buffer;
    param->memref.buffer_h_addr = ((unsigned long long)(uintptr_t)tempRef->buffer) >> H_OFFSET;
    param->memref.size_addr     = (unsigned int)(uintptr_t)&tempRef->size;
    param->memref.size_h_addr   = ((unsigned long long)(uintptr_t)&tempRef->size) >> H_OFFSET;
}

static void TEEC_EncodePartialParam(uint32_t paramType, const TEEC_RegisteredMemoryReference *memRef,
                                    TC_NS_ClientParam *param)
{
    /* buffer offset len */
    if (paramType == TEEC_MEMREF_WHOLE) {
        param->memref.offset      = 0;
        param->memref.size_addr   = (unsigned int)(uintptr_t)&memRef->parent->size;
        param->memref.size_h_addr = ((unsigned long long)(uintptr_t)&memRef->parent->size) >> H_OFFSET;
    } else {
        param->memref.offset      = memRef->offset;
        param->memref.size_addr   = (unsigned int)(uintptr_t)&memRef->size;
        param->memref.size_h_addr = ((unsigned long long)(uintptr_t)&memRef->size) >> H_OFFSET;
    }

    if (memRef->parent->is_allocated) {
        param->memref.buffer        = (unsigned int)(uintptr_t)memRef->parent->buffer;
        param->memref.buffer_h_addr = ((unsigned long long)(uintptr_t)memRef->parent->buffer) >> H_OFFSET;
    } else {
        param->memref.buffer = (unsigned int)(uintptr_t)((unsigned char *)memRef->parent->buffer + memRef->offset);
        param->memref.buffer_h_addr =
            (unsigned long long)(uintptr_t)((unsigned char *)memRef->parent->buffer + memRef->offset) >> H_OFFSET;
        param->memref.offset = 0;
    }
}

static void TEEC_EncodeValueParam(const TEEC_Value *val, TC_NS_ClientParam *param)
{
    param->value.a_addr   = (unsigned int)(uintptr_t)&val->a;
    param->value.a_h_addr = ((unsigned long long)(uintptr_t)&val->a) >> H_OFFSET;
    param->value.b_addr   = (unsigned int)(uintptr_t)&val->b;
    param->value.b_h_addr = ((unsigned long long)(uintptr_t)&val->b) >> H_OFFSET;
}

static void TEEC_EncodeParam(TC_NS_ClientContext *cliContext, const TEEC_Operation *operation)
{
    uint32_t paramType[TEEC_PARAM_NUM];
    uint32_t paramCnt;
    uint32_t diff;

    diff = (uint32_t)TEEC_MEMREF_PARTIAL_INPUT - (uint32_t)TEEC_MEMREF_TEMP_INPUT;

    for (paramCnt = 0; paramCnt < TEEC_PARAM_NUM; paramCnt++) {
        paramType[paramCnt] = TEEC_PARAM_TYPE_GET(operation->paramTypes, paramCnt);
        if (IS_TEMP_MEM(paramType[paramCnt])) {
            TEEC_EncodeTempParam(&operation->params[paramCnt].tmpref, &cliContext->params[paramCnt]);
        } else if (IS_PARTIAL_MEM(paramType[paramCnt])) {
            const TEEC_RegisteredMemoryReference *memref = &operation->params[paramCnt].memref;

            TEEC_EncodePartialParam(paramType[paramCnt], memref, &cliContext->params[paramCnt]);

            /* translate the paramType to know the driver */
            if (paramType[paramCnt] == TEEC_MEMREF_WHOLE) {
                paramType[paramCnt] = TranslateParamType(memref->parent->flags);
            }

            /* if is not allocated,
             * translate TEEC_MEMREF_PARTIAL_XXX to TEEC_MEMREF_TEMP_XXX */
            if (!memref->parent->is_allocated) {
                paramType[paramCnt] = paramType[paramCnt] - diff;
            }
        } else if (IS_VALUE_MEM(paramType[paramCnt])) {
            TEEC_EncodeValueParam(&operation->params[paramCnt].value, &cliContext->params[paramCnt]);
        } else {
            /* if type is none, ignore it */
        }
    }

    cliContext->paramTypes = TEEC_PARAM_TYPES(paramType[0], paramType[1], paramType[2], paramType[3]);
    tlogd("cli param type %x\n", cliContext->paramTypes);
    return;
}

static TEEC_Result TEEC_Encode(TC_NS_ClientContext *cliContext, const TEEC_Session *session,
                               uint32_t cmdId, const TC_NS_ClientLogin *cliLogin, const TEEC_Operation *operation)
{
    errno_t rc;

    rc = memset_s(cliContext, sizeof(TC_NS_ClientContext), 0x00, sizeof(TC_NS_ClientContext));
    if (rc != EOK) {
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }

    cliContext->session_id   = session->session_id;
    cliContext->cmd_id       = cmdId;
    cliContext->returns.code = 0;
    cliContext->returns.origin = TEEC_ORIGIN_API;

    cliContext->login.method = cliLogin->method;
    cliContext->login.mdata  = cliLogin->mdata;

    rc = memcpy_s(cliContext->uuid, sizeof(cliContext->uuid), (uint8_t *)(&session->service_id), sizeof(TEEC_UUID));
    if (rc != EOK) {
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }

    if ((operation == NULL) || (!operation->paramTypes)) {
        return TEEC_SUCCESS;
    }
    cliContext->started = operation->cancel_flag;

    TEEC_EncodeParam(cliContext, operation);

    return TEEC_SUCCESS;
}

static int32_t ObtainTzdriveFd()
{
    int32_t fd = open(TC_NS_CLIENT_DEV_NAME, O_RDWR);
    if (fd < 0) {
        tloge("open tzdriver fd failed\n");
        return -1;
    }
    return fd;
}

static TEEC_Result SetLoginInfo(const CaAuthInfo *caInfo, int32_t fd)
{
    uint8_t *buf = NULL;
    TEEC_Result teeRet = TEEC_ERROR_GENERIC;
    int32_t ret;

    if (caInfo != NULL) {
        uint32_t bufLen = BUFF_LEN_MAX;
        buf = (uint8_t *)malloc(bufLen);
        if (buf == NULL) {
            tloge("malloc failed\n");
            goto END;
        }

        ret = memset_s(buf, bufLen, 0, bufLen);
        if (ret != EOK) {
            tloge("memset buf failed\n");
            goto END;
        }

        ret = TeeGetNativeCert(caInfo->pid, caInfo->uid, &bufLen, buf);
        if (ret) {
            tloge("CERT check failed\n");
            goto END;
        }
    }

    if (buf != NULL) {
        ret = ioctl(fd, TC_NS_CLIENT_IOCTL_LOGIN, buf);
    } else {
        ret = ioctl(fd, TC_NS_CLIENT_IOCTL_LOGIN, 0);
    }

    if (ret) {
        tloge("Failed to set login information for client err = %d\n", ret);
        teeRet = TEEC_ERROR_GENERIC;
    } else {
        teeRet = TEEC_SUCCESS;
    }

END:
    if (buf != NULL) {
        free(buf);
        buf = NULL;
    }

    return teeRet;
}

TEEC_Result TEEC_InitializeContextInner(TEEC_ContextInner *context, const CaAuthInfo *caInfo)
{
    if (context == NULL) {
        tloge("Initial context: context is NULL\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    int32_t fd = ObtainTzdriveFd();
    if (fd < 0) {
        tloge("obtain fd failed\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    if (SetLoginInfo(caInfo, fd) != TEEC_SUCCESS) {
        tloge("set login failed\n");
        close(fd);
        return TEEC_ERROR_GENERIC;
    }

    context->fd           = (uint32_t)fd;
    context->ops_cnt      = 1;

    ListInit(&context->session_list);
    ListInit(&context->shrd_mem_list);

    errno_t nRet = memset_s(context->shm_bitmap, sizeof(context->shm_bitmap), 0x00, sizeof(context->shm_bitmap));
    if (nRet != EOK) {
        tloge("Initial context: context->shm_bitmap memset failed : %d\n", (int)nRet);
        close((int)context->fd);
        return TEEC_FAIL;
    }

    int retMutexLock = MutexLockContext();
    if (retMutexLock != 0) {
        tloge("get context lock failed.\n");
        close((int)context->fd);
        return TEEC_FAIL;
    }
    (void)pthread_mutex_init(&context->sessionLock, NULL);
    (void)pthread_mutex_init(&context->shrMemLock, NULL);
    (void)pthread_mutex_init(&context->shrMemBitMapLock, NULL);
    ListInsertTail(&g_teecContextList, &context->c_node);
    AtomInc(&context->ops_cnt);
    MutexUnlockContext(retMutexLock);

    return TEEC_SUCCESS;
}

/*
 * Function:      TEEC_InitializeContext
 * Description:   This function initializes a new TEE Context, forming a connection between
 *                this Client Application and the TEE identified by the string identifier name.
 * Parameters:   name: a zero-terminated string that describes the TEE to connect to.
 *                If this parameter is set to NULL, the Implementation MUST select a default TEE.
 *                context: a TEEC_Context structure that be initialized by the Implementation.
 * Return:        TEEC_SUCCESS: the initialization was successful.
 *                     other: initialization was not successful.
 */
TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
    TEEC_Result ret;
    errno_t nRet;
    uint32_t conCxt = 0;
    struct ListNode *ptr = NULL;

    (void)name;

    if (context == NULL) {
        tloge("initialize context: context is NULL\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    if (!LIST_EMPTY(&g_teecContextList)) {
        LIST_FOR_EACH(ptr, &g_teecContextList) {
            conCxt++;
        }
    }

    if (conCxt >= MAX_CXTCNT_ONECA) {
        tloge("the contexts is already full, please finalize some of them\n");
        return TEEC_FAIL;
    }

    TEEC_ContextInner *contextInner = (TEEC_ContextInner *)malloc(sizeof(*contextInner));
    if (contextInner == NULL) {
        tloge("initialize context: Failed to malloc teec contextInner\n");
        return TEEC_ERROR_GENERIC;
    }
    nRet = memset_s(contextInner, sizeof(*contextInner), 0, sizeof(*contextInner));
    if (nRet != EOK) {
        tloge("initialize context: contextInner memset failed : %d\n", (int)nRet);
        free(contextInner);
        return TEEC_FAIL;
    }

    ret = TEEC_InitializeContextInner(contextInner, NULL);
    if (ret == TEEC_SUCCESS) {
        context->fd      = contextInner->fd;
        context->ta_path = NULL;

        ListInit(&context->session_list);
        ListInit(&context->shrd_mem_list);
        (void)PutBnContext(contextInner); /* pair with ops_cnt++ when add to list */
        return TEEC_SUCCESS;
    }

    tloge("initialize context: failed:0x%x\n", ret);
    free(contextInner);
    return ret;
}

/*
 * Function:       TEEC_FinalizeContext
 * Description:   This function finalizes an initialized TEE Context.
 * Parameters:   context: an initialized TEEC_Context structure which is to be finalized.
 * Return:         NULL
 */
void TEEC_FinalizeContextInner(TEEC_ContextInner *context)
{
    struct ListNode *ptr           = NULL;
    struct ListNode *n             = NULL;
    TEEC_Session *session          = NULL;
    TEEC_SharedMemoryInner *shrdMem = NULL;

    /* First, check parameters is valid or not */
    if (context == NULL) {
        tloge("finalize context hidl: context is NULL\n");
        return;
    }

    int lockRet = pthread_mutex_lock(&context->sessionLock);
    if (lockRet != 0) {
        tloge("get session lock failed.\n");
        return;
    }
    if (!LIST_EMPTY(&context->session_list)) {
        tlogd("context still has sessions opened, close it\n");

        LIST_FOR_EACH_SAFE(ptr, n, &context->session_list)
        {
            session = CONTAINER_OF(ptr, TEEC_Session, head);
            ListRemoveEntry(&session->head);
            TEEC_CloseSessionInner(session, context);
            /* for service */
            if (context->callFromService) {
                PutBnSession(session); /* pair with open session */
                session = NULL;
            }
        }
    }
    (void)pthread_mutex_unlock(&context->sessionLock);

    lockRet = pthread_mutex_lock(&context->shrMemLock);
    if (lockRet != 0) {
        tloge("get shrmem lock failed.\n");
        return;
    }

    if (!LIST_EMPTY(&context->shrd_mem_list)) {
        tlogd("context contains unreleased Shared Memory blocks, release it\n");

        LIST_FOR_EACH_SAFE(ptr, n, &context->shrd_mem_list)
        {
            shrdMem = CONTAINER_OF(ptr, TEEC_SharedMemoryInner, head);
            ListRemoveEntry(&shrdMem->head);
            PutBnShrMem(shrdMem); /* pair with Initial value 1 */
        }
    }
    (void)pthread_mutex_unlock(&context->shrMemLock);

    close((int)context->fd);
    context->fd = -1;
    (void)pthread_mutex_destroy(&context->sessionLock);
    (void)pthread_mutex_destroy(&context->shrMemLock);
    free(context);
}

void TEEC_FinalizeContext(TEEC_Context *context)
{
    if (context == NULL) {
        tloge("finalize context: context is NULL\n");
        return;
    }

    TEEC_ContextInner *contextInner = FindAndRemoveBnContext(context);
    (void)PutBnContext(contextInner); /* pair with initialize context */
    context->fd = -1;
}

static TEEC_Result TEEC_DoOpenSession(int fd, TC_NS_ClientContext *cliContext, const TEEC_UUID *destination,
                                      TEEC_ContextInner *context, TEEC_Session *session)
{
    int32_t ret;
    TEEC_Result teecRet;

    int i = CA_AUTH_RETRY_TIMES;
    do {
        cliContext->returns.code   = 0;
        cliContext->returns.origin = TEEC_ORIGIN_API;
        ret = ioctl(fd, (int)TC_NS_CLIENT_IOCTL_SES_OPEN_REQ, cliContext);
    } while (((TEEC_Result)cliContext->returns.code == TEE_ERROR_CA_AUTH_FAIL) && i--);

    if (ret < 0) {
        tloge("open session failed, ioctl errno = %d\n", ret);
        teecRet                    = TranslateRetValue(ret);
        cliContext->returns.origin = TEEC_ORIGIN_COMMS;
        goto ERROR;
    } else if (ret > 0) {
        tloge("open session failed(%d), code=0x%x, origin=%u\n", ret, cliContext->returns.code,
              cliContext->returns.origin);
        if (cliContext->returns.code) {
            teecRet = (TEEC_Result)cliContext->returns.code;
        } else {
            teecRet = (TEEC_Result)TEEC_ERROR_GENERIC;
        }
        goto ERROR;
    }

    return AddSessionList(cliContext->session_id, destination, context, session);

ERROR:
    return teecRet;
}

TEEC_Result TEEC_OpenSessionInner(int callingPid, const TaFileInfo *taFile, TEEC_ContextInner *context,
    TEEC_Session *session, const TEEC_UUID *destination, uint32_t connectionMethod,
    const void *connectionData, TEEC_Operation *operation, uint32_t *returnOrigin)
{
    TEEC_Result teecRet = (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    TC_NS_ClientContext cliContext;
    TC_NS_ClientLogin cliLogin = { 0, 0 };

    /* prefirst, we set origin be zero */
    cliContext.returns.origin = TEEC_ORIGIN_API;
    cliContext.file_buffer    = NULL;

    bool condition = (context == NULL) || (taFile == NULL) || (session == NULL) || (destination == NULL);
    if (condition) {
        tloge("context or session or destination is NULL\n");
        goto ERROR;
    }
    /* now only support TEEC_LOGIN_IDENTIFY */
    condition = (connectionMethod != TEEC_LOGIN_IDENTIFY) || (connectionData != NULL);
    if (condition) {
        tloge("Login method is not supported or connection data is not null\n");
        goto ERROR;
    }

    cliLogin.method = connectionMethod;

    if (operation != NULL) {
        /* Params 2 and 3 are used for ident by teecd hence ->TEEC_NONE */
        operation->paramTypes = TEEC_PARAM_TYPES(TEEC_PARAM_TYPE_GET(operation->paramTypes, 0),
                                                 TEEC_PARAM_TYPE_GET(operation->paramTypes, 1), TEEC_NONE, TEEC_NONE);
    }
    teecRet = TEEC_CheckOperation(context, operation);
    if (teecRet != TEEC_SUCCESS) {
        tloge("operation is invalid\n");
        goto ERROR;
    }

    /* Paramters right, start execution */
    /*
     * note:before open session success, we should send session=0 as initial state.
     */
    teecRet = TEEC_Encode(&cliContext, session, GLOBAL_CMD_ID_OPEN_SESSION, &cliLogin, operation);
    if (teecRet != TEEC_SUCCESS) {
        tloge("OpenSession: teec encode failed(0x%x)!\n", teecRet);
        goto ERROR;
    }

    cliContext.callingPid = (unsigned int)callingPid;

    int32_t ret = TEEC_GetApp(taFile, destination, &cliContext);
    if (ret < 0) {
        tloge("get app error\n");
        teecRet = (TEEC_Result)TEEC_ERROR_TRUSTED_APP_LOAD_ERROR;
        goto ERROR;
    }

    teecRet = TEEC_DoOpenSession(context->fd, &cliContext, destination, context, session);

ERROR:
    /* ONLY when ioctl returnCode!=0 and returnOrigin not NULL,
     * set *returnOrigin
     */
    if (returnOrigin != NULL) {
        *returnOrigin = cliContext.returns.origin;
    }

    if (cliContext.file_buffer != NULL) {
        free(cliContext.file_buffer);
    }
    return teecRet;
}

/*
 * Function:     TEEC_OpenSession
 * Description:  This function opens a new Session
 * Parameters:   context: a pointer to an initialized TEE Context.
 *               session: a pointer to a Session structure to open.
 *               destination: a pointer to a UUID structure.
 *               connectionMethod: the method of connection to use.
 *               connectionData: any necessary data required to support the connection method chosen.
 *               operation: a pointer to an Operation containing a set of Parameters.
 *               returnOrigin: a pointer to a variable which will contain the return origin.
 * Return:       TEEC_SUCCESS: success
 *               other:        failure
 */
TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session, const TEEC_UUID *destination,
                             uint32_t connectionMethod, const void *connectionData, TEEC_Operation *operation,
                             uint32_t *returnOrigin)
{
    TEEC_Result ret    = TEEC_ERROR_BAD_PARAMETERS;
    uint32_t retOrigin = TEEC_ORIGIN_API;

    if ((context == NULL) || (session == NULL) || (destination == NULL)) {
        tloge("param is null!\n");
        goto END;
    }

    /*
     * ca may call closesession even if opensession failed,
     * we set session->context here to avoid receive a illegal ptr
     */
    session->context = context;
    session->service_id = *destination;
    session->session_id = 0;

    TaFileInfo taFile;
    taFile.taFp   = NULL;
    taFile.taPath = context->ta_path;

    TEEC_ContextInner *contextInner = GetBnContext(context);
    if (contextInner == NULL) {
        tloge("no context found in hidl service!\n");
        goto END;
    }

    ret = TEEC_OpenSessionInner(0, &taFile, contextInner, session, destination,
        connectionMethod, connectionData, operation, &retOrigin);
    (void)PutBnContext(contextInner);

END:
    if (returnOrigin != NULL) {
        *returnOrigin = retOrigin;
    }
    return ret;
}

void TEEC_CloseSessionInner(TEEC_Session *session, const TEEC_ContextInner *context)
{
    int32_t ret;
    TC_NS_ClientContext cliContext;
    TC_NS_ClientLogin cliLogin = { 0, 0 };
    TEEC_Result teecRet;

    /* First, check parameters is valid or not */
    if ((session == NULL) || (context == NULL)) {
        tloge("close session hidl: session or context is NULL\n");
        return;
    }

    teecRet = TEEC_Encode(&cliContext, session, GLOBAL_CMD_ID_CLOSE_SESSION, &cliLogin, NULL);
    if (teecRet != TEEC_SUCCESS) {
        tloge("close session hidl: teec encode failed(0x%x)!\n", teecRet);
        return;
    }

    ret = ioctl((int)context->fd, (int)TC_NS_CLIENT_IOCTL_SES_CLOSE_REQ, &cliContext);
    if (ret != 0) {
        tloge("close session failed, ret=0x%x\n", ret);
    }
    session->session_id = 0;
    session->context    = NULL;
    errno_t rc =
        memset_s((uint8_t *)&session->service_id, sizeof(session->service_id), 0x00, sizeof(session->service_id));
    if (rc != EOK) {
        tloge("memset service id fail\n");
    }
    return;
}

/*
 * Function:       TEEC_CloseSession
 * Description:   This function closes an opened Session.
 * Parameters:   session: the session to close.
 * Return:         NULL
 */
void TEEC_CloseSession(TEEC_Session *session)
{
    if ((session == NULL) || (session->context == NULL)) {
        tloge("close session: session or session->context is NULL\n");
        return;
    }

    TEEC_ContextInner *contextInner = GetBnContext(session->context);
    if (contextInner == NULL) {
        tloge("context hidl is NULL\n");
        return;
    }
    TEEC_Session *sessionInList = FindAndRemoveSession(session, contextInner);
    if (sessionInList == NULL) {
        tloge("session is not in the context list\n");
        (void)PutBnContext(contextInner);
        return;
    }

    TEEC_CloseSessionInner(session, contextInner);
    (void)PutBnContext(contextInner);
}

static TEEC_Result ProcessInvokeCommand(const TEEC_ContextInner *context, TC_NS_ClientContext *cliContext)
{
    TEEC_Result teecRet;

    int32_t ret = ioctl((int)context->fd, (int)TC_NS_CLIENT_IOCTL_SEND_CMD_REQ, cliContext);
    if (ret == 0) {
        tlogd("invoke cmd success\n");
        teecRet = TEEC_SUCCESS;
    } else if (ret < 0) {
        teecRet                   = TranslateRetValue(-errno);
        tloge("invoke cmd failed, ioctl errno = %d\n", errno);
        cliContext->returns.origin = TEEC_ORIGIN_COMMS;
    } else {
        tloge("invoke cmd failed(%d), code=0x%x, origin=%u\n", ret,
              cliContext->returns.code, cliContext->returns.origin);
        if (cliContext->returns.code) {
            teecRet = (TEEC_Result)cliContext->returns.code;
        } else {
            teecRet = (TEEC_Result)TEEC_ERROR_GENERIC;
        }
    }

    return teecRet;
}

TEEC_Result TEEC_InvokeCommandInner(TEEC_ContextInner *context, const TEEC_Session *session,
    uint32_t commandID, const TEEC_Operation *operation, uint32_t *returnOrigin)
{
    TEEC_Result teecRet = (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    TC_NS_ClientContext cliContext;
    TC_NS_ClientLogin cliLogin = { 0, 0 };
    /* prefirst, we set origin be zero */
    cliContext.returns.origin = TEEC_ORIGIN_API;
    /* First, check parameters is valid or not */
    if ((session == NULL) || (context == NULL)) {
        goto ERROR;
    }
    teecRet = TEEC_CheckOperation(context, operation);
    if (teecRet != TEEC_SUCCESS) {
        tloge("operation is invalid\n");
        goto ERROR;
    }

    /* Paramters all right, start execution */
    teecRet = TEEC_Encode(&cliContext, session, commandID, &cliLogin, operation);
    if (teecRet != TEEC_SUCCESS) {
        tloge("InvokeCommand: teec encode failed(0x%x)!\n", teecRet);
        goto ERROR;
    }

    teecRet = ProcessInvokeCommand(context, &cliContext);
    if (teecRet != TEEC_SUCCESS) {
        tloge("InvokeCommand failed\n");
    }

ERROR:
    /* ONLY when ioctl returnCode!=0 and returnOrigin not NULL,
     * set *returnOrigin
     */
    if (returnOrigin != NULL) {
        *returnOrigin = cliContext.returns.origin;
    }
    return teecRet;
}

/*
 * Function:       TEEC_InvokeCommand
 * Description:   This function invokes a Command within the specified Session.
 * Parameters:   session: the open Session in which the command will be invoked.
 *                     commandID: the identifier of the Command.
 *                     operation: a pointer to an Operation containing a set of Parameters.
 *                     returnOrigin: a pointer to a variable which will contain the return origin.
 * Return:         TEEC_SUCCESS: success
 *                     other: failure
 */
TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t commandID, TEEC_Operation *operation,
                               uint32_t *returnOrigin)
{
    TEEC_Result ret    = TEEC_ERROR_BAD_PARAMETERS;
    uint32_t retOrigin = TEEC_ORIGIN_API;

    if ((session == NULL) || (session->context == NULL)) {
        tloge("invoke failed, session or session context is null\n");
        goto END;
    }
    TEEC_Context *contextTemp     = session->context;
    TEEC_ContextInner *contextInner = GetBnContext(session->context);

    ret = TEEC_InvokeCommandInner(contextInner, session, commandID, operation, &retOrigin);
    if (ret == TEEC_SUCCESS) {
        session->context = contextTemp;
    }
    (void)PutBnContext(contextInner);

END:
    if (returnOrigin != NULL) {
        *returnOrigin = retOrigin;
    }
    return ret;
}

TEEC_Result TEEC_RegisterSharedMemoryInner(TEEC_ContextInner *context, TEEC_SharedMemoryInner *sharedMem)
{
    /* First, check parameters is valid or not */
    if ((context == NULL) || (sharedMem == NULL)) {
        tloge("register shardmem hidl: context or sharedMem is NULL\n");
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }

    bool condition =
        (sharedMem->buffer == NULL) || ((sharedMem->flags != TEEC_MEM_INPUT) && (sharedMem->flags != TEEC_MEM_OUTPUT) &&
                                        (sharedMem->flags != TEEC_MEM_INOUT));
    if (condition) {
        tloge("register shardmem hidl: sharedMem->flags wrong\n");
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }

    /* Paramters all right, start execution */
    sharedMem->ops_cnt      = 1;
    sharedMem->is_allocated = false;
    sharedMem->offset       = (uint32_t)(-1);
    sharedMem->context      = context;
    ListInit(&sharedMem->head);
    int lockRet = pthread_mutex_lock(&context->shrMemLock);
    if (lockRet != 0) {
        tloge("get share mem lock failed.\n");
        return TEEC_ERROR_GENERIC;
    }
    ListInsertTail(&context->shrd_mem_list, &sharedMem->head);
    AtomInc(&sharedMem->ops_cnt);
    (void)pthread_mutex_unlock(&context->shrMemLock);

    return TEEC_SUCCESS;
}

/*
 * Function:       TEEC_RegisterSharedMemory
 * Description:   This function registers a block of existing Client Application memory
 *                     as a block of Shared Memory within the scope of the specified TEE Context.
 * Parameters:   context: a pointer to an initialized TEE Context.
 *                     sharedMem: a pointer to a Shared Memory structure to register.
 * Return:         TEEC_SUCCESS: success
 *                     other: failure
 */
TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem)
{
    TEEC_Result ret;
    TEEC_ContextInner *contextInner  = NULL;
    TEEC_SharedMemoryInner *shmInner = NULL;

    bool condition = (context == NULL) || (sharedMem == NULL);
    if (condition) {
        tloge("register shardmem: context or sharedMem is NULL\n");
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }

    /*
     * ca may call ReleaseShareMemory even if RegisterShareMem failed,
     * we set sharedMem->context here to avoid receive a illegal ptr
     */
    sharedMem->context = context;

    ret = MallocShrMemInner(&shmInner);
    if (ret != TEEC_SUCCESS) {
        return ret;
    }
    shmInner->buffer = sharedMem->buffer;
    shmInner->size   = sharedMem->size;
    shmInner->flags  = sharedMem->flags;

    contextInner = GetBnContext(context);
    ret         = TEEC_RegisterSharedMemoryInner(contextInner, shmInner);
    if (ret == TEEC_SUCCESS) {
        sharedMem->ops_cnt      = shmInner->ops_cnt;
        sharedMem->is_allocated = shmInner->is_allocated;
        ListInit(&sharedMem->head);
        PutBnShrMem(shmInner); /* pair with ops_cnt++ when add to list */
        (void)PutBnContext(contextInner);
        return ret;
    }
    tloge("register shardmem: failed:0x%x\n", ret);
    (void)PutBnContext(contextInner);
    free(shmInner);
    return ret;
}

static void RelaseBufferAndClearBit(TEEC_ContextInner *context, TEEC_SharedMemoryInner *sharedMem)
{
    if (sharedMem->buffer != MAP_FAILED && sharedMem->size != 0) {
        (void)munmap(sharedMem->buffer, sharedMem->size);
    }
    ClearBitWithLock(&context->shrMemBitMapLock, sharedMem->offset,
                     sizeof(context->shm_bitmap), context->shm_bitmap);
    sharedMem->buffer = NULL;
    sharedMem->offset = 0;
}

TEEC_Result TEEC_AllocateSharedMemoryInner(TEEC_ContextInner *context, TEEC_SharedMemoryInner *sharedMem)
{
    TEEC_Result ret;

    /* First, check parameters is valid or not */
    if ((context == NULL) || (sharedMem == NULL)) {
        tloge("allocate shardmem hidl: context or sharedMem is NULL\n");
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }

    bool condition = (sharedMem->flags != TEEC_MEM_INPUT) && (sharedMem->flags != TEEC_MEM_OUTPUT) &&
                     (sharedMem->flags != TEEC_MEM_INOUT);
    if (condition) {
        tloge("allocate shardmem hidl: sharedMem->flags wrong\n");
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }

    /* Paramters all right, start execution */
    sharedMem->buffer = NULL;

    int32_t validBit = GetAndSetBitWithLock(&context->shrMemBitMapLock, context->shm_bitmap,
                                            sizeof(context->shm_bitmap));
    if (validBit < 0) {
        tloge("get valid bit for shm failed\n");
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }

    sharedMem->offset = (uint32_t)validBit;
    if (sharedMem->size != 0) {
        sharedMem->buffer = mmap(0, (unsigned long)sharedMem->size, (PROT_READ | PROT_WRITE), MAP_SHARED,
                                 (int)context->fd, (long)(sharedMem->offset * PAGE_SIZE));
    } else {
        sharedMem->buffer = ZERO_SIZE_PTR;
    }

    if (sharedMem->buffer == MAP_FAILED) {
        tloge("mmap failed\n");
        ret = TEEC_ERROR_OUT_OF_MEMORY;
        goto ERROR;
    }
    sharedMem->ops_cnt      = 1;
    sharedMem->is_allocated = true;
    sharedMem->context      = context;
    ListInit(&sharedMem->head);
    if (pthread_mutex_lock(&context->shrMemLock) != 0) {
        tloge("get share mem lock failed\n");
        ret = TEEC_ERROR_GENERIC;
        goto ERROR;
    }
    ListInsertTail(&context->shrd_mem_list, &sharedMem->head);
    AtomInc(&sharedMem->ops_cnt);
    (void)pthread_mutex_unlock(&context->shrMemLock);
    return TEEC_SUCCESS;

ERROR:
    RelaseBufferAndClearBit(context, sharedMem);
    return ret;
}

/*
 * Function:       TEEC_AllocateSharedMemory
 * Description:   This function allocates a new block of memory as a block of
 *                     Shared Memory within the scope of the specified TEE Context.
 * Parameters:   context: a pointer to an initialized TEE Context.
 *                     sharedMem: a pointer to a Shared Memory structure to allocate.
 * Return:         TEEC_SUCCESS: success
 *                     other: failure
 */
TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem)
{
    TEEC_Result ret;
    TEEC_ContextInner *contextInner  = NULL;
    TEEC_SharedMemoryInner *shmInner = NULL;

    bool condition = (context == NULL) || (sharedMem == NULL);
    if (condition) {
        tloge("allocate shardmem: context or sharedMem is NULL\n");
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }

    /*
     * ca may call ReleaseShareMemory even if AllocateSharedMemory failed,
     * we set sharedMem->context here to avoid receive a illegal ptr
     */
    sharedMem->context = context;

    ret = MallocShrMemInner(&shmInner);
    if (ret != TEEC_SUCCESS) {
        return ret;
    }
    shmInner->size  = sharedMem->size;
    shmInner->flags = sharedMem->flags;

    contextInner = GetBnContext(context);
    ret         = TEEC_AllocateSharedMemoryInner(contextInner, shmInner);
    if (ret == TEEC_SUCCESS) {
        sharedMem->buffer       = shmInner->buffer;
        sharedMem->ops_cnt      = shmInner->ops_cnt;
        sharedMem->is_allocated = shmInner->is_allocated;
        ListInit(&sharedMem->head);
        PutBnShrMem(shmInner); /* pair with ops_cnt++ when add to list */
        (void)PutBnContext(contextInner);
        return TEEC_SUCCESS;
    }

    tloge("allocate shardmem: failed:0x%x\n", ret);
    (void)PutBnContext(contextInner);
    free(shmInner);
    return ret;
}

static bool TEEC_FindAndRemoveShrMemInner(TEEC_SharedMemoryInner **sharedMem, TEEC_ContextInner *contextInner)
{
    bool found                           = false;
    struct ListNode *ptr                 = NULL;
    TEEC_SharedMemoryInner *tempSharedMem = NULL;
    TEEC_SharedMemoryInner *shm           = *sharedMem;

    int lockRet = pthread_mutex_lock(&contextInner->shrMemLock);
    if (lockRet != 0) {
        tloge("get share mem lock failed.\n");
        return false;
    }

    LIST_FOR_EACH(ptr, &contextInner->shrd_mem_list)
    {
        tempSharedMem = CONTAINER_OF(ptr, TEEC_SharedMemoryInner, head);
        if (tempSharedMem->offset == shm->offset && tempSharedMem->context == shm->context) {
            found = true;
            ListRemoveEntry(&tempSharedMem->head);
            *sharedMem = tempSharedMem;
            break;
        }
    }

    (void)pthread_mutex_unlock(&contextInner->shrMemLock);
    return found;
}

void TEEC_ReleaseSharedMemoryInner(TEEC_SharedMemoryInner *sharedMem)
{
    TEEC_SharedMemoryInner *shm = sharedMem;

    /* First, check parameters is valid or not */
    if ((shm == NULL) || (shm->context == NULL)) {
        tloge("Shared Memory is NULL\n");
        return;
    }

    bool found = TEEC_FindAndRemoveShrMemInner(&shm, shm->context);
    if (!found) {
        tloge("Shared Memory is not in the list\n");
        return;
    }

    tloge("Shared Memory found\n");

    PutBnShrMem(shm); /* pair with Initial value 1 */
}

/*
 * Function:       TEEC_ReleaseSharedMemory
 * Description:   This function deregisters or deallocates a previously initialized
 *                      block of Shared Memory..
 * Parameters:   sharedMem: a pointer to a valid Shared Memory structure.
 * Return:         NULL
 */
void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *sharedMem)
{
    if ((sharedMem == NULL) || (sharedMem->context == NULL)) {
        tloge("release shardmem: sharedMem or sharedMem->context is NULL\n");
        return;
    }

    TEEC_SharedMemoryInner shm_hidl = { 0 };
    shm_hidl.buffer                = sharedMem->buffer;
    shm_hidl.size                  = sharedMem->size;
    shm_hidl.flags                 = sharedMem->flags;
    shm_hidl.ops_cnt               = sharedMem->ops_cnt;
    shm_hidl.is_allocated          = sharedMem->is_allocated;

    TEEC_ContextInner *contextInner = GetBnContext(sharedMem->context);
    shm_hidl.context              = contextInner;

    TEEC_ReleaseSharedMemoryInner(&shm_hidl);
    (void)PutBnContext(contextInner);
    sharedMem->buffer  = NULL;
    sharedMem->size    = 0;
    sharedMem->flags   = 0;
    sharedMem->ops_cnt = 0;
    sharedMem->context = NULL;
}

static TEEC_Result TEEC_CheckTmpRef(TEEC_TempMemoryReference tmpref)
{
    if ((tmpref.buffer == NULL) || (tmpref.size == 0)) {
        tloge("tmpref buffer is null, or size is zero\n");
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }
    return (TEEC_Result)TEEC_SUCCESS;
}

static bool CheckSharedBufferExist(TEEC_ContextInner *context, const TEEC_RegisteredMemoryReference *sharedMem)
{
    if (context == NULL) {
        return false;
    }

    struct ListNode *ptr                  = NULL;
    TEEC_SharedMemoryInner *tempSharedMem = NULL;
    TEEC_SharedMemory *shm                = sharedMem->parent;

    int lockRet = pthread_mutex_lock(&context->shrMemLock);
    if (lockRet != 0) {
        tloge("get share mem lock failed\n");
        return false;
    }

    LIST_FOR_EACH(ptr, &context->shrd_mem_list)
    {
        tempSharedMem = CONTAINER_OF(ptr, TEEC_SharedMemoryInner, head);
        if (tempSharedMem->buffer == shm->buffer) {
            (void)pthread_mutex_unlock(&context->shrMemLock);
            return true;
        }
    }

    (void)pthread_mutex_unlock(&context->shrMemLock);
    return false;
}

static TEEC_Result TEEC_CheckMemRef(TEEC_ContextInner *context, TEEC_RegisteredMemoryReference memref,
    uint32_t paramType)
{
    bool condition = (memref.parent == NULL) || (memref.parent->buffer == NULL);
    if (condition) {
        tloge("parent of memref is null, or the buffer is zero\n");
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }

    if (paramType == TEEC_MEMREF_PARTIAL_INPUT) {
        if (!(memref.parent->flags & TEEC_MEM_INPUT)) {
            goto PARAM_ERROR;
        }
    } else if (paramType == TEEC_MEMREF_PARTIAL_OUTPUT) {
        if (!(memref.parent->flags & TEEC_MEM_OUTPUT)) {
            goto PARAM_ERROR;
        }
    } else if (paramType == TEEC_MEMREF_PARTIAL_INOUT) {
        if (!(memref.parent->flags & TEEC_MEM_INPUT)) {
            goto PARAM_ERROR;
        }
        if (!(memref.parent->flags & TEEC_MEM_OUTPUT)) {
            goto PARAM_ERROR;
        }
    } else {
        /*  if type is TEEC_MEMREF_WHOLE, ignore it */
    }

    condition = (paramType == TEEC_MEMREF_PARTIAL_INPUT) || (paramType == TEEC_MEMREF_PARTIAL_OUTPUT) ||
                (paramType == TEEC_MEMREF_PARTIAL_INOUT);
    if (condition) {
        if ((memref.offset + memref.size) > memref.parent->size) {
            tloge("offset + size exceed the parent size\n");
            return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
        }
    }

    if (!CheckSharedBufferExist(context, &memref)) {
        return (TEEC_Result)TEEC_FAIL;
    }
    return (TEEC_Result)TEEC_SUCCESS;
PARAM_ERROR:
    tloge("type of memref not belong to the parent flags\n");
    return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
}

/*
 * Function:       TEEC_CheckOperation
 * Description:   This function checks a operation is valid or not.
 * Parameters:   operation: a pointer to an Operation to be checked.
 * Return:         TEEC_SUCCESS: success
 *                     other: failure
 */
TEEC_Result TEEC_CheckOperation(TEEC_ContextInner *context, const TEEC_Operation *operation)
{
    uint32_t paramType[TEEC_PARAM_NUM];
    uint32_t paramCnt;
    TEEC_Result ret = TEEC_SUCCESS;
    /* GP Support operation is NULL
     * operation: a pointer to a Client Application initialized TEEC_Operation structure,
     * or NULL if there is no payload to send or if the Command does not need to support
     * cancellation.
     */
    if (operation == NULL) {
        return ret;
    }
    if (!operation->started) {
        tloge("sorry, cancellation not support\n");
        return (TEEC_Result)TEEC_ERROR_NOT_IMPLEMENTED;
    }

    for (paramCnt = 0; paramCnt < TEEC_PARAM_NUM; paramCnt++) {
        paramType[paramCnt] = TEEC_PARAM_TYPE_GET(operation->paramTypes, paramCnt);
        if (IS_TEMP_MEM(paramType[paramCnt])) {
            ret = TEEC_CheckTmpRef(operation->params[paramCnt].tmpref);
        } else if (IS_PARTIAL_MEM(paramType[paramCnt])) {
            ret = TEEC_CheckMemRef(context, operation->params[paramCnt].memref, paramType[paramCnt]);
        } else if (IS_VALUE_MEM(paramType[paramCnt])) {
            /*  if type is value, ignore it */
        } else if (paramType[paramCnt] == TEEC_NONE) {
            /*  if type is none, ignore it */
        } else {
            tloge("paramType is not support\n");
            ret = (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
            break;
        }

        if (ret != TEEC_SUCCESS) {
            tloge("paramCnt is %u\n", paramCnt);
            break;
        }
    }
    return ret;
}

/*
 * Function:       TEEC_RequestCancellation
 * Description:   This function requests the cancellation of a pending open Session operation or
            a Command invocation operation.
 * Parameters:   operation:a pointer to a Client Application instantiated Operation structure
 * Return:         void
 */
void TEEC_RequestCancellation(TEEC_Operation *operation)
{
    int32_t ret;
    TEEC_Result teecRet;
    TC_NS_ClientContext cliContext;
    TC_NS_ClientLogin cliLogin = { 0, 0 };

    /* First, check parameters is valid or not */
    if (operation == NULL) {
        return;
    }

    TEEC_Session *session = operation->session;
    if ((session == NULL) || (session->context == NULL)) {
        tloge("session is invalid\n");
        return;
    }
    TEEC_ContextInner *contextInner = GetBnContext(session->context);
    teecRet = TEEC_CheckOperation(contextInner, operation);
    (void)PutBnContext(contextInner);
    if (teecRet != TEEC_SUCCESS) {
        tloge("operation is invalid\n");
        return;
    }

    /* Paramters all right, start execution */
    teecRet = TEEC_Encode(&cliContext, session, TC_NS_CLIENT_IOCTL_CANCEL_CMD_REQ, &cliLogin, operation);
    if (teecRet != TEEC_SUCCESS) {
        tloge("RequestCancellation: teec encode failed(0x%x)!\n", teecRet);
        return;
    }

    ret = ioctl((int)session->context->fd, (int)TC_NS_CLIENT_IOCTL_CANCEL_CMD_REQ, &cliContext);
    if (ret == 0) {
        tlogd("invoke cmd success\n");
    } else if (ret < 0) {
        tloge("invoke cmd failed, ioctl errno = %d\n", ret);
    } else {
        tloge("invoke cmd failed, code=0x%x, origin=%u\n", cliContext.returns.code, cliContext.returns.origin);
    }

    return;
}
