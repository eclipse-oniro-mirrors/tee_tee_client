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

#include "tee_client.h"
#include <fcntl.h>
#include <securec.h>
#include <sys/mman.h>
#include <unistd.h>
#include "ashmem.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "tee_client_api.h"
#include "tee_client_ext_api.h"
#include "tee_client_inner.h"
#include "tee_log.h"
using namespace std;
namespace OHOS {
bool TeeClient::mServiceValid = false;

bool TeeClient::SetCallBack()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (mNotify == nullptr || mTeecService == nullptr) {
        tloge("get call back handle failed\n");
        return false;
    }

    (void)data.WriteInterfaceToken(INTERFACE_TOKEN);
    bool result = data.WriteRemoteObject(mNotify);
    if (!result) {
        tloge("write notify failed\n");
        return false;
    }

    int ret = mTeecService->SendRequest(SET_CALL_BACK, data, reply, option);
    if (ret != ERR_NONE) {
        tloge("send notify failed\n");
        return false;
    }

    return true;
}

bool TeeClient::InitTeecService()
{
    lock_guard<mutex> autoLock(mServiceLock);

    if (mServiceValid) {
        return true;
    }

    if (mNotify == nullptr) {
        mNotify = new IPCObjectStub(u"TeecClientDeathRecipient");
        if (mNotify == nullptr) {
            tloge("new mNotify failed\n");
            return false;
        }
    }

    sptr<ISystemAbilityManager> sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sm == nullptr) {
        tloge("get system ability failed\n");
        return false;
    }

    mTeecService = sm->GetSystemAbility(CA_DAEMON_ID);
    if (mTeecService == nullptr) {
        tloge("get teec service failed\n");
        return false;
    }

    mDeathNotifier = new DeathNotifier(mTeecService);
    if (mDeathNotifier == nullptr) {
        tloge("new death notify failed\n");
        mTeecService = nullptr;
        return false;
    }

    /* death notify, TeecService-->CA */
    bool result = mTeecService->AddDeathRecipient(mDeathNotifier);
    if (!result) {
        tloge("set service to ca failed\n");
        mTeecService = nullptr;
        return false;
    }

    /* death notify, CA-->TeecService */
    result = SetCallBack();
    if (!result) {
        tloge("set ca to service failed\n");
        mTeecService = nullptr;
        return false;
    }

    mServiceValid = true;
    return true;
}

static TEEC_Result TEEC_CheckTmpRef(TEEC_TempMemoryReference tmpref)
{
    if ((tmpref.buffer == nullptr) && (tmpref.size != 0)) {
        tloge("tmpref buffer is null, but size is not zero\n");
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }
    if ((tmpref.buffer != nullptr) && (tmpref.size == 0)) {
        tloge("tmpref buffer is not null, but size is zero\n");
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }
    return (TEEC_Result)TEEC_SUCCESS;
}

static TEEC_Result TEEC_CheckMemRef(TEEC_RegisteredMemoryReference memref, uint32_t paramType)
{
    if ((memref.parent == nullptr) || (memref.parent->buffer == nullptr)) {
        tloge("parent of memref is null, or the buffer is zero\n");
        return TEEC_ERROR_BAD_PARAMETERS;
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

    if ((paramType == TEEC_MEMREF_PARTIAL_INPUT) ||
        (paramType == TEEC_MEMREF_PARTIAL_OUTPUT) ||
        (paramType == TEEC_MEMREF_PARTIAL_INOUT)) {
        if ((UINT32_MAX - memref.offset < memref.size) ||
            ((memref.offset + memref.size) > memref.parent->size)) {
            tloge("partial mem check failed, offset %" PUBLIC "u size %" PUBLIC "u\n", memref.offset, memref.size);
            return TEEC_ERROR_BAD_PARAMETERS;
        }
    }

    return TEEC_SUCCESS;
PARAM_ERROR:
    tloge("type of memref not belong to the parent flags\n");
    return TEEC_ERROR_BAD_PARAMETERS;
}

TEEC_Result TeeClient::TEEC_CheckOperation(const TEEC_Operation *operation)
{
    TEEC_Result ret = TEEC_SUCCESS;

    if (operation == nullptr) {
        return ret;
    }
    if (!operation->started) {
        tloge("sorry, cancellation not support\n");
        return TEEC_ERROR_NOT_IMPLEMENTED;
    }

    for (uint32_t i = 0; i < TEEC_PARAM_NUM; i++) {
        uint32_t paramType = TEEC_PARAM_TYPE_GET(operation->paramTypes, i);
        if (IS_TEMP_MEM(paramType)) {
            ret = TEEC_CheckTmpRef(operation->params[i].tmpref);
        } else if (IS_PARTIAL_MEM(paramType)) {
            ret = TEEC_CheckMemRef(operation->params[i].memref, paramType);
        } else if (IS_VALUE_MEM(paramType)) {
            /*  if type is value, ignore it */
        } else if (paramType == TEEC_NONE) {
            /*  if type is none, ignore it */
        } else if (paramType == TEEC_ION_INPUT) {
          /* Secure Camera */  
        } else {
            tloge("param %" PUBLIC "u has invalid type %" PUBLIC "u\n", i, paramType);
            ret = TEEC_ERROR_BAD_PARAMETERS;
            break;
        }

        if (ret != TEEC_SUCCESS) {
            tloge("param %" PUBLIC "u check failed\n", i);
            break;
        }
    }
    return ret;
}

static inline bool IsOverFlow(uint32_t num1, uint32_t num2)
{
    if (UINT32_MAX - num1 < num2) {
        return true;
    }
    return false;
}

static bool WriteChar(const char *srcStr, MessageParcel &data)
{
    if (srcStr == nullptr) {
        if (data.WriteUint32(0) != true) {
            return false;
        }
    } else {
        if (strnlen(srcStr, PATH_MAX) == PATH_MAX) {
            tloge("param srcStr is too long\n");
            return false;
        }
        string tempStr = srcStr;
        if (data.WriteUint32(strlen(srcStr)) != true) {
            return false;
        }
        if (data.WriteString(tempStr) != true) {
            return false;
        }
    }
    return true;
}

static bool WriteContext(MessageParcel &data, TEEC_Context *context)
{
    return data.WriteBuffer(context, sizeof(*context));
}

static bool WriteSession(MessageParcel &data, TEEC_Session *session)
{
    return data.WriteBuffer(session, sizeof(*session));
}

static bool WriteSharedMem(MessageParcel &data, TEEC_SharedMemory *shm)
{
    return data.WriteBuffer(shm, sizeof(*shm));
}

static bool CheckSharedMemoryFLag(uint32_t flag)
{
    return (flag == TEEC_MEM_INPUT || flag == TEEC_MEM_OUTPUT || flag == TEEC_MEM_INOUT);
}

uint32_t TeeClient::FindShareMemOffset(const void *buffer)
{
    lock_guard<mutex> autoLock(mSharMemLock);
    size_t count = mShareMem.size();
    for (size_t index = 0; index < count; index++) {
        if (mShareMem[index].buffer == buffer) {
            return mShareMem[index].offset;
        }
    }

    return UINT32_MAX;
}

static void UnmapSharedMem(void *buff, uint32_t size)
{
    int ret = munmap(buff, size);
    if (ret != 0) {
        tloge("munmap share mem failed, ret=0x%" PUBLIC "x\n", ret);
    }
}

void TeeClient::FreeAllShareMem()
{
    size_t index;

    lock_guard<mutex> autoLock(mSharMemLock);
    size_t count = mShareMem.size();
    for (index = 0; index < count; index++) {
        if ((mShareMem[index].buffer != nullptr) && (mShareMem[index].buffer != ZERO_SIZE_PTR) &&
            (mShareMem[index].size != 0)) {
            UnmapSharedMem(mShareMem[index].buffer, mShareMem[index].size);
        }
    }
    mShareMem.clear();
    return;
}

void TeeClient::FreeAllShareMemoryInContext(const TEEC_Context *context)
{
    std::vector<TC_NS_ShareMem>::iterator vec;

    lock_guard<mutex> autoLock(mSharMemLock);
    for (vec = mShareMem.begin(); vec != mShareMem.end();) {
        if ((vec->fd == context->fd) && (vec->buffer != nullptr) && (vec->buffer != ZERO_SIZE_PTR) &&
            (vec->size != 0)) {
            UnmapSharedMem(vec->buffer, vec->size);
            vec = mShareMem.erase(vec);
        } else {
            ++vec;
        }
    }
    return;
}

static void SleepNs(long num)
{
    struct timespec ts;
    ts.tv_sec  = 0;
    ts.tv_nsec = num;

    (void)nanosleep(&ts, nullptr);
}

#define SLEEP_TIME (200 * 1000 * 1000)
#define CONNECT_MAX_NUM 10

TEEC_Result TeeClient::InitializeContextSendCmd(const char *name, MessageParcel &reply)
{
    MessageParcel data;
    MessageOption option;
    uint32_t connectTime = 0;
    /* add retry to avoid app start before daemon */
    while (connectTime++ < CONNECT_MAX_NUM) {
        if (InitTeecService()) {
            break;
        }
        tlogd("get cadaemon handle retry\n");
        SleepNs(SLEEP_TIME);
    }
    if (connectTime > CONNECT_MAX_NUM) {
        tloge("get cadaemon handle failed\n");
        return TEEC_FAIL;
    }

    (void)data.WriteInterfaceToken(INTERFACE_TOKEN);

    if (WriteChar(name, data) != true) {
        return TEEC_FAIL;
    }

    if (mTeecService->SendRequest(INIT_CONTEXT, data, reply, option) != ERR_NONE)
        return TEEC_FAIL;

    return TEEC_SUCCESS;
}

TEEC_Result TeeClient::InitializeContext(const char *name, TEEC_Context *context)
{
    if (context == nullptr) {
        tloge("context is nullptr\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    MessageParcel reply;
    int32_t ret = InitializeContextSendCmd(name, reply);
    if ((TEEC_Result)ret != TEEC_SUCCESS) {
        tloge("initialize context send cmd failed\n");
        return TEEC_FAIL;
    }

    if (!reply.ReadInt32(ret)) {
        return TEEC_FAIL;
    }

    if ((TEEC_Result)ret != TEEC_SUCCESS) {
        tloge("init context failed:0x%" PUBLIC "x\n", ret);
        return (TEEC_Result)ret;
    }

    context->ta_path = nullptr;
    if (!reply.ReadInt32(context->fd)) {
        return TEEC_FAIL;
    }

    if (context->fd < 0) {
        return TEEC_FAIL;
    }
    return TEEC_SUCCESS;
}

void TeeClient::FinalizeContext(TEEC_Context *context)
{
    MessageParcel data;
    MessageOption option;
    MessageParcel reply;
    bool parRet = false;

    if (context == nullptr) {
        tloge("invalid context\n");
        return;
    }

    if (!InitTeecService()) {
        return;
    }

    (void)data.WriteInterfaceToken(INTERFACE_TOKEN);
    parRet = WriteContext(data, context);
    if (!parRet) {
        return;
    }

    if (mTeecService->SendRequest(FINAL_CONTEXT, data, reply, option) != ERR_NONE) {
        tloge("close session failed\n");
    }

    FreeAllShareMemoryInContext(context);
    context->fd = -1;
}

TEEC_Result TeeClient::OpenSession(TEEC_Context *context, TEEC_Session *session, const TEEC_UUID *destination,
    uint32_t connectionMethod, const void *connectionData, TEEC_Operation *operation,
    uint32_t *returnOrigin)
{
    uint32_t retOrigin  = TEEC_ORIGIN_API;
    TEEC_Result teecRet = TEEC_ERROR_BAD_PARAMETERS;
    int fd              = -1;

    bool condition = (context == nullptr) || (session == nullptr) || (destination == nullptr);
    if (condition) {
        tloge("open Session: OpenSession in params error!\n");
        goto END;
    }

    /*
     * ca may call closesession even if opensession failed,
     * we set session->context here to avoid receive a illegal ptr
     */
    session->context = context;

    teecRet = TEEC_CheckOperation(operation);
    if (teecRet != TEEC_SUCCESS) {
        tloge("invoke command:check operation failed!\n");
        goto END;
    }

    condition = (connectionMethod != TEEC_LOGIN_IDENTIFY) || (connectionData != nullptr);
    if (condition) {
        tloge("Login method is not supported or connection data is not nullptr\n");
        teecRet = TEEC_ERROR_BAD_PARAMETERS;
        goto END;
    }

    if (operation != nullptr) {
        /* Params 2 and 3 are used for ident by teecd hence ->TEEC_NONE */
        operation->paramTypes = TEEC_PARAM_TYPES(TEEC_PARAM_TYPE_GET(operation->paramTypes, 0),
            TEEC_PARAM_TYPE_GET(operation->paramTypes, 1), TEEC_NONE, TEEC_NONE);
    }

    fd = GetFileFd((const char *)context->ta_path);
    teecRet = OpenSessionSendCmd(context, session, destination, connectionMethod, fd, operation, &retOrigin);

    if (fd >= 0) {
        close(fd);
    }

END:
    if (returnOrigin != nullptr) {
        *returnOrigin = retOrigin;
    }
    return teecRet;
}

static bool WriteOpenData(MessageParcel &data, TEEC_Context *context, int32_t fd,
    const TEEC_UUID *destination, uint32_t connectionMethod)
{
    (void)data.WriteInterfaceToken(INTERFACE_TOKEN);

    if (!WriteContext(data, context)) {
        return false;
    }

    if (!WriteChar((const char *)context->ta_path, data)) {
        return false;
    }

    if (fd < 0) {
        if (!data.WriteBool(false)) {
            return false;
        }
    } else {
        if (!data.WriteBool(true)) {
            return false;
        }
        if (!data.WriteFileDescriptor(fd)) {
            return false;
        }
    }

    if (!data.WriteBuffer(destination, sizeof(*destination))) {
        return false;
    }
    if (!data.WriteUint32(connectionMethod)) {
        return false;
    }

    return true;
}

static bool WriteOperation(MessageParcel &data, TEEC_Operation *operation)
{
    if (operation == nullptr) {
        return data.WriteBool(false);
    }

    if (!data.WriteBool(true)) {
        return false;
    }

    return data.WriteBuffer(operation, sizeof(*operation));
}

static bool WriteIonFd(MessageParcel &data, TEEC_Operation *operation)
{
    if (operation == nullptr) {
        return true;
    }

    uint32_t paramCnt;
    bool teeRet = true;
    for (paramCnt = 0; paramCnt < TEEC_PARAM_NUM; paramCnt++) {
        if (TEEC_PARAM_TYPE_GET(operation->paramTypes, paramCnt) == TEEC_ION_INPUT) {
            teeRet = data.WriteFileDescriptor(operation->params[paramCnt].ionref.ion_share_fd);
        }
        if (teeRet != true) {
            tloge("write ion fd failed. paramCnt: %" PUBLIC "u\n", paramCnt);
            return teeRet;
        }
    }
    return teeRet;
}

bool TeeClient::FormatSession(TEEC_Session *session, MessageParcel &reply)
{
    bool sessFlag = false;
    if (!reply.ReadBool(sessFlag)) {
        return false;
    }

    if (!sessFlag) {
        tloge("session is nullptr\n");
        return false;
    }

    TEEC_Session *sessRet = nullptr;
    size_t len = sizeof(*sessRet);
    sessRet = (TEEC_Session *)(reply.ReadBuffer(len));
    if (sessRet == nullptr) {
        tloge("read session failed\n");
        return false;
    }
    tlogi("reieve sessRet_id = %" PUBLIC "d\n", sessRet->session_id);

    session->session_id = sessRet->session_id;
    session->service_id = sessRet->service_id;
    session->ops_cnt    = sessRet->ops_cnt;
    ListInit(&session->head);
    return true;
}

TEEC_Result TeeClient::GetTeecOptMem(TEEC_Operation *operation,
    size_t optMemSize, sptr<Ashmem> &optMem, MessageParcel &reply)
{
    if (operation == nullptr) {
        return TEEC_SUCCESS;
    }

    bool opFlag = false;
    if (!reply.ReadBool(opFlag)) {
        return TEEC_FAIL;
    }

    if (!opFlag) {
        tloge("operation is nullptr\n");
        return TEEC_FAIL;
    }

    TEEC_Operation *optRet = nullptr;
    size_t len = sizeof(*optRet);
    optRet = (TEEC_Operation *)(reply.ReadBuffer(len));
    if (optRet == nullptr) {
        tloge("the buffer is nullptr\n");
        return TEEC_FAIL;
    }

    const void *data = nullptr;
    if (optMemSize != 0) {
        data = optMem->ReadFromAshmem(optMemSize, 0);
    }
    return TeecOptDecode(operation, optRet, reinterpret_cast<const uint8_t *>(data), optMemSize);
}

TEEC_Result TeeClient::TeecOptDecodePartialMem(TEEC_Parameter *param,
    uint32_t paramType, TEEC_Parameter *inParam, const uint8_t **data, size_t *dataSize)
{
    TEEC_SharedMemory *shm = param->memref.parent;
    /* we put 4 uint32 and 1 bool in sharemem */
    uint32_t shmSize       = 4 * (sizeof(uint32_t)) + 1 * (sizeof(bool));
    uint32_t cSize         = param->memref.size;
    uint32_t tSize         = inParam->memref.size; /* size return from ta */
    uint8_t *p = nullptr;

    if (paramType == TEEC_MEMREF_WHOLE) {
        cSize = shm->size;
        /*
         * Actually, we should usr tSize return from ta,
         * but our process is temporarily not supported,
         * so we usr cSize instead. There will be a problem,
         * if ta write a larger buff size, we can not transfer it to ca
         */
        tSize = cSize;
    }

    if (IsOverFlow(cSize, shmSize) || (*dataSize < (cSize + shmSize))) {
        tloge("cSize:%" PUBLIC "u, shmSize:%" PUBLIC "u, dataSize:%" PUBLIC "zu\n", cSize, shmSize, *dataSize);
        return TEEC_FAIL;
    }

    *data += shmSize;
    *dataSize -= shmSize;
    if (paramType == TEEC_MEMREF_PARTIAL_INPUT) {
        goto END;
    }

    p = reinterpret_cast<uint8_t *>(param->memref.parent->buffer);
    if (p == nullptr) {
        goto COPY_TA_SIZE_TO_CA;
    }
    p += param->memref.offset;

    if (cSize == 0 && tSize == 0) {
        tlogd("cSize=0 && inOpt->memref.size=0\n");
        goto COPY_TA_SIZE_TO_CA;
    }
    if (!shm->is_allocated) {
        /* if ta buff size > ca buff size, copy ta size to ca */
        if (cSize < tSize) {
            tloge("size from ca is:%" PUBLIC "u, size from ta is:%" PUBLIC "u\n", cSize, tSize);
            goto COPY_TA_SIZE_TO_CA;
        }

        if (memcpy_s(p, cSize, *data, tSize) != EOK) {
            tloge("operation memcpy failed\n");
            return TEEC_FAIL;
        }
    }

COPY_TA_SIZE_TO_CA:
    param->memref.size = inParam->memref.size;

END:
    *data += cSize;
    *dataSize -= cSize;
    return TEEC_SUCCESS;
}

TEEC_Result TeeClient::TeecOptDecode(TEEC_Operation *operation,
    TEEC_Operation *inOpt, const uint8_t *data, size_t dataSize)
{
    uint32_t paramType[TEEC_PARAM_NUM] = { 0 };
    uint32_t paramCnt;
    const uint8_t *ptr = data;
    size_t sizeLeft = dataSize;
    TEEC_Result teeRet = TEEC_SUCCESS;

    for (paramCnt = 0; paramCnt < TEEC_PARAM_NUM; paramCnt++) {
        paramType[paramCnt] = TEEC_PARAM_TYPE_GET(operation->paramTypes, paramCnt);
        if (IS_TEMP_MEM(paramType[paramCnt])) {
            if (ptr == nullptr) {
                continue;
            }
            teeRet = TeecOptDecodeTempMem(&(operation->params[paramCnt]), paramType[paramCnt],
                &(inOpt->params[paramCnt]), &ptr, &sizeLeft);
        } else if (IS_PARTIAL_MEM(paramType[paramCnt])) {
            if (ptr == nullptr) {
                return TEEC_ERROR_BAD_PARAMETERS;
            }
            teeRet = TeecOptDecodePartialMem(&(operation->params[paramCnt]), paramType[paramCnt],
                &(inOpt->params[paramCnt]), &ptr, &sizeLeft);
        } else if (IS_VALUE_MEM(paramType[paramCnt])) {
            operation->params[paramCnt].value.a = inOpt->params[paramCnt].value.a;
            operation->params[paramCnt].value.b = inOpt->params[paramCnt].value.b;
        }
        if (teeRet != TEEC_SUCCESS) {
            tloge("opt decode param fail. paramCnt: %" PUBLIC "u, ret: 0x%" PUBLIC "x\n", paramCnt, teeRet);
            return teeRet;
        }
    }
    return TEEC_SUCCESS;
}

TEEC_Result TeeClient::TeecOptDecodeTempMem(TEEC_Parameter *param, uint32_t paramType,
    const TEEC_Parameter *inParam, const uint8_t **data, size_t *dataSize)
{
    size_t sizeLeft = *dataSize;
    const uint8_t *ptr    = *data;
    uint8_t *p = nullptr;
    if (sizeLeft < param->tmpref.size) {
        tloge("size is error:%" PUBLIC "zu:%" PUBLIC "u\n", sizeLeft, param->tmpref.size);
        return TEEC_FAIL;
    }

    if (paramType == TEEC_MEMREF_TEMP_INPUT) {
        ptr += param->tmpref.size;
        sizeLeft -= param->tmpref.size;
        goto END;
    }

    p = reinterpret_cast<uint8_t *>(param->tmpref.buffer);
    if (p != nullptr) {
        /* if ta buff size > ca buff size, copy ta size to ca */
        if (param->tmpref.size < inParam->tmpref.size) {
            tlogw("size from ca is:%" PUBLIC "u, size from ta is:%" PUBLIC "u\n",
                param->tmpref.size, inParam->tmpref.size);
            goto COPY_TA_SIZE_TO_CA;
        }
        if (sizeLeft < inParam->tmpref.size) {
            tloge("size is not enough:%" PUBLIC "zu:%" PUBLIC "u\n", sizeLeft, inParam->tmpref.size);
            return TEEC_FAIL;
        }

        if (memcpy_s(p, param->tmpref.size, ptr, inParam->tmpref.size) != EOK) {
            tloge("peration decode memcpy_s failed\n");
            return TEEC_FAIL;
        }
    }

COPY_TA_SIZE_TO_CA:
    ptr += param->tmpref.size;
    sizeLeft -= param->tmpref.size;
    param->tmpref.size = inParam->tmpref.size;

END:
    *data     = ptr;
    *dataSize = sizeLeft;
    return TEEC_SUCCESS;
}

static inline void ClearAsmMem(sptr<Ashmem> &optMem)
{
    if (optMem != nullptr) {
        optMem->UnmapAshmem();
        optMem->CloseAshmem();
    }
}

TEEC_Result TeeClient::OpenSessionSendCmd(TEEC_Context *context, TEEC_Session *session, const TEEC_UUID *destination,
    uint32_t connectionMethod, int32_t fd, TEEC_Operation *operation, uint32_t *retOrigin)
{
    MessageParcel data, reply;
    MessageOption option;
    int32_t ret = (int32_t)TEEC_FAIL;

    CHECK_ERR_RETURN(InitTeecService(), true, TEEC_FAIL);

    size_t optMemSize;
    sptr<Ashmem> optMem;
    if (GetOptMemSize(operation, &optMemSize) != TEEC_SUCCESS) {
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    TEEC_Result nRet = CopyTeecOptMem(operation, optMemSize, optMem);
    if (nRet != TEEC_SUCCESS) {
        tloge("copy teec opt mem failed\n");
        return nRet;
    }

    CHECK_ERR_GOTO(WriteOpenData(data, context, fd, destination, connectionMethod), true, END);

    if (WriteOperation(data, operation) != true) {
        goto END;
    }

    CHECK_ERR_GOTO(WriteIonFd(data, operation), true, END);

    if (data.WriteUint32(optMemSize) != true) {
        goto END;
    }

    if (optMemSize > 0) {
        if (data.WriteAshmem(optMem) != true) {
            goto END;
        }
    }

    if (mTeecService->SendRequest(OPEN_SESSION, data, reply, option) != ERR_NONE) {
        goto END;
    }

    if (reply.ReadUint32(*retOrigin) != true) {
        goto END;
    }

    if (reply.ReadInt32(ret) != true) {
        ret = (int32_t)TEEC_FAIL;
        goto END;
    }

    if (!FormatSession(session, reply)) {
        ret = (ret == (int32_t)TEEC_SUCCESS) ? (int32_t)TEEC_FAIL : ret;
        goto END;
    }

    nRet = GetTeecOptMem(operation, optMemSize, optMem, reply);
    if (nRet != TEEC_SUCCESS && ret == (int32_t)TEEC_SUCCESS) {
        ret = (int32_t)nRet;
    }

END:
    ClearAsmMem(optMem);
    return (TEEC_Result)ret;
}

TEEC_Result TeeClient::TeecOptEncodeTempMem(const TEEC_Parameter *param, sptr<Ashmem> &optMem, size_t *dataSize)
{
    if (*dataSize < param->tmpref.size) {
        tloge("size is error:%" PUBLIC "zu:%" PUBLIC "u\n", *dataSize, param->tmpref.size);
        return TEEC_FAIL;
    }

    uint8_t *p = reinterpret_cast<uint8_t *>(param->tmpref.buffer);
    if (p == nullptr) {
        return TEEC_SUCCESS;
    }

    bool nRet = optMem->WriteToAshmem(p, (int32_t)(param->tmpref.size),
        optMem->GetAshmemSize() - (int32_t)(*dataSize));
    if (!nRet) {
        tloge("temp mem to hal memcpy failed : %" PUBLIC "d\n", nRet);
        return TEEC_FAIL;
    }

    *dataSize -= param->tmpref.size;

    return TEEC_SUCCESS;
}

bool TeeClient::CovertEncodePtr(sptr<Ashmem> &optMem, size_t *sizeLeft, TEEC_SharedMemory *shm)
{
    if (optMem->WriteToAshmem(&(shm->is_allocated), (int32_t)(sizeof(bool)),
        optMem->GetAshmemSize() - (int32_t)(*sizeLeft)) != true) {
            return false;
        }

    *sizeLeft -= sizeof(bool);

    if (optMem->WriteToAshmem(&(shm->flags), (int32_t)(sizeof(uint32_t)),
        optMem->GetAshmemSize() - (int32_t)(*sizeLeft)) != true) {
            return false;
        }

    *sizeLeft -= sizeof(uint32_t);

    if (optMem->WriteToAshmem(&(shm->ops_cnt), (int32_t)(sizeof(uint32_t)),
        optMem->GetAshmemSize() - (int32_t)(*sizeLeft)) != true) {
            return false;
        }

    *sizeLeft -= sizeof(uint32_t);

    uint32_t shmOffset = FindShareMemOffset(shm->buffer);
    if (optMem->WriteToAshmem(&shmOffset, (int32_t)(sizeof(uint32_t)),
        optMem->GetAshmemSize() - (int32_t)(*sizeLeft)) != true) {
            return false;
        }

    *sizeLeft -= sizeof(uint32_t);

    if (optMem->WriteToAshmem(&(shm->size), (int32_t)(sizeof(uint32_t)),
        optMem->GetAshmemSize() - (int32_t)(*sizeLeft)) != true) {
            return false;
        }

    *sizeLeft -= sizeof(uint32_t);

    return true;
}

TEEC_Result TeeClient::TeecOptEncodePartialMem(const TEEC_Parameter *param,
    uint32_t paramType, sptr<Ashmem> &optMem, size_t *dataSize)
{
    size_t sizeLeft = *dataSize;

    TEEC_SharedMemory *shm = param->memref.parent;

    if ((shm == nullptr) || (shm->buffer == nullptr)) {
        tloge("parent of memref is nullptr, or the buffer is zero\n");
        return (TEEC_Result)TEEC_ERROR_BAD_PARAMETERS;
    }
    /* we put 4 uint32 and 1 bool in sharemem */
    uint32_t shmSize = 4 * (sizeof(uint32_t)) + 1 * (sizeof(bool));
    if (sizeLeft < shmSize) {
        tloge("size is error:%" PUBLIC "zu:%" PUBLIC "u\n", sizeLeft, shmSize);
        return TEEC_FAIL;
    }

    if (CovertEncodePtr(optMem, &sizeLeft, shm) != true) {
        return TEEC_FAIL;
    }

    uint32_t cSize = param->memref.size;
    if (paramType == TEEC_MEMREF_WHOLE) {
        cSize = shm->size;
    }
    if (sizeLeft < cSize) {
        tloge("size is error:%" PUBLIC "zu:%" PUBLIC "u\n", sizeLeft, cSize);
        return TEEC_FAIL;
    }

    if (!shm->is_allocated) {
        uint8_t *p = reinterpret_cast<uint8_t *>(param->memref.parent->buffer);
        if (p != nullptr) {
            if (paramType != TEEC_MEMREF_WHOLE) {
                p += param->memref.offset;
            }
            if ((sizeLeft == 0) || (cSize == 0)) {
                tlogd("size left=%" PUBLIC "zu, ca size=%" PUBLIC "u\n", sizeLeft, cSize);
            } else {
                bool nRet = optMem->WriteToAshmem(p, (int32_t)cSize, optMem->GetAshmemSize() - (int32_t)sizeLeft);
                CHECK_ERR_RETURN(nRet, true, TEEC_FAIL);
            }
        }
    }

    sizeLeft -= cSize;
    *dataSize = sizeLeft;
    return TEEC_SUCCESS;
}

TEEC_Result TeeClient::TeecOptEncode(TEEC_Operation *operation, sptr<Ashmem> &optMem, size_t dataSize)
{
    uint32_t paramType[TEEC_PARAM_NUM] = { 0 };
    uint32_t paramCnt;
    size_t sizeLeft    = dataSize;
    TEEC_Result teeRet = TEEC_SUCCESS;
    for (paramCnt = 0; paramCnt < TEEC_PARAM_NUM; paramCnt++) {
        paramType[paramCnt] = TEEC_PARAM_TYPE_GET(operation->paramTypes, paramCnt);
        if (IS_TEMP_MEM(paramType[paramCnt])) {
            teeRet = TeecOptEncodeTempMem(&(operation->params[paramCnt]), optMem, &sizeLeft);
        } else if (IS_PARTIAL_MEM(paramType[paramCnt])) {
            teeRet = TeecOptEncodePartialMem(&(operation->params[paramCnt]), paramType[paramCnt], optMem, &sizeLeft);
        }
        if (teeRet != TEEC_SUCCESS) {
            tloge("opt encode param fail. paramCnt: %" PUBLIC "u, ret: 0x%" PUBLIC "x\n", paramCnt, teeRet);
            return teeRet;
        }
    }
    return TEEC_SUCCESS;
}

TEEC_Result TeeClient::CopyTeecOptMem(TEEC_Operation *operation, size_t optMemSize, sptr<Ashmem> &optMem)
{
    TEEC_Result ret;
    bool mapRet = false;
    if (optMemSize == 0 || operation == nullptr) {
        return TEEC_SUCCESS;
    }

    optMem = Ashmem::CreateAshmem("TeeClient", static_cast<int32_t>(optMemSize));
    if (optMem == nullptr) {
        tloge("not enough memory for opt size=%" PUBLIC "u", static_cast<uint32_t>(optMemSize));
        goto ERROR;
    }

    mapRet = optMem->MapReadAndWriteAshmem();
    if (!mapRet) {
        tloge("map ashmem failed\n");
        goto ERROR;
    }

    ret = TeecOptEncode(operation, optMem, optMemSize);
    if (ret != TEEC_SUCCESS) {
        tloge("copy ashmem failed\n");
        goto ERROR;
    }

    return TEEC_SUCCESS;

ERROR:
    ClearAsmMem(optMem);
    return TEEC_FAIL;
}


TEEC_Result TeeClient::GetPartialMemSize(TEEC_Operation *operation, size_t optMemSize,
                                         uint32_t paramCnt, uint32_t *cSize)
{
    uint32_t shmSize;
    uint32_t paramType[TEEC_PARAM_NUM] = { 0 };
    TEEC_Parameter *param = &(operation->params[paramCnt]);

    paramType[paramCnt] = TEEC_PARAM_TYPE_GET(operation->paramTypes, paramCnt);
    /* we put 4 uint32 and 1 bool in sharemem */
    shmSize = 4 * (sizeof(uint32_t)) + 1 * (sizeof(bool));
    *cSize            = param->memref.size;
    if (paramType[paramCnt] == TEEC_MEMREF_WHOLE) {
        *cSize = param->memref.parent->size;
    }
    if (IsOverFlow(*cSize, shmSize)) {
        tloge("cSize:%" PUBLIC "u, shmSize:%" PUBLIC "u\n", *cSize, shmSize);
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    *cSize += shmSize;
    if (IsOverFlow(optMemSize, *cSize)) {
        tloge("cSize:%" PUBLIC "u, optMemSize:%" PUBLIC "zu\n", *cSize, optMemSize);
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    return TEEC_SUCCESS;
}

TEEC_Result TeeClient::GetOptMemSize(TEEC_Operation *operation, size_t *memSize)
{
    uint32_t paramType[TEEC_PARAM_NUM] = { 0 };
    uint32_t paramCnt;
    size_t optMemSize = 0;
    uint32_t cSize;
    TEEC_Result ret;

    if (operation == nullptr) {
        *memSize = optMemSize;
        return TEEC_SUCCESS;
    }

    for (paramCnt = 0; paramCnt < TEEC_PARAM_NUM; paramCnt++) {
        paramType[paramCnt] = TEEC_PARAM_TYPE_GET(operation->paramTypes, paramCnt);
        if (IS_TEMP_MEM(paramType[paramCnt])) {
            cSize = operation->params[paramCnt].tmpref.size;
            if (IsOverFlow(optMemSize, cSize)) {
                tloge("cSize:%" PUBLIC "u, optMemSize:%" PUBLIC "zu\n", cSize, optMemSize);
                return TEEC_ERROR_BAD_PARAMETERS;
            }
            optMemSize += cSize;
        } else if (IS_PARTIAL_MEM(paramType[paramCnt])) {
            ret = GetPartialMemSize(operation, optMemSize, paramCnt, &cSize);
            if (ret == TEEC_ERROR_BAD_PARAMETERS) {
                return TEEC_ERROR_BAD_PARAMETERS;
            }
            optMemSize += cSize;
        }
    }

    if (optMemSize > PARAM_SIZE_LIMIT) {
        tloge("opt mem size over limit:%" PUBLIC "zu\n", optMemSize);
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    *memSize = optMemSize;
    return TEEC_SUCCESS;
}

TEEC_Result TeeClient::InvokeCommand(TEEC_Session *session, uint32_t commandID,
    TEEC_Operation *operation, uint32_t *returnOrigin)
{
    uint32_t retOrigin  = TEEC_ORIGIN_API;
    TEEC_Result ret = TEEC_ERROR_BAD_PARAMETERS;

    if (session == nullptr || session->context == nullptr) {
        tloge("InvokeCommand in params error!\n");
        goto END;
    }

    ret = TEEC_CheckOperation(operation);
    if (ret != TEEC_SUCCESS) {
        tloge("invoke command:check operation failed!\n");
        goto END;
    }

    ret = InvokeCommandSendCmd(session->context, session, commandID, operation, &retOrigin);
    if (ret != TEEC_SUCCESS) {
        tloge("invokeCommand: send cmd failed, ret=0x%" PUBLIC "x\n", ret);
    }

END:
        if (returnOrigin != nullptr) {
            *returnOrigin = retOrigin;
        }
        return ret;
}

static bool WriteInvokeData(MessageParcel &data, TEEC_Context *context,
    TEEC_Session *session, uint32_t commandID, TEEC_Operation *operation)
{
    (void)data.WriteInterfaceToken(INTERFACE_TOKEN);

    if (WriteContext(data, context) != true) {
        return false;
    }

    if (WriteSession(data, session) != true) {
        return false;
    }

    if (data.WriteUint32(commandID) != true) {
        return false;
    }

    if (WriteOperation(data, operation) != true) {
        return false;
    }

    if (WriteIonFd(data, operation) != true) {
        return false;
    }
    return true;
}

static inline bool RecReply(MessageParcel &reply, int32_t &ret, uint32_t *returnOrigin)
{
    if (reply.ReadUint32(*returnOrigin) != true) {
        return false;
    }

    if (reply.ReadInt32(ret) != true) {
        return false;
    }

    return true;
}

TEEC_Result TeeClient::InvokeCommandSendCmd(TEEC_Context *context, TEEC_Session *session,
    uint32_t commandID, TEEC_Operation *operation, uint32_t *returnOrigin)
{
    MessageParcel data;
    MessageOption option;
    MessageParcel reply;
    int32_t ret = (int32_t)TEEC_FAIL;

    CHECK_ERR_RETURN(InitTeecService(), true, TEEC_FAIL);

    size_t optMemSize;
    sptr<Ashmem> optMem;
    if (GetOptMemSize(operation, &optMemSize) != TEEC_SUCCESS) {
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    CHECK_ERR_RETURN(WriteInvokeData(data, context, session, commandID, operation), true, TEEC_ERROR_BAD_PARAMETERS);

    if (data.WriteUint32(optMemSize) != true) {
        return TEEC_FAIL;
    }

    TEEC_Result nRet = CopyTeecOptMem(operation, optMemSize, optMem);
    if (nRet != TEEC_SUCCESS) {
        tloge("copy teec opt mem failed\n");
        return nRet;
    }

    if (optMemSize > 0) {
        if (!data.WriteAshmem(optMem)) {
            tloge("write ash mem to parcel failed\n");
            goto CLEAR_MEM;
        }
    }

    if (mTeecService->SendRequest(INVOKE_COMMND, data, reply, option) != ERR_NONE) {
        tloge("invoke command failed\n");
        ret = TEEC_FAIL;
        goto CLEAR_MEM;
    }

    if (!RecReply(reply, ret, returnOrigin)) {
        ret = TEEC_FAIL;
        goto CLEAR_MEM;
    }

    nRet = GetTeecOptMem(operation, optMemSize, optMem, reply);
    if (nRet != TEEC_SUCCESS && ret == TEEC_SUCCESS) {
        ret = nRet;
    }

CLEAR_MEM:
    ClearAsmMem(optMem);
    return (TEEC_Result)ret;
}

void TeeClient::CloseSession(TEEC_Session *session)
{
    MessageParcel data;
    MessageOption option;
    MessageParcel reply;
    bool parRet = false;

    if ((session == nullptr) || (session->context == nullptr)) {
        tloge("closeSession: invalid params\n");
        return;
    }

    if (!InitTeecService()) {
        return;
    }

    (void)data.WriteInterfaceToken(INTERFACE_TOKEN);
    parRet = WriteContext(data, session->context);
    if (!parRet) {
        return;
    }

    parRet = WriteSession(data, session);
    if (!parRet) {
        return;
    }

    if (mTeecService->SendRequest(CLOSE_SESSION, data, reply, option) != ERR_NONE) {
        tloge("close session failed\n");
    }

    session->session_id = 0;
    session->ops_cnt    = 0;
    session->context    = nullptr;
}

int32_t TeeClient::GetFileFd(const char *filePath)
{
    if (filePath == nullptr) {
        return -1;
    }

    if (!((strlen(filePath) < MAX_TA_PATH_LEN) && strstr(filePath, ".sec"))) {
        tloge("ta_path format is wrong\n");
        return -1;
    }

    char realLoadFile[PATH_MAX + 1] = { 0 };
    if (realpath(filePath, realLoadFile) == nullptr) {
        tloge("real path failed err=%" PUBLIC "d\n", errno);
        return -1;
    }

    if (strncmp(realLoadFile, "/data/", sizeof("/data/") - 1) == 0 ||
        strncmp(realLoadFile, "/chip_prod/", sizeof("/chip_prod/") - 1) == 0 ||
        strncmp(realLoadFile, "/system/", sizeof("/system/") - 1) == 0) {
        int fd = open(realLoadFile, O_RDONLY);
        if (fd == -1) {
            tloge("open ta failed\n");
        }
        return fd;
    }
    return -1;
}

TEEC_Result TeeClient::FormatSharedMemory(MessageParcel &reply, TEEC_SharedMemory *sharedMem, uint32_t *offset)
{
    TEEC_SharedMemory *shmRet = nullptr;
    size_t len = sizeof(*shmRet);
    shmRet = (TEEC_SharedMemory *)(reply.ReadBuffer(len));
    if (shmRet == nullptr) {
        tloge("read session failed\n");
        return TEEC_FAIL;
    }
    tloge("reieve shmRet_is_allocated = %" PUBLIC "d\n", shmRet->is_allocated);

    sharedMem->ops_cnt      = shmRet->ops_cnt;
    sharedMem->is_allocated = shmRet->is_allocated;
    ListInit(&sharedMem->head);

    if (offset != nullptr) {
        if (reply.ReadUint32(*offset) != true) {
            return TEEC_FAIL;
        }
    }
    return TEEC_SUCCESS;
}

TEEC_Result TeeClient::RegisterSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if ((context == nullptr) || (sharedMem == nullptr)) {
        tloge("context or sharedMem is nullptr\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    /*
     * ca may call ReleaseShareMemory even if RegisterShareMem failed,
     * we set sharedMem->context here to avoid receive a illegal ptr
     */
    sharedMem->context = context;

    if (sharedMem->buffer == nullptr || !CheckSharedMemoryFLag(sharedMem->flags)) {
        tloge("register shr mem failed: flag %" PUBLIC "d is invalid\n", sharedMem->flags);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    if (!InitTeecService()) {
        tloge("teec service not valid\n");
        return TEEC_FAIL;
    }

    (void)data.WriteInterfaceToken(INTERFACE_TOKEN);

    if (WriteContext(data, context) != true) {
        return TEEC_FAIL;
    }

    if (WriteSharedMem(data, sharedMem) != true) {
        return TEEC_FAIL;
    }

    int32_t ret = mTeecService->SendRequest(REGISTER_MEM, data, reply, option);
    if (ret != ERR_NONE) {
        return TEEC_FAIL;
    }

    if (reply.ReadInt32(ret) != true) {
        return TEEC_FAIL;
    }

    if ((TEEC_Result)ret != TEEC_SUCCESS) {
        tloge("return failed from tee\n");
        return (TEEC_Result)ret;
    }
    return FormatSharedMemory(reply, sharedMem, nullptr);
}

TEEC_Result TeeClient::MapSharedMemory(int fd, uint32_t offset, TEEC_SharedMemory *sharedMem)
{
    if (sharedMem->size != 0) {
        sharedMem->buffer = mmap(0, sharedMem->size,
            (PROT_READ | PROT_WRITE), MAP_SHARED, fd, (off_t)(offset * PAGE_SIZE));
    } else {
        sharedMem->buffer = ZERO_SIZE_PTR;
    }

    if (sharedMem->buffer == MAP_FAILED) {
        tloge("mmap failed\n");
        sharedMem->buffer = nullptr;
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    return TEEC_SUCCESS;
}

void TeeClient::AddShareMem(void *buffer, uint32_t offset, uint32_t size, int32_t fd)
{
    TC_NS_ShareMem shareMem;

    shareMem.offset = offset;
    shareMem.buffer = buffer;
    shareMem.size   = size;
    shareMem.fd     = fd;
    lock_guard<mutex> autoLock(mSharMemLock);
    mShareMem.push_back(shareMem);
    return;
}

TEEC_Result TeeClient::ProcAllocateSharedMemory(MessageParcel &reply, TEEC_SharedMemory *sharedMem)
{
    int32_t ret;

    if (reply.ReadInt32(ret) != true) {
        return TEEC_FAIL;
    }

    if ((TEEC_Result)ret != TEEC_SUCCESS) {
        tloge("alloca share mem return failed\n");
        return (TEEC_Result)ret;
    }

    uint32_t offset;
    TEEC_Result rRet = FormatSharedMemory(reply, sharedMem, &offset);
    if (rRet != TEEC_SUCCESS) {
        return rRet;
    }

    int fd = reply.ReadFileDescriptor();
    if (fd < 0) {
        tloge("alloca share mem read fd failed\n");
        return TEEC_FAIL;
    }

    rRet = MapSharedMemory(fd, offset, sharedMem);
    if (rRet != TEEC_SUCCESS) {
        tloge("map shared mem failed\n");
        goto END;
    }

    AddShareMem(sharedMem->buffer, offset, sharedMem->size, sharedMem->context->fd);

END:
    if (fd >= 0) {
        close(fd);
    }
    return TEEC_SUCCESS;
}

TEEC_Result TeeClient::AllocateSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if ((context == nullptr) || (sharedMem == nullptr)) {
        tloge("alloca share mem: context or sharedMem is nullptr\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    /*
     * ca may call ReleaseShareMemory even if AllocateSharedMemory failed,
     * we set sharedMem->context here to avoid receive a illegal ptr
     */
    sharedMem->context = context;

    if (!CheckSharedMemoryFLag(sharedMem->flags)) {
        tloge("alloc shr mem: failed: flag %" PUBLIC "d is invalid\n", sharedMem->flags);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    if (!InitTeecService()) {
        tloge("alloca share mem: teec service not valid\n");
        return TEEC_FAIL;
    }

    (void)data.WriteInterfaceToken(INTERFACE_TOKEN);
    if (WriteContext(data, context) != true) {
        return TEEC_FAIL;
    }

    if (WriteSharedMem(data, sharedMem) != true) {
        return TEEC_FAIL;
    }

    if (mTeecService->SendRequest(ALLOC_MEM, data, reply, option) != ERR_NONE) {
        return TEEC_FAIL;
    }

    return ProcAllocateSharedMemory(reply, sharedMem);
}

TEEC_Result TeeClient::FreeShareMem(TEEC_SharedMemory *sharedMem)
{
    size_t index;
    bool findFlag = false;

    lock_guard<mutex> autoLock(mSharMemLock);
    size_t count = mShareMem.size();
    for (index = 0; index < count; index++) {
        if (mShareMem[index].buffer == sharedMem->buffer) {
            findFlag = true;
            break;
        }
    }

    if (findFlag) {
        if ((sharedMem->buffer != nullptr) && (sharedMem->buffer != ZERO_SIZE_PTR) && (sharedMem->size != 0)) {
            int32_t ret = munmap(sharedMem->buffer, sharedMem->size);
            if (ret != 0) {
                tloge("munmap share mem failed, ret=0x%" PUBLIC "x\n", ret);
            }
            sharedMem->buffer = nullptr;
            sharedMem->size   = 0;
        }
        mShareMem.erase(mShareMem.begin() + index);
    } else {
        tloge("failed to find share mem in vector\n");
        return TEEC_FAIL;
    }

    return TEEC_SUCCESS;
}

void TeeClient::ReleaseSharedMemory(TEEC_SharedMemory *sharedMem)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (sharedMem == nullptr || sharedMem->context == nullptr) {
        tloge("releaseSharemem: wrong params");
        return;
    }

    uint32_t shmOffset = UINT32_MAX;
    if (sharedMem->buffer != nullptr) {
        shmOffset = FindShareMemOffset(sharedMem->buffer);
        if (sharedMem->is_allocated) {
            if (FreeShareMem(sharedMem)) {
                tloge("releaseSharemem: free share mem failed\n");
            }
        }
    }

    if (!InitTeecService()) {
        return;
    }

    (void)data.WriteInterfaceToken(INTERFACE_TOKEN);
    if (!WriteContext(data, sharedMem->context)) {
        return;
    }

    if (!WriteSharedMem(data, sharedMem)) {
        return;
    }

    if (!data.WriteUint32(shmOffset)) {
        return;
    }

    if (mTeecService->SendRequest(RELEASE_MEM, data, reply, option) != ERR_NONE) {
        tloge("releaseSharemem: send request failed\n");
        return;
    }

    sharedMem->buffer  = nullptr;
    sharedMem->size    = 0;
    sharedMem->flags   = 0;
    sharedMem->ops_cnt = 0;
    sharedMem->context = nullptr;
}

void TeeClient::RequestCancellation(const TEEC_Operation *operation)
{
    tloge("requestCancellation not support!\n");
    (void)operation;
    return;
}

TEEC_Result TeeClient::SendSecfile(const char *path, TEEC_Session *session)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t result = TEEC_FAIL;
    if (path == nullptr || session == nullptr || session->context == nullptr) {
        tloge("the params is error\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    if (!InitTeecService()) {
        return TEEC_FAIL;
    }

    (void)data.WriteInterfaceToken(INTERFACE_TOKEN);
    int fd = GetFileFd(path);
    if (fd < 0) {
        tloge("open the path error\n");
        return TEEC_FAIL;
    }

    if (WriteChar(path, data) != true) {
        goto teec_error;
    }

    if (data.WriteBool(true) != true) {
        goto teec_error;
    }
    if (data.WriteFileDescriptor(fd) != true) {
        goto teec_error;
    }

    if (WriteContext(data, session->context) != true) {
        goto teec_error;
    }

    if (WriteSession(data, session)!= true) {
        goto teec_error;
    }

    if (mTeecService->SendRequest(SEND_SECFILE, data, reply, option) != ERR_NONE) {
        goto teec_error;
    }

    if (reply.ReadUint32(result) != true) {
        goto teec_error;
    }

teec_error:
    close(fd);
    return (TEEC_Result)result;
}

TEEC_Result TeeClient::GetTeeVersion(uint32_t &teeVersion)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!InitTeecService()) {
        return TEEC_FAIL;
    }

    if (mTeecService->SendRequest(GET_TEE_VERSION, data, reply, option) != ERR_NONE) {
        return TEEC_FAIL;
    }

    if (reply.ReadUint32(teeVersion) != true) {
        return TEEC_FAIL;
    }
    return TEEC_SUCCESS;
}

} // namespace OHOS


TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
    return OHOS::TeeClient::GetInstance().InitializeContext(name, context);
}

void TEEC_FinalizeContext(TEEC_Context *context)
{
    OHOS::TeeClient::GetInstance().FinalizeContext(context);
}

TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session, const TEEC_UUID *destination,
    uint32_t connectionMethod, const void *connectionData, TEEC_Operation *operation,
    uint32_t *returnOrigin)
{
    return OHOS::TeeClient::GetInstance().OpenSession(context, session, destination,
        connectionMethod, connectionData, operation, returnOrigin);
}

void TEEC_CloseSession(TEEC_Session *session)
{
    OHOS::TeeClient::GetInstance().CloseSession(session);
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t commandID, TEEC_Operation *operation,
    uint32_t *returnOrigin)
{
    return OHOS::TeeClient::GetInstance().InvokeCommand(session, commandID, operation, returnOrigin);
}

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem)
{
    return OHOS::TeeClient::GetInstance().RegisterSharedMemory(context, sharedMem);
}

TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem)
{
    return OHOS::TeeClient::GetInstance().AllocateSharedMemory(context, sharedMem);
}

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *sharedMem)
{
    return OHOS::TeeClient::GetInstance().ReleaseSharedMemory(sharedMem);
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
    OHOS::TeeClient::GetInstance().RequestCancellation(operation);
}

TEEC_Result TEEC_SendSecfile(const char *path, TEEC_Session *session)
{
    return OHOS::TeeClient::GetInstance().SendSecfile(path, session);
}

uint32_t TEEC_GetTEEVersion(void)
{
    uint32_t teeVersion = 0;
    TEEC_Result result = OHOS::TeeClient::GetInstance().GetTeeVersion(teeVersion);
    if (result != TEEC_SUCCESS || teeVersion == 0) {
        tloge("get the tee version failed, result:0x%" PUBLIC "x, the version:0x%" PUBLIC "x", result, teeVersion);
    }
    return teeVersion;
}
