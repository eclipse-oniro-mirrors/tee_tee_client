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

#include "cadaemon_stub.h"
#include <memory>
#include <securec.h>
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "string_ex.h"
#include "tee_client_api.h"
#include "tee_client_inner.h"
#include "tee_log.h"

using namespace std;

namespace OHOS {
namespace CaDaemon {
const std::u16string INTERFACE_TOKEN = u"ohos.distributedhardware.accessToken";
CaDaemonStub::CaDaemonStub()
{
    memberFuncMap_[INIT_CONTEXT] = &CaDaemonStub::InitContextRecvProc;
    memberFuncMap_[FINAL_CONTEXT] = &CaDaemonStub::FinalContextRecvProc;
    memberFuncMap_[OPEN_SESSION] = &CaDaemonStub::OpenSessionRecvProc;
    memberFuncMap_[CLOSE_SESSION] = &CaDaemonStub::CloseSessionRecvProc;
    memberFuncMap_[INVOKE_COMMND] = &CaDaemonStub::InvokeCommandRecvProc;
    memberFuncMap_[REGISTER_MEM] = &CaDaemonStub::RegisterMemRecvProc;
    memberFuncMap_[ALLOC_MEM] = &CaDaemonStub::AllocMemRecvProc;
    memberFuncMap_[RELEASE_MEM] = &CaDaemonStub::ReleaseMemRecvProc;
    memberFuncMap_[SET_CALL_BACK] = &CaDaemonStub::SetCallBackRecvProc;
}

CaDaemonStub::~CaDaemonStub()
{
    memberFuncMap_.clear();
}

int32_t CaDaemonStub::OnRemoteRequest(uint32_t code,
    MessageParcel& data, MessageParcel &reply, MessageOption &option)
{
    tlogi("CaDaemonStub::OnReceived, code = %{public}u, flags= %{public}d.", code, option.GetFlags());
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data, reply);
        }
    }
    tlogw("CaDaemonStub: default case, need check");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

static bool GetChar(MessageParcel &data, char tempChar[], const char **str)
{
    uint32_t strLen;
    string tempStr;
    int32_t ret;

    ret = data.ReadUint32(strLen);
    CHECK_ERR_RETURN(ret, true, ret);

    if (strLen > 0) {
        ret = data.ReadString(tempStr);
        CHECK_ERR_RETURN(ret, true, ret);
        if (strnlen(tempStr.c_str(), PATH_MAX) == PATH_MAX || strLen != strnlen(tempStr.c_str(), PATH_MAX)) {
            tloge("recv str length check fail\n");
            return false;
        }

        if (strcpy_s(tempChar, PATH_MAX + 1, tempStr.c_str()) != EOK) {
            tloge("copy str fail, errno = %{public}d\n", errno);
            return false;
        }
        *str = tempChar;
    }

    return true;
}

int32_t CaDaemonStub::InitContextRecvProc(MessageParcel &data, MessageParcel &reply)
{
    tloge("CaDaemonStub: InitContextRecvProc start");
    if (!EnforceInterceToken(data)) {
        tloge("CaDaemonStub: InitContextRecvProc interface token check failed!");
        return ERR_UNKNOWN_REASON;
    }

    const char *name = nullptr;
    char tempChar[PATH_MAX + 1] = { 0 };
    if (!GetChar(data, tempChar, &name)) {
        tloge("InitContextRecvProc: get name failed\n");
        return ERR_UNKNOWN_OBJECT;
    }

    if (InitializeContext(name, reply) != TEEC_SUCCESS) {
        tloge("initialize context failed\n");
        return ERR_UNKNOWN_REASON;
    }

    return ERR_NONE;
}

int32_t CaDaemonStub::FinalContextRecvProc(MessageParcel &data, MessageParcel &reply)
{
    (void)reply;
    tloge("CaDaemonStub: FinalContextRecvProc start");
    if (!EnforceInterceToken(data)) {
        tloge("CaDaemonStub: FinalContextRecvProc interface token check failed!");
        return -1;
    }

    TEEC_Context *context = nullptr;
    size_t len = sizeof(*context);
    context = (TEEC_Context *)(data.ReadBuffer(len));
    if (context == nullptr) {
        return ERR_UNKNOWN_OBJECT;
    }

    if (FinalizeContext(context) != TEEC_SUCCESS) {
        return ERR_UNKNOWN_REASON;
    }

    return ERR_NONE;
}

static bool GetContextFromData(MessageParcel &data, TEEC_Context *context)
{
    size_t len = sizeof(*context);
    TEEC_Context *tempContext = (TEEC_Context *)(data.ReadBuffer(len));
    if (tempContext == nullptr) {
        return false;
    }

    if (memcpy_s(context, len, tempContext, len) != EOK) {
        tloge("getContext: operation memcpy failed\n");
        return false;
    }
    return true;
}

static bool GetSessionFromData(MessageParcel &data, TEEC_Session *session)
{
    TEEC_Session *tempSession = nullptr;
    size_t len = sizeof(*tempSession);
    tempSession = (TEEC_Session *)(data.ReadBuffer(len));
    if (tempSession == nullptr) {
        return ERR_UNKNOWN_OBJECT;
    }

    if (memcpy_s(session, len, tempSession, len) != EOK) {
        tloge("getSession: operation memcpy failed\n");
        return false;
    }
    return true;
}

static bool GetSharedMemFromData(MessageParcel &data, TEEC_SharedMemory *shm)
{
    tloge("start to recieve sharedmem\n");
    TEEC_SharedMemory *tempShm = nullptr;
    size_t len = sizeof(*tempShm);
    tempShm = (TEEC_SharedMemory *)(data.ReadBuffer(len));
    if (tempShm == nullptr) {
        return ERR_UNKNOWN_OBJECT;
    }

    if (memcpy_s(shm, len, tempShm, len) != EOK) {
        tloge("getShamem: operation memcpy failed\n");
        return false;
    }
    return true;
}

static bool GetOperationFromData(MessageParcel &data, TEEC_Operation *operation, bool &opFlag)
{
    bool retTmp = data.ReadBool(opFlag);
    uint32_t paramType[TEEC_PARAM_NUM] = { 0 };
    CHECK_ERR_RETURN(retTmp, true, retTmp);

    if (!opFlag) {
        tloge("operation is nullptr\n");
        return true;
    }

    size_t len = sizeof(*operation);
    TEEC_Operation *tempOp = (TEEC_Operation *)(data.ReadBuffer(len));
    if (tempOp == nullptr) {
        return false;
    }

    if (memcpy_s(operation, len, tempOp, len) != EOK) {
        tloge("getOperation: operation memcpy failed\n");
        return false;
    }

    /* clear the pointer from ca to avoid access to invalid address */
    operation->session = nullptr;
    for (uint32_t paramCnt = 0; paramCnt < TEEC_PARAM_NUM; paramCnt++) {
        paramType[paramCnt] = TEEC_PARAM_TYPE_GET(operation->paramTypes, paramCnt);
        if (IS_TEMP_MEM(paramType[paramCnt])) {
            operation->params[paramCnt].tmpref.buffer = nullptr;
        } else if (IS_PARTIAL_MEM(paramType[paramCnt])) {
            operation->params[paramCnt].memref.parent = nullptr;
        }
    }
    return true;
}


static bool ReadFd(MessageParcel &data, int32_t &fd)
{
    bool fdFlag = false;

    bool retTmp = data.ReadBool(fdFlag);
    CHECK_ERR_RETURN(retTmp, true, retTmp);

    if (fdFlag) {
        fd = data.ReadFileDescriptor();
        if (fd < 0) {
            tloge("read fd failed\n");
            return false;
        }
        tloge("read fd success = %{public}d\n", fd);
    }
    return true;
}

static void ClearAsmMem(sptr<Ashmem> &optMem)
{
    if (optMem != nullptr) {
        optMem->UnmapAshmem();
        optMem->CloseAshmem();
    }
}

static bool GetOptMemFromData(MessageParcel &data, sptr<Ashmem> &optMem, uint32_t &optMemSize)
{
    tloge("get optMem start\n");
    bool retTmp = data.ReadUint32(optMemSize);
    CHECK_ERR_RETURN(retTmp, true, retTmp);

    if (optMemSize > 0) {
        optMem = data.ReadAshmem();
        if (optMem == nullptr) {
            tloge("get optMem failed\n");
            return false;
        }

        bool ret = optMem->MapReadAndWriteAshmem();
        if (!ret) {
            tloge("map ashmem failed\n");
            return false;
        }
        tloge("get optMem success\n");
    }

    return true;
}

static int32_t ReadOpenData(MessageParcel &data, int32_t &fd, TEEC_UUID **uuid, uint32_t &connMethod)
{
    size_t len = sizeof(**uuid);

    bool retTmp = ReadFd(data, fd);
    if (!retTmp) {
        tloge("read ta fd failed\n");
        goto ERROR;
    }

    *uuid = (TEEC_UUID *)(data.ReadBuffer(len));
    if (*uuid == nullptr) {
        tloge("read uuid failed\n");
        goto ERROR;
    }

    retTmp = data.ReadUint32(connMethod);
    if (!retTmp) {
        tloge("read connection method failed\n");
        goto ERROR;
    }

    return ERR_NONE;

ERROR:
    if (fd >= 0) {
        close(fd);
    }

    return ERR_UNKNOWN_OBJECT;
}

int32_t CaDaemonStub::OpenSessionRecvProc(MessageParcel &data, MessageParcel &reply)
{
    int32_t result = ERR_NONE;
    tloge("CaDaemonStub: OpenSessionRecvProc start");
    if (!EnforceInterceToken(data)) {
        tloge("CaDaemonStub: OpenSessionRecvProc interface token check failed!");
        return -1;
    }

    TEEC_Context context;
    bool retTmp = GetContextFromData(data, &context);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    const char *taPath = nullptr;
    char tempChar[PATH_MAX + 1] = { 0 };
    retTmp = GetChar(data, tempChar, &taPath);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);
    if (taPath != nullptr) {
        tloge("recieve taPath is not nullptr\n");
        context.ta_path = reinterpret_cast<uint8_t *>(const_cast<char *>(taPath));
    }

    int32_t fd = -1;
    TEEC_UUID *uuid = nullptr;
    uint32_t connMethod;
    result = ReadOpenData(data, fd, &uuid, connMethod);

    TEEC_Operation operation;
    bool opFlag = false;
    retTmp = GetOperationFromData(data, &operation, opFlag);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    uint32_t optMemSize;
    sptr<Ashmem> optMem;
    retTmp = GetOptMemFromData(data, optMem, optMemSize);
    if (!retTmp) {
        result = ERR_UNKNOWN_OBJECT;
        goto END;
    }

    if (opFlag) {
        result = OpenSession(&context, taPath, fd, uuid, connMethod, &operation, optMemSize, optMem, reply);
    } else {
        result = OpenSession(&context, taPath, fd, uuid, connMethod, nullptr, optMemSize, optMem, reply);
    }

END:
    ClearAsmMem(optMem);

    if (fd >= 0) {
        close(fd);
    }

    return result;
}

int32_t CaDaemonStub::CloseSessionRecvProc(MessageParcel &data, MessageParcel &reply)
{
    (void)reply;
    tloge("CaDaemonStub: CloseSessionRecvProc start");
    if (!EnforceInterceToken(data)) {
        tloge("CaDaemonStub: CloseSessionRecvProc interface token check failed!");
        return -1;
    }

    TEEC_Context context;
    bool retTmp = GetContextFromData(data, &context);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    TEEC_Session session;
    retTmp = GetSessionFromData(data, &session);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    if (CloseSession(&session, &context) != TEEC_SUCCESS) {
        return ERR_UNKNOWN_REASON;
    }

    return ERR_NONE;
}
int32_t CaDaemonStub::InvokeCommandRecvProc(MessageParcel &data, MessageParcel &reply)
{
    int32_t result = ERR_NONE;
    tloge("CaDaemonStub: InvokeCommandRecvProc start");
    if (!EnforceInterceToken(data)) {
        tloge("CaDaemonStub: InvokeCommandRecvProc interface token check failed!");
        return -1;
    }

    TEEC_Context context;
    bool retTmp = GetContextFromData(data, &context);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    TEEC_Session session;
    retTmp = GetSessionFromData(data, &session);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    uint32_t commandID;
    retTmp = data.ReadUint32(commandID);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    TEEC_Operation operation;
    bool opFlag = false;
    retTmp = GetOperationFromData(data, &operation, opFlag);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    uint32_t optMemSize;
    sptr<Ashmem> optMem;
    retTmp = GetOptMemFromData(data, optMem, optMemSize);
    if (!retTmp) {
        result = ERR_UNKNOWN_OBJECT;
        goto END;
    }

    if (opFlag) {
        result = InvokeCommand(&context, &session, commandID, &operation, optMemSize, optMem, reply);
    } else {
        result = InvokeCommand(&context, &session, commandID, nullptr, optMemSize, optMem, reply);
    }

END:
    ClearAsmMem(optMem);
    return result;
}

int32_t CaDaemonStub::RegisterMemRecvProc(MessageParcel &data, MessageParcel &reply)
{
    tloge("CaDaemonStub: RegisterMemRecvProc start");
    if (!EnforceInterceToken(data)) {
        tloge("CaDaemonStub: RegisterMemRecvProc interface token check failed!");
        return -1;
    }

    TEEC_Context context;
    bool retTmp = GetContextFromData(data, &context);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    TEEC_SharedMemory sharedMem;
    retTmp = GetSharedMemFromData(data, &sharedMem);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    if (RegisterSharedMemory(&context, &sharedMem, reply) != TEEC_SUCCESS) {
        return ERR_UNKNOWN_REASON;
    }

    return ERR_NONE;
}

int32_t CaDaemonStub::AllocMemRecvProc(MessageParcel &data, MessageParcel &reply)
{
    tloge("CaDaemonStub: AllocMemRecvProc start");
    if (!EnforceInterceToken(data)) {
        tloge("CaDaemonStub: AllocMemRecvProc interface token check failed!");
        return -1;
    }

    TEEC_Context context;
    bool retTmp = GetContextFromData(data, &context);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    TEEC_SharedMemory sharedMem;
    retTmp = GetSharedMemFromData(data, &sharedMem);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    if (AllocateSharedMemory(&context, &sharedMem, reply) != TEEC_SUCCESS) {
        return ERR_UNKNOWN_REASON;
    }

    return ERR_NONE;
}

int32_t CaDaemonStub::ReleaseMemRecvProc(MessageParcel &data, MessageParcel &reply)
{
    tloge("CaDaemonStub: ReleaseMemRecvProc start");
    if (!EnforceInterceToken(data)) {
        tloge("CaDaemonStub: ReleaseMemRecvProc interface token check failed!");
        return -1;
    }

    TEEC_Context context;
    bool retTmp = GetContextFromData(data, &context);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    TEEC_SharedMemory sharedMem;
    retTmp = GetSharedMemFromData(data, &sharedMem);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    uint32_t shmOffset;
    retTmp = data.ReadUint32(shmOffset);
    CHECK_ERR_RETURN(retTmp, true, ERR_UNKNOWN_OBJECT);

    ReleaseSharedMemory(&context, &sharedMem, shmOffset, reply);

    return ERR_NONE;
}

int32_t CaDaemonStub::SetCallBackRecvProc(MessageParcel &data, MessageParcel &reply)
{
    tloge("CaDaemonStub: SetCallBackRecvProc start");
    if (!EnforceInterceToken(data)) {
        tloge("CaDaemonStub: SetCallBackRecvProc interface token check failed!");
        return -1;
    }

    sptr<IRemoteObject> notify = nullptr;
    notify = data.ReadRemoteObject();
    if (notify == nullptr) {
        tloge("CaDaemonStub: recieve notify is nullptr\n");
        return ERR_NONE;
    }

    return SetCallBack(notify);
}

bool CaDaemonStub::EnforceInterceToken(MessageParcel& data)
{
    u16string interfaceToken = data.ReadInterfaceToken();
    return interfaceToken == INTERFACE_TOKEN;
}
} // namespace CaDaemon
} // namespace OHOS
