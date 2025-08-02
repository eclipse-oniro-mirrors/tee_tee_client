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
#include <malloc.h>
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
const std::u16string INTERFACE_TOKEN = u"ohos.tee_client.accessToken";

int32_t CaDaemonStub::OnRemoteRequest(uint32_t code,
    MessageParcel& data, MessageParcel &reply, MessageOption &option)
{
    tlogi("CaDaemonStub::OnReceived, code = %" PUBLIC "u, flags= %" PUBLIC "d.", code, option.GetFlags());
    int32_t result;
    (void)mallopt(M_SET_THREAD_CACHE, M_THREAD_CACHE_DISABLE);
    (void)mallopt(M_DELAYED_FREE, M_DELAYED_FREE_DISABLE);
    switch (code) {
        case static_cast<uint32_t>(CadaemonOperationInterfaceCode::INIT_CONTEXT):
            result = InitContextRecvProc(data, reply);
            break;
        case static_cast<uint32_t>(CadaemonOperationInterfaceCode::FINAL_CONTEXT):
            result = FinalContextRecvProc(data, reply);
            break;
        case static_cast<uint32_t>(CadaemonOperationInterfaceCode::OPEN_SESSION):
            result = OpenSessionRecvProc(data, reply);
            break;
        case static_cast<uint32_t>(CadaemonOperationInterfaceCode::CLOSE_SESSION):
            result = CloseSessionRecvProc(data, reply);
            break;
        case static_cast<uint32_t>(CadaemonOperationInterfaceCode::INVOKE_COMMND):
            result = InvokeCommandRecvProc(data, reply);
            break;
        case static_cast<uint32_t>(CadaemonOperationInterfaceCode::REGISTER_MEM):
            result = RegisterMemRecvProc(data, reply);
            break;
        case static_cast<uint32_t>(CadaemonOperationInterfaceCode::ALLOC_MEM):
            result = AllocMemRecvProc(data, reply);
            break;
        case static_cast<uint32_t>(CadaemonOperationInterfaceCode::RELEASE_MEM):
            result = ReleaseMemRecvProc(data, reply);
            break;
        case static_cast<uint32_t>(CadaemonOperationInterfaceCode::SET_CALL_BACK):
            result = SetCallBackRecvProc(data, reply);
            break;
        case static_cast<uint32_t>(CadaemonOperationInterfaceCode::SEND_SECFILE):
            result = SendSecFileRecvProc(data, reply);
            break;
        case static_cast<uint32_t>(CadaemonOperationInterfaceCode::GET_TEE_VERSION):
            result = GetTeeVersionRecvProc(data, reply);
            break;
        default:
            tlogi("CaDaemonStub: default case, need check");
            (void)mallopt(M_FLUSH_THREAD_CACHE, 0);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    (void)mallopt(M_FLUSH_THREAD_CACHE, 0);
    return result;
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
            tloge("copy str fail, errno = %" PUBLIC "d\n", errno);
            return false;
        }
        *str = tempChar;
    }

    return true;
}

int32_t CaDaemonStub::InitContextRecvProc(MessageParcel &data, MessageParcel &reply)
{
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
        return false;
    }

    if (memcpy_s(session, len, tempSession, len) != EOK) {
        tloge("getSession: operation memcpy failed\n");
        return false;
    }
    return true;
}

static bool GetSharedMemFromData(MessageParcel &data, TEEC_SharedMemory *shm)
{
    tlogi("start to recieve sharedmem\n");
    TEEC_SharedMemory *tempShm = nullptr;
    size_t len = sizeof(*tempShm);
    tempShm = (TEEC_SharedMemory *)(data.ReadBuffer(len));
    if (tempShm == nullptr) {
        return false;
    }

    if (memcpy_s(shm, len, tempShm, len) != EOK) {
        tloge("getShamem: operation memcpy failed\n");
        return false;
    }
    return true;
}

static void SetInvalidIonFd(TEEC_Operation *operation)
{
    uint32_t paramType[TEEC_PARAM_NUM] = { 0 };
    for (uint32_t paramCnt = 0; paramCnt < TEEC_PARAM_NUM; paramCnt++) {
        paramType[paramCnt] = TEEC_PARAM_TYPE_GET(operation->paramTypes, paramCnt);
        if (paramType[paramCnt] == TEEC_ION_INPUT) {
            operation->params[paramCnt].ionref.ion_share_fd = -1;
        }
    }
}

static void CloseDupIonFd(TEEC_Operation *operation)
{
    uint32_t paramType[TEEC_PARAM_NUM] = { 0 };
    for (uint32_t paramCnt = 0; paramCnt < TEEC_PARAM_NUM; paramCnt++) {
        paramType[paramCnt] = TEEC_PARAM_TYPE_GET(operation->paramTypes, paramCnt);
        if (paramType[paramCnt] != TEEC_ION_INPUT) {
            continue;
        }
        if (operation->params[paramCnt].ionref.ion_share_fd >= 0) {
            close(operation->params[paramCnt].ionref.ion_share_fd);
        }
    }
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

    /* First, set ion fd invalid, easy to judge if a dup fd can be closed */
    SetInvalidIonFd(operation);
    /* clear the pointer from ca to avoid access to invalid address */
    operation->session = nullptr;
    for (uint32_t paramCnt = 0; paramCnt < TEEC_PARAM_NUM; paramCnt++) {
        paramType[paramCnt] = TEEC_PARAM_TYPE_GET(operation->paramTypes, paramCnt);
        if (IS_TEMP_MEM(paramType[paramCnt])) {
            operation->params[paramCnt].tmpref.buffer = nullptr;
        } else if (IS_PARTIAL_MEM(paramType[paramCnt])) {
            operation->params[paramCnt].memref.parent = nullptr;
        } else if (paramType[paramCnt] == TEEC_ION_INPUT) {
            operation->params[paramCnt].ionref.ion_share_fd = data.ReadFileDescriptor();
            if (operation->params[paramCnt].ionref.ion_share_fd < 0) {
                tloge("read ion fd from parcel failed\n");
                CloseDupIonFd(operation);
                return false;
            }
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
        tloge("read fd success = %" PUBLIC "d\n", fd);
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
        tlogi("recieve taPath is not nullptr\n");
        context.ta_path = reinterpret_cast<uint8_t *>(const_cast<char *>(taPath));
    }

    int32_t fd = -1;
    TEEC_UUID *uuid = nullptr;
    uint32_t connMethod;
    result = ReadOpenData(data, fd, &uuid, connMethod);
    CHECK_ERR_RETURN(result, ERR_NONE, ERR_UNKNOWN_OBJECT);

    TEEC_Operation operation;
    bool opFlag = false;
    /* from now on, default return value is ERR_UNKNOWN_OBJECT */
    result = ERR_UNKNOWN_OBJECT;
    retTmp = GetOperationFromData(data, &operation, opFlag);
    CHECK_ERR_GOTO(retTmp, true, END2);

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
    CloseDupIonFd(&operation);
END2:
    if (fd >= 0) {
        close(fd);
    }

    return result;
}

int32_t CaDaemonStub::CloseSessionRecvProc(MessageParcel &data, MessageParcel &reply)
{
    (void)reply;
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
    CloseDupIonFd(&operation);
    return result;
}

int32_t CaDaemonStub::RegisterMemRecvProc(MessageParcel &data, MessageParcel &reply)
{
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

int32_t CaDaemonStub::SendSecFileRecvProc(MessageParcel& data, MessageParcel &reply)
{
    if (!EnforceInterceToken(data)) {
        tloge("CaDaemonStub: SendSecFileRecvProc interface token check failed!");
        return -1;
    }
    const char *path = nullptr;
    char tempChar[PATH_MAX + 1] = {0};
    if (!GetChar(data, tempChar, &path)) {
        tloge("SendSecFileRecvProc: get path failed\n");
        return ERR_UNKNOWN_OBJECT;
    }

    int fd = -1;
    (void)ReadFd(data, fd);
    if (fd < 0) {
        tloge("SendSecFileRecvProc: ReadFd failed\n");
        return ERR_UNKNOWN_OBJECT;
    }

    TEEC_Context context;
    if (GetContextFromData(data, &context) != true) {
        tloge("SendSecFileRecvProc: get context failed\n");
        close(fd);
        return ERR_UNKNOWN_OBJECT;
    }

    TEEC_Session session;
    if (GetSessionFromData(data, &session) != true) {
        tloge("SendSecFileRecvProc: get session failed\n");
        close(fd);
        return ERR_UNKNOWN_OBJECT;
    }

    FILE *fp = fdopen(fd, "r");
    if (fp != nullptr) {
        (void)SendSecfile(path, context.fd, fp, reply);
        /* within fclose function, fd has been closed */
        fclose(fp);
    } else {
        tloge("SendSecFileRecvProc: fdopen failed\n");
        close(fd);
        return ERR_INVALID_DATA;
    }

    return ERR_NONE;
}

int32_t CaDaemonStub::GetTeeVersionRecvProc(MessageParcel& data, MessageParcel &reply)
{
    (void)GetTeeVersion(reply);
    return ERR_NONE;
}
} // namespace CaDaemon
} // namespace OHOS
