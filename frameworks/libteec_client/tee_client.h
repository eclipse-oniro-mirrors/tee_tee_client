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

#ifndef TEE_CLIENT_H
#define TEE_CLIENT_H

#include <cstdint>
#include <cstdio>
#include <mutex>
#include "ashmem.h"
#include "ipc_types.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "tee_client_api.h"
#include "tee_client_inner.h"
#include "tee_log.h"

namespace OHOS {
const std::u16string INTERFACE_TOKEN = u"ohos.tee_client.accessToken";
using TC_NS_ShareMem = struct {
    uint32_t offset;
    void *buffer;
    uint32_t size;
    int32_t fd; /* Used to mark which context sharemem belongs to */
};

/* keep same with cadaemon interface defines */
enum {
    INIT_CONTEXT = 0,
    FINAL_CONTEXT,
    OPEN_SESSION,
    CLOSE_SESSION,
    INVOKE_COMMND,
    REGISTER_MEM,
    ALLOC_MEM,
    RELEASE_MEM,
    SET_CALL_BACK
};

class TeeClient {
public:
    static TeeClient &GetInstance()
    {
        static TeeClient instance;
        return instance;
    }
    TEEC_Result InitializeContext(const char *name, TEEC_Context *context);
    void FinalizeContext(TEEC_Context *context);
    TEEC_Result OpenSession(TEEC_Context *context, TEEC_Session *session, const TEEC_UUID *destination,
        uint32_t connectionMethod, const void *connectionData, TEEC_Operation *operation, uint32_t *returnOrigin);
    void CloseSession(TEEC_Session *session);
    TEEC_Result InvokeCommand(TEEC_Session *session, uint32_t commandID,
        TEEC_Operation *operation, uint32_t *returnOrigin);
    TEEC_Result RegisterSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem);
    TEEC_Result AllocateSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem);
    void ReleaseSharedMemory(TEEC_SharedMemory *sharedMem);
    void RequestCancellation(const TEEC_Operation *operation);
    TEEC_Result SendSecfile(const char *path, TEEC_Session *session);

    class DeathNotifier : public IRemoteObject::DeathRecipient {
    public:
        explicit DeathNotifier(const sptr<IRemoteObject> &binder) : serviceBinder(binder)
        {
        }
        virtual ~DeathNotifier()
        {
            if (mServiceValid && (serviceBinder != nullptr)) {
                serviceBinder->RemoveDeathRecipient(this);
            }
        }
        virtual void OnRemoteDied(const wptr<IRemoteObject> &binder)
        {
            (void)binder;
            tloge("teec service died");
            mServiceValid = false;
        }

    private:
        sptr<IRemoteObject> serviceBinder;
    };

    friend class DeathNotifier;

private:
    TeeClient() : mTeecService(nullptr), mDeathNotifier(nullptr), mNotify(nullptr)
    {
        tloge("Init TeeClient\n");
    }

    ~TeeClient()
    {
        FreeAllShareMem();
        tloge("TeeClient Destroy\n");
    }

    TeeClient(const TeeClient &) = delete;
    TeeClient &operator=(const TeeClient &) = delete;

    void InitTeecService();
    bool SetCallBack();
    int32_t GetFileFd(const char *filePath);
    TEEC_Result InitializeContextSendCmd(const char *name, MessageParcel &reply);
    TEEC_Result OpenSessionSendCmd(TEEC_Context *context, TEEC_Session *session, const TEEC_UUID *destination,
        uint32_t connectionMethod, int32_t fd, TEEC_Operation *operation, uint32_t *retOrigin);
    bool FormatSession(TEEC_Session *session, MessageParcel &reply);
    TEEC_Result InvokeCommandSendCmd(TEEC_Context *context, TEEC_Session *session, uint32_t commandID,
    TEEC_Operation *operation, uint32_t *returnOrigin);
    TEEC_Result GetOptMemSize(TEEC_Operation *operation, size_t *memSize);
    TEEC_Result GetPartialMemSize(TEEC_Operation *operation, size_t optMemSize,
        uint32_t paramCnt, uint32_t *cSize);
    TEEC_Result CopyTeecOptMem(TEEC_Operation *operation, size_t optMemSize, sptr<Ashmem> &optMem);
    TEEC_Result TeecOptEncode(TEEC_Operation *operation, sptr<Ashmem> &optMem, size_t dataSize);
    TEEC_Result TeecOptEncodeTempMem(const TEEC_Parameter *param, sptr<Ashmem> &optMem, size_t *dataSize);
    TEEC_Result GetTeecOptMem(TEEC_Operation *operation, size_t optMemSize, sptr<Ashmem> &optMem, MessageParcel &reply);
    TEEC_Result TeecOptDecode(TEEC_Operation *operation, TEEC_Operation *inOpt, const uint8_t *data, size_t dataSize);
    TEEC_Result TeecOptDecodeTempMem(TEEC_Parameter *param, uint32_t paramType, const TEEC_Parameter *inParam,
        const uint8_t **data, size_t *dataSize);
    TEEC_Result TeecOptDecodePartialMem(TEEC_Parameter *param, uint32_t paramType,
        TEEC_Parameter *inParam, const uint8_t **data, size_t *dataSize);
    TEEC_Result TeecOptEncodePartialMem(const TEEC_Parameter *param,
        uint32_t paramType, sptr<Ashmem> &optMem, size_t *dataSize);
    bool CovertEncodePtr(sptr<Ashmem> &optMem, size_t *sizeLeft, TEEC_SharedMemory *shm);
    TEEC_Result FormatSharedMemory(MessageParcel &reply, TEEC_SharedMemory *sharedMem, uint32_t *offset);
    TEEC_Result MapSharedMemory(int fd, uint32_t offset, TEEC_SharedMemory *sharedMem);
    TEEC_Result ProcAllocateSharedMemory(MessageParcel &reply, TEEC_SharedMemory *sharedMem);
    uint32_t FindShareMemOffset(const void *buffer);
    void AddShareMem(void *buffer, uint32_t offset, uint32_t size, int32_t fd);
    void FreeAllShareMem();
    void FreeAllShareMemoryInContext(const TEEC_Context *context);
    TEEC_Result FreeShareMem(TEEC_SharedMemory *sharedMem);
    TEEC_Result TEEC_CheckOperation(const TEEC_Operation *operation);

    std::mutex mServiceLock;
    std::mutex mSharMemLock;
    static bool mServiceValid;
    sptr<IRemoteObject> mTeecService;
    sptr<DeathNotifier> mDeathNotifier;
    sptr<IRemoteObject> mNotify;
    std::vector<TC_NS_ShareMem> mShareMem;
};
} // namespace OHOS
#endif
