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

#ifndef CA_DAEMON_SERVICE_H
#define CA_DAEMON_SERVICE_H

#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include "cadaemon_interface.h"
#include "cadaemon_stub.h"
#include "iremote_stub.h"
#include "system_ability.h"
#include "tee_auth_common.h"
#include "tee_client_api.h"
#include "tee_client_inner_api.h"
#include "tee_client_type.h"

using DaemonProcdata = struct {
    int callingPid;
    uint32_t opsCnt;
    int32_t cxtFd[MAX_CXTCNT_ONECA];
    struct ListNode procdataHead;
};

using TidData = struct {
    int callingPid;
    int tid;
    struct ListNode tidHead;
};

using InputPara = struct {
    uint32_t offset;
    uint32_t memSize;
    uint32_t totalSize;
    uint32_t paraType;
};

using DecodePara = struct {
    TEEC_SharedMemory shm[TEEC_PARAM_NUM];
    TEEC_SharedMemoryInner *shmInner[TEEC_PARAM_NUM];
    TEEC_ContextInner *contextInner;
};

namespace OHOS {
namespace CaDaemon {
enum class ServiceRunningState {
    STATE_NOT_START,
    STATE_RUNNING
};

class CaDaemonService : public SystemAbility, public CaDaemonStub {
DECLARE_SYSTEM_ABILITY(CaDaemonService);
public:
    CaDaemonService(int32_t systemAbilityId, bool runOnCreate):SystemAbility(systemAbilityId, runOnCreate) {}
    ~CaDaemonService() = default;
    void OnStart() override;
    void OnStop() override;
    ServiceRunningState QueryServiceState() const
    {
        return state_;
    }
    TEEC_Result InitializeContext(const char *name, MessageParcel &reply) override;
    TEEC_Result FinalizeContext(TEEC_Context *context) override;
    TEEC_Result OpenSession(TEEC_Context *context, const char *taPath, int32_t fd,
        const TEEC_UUID *destination, uint32_t connectionMethod, TEEC_Operation *operation,
        uint32_t optMemSize, sptr<Ashmem> &optMem, MessageParcel &reply) override;
    TEEC_Result CloseSession(TEEC_Session *session, TEEC_Context *context) override;
    TEEC_Result InvokeCommand(TEEC_Context *context, TEEC_Session *session, uint32_t commandID,
        TEEC_Operation *operation, uint32_t optMemSize, sptr<Ashmem> &optMem, MessageParcel &reply) override;
    TEEC_Result RegisterSharedMemory(TEEC_Context *context,
        TEEC_SharedMemory *sharedMem,  MessageParcel &reply) override;
    TEEC_Result AllocateSharedMemory(TEEC_Context *context,
        TEEC_SharedMemory *sharedMem, MessageParcel &reply) override;
    TEEC_Result ReleaseSharedMemory(TEEC_Context *context,
        TEEC_SharedMemory *sharedMem, uint32_t shmOffset, MessageParcel &reply) override;
    int32_t SetCallBack(const sptr<IRemoteObject> &notify) override;

private:
    bool Init();
    bool registerToService_ = false;
    std::mutex mProcDataLock;
    ServiceRunningState state_ = ServiceRunningState::STATE_NOT_START;
    TEEC_Result SetContextToProcData(int32_t pid, TEEC_ContextInner *outContext);
    DaemonProcdata *CallGetProcDataPtr(int pid);
    bool IsValidContext(const TEEC_Context *context, int pid);
    bool IsValidContextWithoutLock(const TEEC_Context *context, int pid);
    void PutBnContextAndReleaseFd(int32_t pid, TEEC_ContextInner *outContext);
    TEEC_Result CallFinalizeContext(int32_t pid, const TEEC_Context *contextPtr);
    TEEC_Result CallGetBnContext(const TEEC_Context *inContext, int pid,
        TEEC_Session **outSession, TEEC_ContextInner **outContext);
    TEEC_Result CallGetBnSession(int pid, const TEEC_Context *inContext,
    const TEEC_Session *inSession, TEEC_ContextInner **outContext, TEEC_Session **outSession);
    TEEC_Result TeecOptDecodeTempMem(TEEC_Parameter *param, uint8_t **data, size_t *dataSize);
    TEEC_Result GetTeecOptMem(TEEC_Operation *operation, size_t optMemSize,
        sptr<Ashmem> &optMem, DecodePara *paraDecode);
    TEEC_Result TeecOptDecodePartialMem(DecodePara *paraDecode, uint8_t *data,
        InputPara *inputPara, TEEC_Operation *operation, uint32_t paramCnt);
    void PutAllocShrMem(TEEC_SharedMemoryInner *shmInner[], uint32_t shmNum);
    int32_t AddClient(pid_t pid, const sptr<IRemoteObject> &notify);
    void CleanProcDataForOneCa(DaemonProcdata *procData);
    void ProcessCaDied(int32_t pid);

    class Client : public IRemoteObject::DeathRecipient {
    public:
        Client(pid_t pid, const sptr<IRemoteObject> &notify, const sptr<CaDaemonService> &caDaemonService)
            : mPid(pid), mNotify(notify), mService(caDaemonService)
        {
        }
        virtual ~Client();
        pid_t GetMyPid() const;
        virtual void OnRemoteDied(const wptr<IRemoteObject> &binder);

    private:
        pid_t mPid;
        sptr<IRemoteObject> mNotify;
        sptr<CaDaemonService> mService;
    };
    std::mutex mClientLock;
    std::vector<sptr<Client>> mClients;
};
} // namespace CaDaemon
} // namespace OHOS
#endif
