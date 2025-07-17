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

#include "cadaemon_service.h"
#include <cerrno>
#include <csignal>
#include <memory>
#include <thread>
#include <pthread.h>
#include <securec.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <sys/tgkill.h>
#include <sys/types.h>
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "tee_log.h"
#include "tee_auth_system.h"
#include "tcu_authentication.h"
#include "tc_ns_client.h"
#include "tee_ioctl_cmd.h"
#include <sys/ioctl.h>
#include "tee_client_inner.h"
#include "tui_threadwork.h"
#include "tee_file.h"
using namespace std;

namespace OHOS {
namespace CaDaemon {
static LIST_DECLARE(g_teecProcDataList);
static LIST_DECLARE(g_teecTidList);
static pthread_mutex_t g_mutexTidList = PTHREAD_MUTEX_INITIALIZER;

REGISTER_SYSTEM_ABILITY_BY_ID(CaDaemonService, CA_DAEMON_ID, true);

void CaDaemonService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        tlogd("CaDaemonService has already started.");
        return;
    }
    if (!Init()) {
        tloge("failed to init CaDaemonService");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    if (GetTEEVersion()) {
        tloge("get the tee version failed\n");
        mTeeVersion = 0;
    }
    tloge("the tee version is %" PUBLIC "x\n", mTeeVersion);
    CreateTuiThread();
    CreateDstbTeeService();
}

int CaDaemonService::GetTEEVersion()
{
    int ret;

    int fd = tee_open(TC_PRIVATE_DEV_NAME, O_RDWR, 0);
    if (fd == -1) {
        tloge("Failed to open %" PUBLIC "s: %" PUBLIC "d\n", TC_PRIVATE_DEV_NAME, errno);
        return -1;
    }

    ret = ioctl(fd, TC_NS_CLIENT_IOCTL_GET_TEE_VERSION, &mTeeVersion);
    tee_close(&fd);
    if (ret != 0) {
        tloge("Failed to get tee version, err=%" PUBLIC "d\n", ret);
        return -1;
    }

    return ret;
}

void CaDaemonService::CreateTuiThread()
{
    std::thread tuiThread(TeeTuiThreadWork);
    tuiThread.detach();
    tlogi("CaDaemonService teeTuiThreadWork start \n");
}

void CaDaemonService::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    void (*initDevMgr)(void) = nullptr;
    switch (systemAbilityId) {
        case DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID:
            initDevMgr = (void(*)(void))dlsym(mDstbHandle, "InitDeviceManager");
            if (initDevMgr == nullptr) {
                tloge("get InitDeviceManager handle is null, error=%" PUBLIC "s\n", dlerror());
                return;
            }
            tlogi("callback init device manager\n");
            initDevMgr();
            break;
        default:
            tloge("invalid systemAbilityId\n");
            break;
    }

    return;
}

__attribute__((no_sanitize("cfi"))) void CaDaemonService::CreateDstbTeeService()
{
    TEEC_FuncMap funcMap = {
        .initializeContext = TEEC_InitializeContext,
        .finalizeContext = TEEC_FinalizeContext,
        .openSession = TEEC_OpenSession,
        .closeSession = TEEC_CloseSession,
        .invokeCommand = TEEC_InvokeCommand,
    };

#if defined(__LP64__)
    mDstbHandle = dlopen("/system/lib64/libdistributed_tee_service.so", RTLD_LAZY);
#else
    mDstbHandle = dlopen("/system/lib/libdistributed_tee_service.so", RTLD_LAZY);
#endif
    if (mDstbHandle == nullptr) {
        tlogi("dstb tee service handle is null");
        return;
    }

    void (*initDstbTee)(TEEC_FuncMap *funcMap) = nullptr;
    initDstbTee = (void(*)(TEEC_FuncMap *funcMap))dlsym(mDstbHandle, "InitDstbTeeService");
    if (initDstbTee == nullptr) {
        tloge("dstb tee service init func is null\n");
        return;
    }

    if (AddSystemAbilityListener(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID) == false) {
        tloge("add DHDM system ability listener faile\n");
    }

    initDstbTee(&funcMap);
}

bool CaDaemonService::Init()
{
    tlogi("CaDaemonService::Init ready to init");
    if (!registerToService_) {
        bool ret = Publish(this);
        if (!ret) {
            tloge("CaDaemonService::Init Publish failed!");
            return false;
        }
        registerToService_ = true;
    }
    tlogi("CaDaemonService::Init init success");
    return true;
}

void CaDaemonService::OnStop()
{
    tlogi("CaDaemonService service stop");
    state_ = ServiceRunningState::STATE_NOT_START;
    registerToService_ = false;
}

static DaemonProcdata *GetProcdataByPid(int pid)
{
    /* found server procdata */
    DaemonProcdata *procDataInList = nullptr;
    struct ListNode *ptr = nullptr;

    /* Paramters right, start execution */
    if (!LIST_EMPTY(&g_teecProcDataList)) {
        LIST_FOR_EACH(ptr, &g_teecProcDataList) {
            DaemonProcdata *tmp = LIST_ENTRY(ptr, DaemonProcdata, procdataHead);
            if (tmp->callingPid == pid) {
                procDataInList = tmp;
                break;
            }
        }
    }
    return procDataInList;
}

static bool CheckProcDataFdEmpty(DaemonProcdata *procData)
{
    int i;
    for (i = 0; i < MAX_CXTCNT_ONECA; i++) {
        if (procData->cxtFd[i] != -1) {
            return false;
        }
    }
    return true;
}

static void RemoveContextFromProcData(DaemonProcdata *outProcData, int32_t outContextFd)
{
    int i;
    for (i = 0; i < MAX_CXTCNT_ONECA; i++) {
        if (outContextFd == outProcData->cxtFd[i]) {
            outProcData->cxtFd[i] = -1;
            return;
        }
    }
    tloge("can not find context in outProcdata\n");
}

static int32_t TidMutexLock(void)
{
    int lockRet = pthread_mutex_lock(&g_mutexTidList);
    return lockRet;
}

static void TidMutexUnlock(int lockRet)
{
    int unlockRet;
    if (lockRet != 0) {
        tloge("not exe, mutex not in lock state. lock_ret = %" PUBLIC "d\n", lockRet);
        return;
    }
    unlockRet = pthread_mutex_unlock(&g_mutexTidList);
    if (unlockRet != 0) {
        tloge("exe mutexUnlock error, ret = %" PUBLIC "d\n", unlockRet);
    }
}

static void SigUsr1Handler(int sign)
{
    (void)sign;
    return;
}

static void RemoveTidFromList(TidData *tidData)
{
    int retMutexLock = TidMutexLock();
    if (retMutexLock) {
        tloge("tid mutex lock failed\n");
    }

    ListRemoveEntry(&tidData->tidHead);
    TidMutexUnlock(retMutexLock);
    free(tidData);
    return;
}

static TEEC_Result AddTidData(TidData **tidData, int pid)
{
    int mutexRet;
    *tidData = static_cast<TidData *>(malloc(sizeof(TidData)));
    if (*tidData == nullptr) {
        tloge("tid_data malloc failed\n");
        return TEEC_FAIL;
    }
    (*tidData)->tid = syscall(SYS_gettid);
    (*tidData)->callingPid = pid;
    ListInit(&(*tidData)->tidHead);

    mutexRet = TidMutexLock();
    if (mutexRet != 0) {
        tloge("tid mutex lock failed\n");
        free(*tidData);
        *tidData = nullptr;
        return TEEC_FAIL;
    }
    ListInsertTail(&g_teecTidList, &(*tidData)->tidHead);
    TidMutexUnlock(mutexRet);
    tlogd("tid %" PUBLIC "d is sending command to TEE\n", (*tidData)->tid);
    return TEEC_SUCCESS;
}

static void SendSigToTzdriver(int pid)
{
    int mutexRet;
    struct ListNode *ptr = nullptr;

    signal(SIGUSR1, SigUsr1Handler);
    tlogd("ignore signal SIGUSR1!\n");

    mutexRet = TidMutexLock();
    if (mutexRet != 0) {
        tloge("tid mutex lock failed\n");
        return;
    }
    if (!LIST_EMPTY(&g_teecTidList)) {
        LIST_FOR_EACH(ptr, &g_teecTidList) {
            TidData *tmp = LIST_ENTRY(ptr, TidData, tidHead);
            if (tmp->callingPid == pid) {
                int ret = tgkill(getpid(), tmp->tid, SIGUSR1);
                tlogd("send signal SIGUSR1 to tid: %" PUBLIC "d! ret = %" PUBLIC "d\n", tmp->tid, ret);
            }
        }
    }
    TidMutexUnlock(mutexRet);
}

bool CaDaemonService::IsValidContextWithoutLock(const TEEC_Context *context, int pid, int uid, uint32_t tokenid)
{
    int i;
    if (context == nullptr || context->fd < 0) {
        tloge("invalid input context\n");
        return false;
    }

    DaemonProcdata *outProcData = GetProcdataByPid(pid);
    if (outProcData == nullptr) {
        tloge("pid %" PUBLIC "d donnot have proc data in cadaemon\n", pid);
        return false;
    }

    if (outProcData->callingUid != uid || outProcData->callingTokenid != tokenid) {
        tloge("procdata with pid %" PUBLIC "d have mismatch uid or tokenid\n", pid);
        return false;
    }

    for (i = 0; i < MAX_CXTCNT_ONECA; i++) {
        if (context->fd == outProcData->cxtFd[i]) {
            return true;
        }
    }
    return false;
}

bool CaDaemonService::IsValidContext(const TEEC_Context *context, int pid, int uid, uint32_t tokenid)
{
    lock_guard<mutex> autoLock(mProcDataLock);
    return IsValidContextWithoutLock(context, pid, uid, tokenid);
}

DaemonProcdata *CaDaemonService::CallGetProcDataPtr(int pid, int uid, uint32_t tokenid)
{
    DaemonProcdata *outProcData = GetProcdataByPid(pid);
    if (outProcData != nullptr) {
        if (outProcData->callingUid != uid || outProcData->callingTokenid != tokenid) {
            tloge("procdata with pid %" PUBLIC "d have ismatch uid or tokenid\n", pid);
            return nullptr;
        }
    } else {
        auto *procData = static_cast<DaemonProcdata *>(malloc(sizeof(DaemonProcdata)));
        if (procData == nullptr) {
            tloge("procdata malloc failed\n");
            return nullptr;
        }
        (void)memset_s(procData, sizeof(DaemonProcdata), 0, sizeof(DaemonProcdata));

        for (int i = 0; i < MAX_CXTCNT_ONECA; i++) {
            procData->cxtFd[i] = -1;
        }
        procData->callingPid = pid;
        procData->callingUid = uid;
        procData->callingTokenid = tokenid;
        ListInit(&(procData->procdataHead));
        ListInsertTail(&g_teecProcDataList, &procData->procdataHead);

        outProcData = procData;
    }
    return outProcData;
}

TEEC_Result CaDaemonService::SetContextToProcData(int pid, int uid, uint32_t tokenid, TEEC_ContextInner *outContext)
{
    int i;
    {
        lock_guard<mutex> autoLock(mProcDataLock);
        DaemonProcdata *outProcData = CallGetProcDataPtr(pid, uid, tokenid);
        if (outProcData == nullptr) {
            tloge("proc data not found\n");
            return TEEC_FAIL;
        }

        for (i = 0; i < MAX_CXTCNT_ONECA; i++) {
            if (outProcData->cxtFd[i] == -1) {
                outProcData->cxtFd[i] = outContext->fd;
                return TEEC_SUCCESS;
            }
        }
    }

    tloge("the cnt of contexts in outProcData is already %" PUBLIC "d, please finalize some of them\n", i);
    return TEEC_FAIL;
}

void CaDaemonService::PutBnContextAndReleaseFd(int pid, TEEC_ContextInner *outContext)
{
    if (outContext == nullptr) {
        tlogd("put context is null\n");
        return;
    }

    int32_t contextFd = outContext->fd;
    DaemonProcdata *outProcData = nullptr;

    lock_guard<mutex> autoLock(mProcDataLock);

    if (!PutBnContext(outContext)) {
        return;
    }

    tloge("clear context success\n");

    outProcData = GetProcdataByPid(pid);
    if (outProcData == nullptr) {
        tloge("outProcdata is nullptr\n");
        return;
    }

    RemoveContextFromProcData(outProcData, contextFd);

    if (CheckProcDataFdEmpty(outProcData)) {
        tloge("ProcData is empty\n");
        ListRemoveEntry(&outProcData->procdataHead);
        free(outProcData);
    } else {
        tlogd("still have context not finalize in pid[%" PUBLIC "d]\n", pid);
    }
}

static TEEC_Result InitCaAuthInfo(CaAuthInfo *caInfo, int pid, int uid, uint32_t tokenid)
{
    caInfo->pid = pid;
    caInfo->uid = (unsigned int)uid;
    static bool sendXmlSuccFlag = false;
    /* Trans the system xml file to tzdriver */
    if (!sendXmlSuccFlag) {
        tlogd("cadaemon send system hash xml file\n");
        if (TcuAuthentication(HASH_TYPE_SYSTEM) != 0) {
            tloge("send system hash xml file failed\n");
        } else {
            sendXmlSuccFlag = true;
        }
    }

    TEEC_Result ret = (TEEC_Result)ConstructCaAuthInfo(tokenid, caInfo);
    if (ret != 0) {
        tloge("construct ca auth info failed, ret %" PUBLIC "d\n", ret);
        return TEEC_FAIL;
    }

    return TEEC_SUCCESS;
}

void CaDaemonService::ReleaseContext(int pid, TEEC_ContextInner **contextInner)
{
    TEEC_Context tempContext = { 0 };
    PutBnContextAndReleaseFd(pid, *contextInner); /* pair with ops_cnt++ when add to list */
    tempContext.fd = (*contextInner)->fd;
    if (CallFinalizeContext(pid, &tempContext) < 0) {
        tloge("CallFinalizeContext failed!\n");
    }

    /* contextInner have been freed by finalize context */
    *contextInner = nullptr;
}

TEEC_Result CaDaemonService::InitializeContext(const char *name, MessageParcel &reply)
{
    TEEC_Result ret = TEEC_FAIL;
    int callingPid = IPCSkeleton::GetCallingPid();
    int callingUid = IPCSkeleton::GetCallingUid();
    uint32_t callingTokenid = IPCSkeleton::GetCallingTokenID();
    TEEC_ContextInner *contextInner = (TEEC_ContextInner *)malloc(sizeof(*contextInner));
    CaAuthInfo *caInfo = (CaAuthInfo *)malloc(sizeof(*caInfo));
    if (contextInner == nullptr || caInfo == nullptr) {
        tloge("malloc context and cainfo failed\n");
        goto FREE_CONTEXT;
    }
    (void)memset_s(contextInner, sizeof(*contextInner), 0, sizeof(*contextInner));
    (void)memset_s(caInfo, sizeof(*caInfo), 0, sizeof(*caInfo));

    if (InitCaAuthInfo(caInfo, callingPid, callingUid, callingTokenid) != TEEC_SUCCESS) {
        goto FREE_CONTEXT;
    }

    ret = TEEC_InitializeContextInner(contextInner, caInfo);
    if (ret != TEEC_SUCCESS) {
        goto FREE_CONTEXT;
    }

    contextInner->callFromService = true;
    ret = SetContextToProcData(callingPid, callingUid, callingTokenid, contextInner);
    if (ret != TEEC_SUCCESS) {
        goto RELEASE_CONTEXT;
    }

    if (!reply.WriteInt32((int32_t)ret)) {
        ret = TEEC_FAIL;
        goto RELEASE_CONTEXT;
    }

    if (!reply.WriteInt32((int32_t)ret)) {
        ret = TEEC_FAIL;
        goto RELEASE_CONTEXT;
    }

    PutBnContextAndReleaseFd(caInfo->pid, contextInner); /* pair with ops_cnt++ when add to list */
    goto END;

RELEASE_CONTEXT:
    ReleaseContext(caInfo->pid, &contextInner);

FREE_CONTEXT:
    if (contextInner != nullptr) {
        free(contextInner);
    }
    LogException(ret, nullptr, TEEC_ORIGIN_API, TYPE_INITIALIZE_FAIL);

END:
    if (caInfo != nullptr) {
        (void)memset_s(caInfo, sizeof(*caInfo), 0, sizeof(*caInfo));
        free(caInfo);
    }
    return ret;
}

TEEC_Result CaDaemonService::FinalizeContext(TEEC_Context *context)
{
    int pid = IPCSkeleton::GetCallingPid();
    int uid = IPCSkeleton::GetCallingUid();
    uint32_t tokenid = IPCSkeleton::GetCallingTokenID();
    if (context == nullptr) {
        tloge("finalizeContext: invalid context!\n");
        return TEEC_FAIL;
    }

    if (!IsValidContext(context, pid, uid, tokenid)) {
        tloge("context and procdata have been released by service_died!\n");
        return TEEC_FAIL;
    }

    return CallFinalizeContext(pid, context);
}

TEEC_Result CaDaemonService::CallFinalizeContext(int pid, const TEEC_Context *contextPtr)
{
    TEEC_ContextInner *outContext = FindAndRemoveBnContext(contextPtr);
    if (outContext == nullptr) {
        tloge("no context found in service!\n");
        return TEEC_FAIL;
    }

    PutBnContextAndReleaseFd(pid, outContext); /* pair with initialize context */

    return TEEC_SUCCESS;
}


TEEC_Result CaDaemonService::CallGetBnContext(const TEEC_Context *inContext,
    int pid, TEEC_Session **outSession, TEEC_ContextInner **outContext)
{
    TEEC_ContextInner *tempContext = nullptr;

    if (inContext == nullptr) {
        tloge("getBnContext: invalid context!\n");
        return TEEC_FAIL;
    }

    tempContext = GetBnContext(inContext);
    if (tempContext == nullptr) {
        tloge("no context found in auth_daemon service.\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    TEEC_Session *tempSession = (TEEC_Session *)malloc(sizeof(TEEC_Session));
    if (tempSession == nullptr) {
        tloge("tempSession malloc failed!\n");
        PutBnContextAndReleaseFd(pid, tempContext);
        return TEEC_FAIL;
    }
    (void)memset_s(tempSession, sizeof(TEEC_Session), 0x00, sizeof(TEEC_Session));

    *outSession = tempSession;
    *outContext = tempContext;
    return TEEC_SUCCESS;
}

static bool WriteSession(MessageParcel &reply, TEEC_Session *session)
{
    if (session == nullptr) {
        return reply.WriteBool(false);
    }

    bool parRet = reply.WriteBool(true);
    CHECK_ERR_RETURN(parRet, true, false);

    TEEC_Session retSession;
    (void)memcpy_s(&retSession, sizeof(TEEC_Session), session, sizeof(TEEC_Session));

    /* clear session ptr, avoid to write back to CA */
    retSession.context = nullptr;
    (void)memset_s(&(retSession.head), sizeof(struct ListNode), 0, sizeof(struct ListNode));
    return reply.WriteBuffer(&retSession, sizeof(retSession));
}

static bool WriteOperation(MessageParcel &reply, TEEC_Operation *operation)
{
    if (operation == nullptr) {
        return reply.WriteBool(false);
    }

    bool parRet = reply.WriteBool(true);
    CHECK_ERR_RETURN(parRet, true, false);

    TEEC_Operation retOperation;
    (void)memcpy_s(&retOperation, sizeof(TEEC_Operation), operation, sizeof(TEEC_Operation));

    /* clear operation ptr avoid writing back to CA */
    retOperation.session = nullptr;
    for (uint32_t i = 0; i < TEEC_PARAM_NUM; i++) {
        uint32_t type = TEEC_PARAM_TYPE_GET(retOperation.paramTypes, i);
        switch (type) {
            case TEEC_MEMREF_TEMP_INPUT:
            case TEEC_MEMREF_TEMP_OUTPUT:
            case TEEC_MEMREF_TEMP_INOUT:
                retOperation.params[i].tmpref.buffer = nullptr;
                break;
            case TEEC_MEMREF_WHOLE:
            case TEEC_MEMREF_PARTIAL_INPUT:
            case TEEC_MEMREF_PARTIAL_OUTPUT:
            case TEEC_MEMREF_PARTIAL_INOUT:
                retOperation.params[i].memref.parent = nullptr;
                break;
            default:
                break;
        }
    }

    return reply.WriteBuffer(&retOperation, sizeof(retOperation));
}

static bool WriteSharedMem(MessageParcel &data, TEEC_SharedMemory *shm)
{
    TEEC_SharedMemory retShm;
    (void)memcpy_s(&retShm, sizeof(TEEC_SharedMemory),
        shm, sizeof(TEEC_SharedMemory));

    /* clear retShm ptr, avoid writing back to CA */
    retShm.buffer = nullptr;
    retShm.context = nullptr;
    memset_s(&(retShm.head), sizeof(struct ListNode), 0, sizeof(struct ListNode));
    return data.WriteBuffer(&retShm, sizeof(retShm));
}

static bool CheckSizeStatus(uint32_t shmInfoOffset, uint32_t refSize,
                            uint32_t totalSize, uint32_t memSize)
{
    return ((shmInfoOffset + refSize < shmInfoOffset) || (shmInfoOffset + refSize < refSize) ||
            (shmInfoOffset + refSize > totalSize) || (refSize > memSize));
}

static void CopyToShareMemory(TEEC_SharedMemory *shareMemBuf, uint8_t *data,
                              uint32_t shmInfoOffset, uint32_t *shmOffset)
{
    shareMemBuf->is_allocated = *reinterpret_cast<bool *>(data + shmInfoOffset);
    shmInfoOffset += sizeof(bool);

    shareMemBuf->flags = *reinterpret_cast<uint32_t *>(data + shmInfoOffset);
    shmInfoOffset += sizeof(uint32_t);

    shareMemBuf->ops_cnt = *reinterpret_cast<uint32_t *>(data + shmInfoOffset);
    shmInfoOffset += sizeof(uint32_t);

    *shmOffset = *reinterpret_cast<uint32_t *>(data + shmInfoOffset);
    shmInfoOffset += sizeof(uint32_t);

    shareMemBuf->size = *reinterpret_cast<uint32_t *>(data + shmInfoOffset);
}

#define STRUCT_SIZE (4 * (sizeof(uint32_t)) + 1 * (sizeof(bool)))
TEEC_Result CaDaemonService::TeecOptDecodePartialMem(DecodePara *paraDecode, uint8_t *data,
    InputPara *inputPara, TEEC_Operation *operation, uint32_t paramCnt)
{
    uint32_t shmInfoOffset = inputPara->offset;
    uint32_t memSize = inputPara->memSize;
    uint32_t shmOffset = 0;
    uint32_t refSize = STRUCT_SIZE;
    TEEC_SharedMemory *shareMemBuf = &(paraDecode->shm[paramCnt]);
    TEEC_SharedMemoryInner **shmInner = &(paraDecode->shmInner[paramCnt]);
    TEEC_ContextInner *outContext = paraDecode->contextInner;
    TEEC_Parameter *params = &(operation->params[paramCnt]);

    if (CheckSizeStatus(shmInfoOffset, refSize, inputPara->totalSize, memSize)) {
        goto FILLBUFFEREND;
    }

    CopyToShareMemory(shareMemBuf, data, shmInfoOffset, &shmOffset);
    memSize -= refSize;
    shmInfoOffset += refSize;

    refSize = params->memref.size;
    if (inputPara->paraType == TEEC_MEMREF_WHOLE)
        refSize = shareMemBuf->size;

    if (CheckSizeStatus(shmInfoOffset, refSize, inputPara->totalSize, memSize)) {
        goto FILLBUFFEREND;
    }

    if (!shareMemBuf->is_allocated) {
        shareMemBuf->buffer = data + shmInfoOffset;
        params->memref.offset = 0;
    } else {
        TEEC_SharedMemoryInner *shmTemp = GetBnShmByOffset(shmOffset, outContext);
        if (shmTemp == nullptr || shmTemp->buffer == nullptr) {
            tloge("no shm buffer found in service!\n");
            return TEEC_ERROR_BAD_PARAMETERS;
        }
        shareMemBuf->buffer = shmTemp->buffer;
        *shmInner = shmTemp;
    }
    params->memref.parent = shareMemBuf;
    memSize -= refSize;
    shmInfoOffset += refSize;

    inputPara->offset = shmInfoOffset;
    inputPara->memSize = memSize;
    return TEEC_SUCCESS;

FILLBUFFEREND:
    tloge("partial mem:%" PUBLIC "x greater than mem:%" PUBLIC "x:%" PUBLIC "x:%" PUBLIC "x\n",
        refSize, shmInfoOffset, memSize, inputPara->totalSize);
    return TEEC_FAIL;
}

TEEC_Result CaDaemonService::GetTeecOptMem(TEEC_Operation *operation, size_t optMemSize,
    sptr<Ashmem> &optMem, DecodePara *paraDecode)
{
    if (operation == nullptr || optMemSize == 0) {
        return TEEC_SUCCESS;
    }

    uint32_t paramType[TEEC_PARAM_NUM] = { 0 };
    uint32_t paramCnt;
    size_t sizeLeft    = optMemSize;
    TEEC_Result teeRet = TEEC_SUCCESS;
    uint32_t shmInfoOffset = 0;

    uint8_t *ptr = static_cast<uint8_t *>(const_cast<void *>(optMem->ReadFromAshmem(optMemSize, 0)));
    if (ptr == nullptr) {
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    for (paramCnt = 0; paramCnt < TEEC_PARAM_NUM; paramCnt++) {
        paramType[paramCnt] = TEEC_PARAM_TYPE_GET(operation->paramTypes, paramCnt);
        if (IS_TEMP_MEM(paramType[paramCnt])) {
            uint32_t refSize = operation->params[paramCnt].tmpref.size;
            if (CheckSizeStatus(shmInfoOffset, refSize, optMemSize, sizeLeft)) {
                tloge("temp mem:%" PUBLIC "x greater than opt mem:%" PUBLIC "x:%" PUBLIC "x:%" PUBLIC "x\n",
                    refSize, shmInfoOffset, (uint32_t)sizeLeft, (uint32_t)optMemSize);
                return TEEC_FAIL;
            }
            if (refSize != 0) {
                operation->params[paramCnt].tmpref.buffer = static_cast<void *>(ptr + shmInfoOffset);
            }
            sizeLeft -= refSize;
            shmInfoOffset += refSize;
        } else if (IS_PARTIAL_MEM(paramType[paramCnt])) {
            InputPara tmpInputPara;
            tmpInputPara.paraType = paramType[paramCnt];
            tmpInputPara.offset = shmInfoOffset;
            tmpInputPara.memSize = sizeLeft;
            tmpInputPara.totalSize = optMemSize;
            teeRet = TeecOptDecodePartialMem(paraDecode, ptr, &tmpInputPara, operation, paramCnt);
            if (teeRet) {
                return teeRet;
            }
            shmInfoOffset = tmpInputPara.offset;
            sizeLeft = tmpInputPara.memSize;
        } else if (IS_VALUE_MEM(paramType[paramCnt])) {
            /* no need to do some thing */
            tlogd("value_mem, doing noting\n");
        }

        if (teeRet != TEEC_SUCCESS) {
            tloge("decodeTempMem: opt decode param fail. paramCnt: %" PUBLIC "u, ret: 0x%" PUBLIC "x\n",
                paramCnt, teeRet);
            return teeRet;
        }
    }

    return TEEC_SUCCESS;
}

static bool RecOpenReply(uint32_t returnOrigin, TEEC_Result ret, TEEC_Session *outSession,
    TEEC_Operation *operation, MessageParcel &reply)
{
    bool writeRet = reply.WriteUint32(returnOrigin);
    CHECK_ERR_RETURN(writeRet, true, writeRet);

    writeRet = reply.WriteInt32((int32_t)ret);
    CHECK_ERR_RETURN(writeRet, true, writeRet);

    if (ret != TEEC_SUCCESS) {
        return false;
    }

    writeRet = WriteSession(reply, outSession);
    CHECK_ERR_RETURN(writeRet, true, writeRet);

    writeRet = WriteOperation(reply, operation);
    CHECK_ERR_RETURN(writeRet, true, writeRet);

    return true;
}

static void PrePareParmas(DecodePara &paraDecode, TaFileInfo &taFile,
    TEEC_ContextInner *outContext, const char *taPath, int32_t fd)
{
    (void)memset_s(&(paraDecode.shm), sizeof(paraDecode.shm), 0x00, sizeof(paraDecode.shm));
    (void)memset_s(&(paraDecode.shmInner), sizeof(paraDecode.shmInner), 0x00, sizeof(paraDecode.shmInner));
    paraDecode.contextInner = outContext;

    taFile.taPath = (const uint8_t *)taPath;
    if (fd >= 0) {
        taFile.taFp = fdopen(fd, "r");
    }
}

static void CloseTaFile(TaFileInfo taFile, int32_t &fd)
{
    if (taFile.taFp != nullptr) {
        fclose(taFile.taFp);
        taFile.taFp = nullptr;
        /* close taFp will close fd, resolve double close */
        fd = -1;
    }
}

TEEC_Result CaDaemonService::OpenSession(TEEC_Context *context, const char *taPath, int32_t &fd,
    const TEEC_UUID *destination, uint32_t connectionMethod,
    TEEC_Operation *operation, uint32_t optMemSize, sptr<Ashmem> &optMem, MessageParcel &reply)
{
    DecodePara paraDecode;
    bool writeRet = false;
    uint32_t returnOrigin = TEEC_ORIGIN_API;
    TEEC_Session *outSession = nullptr;
    TEEC_ContextInner *outContext = nullptr;
    TidData *tidData = nullptr;
    pid_t pid = IPCSkeleton::GetCallingPid();
    TaFileInfo taFile = { .taPath = nullptr, .taFp = nullptr };

    TEEC_Result ret = CallGetBnContext(context, pid, &outSession, &outContext);
    if (ret != TEEC_SUCCESS) {
        goto ERROR;
    }

    PrePareParmas(paraDecode, taFile, outContext, taPath, fd);

    ret = GetTeecOptMem(operation, optMemSize, optMem, &paraDecode);
    if (ret != TEEC_SUCCESS) {
        goto ERROR;
    }

    if (AddTidData(&tidData, pid) != TEEC_SUCCESS) {
        ret = TEEC_FAIL;
        goto ERROR;
    }

    outSession->service_id = *destination;
    outSession->session_id = 0;
    ret = TEEC_OpenSessionInner(pid, &taFile, outContext, outSession,
        destination, connectionMethod, nullptr, operation, &returnOrigin);
    RemoveTidFromList(tidData);
    tidData = nullptr;

    PutAllocShrMem(paraDecode.shmInner, TEEC_PARAM_NUM);
    PutBnContextAndReleaseFd(pid, outContext); /* pairs with CallGetBnContext */

    writeRet = RecOpenReply(returnOrigin, ret, outSession, operation, reply);
    if (!writeRet) {
        goto ERROR;
    }

    PutBnSession(outSession); /* pair with ops_cnt++ when add to list */
    CloseTaFile(taFile, fd);

    return TEEC_SUCCESS;

ERROR:
    if (outSession != nullptr) {
        free(outSession);
        outSession = nullptr;
    }

    CloseTaFile(taFile, fd);
    LogException(ret, destination, returnOrigin, TYPE_OPEN_SESSION_FAIL);

    writeRet = reply.WriteUint32(returnOrigin);
    CHECK_ERR_RETURN(writeRet, true, TEEC_FAIL);

    writeRet = reply.WriteInt32((int32_t)ret);
    CHECK_ERR_RETURN(writeRet, true, TEEC_FAIL);

    return TEEC_SUCCESS;
}

TEEC_Result CaDaemonService::CallGetBnSession(int pid, const TEEC_Context *inContext,
    const TEEC_Session *inSession, TEEC_ContextInner **outContext, TEEC_Session **outSession)
{
    TEEC_ContextInner *tmpContext = nullptr;
    TEEC_Session *tmpSession = nullptr;
    int uid = IPCSkeleton::GetCallingUid();
    uint32_t tokenid = IPCSkeleton::GetCallingTokenID();

    bool tmpCheckStatus = ((inContext == nullptr) || (inSession == nullptr) ||
                           (!IsValidContext(inContext, pid, uid, tokenid)));
    if (tmpCheckStatus) {
        tloge("getSession: invalid context!\n");
        return TEEC_FAIL;
    }

    tmpContext = GetBnContext(inContext);
    if (tmpContext == nullptr) {
        tloge("getSession: no context found in service!\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    tmpSession = GetBnSession(inSession, tmpContext);
    if (tmpSession == nullptr) {
        tloge("getSession: no session found in service!\n");
        PutBnContextAndReleaseFd(pid, tmpContext);
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    *outContext = tmpContext;
    *outSession = tmpSession;
    return TEEC_SUCCESS;
}

TEEC_Result CaDaemonService::InvokeCommand(TEEC_Context *context, TEEC_Session *session, uint32_t commandID,
    TEEC_Operation *operation, uint32_t optMemSize, sptr<Ashmem> &optMem, MessageParcel &reply)
{
    TEEC_ContextInner *outContext = nullptr;
    TEEC_Session *outSession = nullptr;
    TidData *tidData = nullptr;
    bool writeRet = false;
    uint32_t returnOrigin = TEEC_ORIGIN_API;
    DecodePara paraDecode;
    pid_t pid = IPCSkeleton::GetCallingPid();

    TEEC_Result ret = CallGetBnSession(pid, context, session, &outContext, &outSession);
    if (ret != TEEC_SUCCESS) {
        tloge("get context and session failed\n");
        goto END;
    }

    (void)memset_s(&(paraDecode.shm), sizeof(paraDecode.shm), 0x00, sizeof(paraDecode.shm));
    (void)memset_s(&(paraDecode.shmInner), sizeof(paraDecode.shmInner), 0x00, sizeof(paraDecode.shmInner));
    paraDecode.contextInner = outContext;
    ret = GetTeecOptMem(operation, optMemSize, optMem, &paraDecode);
    if (ret != TEEC_SUCCESS) {
        PutBnSession(outSession);
        PutBnContextAndReleaseFd(pid, outContext);
        goto END;
    }

    if (AddTidData(&tidData, pid) != TEEC_SUCCESS) {
        PutBnSession(outSession);
        PutBnContextAndReleaseFd(pid, outContext);
        goto END;
    }
    ret = TEEC_InvokeCommandInner(outContext, outSession, commandID, operation, &returnOrigin);
    RemoveTidFromList(tidData);
    tidData = nullptr;

    PutAllocShrMem(paraDecode.shmInner, TEEC_PARAM_NUM);
    PutBnSession(outSession);
    PutBnContextAndReleaseFd(pid, outContext);

END:
    writeRet = reply.WriteUint32(returnOrigin);
    CHECK_ERR_RETURN(writeRet, true, TEEC_FAIL);

    writeRet = reply.WriteInt32((int32_t)ret);
    CHECK_ERR_RETURN(writeRet, true, TEEC_FAIL);

    writeRet = WriteOperation(reply, operation);
    CHECK_ERR_RETURN(writeRet, true, TEEC_FAIL);

    return TEEC_SUCCESS;
}

TEEC_Result CaDaemonService::CloseSession(TEEC_Session *session, TEEC_Context *context)
{
    int pid = IPCSkeleton::GetCallingPid();
    int uid = IPCSkeleton::GetCallingUid();
    uint32_t tokenid = IPCSkeleton::GetCallingTokenID();
    TidData *tidData = nullptr;
    bool ret = (session == nullptr) || (context == nullptr) ||
               (!IsValidContext(context, pid, uid, tokenid));
    if (ret) {
        tloge("closeSession: invalid context!\n");
        return TEEC_FAIL;
    }

    TEEC_ContextInner *outContext = GetBnContext(context);
    if (outContext == nullptr) {
        tloge("closeSession: no context found in service!\n");
        return TEEC_FAIL;
    }

    TEEC_Session *outSession = FindAndRemoveSession(session, outContext);
    if (outSession == nullptr) {
        tloge("closeSession: no session found in service!\n");
        PutBnContextAndReleaseFd(pid, outContext);
        return TEEC_FAIL;
    }

    if (AddTidData(&tidData, pid) != TEEC_SUCCESS) {
        return TEEC_FAIL;
    }
    int32_t rc = TEEC_CloseSessionInner(outSession, outContext);
    if (rc != 0) {
        LogException(rc, &session->service_id, 0, TYPE_CLOSE_SESSION_FAIL);
    }
    RemoveTidFromList(tidData);
    tidData = nullptr;

    PutBnSession(outSession); /* pair with open session */
    PutBnContextAndReleaseFd(pid, outContext);
    return TEEC_SUCCESS;
}

TEEC_Result CaDaemonService::RegisterSharedMemory(TEEC_Context *context,
    TEEC_SharedMemory *sharedMem, MessageParcel &reply)
{
    pid_t pid = IPCSkeleton::GetCallingPid();
    TEEC_Result ret = TEEC_FAIL;
    TEEC_SharedMemoryInner *outShm = nullptr;
    TEEC_ContextInner *outContext = nullptr;
    bool writeRet = false;

    if ((context == nullptr) || (sharedMem == nullptr)) {
        tloge("registeMem: invalid context or sharedMem\n");
        goto ERROR_END;
    }

    outContext = GetBnContext(context);
    if (outContext == nullptr) {
        tloge("registeMem: no context found in service!\n");
        ret = TEEC_ERROR_BAD_PARAMETERS;
        goto ERROR_END;
    }

    outShm = static_cast<TEEC_SharedMemoryInner *>(malloc(sizeof(TEEC_SharedMemoryInner)));
    if (outShm == nullptr) {
        tloge("registeMem: outShm malloc failed.\n");
        goto ERROR_END;
    }

    (void)memset_s(outShm, sizeof(TEEC_SharedMemoryInner), 0, sizeof(TEEC_SharedMemoryInner));

    if (memcpy_s(outShm, sizeof(*outShm), sharedMem, sizeof(*sharedMem))) {
        tloge("registeMem: memcpy failed when copy data to shm, errno = %" PUBLIC "d!\n", errno);
        free(outShm);
        PutBnContextAndReleaseFd(pid, outContext);
        goto ERROR_END;
    }

    ret = TEEC_RegisterSharedMemoryInner(outContext, outShm);
    if (ret != TEEC_SUCCESS) {
        free(outShm);
        PutBnContextAndReleaseFd(pid, outContext);
        goto ERROR_END;
    }

    PutBnShrMem(outShm);
    PutBnContextAndReleaseFd(pid, outContext);

    sharedMem->ops_cnt = outShm->ops_cnt;
    sharedMem->is_allocated = outShm->is_allocated;

    writeRet = reply.WriteInt32((int32_t)ret);
    CHECK_ERR_RETURN(writeRet, true, TEEC_FAIL);

    writeRet = WriteSharedMem(reply, sharedMem);
    CHECK_ERR_RETURN(writeRet, true, TEEC_FAIL);

    writeRet = reply.WriteUint32(outShm->offset);
    CHECK_ERR_RETURN(writeRet, true, TEEC_FAIL);

    return TEEC_SUCCESS;

ERROR_END:
    writeRet = reply.WriteInt32((int32_t)ret);
    CHECK_ERR_RETURN(writeRet, true, TEEC_FAIL);
    return TEEC_SUCCESS;
}

static bool RecAllocReply(TEEC_Result ret, TEEC_SharedMemory *sharedMem,
    uint32_t offset, int32_t fd, MessageParcel &reply)
{
    bool writeRet = reply.WriteInt32((int32_t)ret);
    CHECK_ERR_RETURN(writeRet, true, writeRet);

    writeRet = WriteSharedMem(reply, sharedMem);
    CHECK_ERR_RETURN(writeRet, true, writeRet);

    writeRet = reply.WriteUint32(offset);
    CHECK_ERR_RETURN(writeRet, true, writeRet);

    writeRet = reply.WriteFileDescriptor(fd);

    return writeRet;
}

TEEC_Result CaDaemonService::AllocateSharedMemory(TEEC_Context *context,
    TEEC_SharedMemory *sharedMem, MessageParcel &reply)
{
    TEEC_Result ret = TEEC_FAIL;
    bool writeRet = false;
    TEEC_ContextInner *outContext = nullptr;
    TEEC_SharedMemoryInner *outShm = nullptr;
    pid_t pid = IPCSkeleton::GetCallingPid();

    if ((context == nullptr) || (sharedMem == nullptr)) {
        tloge("allocateShamem: invalid context or sharedMem\n");
        goto ERROR;
    }

    outContext = GetBnContext(context);
    if (outContext == nullptr) {
        ret = TEEC_ERROR_BAD_PARAMETERS;
        goto ERROR;
    }

    outShm = (TEEC_SharedMemoryInner *)malloc(sizeof(TEEC_SharedMemoryInner));
    if (outShm == nullptr) {
        tloge("allocateShamem: outShm malloc failed\n");
        goto ERROR;
    }

    (void)memset_s(outShm, sizeof(*outShm), 0, sizeof(*outShm));
    (void)memcpy_s(outShm, sizeof(*outShm), sharedMem, sizeof(*sharedMem));

    ret = TEEC_AllocateSharedMemoryInner(outContext, outShm);
    if (ret != TEEC_SUCCESS) {
        goto ERROR;
    }

    sharedMem->ops_cnt = outShm->ops_cnt;
    sharedMem->is_allocated = outShm->is_allocated;

    writeRet = RecAllocReply(ret, sharedMem, outShm->offset, outContext->fd, reply);
    PutBnShrMem(outShm);
    PutBnContextAndReleaseFd(pid, outContext);
    if (!writeRet) {
        ListRemoveEntry(&outShm->head);
        PutBnShrMem(outShm);
        return TEEC_FAIL;
    }

    return TEEC_SUCCESS;

ERROR:
    if (outShm != nullptr) {
        free(outShm);
    }
    PutBnContextAndReleaseFd(pid, outContext);
    writeRet = reply.WriteInt32((int32_t)ret);
    CHECK_ERR_RETURN(writeRet, true, TEEC_FAIL);
    return TEEC_SUCCESS;
}

TEEC_Result CaDaemonService::ReleaseSharedMemory(TEEC_Context *context,
    TEEC_SharedMemory *sharedMem, uint32_t shmOffset, MessageParcel &reply)
{
    TEEC_ContextInner *outContext = nullptr;
    TEEC_SharedMemoryInner outShm;
    pid_t pid = IPCSkeleton::GetCallingPid();

    if ((context == nullptr) || (sharedMem == nullptr)) {
        tloge("releaseShamem: invalid context or sharedMem\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    outContext = GetBnContext(context);
    if (outContext == nullptr) {
        tloge("releaseShamem: no context found in service!\n");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    (void)memset_s(&outShm, sizeof(TEEC_SharedMemoryInner), 0, sizeof(TEEC_SharedMemoryInner));

    if (memcpy_s(&outShm, sizeof(outShm), sharedMem, sizeof(*sharedMem))) {
        tloge("releaseShamem: memcpy failed when copy data to shm, errno = %" PUBLIC "d!\n", errno);
        return TEEC_FAIL;
    }

    outShm.offset = shmOffset;
    outShm.context = outContext;

    TEEC_ReleaseSharedMemoryInner(&outShm);
    PutBnContextAndReleaseFd(pid, outContext);
    return TEEC_SUCCESS;
}

void CaDaemonService::PutAllocShrMem(TEEC_SharedMemoryInner *shmInner[], uint32_t shmNum)
{
    uint32_t paramCnt;
    for (paramCnt = 0; paramCnt < shmNum; paramCnt++) {
        if (shmInner[paramCnt] != nullptr) {
            PutBnShrMem(shmInner[paramCnt]);
        }
    }

    return;
}

int32_t CaDaemonService::SetCallBack(const sptr<IRemoteObject> &notify)
{
    if (notify == nullptr) {
        tloge("notify is nullptr\n");
        return ERR_UNKNOWN_OBJECT;
    }

    /* register CA dead notify */
    pid_t pid = IPCSkeleton::GetCallingPid();
    tloge("SetCallBack, ca pid=%" PUBLIC "d", pid);

    int32_t ret = AddClient(pid, notify);
    if (ret != 0) {
        tloge("client link to death failed, pid=%" PUBLIC "d", pid);
    }
    return ret;
}

int32_t CaDaemonService::AddClient(pid_t pid, const sptr<IRemoteObject> &notify)
{
    lock_guard<mutex> autoLock(mClientLock);
    size_t count = mClients.size();
    for (size_t index = 0; index < count; index++) {
        if (mClients[index]->GetMyPid() == pid) {
            tloge("client exist, pid=%" PUBLIC "d", pid);
            return ERR_NONE;
        }
    }

    sptr<Client> c = new (std::nothrow) Client(pid, notify, this);
    if (c == nullptr) {
        tloge("addclient:new client failed, pid=%" PUBLIC "d", pid);
        return ERR_UNKNOWN_REASON;
    }
    bool ret = notify->AddDeathRecipient(c);
    if (!ret) {
        tloge("addclient:link to death failed, pid=%" PUBLIC "d", pid);
        return ERR_UNKNOWN_REASON;
    }
    mClients.push_back(c);
    return ERR_NONE;
}

CaDaemonService::Client::~Client()
{
    tloge("delete client come in, pid=%" PUBLIC "d", mPid);
}

pid_t CaDaemonService::Client::GetMyPid() const
{
    return mPid;
}

void CaDaemonService::Client::OnRemoteDied(const wptr<IRemoteObject> &deathNotify)
{
    (void)deathNotify;
    tloge("teec client is died, pid=%" PUBLIC "d", mPid);
    vector<sptr<Client>>::iterator vec;
    if (mService != nullptr) {
        size_t index = 0;
        lock_guard<mutex> autoLock(mService->mClientLock);
        for (vec = mService->mClients.begin(); vec != mService->mClients.end();) {
            if (mService->mClients[index]->GetMyPid() == mPid) {
                tloge("died teec client found, pid=%" PUBLIC "d", mPid);
                /* release resources */
                mService->ProcessCaDied(mPid);
                vec = mService->mClients.erase(vec);
            } else {
                ++vec;
                index++;
            }
        }
    }
}

void CaDaemonService::CleanProcDataForOneCa(DaemonProcdata *procData)
{
    for (int i = 0; i < MAX_CXTCNT_ONECA; i++) {
        if (procData->cxtFd[i] == -1) {
            continue;
        }

        TEEC_Context context;
        context.fd = procData->cxtFd[i];
        procData->cxtFd[i] = -1;

        TEEC_ContextInner *outContext = FindAndRemoveBnContext(&context);
        if (outContext == nullptr) {
            tloge("no context found in service!\n");
            continue;
        }
        (void)PutBnContext(outContext); /* pair with initialize context */
    }
}

void CaDaemonService::ProcessCaDied(int32_t pid)
{
    tloge("caDied: getCallingPid=%" PUBLIC "d\n", pid);
    DaemonProcdata *outProcData = nullptr;
    {
        lock_guard<mutex> autoLock(mProcDataLock);
        outProcData = GetProcdataByPid(pid);
        if (outProcData == nullptr) {
            tloge("caDied: outProcdata[%" PUBLIC "d] not in the list\n", pid);
            return;
        }
        ListRemoveEntry(&outProcData->procdataHead);
    }

    SendSigToTzdriver(pid);
    CleanProcDataForOneCa(outProcData);
    free(outProcData);
}

TEEC_Result CaDaemonService::SendSecfile(const char *path, int fd, FILE *fp, MessageParcel &reply)
{
    if (path == nullptr || fp == nullptr) {
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    uint32_t ret = TEEC_SendSecfileInner(path, fd, fp);
    bool retTmp = reply.WriteUint32(ret);
    CHECK_ERR_RETURN(retTmp, true, TEEC_FAIL);
    return TEEC_SUCCESS;
}

TEEC_Result CaDaemonService::GetTeeVersion(MessageParcel &reply)
{
    bool retTmp = reply.WriteUint32(mTeeVersion);
    CHECK_ERR_RETURN(retTmp, true, TEEC_FAIL);
    return TEEC_SUCCESS;
}
} // namespace CaDaemon
} // namespace OHOS
