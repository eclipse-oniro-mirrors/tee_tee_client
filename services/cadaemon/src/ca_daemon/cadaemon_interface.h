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

#ifndef CA_DAEMON_INTERFACE_H
#define CA_DAEMON_INTERFACE_H

#include <cstdint>
#include <cstdio>
#include "ipc_types.h"
#include "iremote_broker.h"
#include "tee_client_type.h"

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

namespace OHOS {
namespace CaDaemon {
class CaDaemon : public OHOS::IRemoteBroker {
public:
    virtual TEEC_Result InitializeContext(const char *name, MessageParcel &reply) = 0;
    virtual TEEC_Result FinalizeContext(TEEC_Context *context) = 0;
    virtual TEEC_Result OpenSession(TEEC_Context *context, const char *taPath, int32_t fd,
        const TEEC_UUID *destination, uint32_t connectionMethod,
        TEEC_Operation *operation, uint32_t optMemSize, sptr<Ashmem> &optMem, MessageParcel &reply) = 0;
    virtual TEEC_Result CloseSession(TEEC_Session *session, TEEC_Context *context) = 0;
    virtual TEEC_Result InvokeCommand(TEEC_Context *context, TEEC_Session *session, uint32_t commandID,
        TEEC_Operation *operation, uint32_t optMemSize, sptr<Ashmem> &optMem, MessageParcel &reply) = 0;
    virtual TEEC_Result RegisterSharedMemory(TEEC_Context *context,
        TEEC_SharedMemory *sharedMem, MessageParcel &reply) = 0;
    virtual TEEC_Result AllocateSharedMemory(TEEC_Context *context,
        TEEC_SharedMemory *sharedMem, MessageParcel &reply) = 0;
    virtual TEEC_Result ReleaseSharedMemory(TEEC_Context *context,
        TEEC_SharedMemory *sharedMem, uint32_t shmOffset, MessageParcel &reply) = 0;
    virtual int32_t SetCallBack(const sptr<IRemoteObject> &notify) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.CaDaemon.CaDaemon");
};
} // namespace CaDaemon
} // namespace OHOS
#endif
