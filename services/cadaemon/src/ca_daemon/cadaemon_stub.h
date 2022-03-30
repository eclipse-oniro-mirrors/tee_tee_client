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

#ifndef CA_DAEMON_STUB_H
#define CA_DAEMON_STUB_H

#include <cstdint>
#include <cstdio>
#include <map>
#include "cadaemon_interface.h"
#include "iremote_stub.h"

namespace OHOS {
namespace CaDaemon {
class CaDaemonStub : public IRemoteStub<CaDaemon> {
public:
    CaDaemonStub();
    virtual ~CaDaemonStub();
    int32_t OnRemoteRequest(uint32_t code,
        MessageParcel& data, MessageParcel &reply, MessageOption &option) override;
private:
    int32_t InitContextRecvProc(MessageParcel &data, MessageParcel &reply);
    int32_t FinalContextRecvProc(MessageParcel &data, MessageParcel &reply);
    int32_t OpenSessionRecvProc(MessageParcel &data, MessageParcel &reply);
    int32_t CloseSessionRecvProc(MessageParcel &data, MessageParcel &reply);
    int32_t InvokeCommandRecvProc(MessageParcel &data, MessageParcel &reply);
    int32_t RegisterMemRecvProc(MessageParcel &data, MessageParcel &reply);
    int32_t AllocMemRecvProc(MessageParcel &data, MessageParcel &reply);
    int32_t ReleaseMemRecvProc(MessageParcel &data, MessageParcel &reply);
    int32_t SetCallBackRecvProc(MessageParcel &data, MessageParcel &reply);
    bool EnforceInterceToken(MessageParcel& data);
    using CaDaemonFunc = int32_t (CaDaemonStub::*)(MessageParcel& data, MessageParcel& reply);
    std::map<uint32_t, CaDaemonFunc> memberFuncMap_;
};
} // namespace CaDaemon
} // namespace OHOS
#endif
