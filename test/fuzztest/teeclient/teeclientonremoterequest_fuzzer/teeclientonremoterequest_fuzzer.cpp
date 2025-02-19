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

#include "teeclientonremoterequest_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "tee_client_api.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"
#include "cadaemon_stub.h"
#include "message_parcel.h"
#include "securec.h"
#include "cadaemon_service.h"
#include "cadaemon_ipc_interface_code.h"

namespace OHOS {
    namespace CaDaemon {
        constexpr size_t FOO_MAX_LEN = 1024;
        constexpr size_t U32_AT_SIZE = 4;
        const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.tee_client.accessToken";

        bool TeeClientOnRemoteRequestFuzzTest(const uint8_t *data, size_t size)
        {
            MessageParcel datas;
            datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
            datas.WriteBuffer(data, size);
            datas.RewindRead(0);
            MessageParcel *reply = new MessageParcel();
            MessageOption option;
            CaDaemonService *tmp = new CaDaemonService(1, 0);
            tmp->CaDaemonStub::OnRemoteRequest(static_cast<uint32_t>(CadaemonOperationInterfaceCode::INIT_CONTEXT),
                                               datas, *reply, option);
            tmp->CaDaemonStub::OnRemoteRequest(static_cast<uint32_t>(CadaemonOperationInterfaceCode::FINAL_CONTEXT),
                                               datas, *reply, option);
            tmp->CaDaemonStub::OnRemoteRequest(static_cast<uint32_t>(CadaemonOperationInterfaceCode::OPEN_SESSION),
                                               datas, *reply, option);
            tmp->CaDaemonStub::OnRemoteRequest(static_cast<uint32_t>(CadaemonOperationInterfaceCode::CLOSE_SESSION),
                                               datas, *reply, option);
            tmp->CaDaemonStub::OnRemoteRequest(static_cast<uint32_t>(CadaemonOperationInterfaceCode::INVOKE_COMMND),
                                               datas, *reply, option);
            tmp->CaDaemonStub::OnRemoteRequest(static_cast<uint32_t>(CadaemonOperationInterfaceCode::REGISTER_MEM),
                                               datas, *reply, option);
            tmp->CaDaemonStub::OnRemoteRequest(static_cast<uint32_t>(CadaemonOperationInterfaceCode::ALLOC_MEM),
                                               datas, *reply, option);
            tmp->CaDaemonStub::OnRemoteRequest(static_cast<uint32_t>(CadaemonOperationInterfaceCode::RELEASE_MEM),
                                               datas, *reply, option);
            tmp->CaDaemonStub::OnRemoteRequest(static_cast<uint32_t>(CadaemonOperationInterfaceCode::SET_CALL_BACK),
                                               datas, *reply, option);
            tmp->CaDaemonStub::OnRemoteRequest(static_cast<uint32_t>(CadaemonOperationInterfaceCode::SEND_SECFILE),
                                               datas, *reply, option);
            tmp->CaDaemonStub::OnRemoteRequest(static_cast<uint32_t>(CadaemonOperationInterfaceCode::GET_TEE_VERSION),
                                               datas, *reply, option);
            delete (tmp);
            delete (reply);
            return true;
        }
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    tloge("begin LLVMFuzzerTestOneInput\n");
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::CaDaemon::U32_AT_SIZE) {
        return 0;
    }

    /* Validate the length of size */
    if (size == 0 || size > OHOS::CaDaemon::FOO_MAX_LEN) {
        return 0;
    }

    uint8_t *ch = static_cast<uint8_t *>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }
    /* Run your code on data */
    OHOS::CaDaemon::TeeClientOnRemoteRequestFuzzTest(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}