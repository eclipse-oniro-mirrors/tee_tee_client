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

#include "teeclientopensession_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "tee_client_api.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"

namespace OHOS {
    bool TeeClientOpenSessionFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size > sizeof(TEEC_Context) + sizeof(TEEC_Session) + sizeof(TEEC_UUID) + sizeof(uint32_t) +
            sizeof(TEEC_Operation) + sizeof(uint32_t) + sizeof(TEEC_Parameter) + sizeof(TEEC_SharedMemory)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            TEEC_Context context = *reinterpret_cast<TEEC_Context *>(temp);
            temp += sizeof(TEEC_Context);
            TEEC_Session session = *reinterpret_cast<TEEC_Session *>(temp);
            temp += sizeof(TEEC_Session);
            TEEC_UUID uuid = *reinterpret_cast<TEEC_UUID *>(temp);
            temp += sizeof(TEEC_UUID);
            uint32_t connectionMethod = *reinterpret_cast<uint32_t *>(temp);
            temp += sizeof(uint32_t);
            TEEC_Operation operation = *reinterpret_cast<TEEC_Operation *>(temp);
            temp += sizeof(TEEC_Operation);
            uint32_t returnOrigin = *reinterpret_cast<uint32_t *>(temp);
            temp += sizeof(uint32_t);

            TEEC_Parameter param = *reinterpret_cast<TEEC_Parameter *>(temp);
            temp += sizeof(TEEC_Parameter);
            TEEC_SharedMemory memory = *reinterpret_cast<TEEC_SharedMemory *>(temp);
            temp += sizeof(TEEC_SharedMemory);
            memory.context = &context;
            param.memref.parent = &memory;
            operation.params[0] = param;
            operation.params[1] = param;
            operation.params[2] = param;
            operation.params[3] = param;
            operation.session = &session;

            TEEC_Result ret = TEEC_OpenSession(&context, &session, &uuid, connectionMethod,
                reinterpret_cast<const char *>(temp), &operation, &returnOrigin);
            if (ret == TEEC_SUCCESS) {
                TEEC_CloseSession(&session);
            }
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::TeeClientOpenSessionFuzzTest(data, size);
    return 0;
}