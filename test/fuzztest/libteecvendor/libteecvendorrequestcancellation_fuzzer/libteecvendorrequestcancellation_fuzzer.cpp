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

#include "libteecvendorrequestcancellation_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <malloc.h>
#include <string>
#include "tee_client_api.h"
#include "tee_client_ext_api.h"
#include "tee_client_inner_api.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"
#include "tee_client_app_load.h"
#include "load_sec_file.h"

namespace OHOS {
    bool LibteecVendorRequestCancellationFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size > sizeof(TEEC_Session) + sizeof(TEEC_Operation) + sizeof(TEEC_Context) +
            sizeof(TEEC_Parameter) + sizeof(TEEC_SharedMemory)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            TEEC_Session session = *reinterpret_cast<TEEC_Session *>(temp);
            temp += sizeof(TEEC_Session);
            TEEC_Operation operation = *reinterpret_cast<TEEC_Operation *>(temp);
            temp += sizeof(TEEC_Operation);
            TEEC_Context context = *reinterpret_cast<TEEC_Context *>(temp);
            temp += sizeof(TEEC_Context);
            TEEC_Parameter param = *reinterpret_cast<TEEC_Parameter *>(temp);
            temp += sizeof(TEEC_Parameter);
            TEEC_SharedMemory memory = *reinterpret_cast<TEEC_SharedMemory *>(temp);

            TEEC_Result ret = TEEC_AllocateSharedMemory(&context, &memory);
            if (ret != TEEC_SUCCESS) {
                return result;
            }
            if (param.tmpref.size > 0) {
                param.tmpref.buffer = malloc(param.tmpref.size);
                if (param.tmpref.buffer == nullptr) {
                    return result;
                }
            }

            session.context = &context;
            param.memref.parent = &memory;
            operation.params[0] = param;
            operation.params[1] = param;
            operation.params[2] = param;
            operation.params[3] = param;
            operation.session = &session;

            (void)TEEC_RequestCancellation(&operation);

            if (param.tmpref.size > 0 && param.tmpref.buffer != nullptr) {
                free(param.tmpref.buffer);
                param.tmpref.buffer = nullptr;
            }
            TEEC_ReleaseSharedMemory(&memory);
        }
        return result;
    }
    void TEEC_RequestCancellationTest_001(const uint8_t *data, size_t size)
    {
        (void)data;
        (void)size;
        TEEC_Operation operation = { 0 };

        TEEC_RequestCancellation(nullptr);

        operation.session = nullptr;
        TEEC_RequestCancellation(&operation);

        TEEC_Session session = { 0 };
        operation.session = &session;
        session.context = nullptr;
        TEEC_RequestCancellation(&operation);

        TEEC_Context context = { 0 };
        TEEC_Result result = TEEC_InitializeContext(nullptr, &context);
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        TEEC_UUID uuid = { 0xabe89147, 0xcd61, 0xf43f, { 0x71, 0xc4, 0x1a, 0x31, 0x7e, 0x40, 0x53, 0x12 } };
        result = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, nullptr);

        TEEC_RequestCancellation(&operation);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::LibteecVendorRequestCancellationFuzzTest(data, size);
    OHOS::TEEC_RequestCancellationTest_001(data, size);
    return 0;
}