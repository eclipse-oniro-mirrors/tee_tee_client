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

#include "teeclientrequestcancellation_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "tee_client_api.h"
#include "tee_client_inner_api.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"

namespace OHOS {
    bool TeeClientRequestCancellationFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size > sizeof(TEEC_Operation)) {
            TEEC_Operation operation = *reinterpret_cast<TEEC_Operation *>(const_cast<uint8_t *>(data));
            (void)TEEC_RequestCancellation(&operation);
        }
        return result;
    }

    void TEEC_RequestCancellationTest_001(const uint8_t *data, size_t size)
    {
        (void)data;
        (void)size;
        TEEC_Operation operation = { 0 };

        GetBnShmByOffset(0, nullptr);
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
    OHOS::TeeClientRequestCancellationFuzzTest(data, size);
    OHOS::TEEC_RequestCancellationTest_001(data, size);
    return 0;
}