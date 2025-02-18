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

#include "libteecvendorclosesession_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "tee_client_api.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"
#include "tee_client_inner.h"
#include "tee_client_inner_api.h"

namespace OHOS {
    bool LibteecVendorCloseSessionFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size >= sizeof(TEEC_Context) + sizeof(TEEC_Session)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            TEEC_Context context = *reinterpret_cast<TEEC_Context *>(temp);
            temp += sizeof(TEEC_Context);
            TEEC_Session session = *reinterpret_cast<TEEC_Session *>(temp);
            session.context = &context;

            (void)TEEC_CloseSession(&session);
        }
        return result;
    }
    void TEEC_CloseSessionInnerTest_001(const uint8_t *data, size_t size)
    {
        TEEC_Session session = { 0 };
        TEEC_ContextInner contextInner = { 0 };

        TEEC_CloseSessionInner(NULL, NULL);
        TEEC_CloseSessionInner(&session, NULL);

        TEEC_Context context = { 0 };
        TEEC_Result result = TEEC_InitializeContext(NULL, &context);
        TEEC_CloseSessionInner(&session, &contextInner);
        (void)data;
        (void)size;
        (void)result;
    }
    void TEEC_CloseSessionTest_001(const uint8_t *data, size_t size)
    {
        TEEC_Session session = { 0 };

        TEEC_CloseSession(NULL);

        session.context = NULL;
        TEEC_CloseSession(&session);
        (void)data;
        (void)size;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::LibteecVendorCloseSessionFuzzTest(data, size);
    OHOS::TEEC_CloseSessionInnerTest_001(data, size);
    OHOS::TEEC_CloseSessionTest_001(data, size);
    return 0;
}