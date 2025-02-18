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

#include "libteecvendorinitializecontext_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include "tee_client_api.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"
#include "tee_client_inner_api.h"

namespace OHOS {
    bool LibteecVendorInitializeContextFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size >= sizeof(TEEC_Context)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            TEEC_Context context = *reinterpret_cast<TEEC_Context *>(temp);
            temp += sizeof(TEEC_Context);
            std::string name(reinterpret_cast<const char *>(temp), size - sizeof(TEEC_Context));

            TEEC_Result ret = TEEC_InitializeContext(name.c_str(), &context);
            if (ret == TEEC_SUCCESS) {
                TEEC_FinalizeContext(&context);
            }
        }
        return result;
    }

    void SetBitFuzzTest_001(const uint8_t *data, size_t size)
    {
        uint32_t i = 0, byteMax = 0;
        uint8_t bitMap = 0;

        SetBit(i, byteMax, NULL);

        byteMax = 1;
        SetBit(i, byteMax, NULL);

        SetBit(i, byteMax, &bitMap);

        (void)data;
        (void)size;
    }

    void CheckBitFuzzTest_001(const uint8_t *data, size_t size)
    {
        uint32_t i = 0, byteMax = 0;
        uint8_t bitMap = 0;

        CheckBit(i, byteMax, NULL);

        byteMax = 1;
        CheckBit(i, byteMax, NULL);

        CheckBit(i, byteMax, &bitMap);
        (void)data;
        (void)size;
    }

    void ClearBitFuzzTest_001(const uint8_t *data, size_t size)
    {
        uint32_t i = 0, byteMax = 0;
        uint8_t bitMap = 0;

        ClearBit(i, byteMax, NULL);

        byteMax = 1;
        ClearBit(i, byteMax, NULL);

        ClearBit(i, byteMax, &bitMap);
        (void)data;
        (void)size;
    }

    void GetAndSetBitFuzzTest_001(const uint8_t *data, size_t size)
    {
        uint8_t bitMap[1] = { 0 };
        uint32_t byteMax = 0;

        GetAndSetBit(NULL, byteMax);

        byteMax = 1;
        GetAndSetBit(bitMap, byteMax);

        bitMap[0] = 0xff;
        GetAndSetBit(bitMap, byteMax);
        (void)data;
        (void)size;
    }

    void GetAndCleartBitFuzzTest_001(const uint8_t *data, size_t size)
    {
        uint8_t bitMap[1] = { 0 };
        uint32_t byteMax = 0;

        GetAndCleartBit(NULL, byteMax);

        byteMax = 1;
        GetAndCleartBit(bitMap, byteMax);

        bitMap[0] = 0xff;
        GetAndCleartBit(bitMap, byteMax);
        (void)data;
        (void)size;
    }

    void GetBnSessionFuzzTest_001(const uint8_t *data, size_t size)
    {
        TEEC_Session session = { 0 };
        TEEC_ContextInner context = { 0 };

        GetBnSession(NULL, &context);
        GetBnSession(&session, NULL);
        (void)data;
        (void)size;
    }

    void PutBnSessionTest_001(void)
    {
        PutBnSession(NULL);
    }

    void PutBnShrMemTest_001(void)
    {
        PutBnShrMem(NULL);
    }

    void GetBnShmByOffsetTest_001(void)
    {
        GetBnShmByOffset(0, NULL);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::LibteecVendorInitializeContextFuzzTest(data, size);
    OHOS::SetBitFuzzTest_001(data, size);
    OHOS::CheckBitFuzzTest_001(data, size);
    OHOS::ClearBitFuzzTest_001(data, size);
    OHOS::GetAndSetBitFuzzTest_001(data, size);
    OHOS::GetAndCleartBitFuzzTest_001(data, size);
    OHOS::GetBnSessionFuzzTest_001(data, size);
    OHOS::PutBnSessionTest_001();
    OHOS::PutBnShrMemTest_001();
    OHOS::GetBnShmByOffsetTest_001();

    return 0;
}