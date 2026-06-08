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
#include <cstdlib>
#include <string>
#include "securec.h"
#include "tee_client_api.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"
#include "tee_client_inner_api.h"
#include "fuzzer/FuzzedDataProvider.h"

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
        if (size < sizeof(uint32_t) + sizeof(uint32_t)) {
            return;
        }

        // 1. 从随机数据流中拆出参数 i
        uint32_t i = 0;
        uint32_t byteMax = 0;

        uint8_t *bitMap = nullptr;
        SetBit(i, byteMax, bitMap);
        CheckBit(i, byteMax, bitMap);
        ClearBit(i, byteMax, bitMap);

        memcpy_s(&i, sizeof(i), data, sizeof(uint32_t));
        memcpy_s(&byteMax, sizeof(byteMax), data + sizeof(uint32_t), sizeof(uint32_t));
        uint32_t safeSize = (byteMax > 1024) ? 1024 : byteMax;
        if (safeSize == 0) {
            safeSize = 1;
        }
        bitMap = (uint8_t *)calloc(safeSize, sizeof(uint8_t));
        if (bitMap == nullptr) {
            return;
        }

        SetBit(i, byteMax, bitMap);
        CheckBit(i, byteMax, bitMap);
        ClearBit(i, byteMax, bitMap);
        CheckBit(i, byteMax, bitMap);

        free(bitMap);
        bitMap = nullptr;
        i = 0;
        byteMax = 1;
        SetBit(i, byteMax, bitMap);
        CheckBit(i, byteMax, bitMap);
        ClearBit(i, byteMax, bitMap);
        CheckBit(i, byteMax, bitMap);
    }

    void GetAndSetBitFuzzTest_001(const uint8_t *data, size_t size)
    {
        if (size < sizeof(uint32_t)) {
            return;
        }

        uint32_t byteMax;
        memcpy_s(&byteMax, sizeof(byteMax), data, sizeof(uint32_t));

        size_t remainingSize = size - sizeof(uint32_t);

        uint32_t safeSize = (byteMax > 1024) ? 1024 : byteMax;
        if (safeSize == 0) {
            safeSize = 1;
        }

        uint8_t *bitMap = (uint8_t *)calloc(safeSize, sizeof(uint8_t));
        if (bitMap == nullptr) {
            return;
        }

        size_t fillSize = (remainingSize > safeSize) ? safeSize : remainingSize;
        if (fillSize > 0) {
            memcpy_s(bitMap, safeSize, data + sizeof(uint32_t), fillSize);
        }

        uint8_t *testMap = (size % 10 == 0) ? nullptr : bitMap;

        int32_t index = GetAndSetBit(testMap, byteMax);
        index = GetAndCleartBit(testMap, byteMax);
        byteMax = 1;
        bitMap[0] = 0xff;
        GetAndSetBit(testMap, byteMax);
        GetAndCleartBit(testMap, byteMax);
        free(bitMap);
        bitMap = nullptr;
        testMap = nullptr;
        return;
    }

    void GetBnSessionFuzzTest_001(const uint8_t *data, size_t size)
    {
        if (size < sizeof(uint32_t)) {
            return;
        }

        TEEC_Session session = { 0 };
        TEEC_ContextInner context = { 0 };
        TEEC_SharedMemoryInner shrMem = { 0 };
        uint32_t shmOffset = 0;
        GetBnSession(nullptr, &context);
        GetBnSession(&session, nullptr);
        PutBnShrMem(nullptr);
        GetBnShmByOffset(0, nullptr);

        ListInit(&context.session_list);
        ListInit(&context.shrd_mem_list);

        FuzzedDataProvider provider(data, size);
        session.session_id = provider.ConsumeIntegral<uint32_t>();
        session.ops_cnt = provider.ConsumeIntegral<uint32_t>();
        shrMem.ops_cnt = provider.ConsumeIntegral<uint32_t>();
        shmOffset = provider.ConsumeIntegral<uint32_t>();

        GetBnSession(&session, &context);
        PutBnSession(&session);
        PutBnShrMem(&shrMem);
        GetBnShmByOffset(shmOffset, &context);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::LibteecVendorInitializeContextFuzzTest(data, size);
    OHOS::SetBitFuzzTest_001(data, size);
    OHOS::GetAndSetBitFuzzTest_001(data, size);
    OHOS::GetBnSessionFuzzTest_001(data, size);

    return 0;
}