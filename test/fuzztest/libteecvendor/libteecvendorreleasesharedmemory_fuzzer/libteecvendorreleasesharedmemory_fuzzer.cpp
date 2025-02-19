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

#include "libteecvendorreleasesharedmemory_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "tee_client_api.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"
#include "tee_client_inner_api.h"

namespace OHOS {
    bool LibteecVendorReleaseSharedMemoryFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size > sizeof(TEEC_Context) + sizeof(TEEC_SharedMemory)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            TEEC_Context context = *reinterpret_cast<TEEC_Context *>(temp);
            temp += sizeof(TEEC_Context);
            TEEC_SharedMemory memory = *reinterpret_cast<TEEC_SharedMemory *>(temp);
            memory.context = &context;
            TEEC_ReleaseSharedMemory(&memory);
        }
        return result;
    }

    void TEEC_ReleaseSharedMemoryInnerTest_001(const uint8_t *data, size_t size)
    {
        TEEC_ReleaseSharedMemoryInner(NULL);

        TEEC_SharedMemoryInner sharedMem = { 0 };
        sharedMem.context = NULL;
        TEEC_ReleaseSharedMemoryInner(&sharedMem);
        (void)data;
        (void)size;
    }

    void TEEC_ReleaseSharedMemoryTest_001(const uint8_t *data, size_t size)
    {
        TEEC_Context context = { 0 };
        TEEC_SharedMemory sharedMem = { 0 };

        TEEC_InitializeContext(NULL, &context);

        char buf[4] = { 0 };
        sharedMem.buffer = buf;
        sharedMem.size = 4; // 4 size of memory
        sharedMem.flags = TEEC_MEM_INPUT;
        TEEC_RegisterSharedMemory(&context, &sharedMem);

        TEEC_ReleaseSharedMemory(&sharedMem);

        (void)data;
        (void)size;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::LibteecVendorReleaseSharedMemoryFuzzTest(data, size);
    OHOS::TEEC_ReleaseSharedMemoryInnerTest_001(data, size);
    OHOS::TEEC_ReleaseSharedMemoryTest_001(data, size);
    return 0;
}