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

#include "teeclientinitializecontext_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include "tee_client_api.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"

namespace OHOS {
    bool TeeClientInitializeContextFuzzTest(const uint8_t *data, size_t size)
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
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::TeeClientInitializeContextFuzzTest(data, size);
    return 0;
}