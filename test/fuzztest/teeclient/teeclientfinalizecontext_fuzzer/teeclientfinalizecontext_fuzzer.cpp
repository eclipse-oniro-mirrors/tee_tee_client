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

#include "teeclientfinalizecontext_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "tee_client_api.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"

namespace OHOS {
    bool TeeClientFinalizeContextFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size >= sizeof(TEEC_Context)) {
            TEEC_Context context = *reinterpret_cast<TEEC_Context *>(const_cast<uint8_t *>(data));
            (void)TEEC_FinalizeContext(&context);
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::TeeClientFinalizeContextFuzzTest(data, size);
    return 0;
}