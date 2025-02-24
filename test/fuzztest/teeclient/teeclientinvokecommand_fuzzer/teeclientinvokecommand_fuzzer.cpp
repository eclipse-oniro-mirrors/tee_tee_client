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

#include "teeclientinvokecommand_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <malloc.h>
#include <map>
#include "tee_client_api.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"

#define MAX_PARAM_COUNT 4

#define IS_TEMP_MEM(paramType)                                                              \
    (((paramType) == TEEC_MEMREF_TEMP_INPUT) || ((paramType) == TEEC_MEMREF_TEMP_OUTPUT) || \
     ((paramType) == TEEC_MEMREF_TEMP_INOUT))

#define IS_PARTIAL_MEM(paramType)                                                        \
    (((paramType) == TEEC_MEMREF_WHOLE) || ((paramType) == TEEC_MEMREF_PARTIAL_INPUT) || \
     ((paramType) == TEEC_MEMREF_PARTIAL_OUTPUT) || ((paramType) == TEEC_MEMREF_PARTIAL_INOUT))

namespace OHOS {
    std::map<int, int> g_recordShareMemory;
    uint32_t g_paramType[TEEC_PARAM_NUM];
    uint32_t g_shareMemoryCnt = 0;

    void InitTeecParam(uint8_t *temp, TEEC_Parameter (&param)[4], TEEC_Operation &operation,
                       TEEC_SharedMemory (&memory)[4], TEEC_Context context)
    {
        for (uint32_t paramCnt = 0; paramCnt < TEEC_PARAM_NUM; paramCnt++) {
            param[paramCnt] = *reinterpret_cast<TEEC_Parameter *>(temp);
            temp += sizeof(TEEC_Parameter);
            g_paramType[paramCnt] = TEEC_PARAM_TYPE_GET(operation.paramTypes, paramCnt);
            if (IS_TEMP_MEM(g_paramType[paramCnt])) {
                if (param[paramCnt].tmpref.size > 0) {
                    param[paramCnt].tmpref.buffer = malloc(param[paramCnt].tmpref.size);
                }
            } else if (IS_PARTIAL_MEM(g_paramType[paramCnt])) {
                memory[g_shareMemoryCnt] = *reinterpret_cast<TEEC_SharedMemory *>(temp);
                temp += sizeof(TEEC_SharedMemory);
                TEEC_Result allocRet = TEEC_AllocateSharedMemory(&context, &memory[g_shareMemoryCnt]);
                if (allocRet == TEEC_SUCCESS) {
                    g_recordShareMemory[g_shareMemoryCnt] = paramCnt;
                    param[paramCnt].memref.parent = &memory[g_shareMemoryCnt];
                    g_shareMemoryCnt++;
                } else {
                    param[paramCnt].memref.parent = nullptr;
                }
            }
        }
    }

    void ReleaseTeecParam(TEEC_Parameter (&param)[4], TEEC_SharedMemory (&memory)[4])
    {
        g_shareMemoryCnt = 0;
        for (uint32_t paramCnt = 0; paramCnt < TEEC_PARAM_NUM; paramCnt++) {
            if (IS_TEMP_MEM(g_paramType[paramCnt])) {
                if (param[paramCnt].tmpref.size > 0 && param[paramCnt].tmpref.buffer != nullptr) {
                    free(param[paramCnt].tmpref.buffer);
                    param[paramCnt].tmpref.buffer = nullptr;
                }
            } else if (IS_PARTIAL_MEM(g_paramType[paramCnt]) && g_recordShareMemory[g_shareMemoryCnt] == paramCnt) {
                TEEC_ReleaseSharedMemory(&memory[g_shareMemoryCnt]);
                g_shareMemoryCnt++;
            }
        }
    }

    bool TeeClientInvokeCommandFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size > sizeof(TEEC_Session) + sizeof(uint32_t) + sizeof(TEEC_Operation) + sizeof(uint32_t) +
            sizeof(TEEC_Context) + sizeof(TEEC_Parameter) * MAX_PARAM_COUNT +
            sizeof(TEEC_SharedMemory) * MAX_PARAM_COUNT) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            TEEC_Session session = *reinterpret_cast<TEEC_Session *>(temp);
            temp += sizeof(TEEC_Session);
            uint32_t commandID = *reinterpret_cast<uint32_t *>(temp);
            temp += sizeof(uint32_t);
            TEEC_Operation operation = *reinterpret_cast<TEEC_Operation *>(temp);
            temp += sizeof(TEEC_Operation);
            uint32_t returnOrigin = *reinterpret_cast<uint32_t *>(temp);
            temp += sizeof(uint32_t);
            TEEC_Context context = *reinterpret_cast<TEEC_Context *>(temp);
            temp += sizeof(TEEC_Context);
            TEEC_Parameter param[4];
            TEEC_SharedMemory memory[4];
            InitTeecParam(temp, param, operation, memory, context);

            session.context = &context;
            operation.params[0] = param[0];
            operation.params[1] = param[1];
            operation.params[2] = param[2];
            operation.params[3] = param[3];
            operation.session = &session;

            (void)TEEC_InvokeCommand(&session, commandID, &operation, &returnOrigin);

            ReleaseTeecParam(param, memory);
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::TeeClientInvokeCommandFuzzTest(data, size);
    return 0;
}