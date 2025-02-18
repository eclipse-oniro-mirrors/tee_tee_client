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

#include "libteecvendoropensession_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "tee_client_api.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"
#include "tee_client_inner.h"
#include "tee_client_inner_api.h"

namespace OHOS {
    bool LibteecVendorOpenSessionFuzzTest(const uint8_t *data, size_t size)
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

    void TEEC_OpenSessionTest_001(const uint8_t *data, size_t size)
    {
        TEEC_Context context = { 0 };
        TEEC_Session session = { 0 };
        TEEC_UUID uuid = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f } };

        TEEC_Result ret = TEEC_OpenSession(NULL, NULL, NULL, TEEC_LOGIN_IDENTIFY, NULL, NULL, NULL);

        ret = TEEC_OpenSession(&context, NULL, NULL, TEEC_LOGIN_IDENTIFY, NULL, NULL, NULL);

        ret = TEEC_OpenSession(&context, &session, NULL, TEEC_LOGIN_IDENTIFY, NULL, NULL, NULL);

        ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, NULL, NULL, NULL);
        if (ret == TEEC_SUCCESS) {
            TEEC_CloseSession(&session);
        }
        (void)data;
        (void)size;
    }

    void TEEC_OpenSessionInnerTest_001(const uint8_t *data, size_t size)
    {
        int callingPid = 0;
        TaFileInfo taFile;
        taFile.taFp = NULL;
        char path[] = "/vendor/bin/95b9ad1e-0af8-4201-9891-0dbe8602f35f.sec";
        taFile.taPath = (uint8_t *)path;

        TEEC_ContextInner contextInner = { 0 };
        TEEC_Session session = { 0 };
        TEEC_UUID destination = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f } };
        TEEC_Operation operation = { 0 };
        uint32_t retOrigin = 0;

        TEEC_Result ret = TEEC_OpenSessionInner(callingPid, &taFile, NULL, &session, &destination,
            TEEC_LOGIN_IDENTIFY, NULL, &operation, &retOrigin);

        ret = TEEC_OpenSessionInner(callingPid, NULL, &contextInner, &session, &destination,
            TEEC_LOGIN_IDENTIFY, NULL, &operation, &retOrigin);

        ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, NULL, &destination,
            TEEC_LOGIN_IDENTIFY, NULL, &operation, &retOrigin);

        ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, NULL,
            TEEC_LOGIN_IDENTIFY, NULL, &operation, &retOrigin);

        ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
            ~TEEC_LOGIN_IDENTIFY, NULL, &operation, &retOrigin);

        ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
            TEEC_LOGIN_IDENTIFY, (void *)&callingPid, &operation, &retOrigin);

        operation.started = 0;
        ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
            TEEC_LOGIN_IDENTIFY, NULL, NULL, &retOrigin);

        operation.started = 0;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
            TEEC_LOGIN_IDENTIFY, NULL, &operation, &retOrigin);
        if (ret == TEEC_SUCCESS) {
            TEEC_CloseSession(&session);
        }
        (void)data;
        (void)size;
    }

    void TEEC_OpenSessionInnerTest_002(const uint8_t *data, size_t size)
    {
        int callingPid = 0;
        uint32_t retOrigin = 0;
        TaFileInfo taFile;
        taFile.taFp = NULL;
        char path[] = "/vendor/bin/95b9ad1e-0af8-4201-9891-0dbe8602f35f";
        taFile.taPath = (uint8_t *)path;

        TEEC_ContextInner contextInner = { 0 };
        TEEC_Session session = { 0 };
        TEEC_UUID destination = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f } };

        TEEC_Result ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
            TEEC_LOGIN_IDENTIFY, NULL, NULL, &retOrigin);
        if (ret == TEEC_SUCCESS) {
            TEEC_CloseSession(&session);
        }
        (void)data;
        (void)size;
    }

    void TEEC_EncodeParamTest_001(const uint8_t *data, size_t size)
    {
        int callingPid = 0;
        uint32_t retOrigin = 0;
        TaFileInfo taFile;
        taFile.taFp = NULL;
        char path[] = "/vendor/bin/95b9ad1e-0af8-4201-9891-0dbe8602f35f.sec";
        taFile.taPath = (uint8_t *)path;

        TEEC_ContextInner contextInner = { 0 };
        TEEC_Session session = { 0 };
        TEEC_UUID destination = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f } };
        TEEC_Operation operation = { 0 };
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        char buf[4] = { 0 };
        operation.params[0].tmpref.buffer = (void *)buf;
        operation.params[0].tmpref.size = 4; // 4 size of memory
        TEEC_Result ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
            TEEC_LOGIN_IDENTIFY, NULL, &operation, &retOrigin);
        if (ret == TEEC_SUCCESS) {
            TEEC_CloseSession(&session);
        }
        (void)data;
        (void)size;
    }

    void TEEC_EncodePartialParamTest_001(const uint8_t *data, size_t size)
    {
        int callingPid = 0;
        uint32_t retOrigin = 0;
        TaFileInfo taFile;
        taFile.taFp = NULL;
        char path[] = "/vendor/bin/95b9ad1e-0af8-4201-9891-0dbe8602f35f.sec";
        taFile.taPath = (uint8_t *)path;

        char buf[4] = { 0 };
        TEEC_ContextInner contextInner = { 0 };
        TEEC_Session session = { 0 };
        TEEC_UUID destination = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f } };
        TEEC_Operation operation = { 0 };
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_SHARED_INOUT,
            TEEC_NONE, TEEC_NONE);
        TEEC_SharedMemory sharedMem0 = { 0 }, sharedMem1 = { 0 };
        operation.params[0].memref.parent = &sharedMem0;
        operation.params[0].memref.parent->is_allocated = 0;
        operation.params[0].memref.parent->buffer = (void *)buf;
        operation.params[0].memref.parent->size = 4; // 4 size of memory
        operation.params[0].memref.size = 4; // 4 size of memory
        operation.params[0].memref.offset = 0;
        operation.params[1].memref.parent = &sharedMem1;
        operation.params[1].memref.parent->is_allocated = 1;
        operation.params[1].memref.parent->buffer = (void *)buf;
        operation.params[1].memref.parent->size = 4; // 4 size of memory
        operation.params[1].memref.size = 4; // 4 size of memory
        operation.params[1].memref.offset = 0;

        TEEC_Result ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
            TEEC_LOGIN_IDENTIFY, NULL, &operation, &retOrigin);
        if (ret == TEEC_SUCCESS) {
            TEEC_CloseSession(&session);
        }
        (void)data;
        (void)size;
    }

    void TranslateParamTypeTest_001(const uint8_t *data, size_t size)
    {
        int callingPid = 0;
        uint32_t retOrigin = 0;
        TaFileInfo taFile;
        taFile.taFp = NULL;
        char path[] = "/vendor/bin/95b9ad1e-0af8-4201-9891-0dbe8602f35f.sec";
        taFile.taPath = (uint8_t *)path;

        char buf[4] = { 0 };
        TEEC_ContextInner contextInner = { 0 };
        TEEC_Session session = { 0 };
        TEEC_UUID destination = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f } };
        TEEC_Operation operation = { 0 };
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);
        TEEC_SharedMemory sharedMem = { 0 };
        operation.params[0].memref.parent = &sharedMem;
        operation.params[0].memref.parent->is_allocated = 0;
        operation.params[0].memref.parent->flags = TEEC_MEM_INPUT;
        operation.params[0].memref.parent->buffer = (void *)buf;
        operation.params[0].memref.parent->size = 4; // 4 size of memory
        operation.params[0].memref.size = 4; // 4 size of memory
        operation.params[0].memref.offset = 0;
        operation.params[1].memref.parent = &sharedMem;
        operation.params[1].memref.parent->is_allocated = 0;
        operation.params[1].memref.parent->flags = TEEC_MEM_OUTPUT;
        operation.params[1].memref.parent->buffer = (void *)buf;
        operation.params[1].memref.parent->size = 4; // 4 size of memory
        operation.params[1].memref.size = 4; // 4 size of memory
        operation.params[1].memref.offset = 0;

        TEEC_Result ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
            TEEC_LOGIN_IDENTIFY, NULL, &operation, &retOrigin);

        operation.params[0].memref.parent->flags = TEEC_MEM_INOUT;
        operation.params[1].memref.parent->flags = 0xffffffff;
        ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
            TEEC_LOGIN_IDENTIFY, NULL, &operation, &retOrigin);
        if (ret == TEEC_SUCCESS) {
            TEEC_CloseSession(&session);
        }
        (void)data;
        (void)size;
    }

    void TEEC_EncodeIonParam_001(const uint8_t *data, size_t size)
    {
        int callingPid = 0;
        uint32_t retOrigin = 0;
        TaFileInfo taFile;
        taFile.taFp = NULL;
        char path[] = "/vendor/bin/95b9ad1e-0af8-4201-9891-0dbe8602f35f.sec";
        taFile.taPath = (uint8_t *)path;

        TEEC_ContextInner contextInner = { 0 };
        TEEC_Session session = { 0 };
        TEEC_UUID destination = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f } };
        TEEC_Operation operation = { 0 };
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_ION_INPUT, TEEC_ION_SGLIST_INPUT, TEEC_NONE, TEEC_NONE);
        operation.params[0].ionref.ion_share_fd = 0;
        operation.params[0].ionref.ion_size = 1;
        operation.params[1].ionref.ion_share_fd = 0;
        operation.params[1].ionref.ion_size = 1;

        TEEC_Result ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
            TEEC_LOGIN_IDENTIFY, NULL, &operation, &retOrigin);
        if (ret == TEEC_SUCCESS) {
            TEEC_CloseSession(&session);
        }
        (void)data;
        (void)size;
    }

    void TEEC_CheckTmpRefTest_001(const uint8_t *data, size_t size)
    {
        TEEC_ContextInner context = { 0 };
        TEEC_Operation operation = { 0 };
        operation.started = 1;

        operation.paramTypes = TEEC_MEMREF_TEMP_INPUT;
        operation.params[0].tmpref.buffer = NULL;
        operation.params[0].tmpref.size = 1;
        TEEC_Result ret = TEEC_CheckOperation(&context, &operation);

        operation.paramTypes = TEEC_MEMREF_TEMP_INPUT;
        operation.params[0].tmpref.buffer = (void *)1;
        operation.params[0].tmpref.size = 0;
        ret = TEEC_CheckOperation(&context, &operation);
        (void)ret;
        (void)data;
        (void)size;
    }

    void TEEC_CheckMemRefTest_001(const uint8_t *data, size_t size)
    {
        TEEC_ContextInner context = { 0 };
        TEEC_Operation operation = { 0 };
        operation.started = 1;
        operation.paramTypes = TEEC_MEMREF_PARTIAL_INPUT;

        operation.params[0].memref.parent = NULL;
        TEEC_Result ret = TEEC_CheckOperation(&context, &operation);

        TEEC_SharedMemory sharedMem = { 0 };
        operation.params[0].memref.parent = &sharedMem;
        operation.params[0].memref.parent->buffer = NULL;
        ret = TEEC_CheckOperation(&context, &operation);

        char buf[4] = { 0 };
        operation.params[0].memref.parent->buffer = (void *)buf;
        operation.params[0].memref.parent->size = 0;
        ret = TEEC_CheckOperation(&context, &operation);

        operation.params[0].memref.parent->size = 4; // 4 size of memory
        operation.params[0].memref.parent->flags = 0;
        ret = TEEC_CheckOperation(&context, &operation);

        operation.paramTypes = TEEC_MEMREF_PARTIAL_OUTPUT;
        operation.params[0].memref.parent->flags = 0;
        ret = TEEC_CheckOperation(&context, &operation);

        operation.paramTypes = TEEC_MEMREF_PARTIAL_INOUT;
        operation.params[0].memref.parent->flags = 0;
        ret = TEEC_CheckOperation(&context, &operation);

        operation.paramTypes = TEEC_MEMREF_PARTIAL_INOUT;
        operation.params[0].memref.parent->flags = TEEC_MEM_INPUT;
        ret = TEEC_CheckOperation(&context, &operation);

        operation.paramTypes = TEEC_MEMREF_WHOLE;
        operation.params[0].memref.parent->flags = TEEC_MEM_INOUT;
        operation.params[0].memref.parent->is_allocated = 0;
        ret = TEEC_CheckOperation(&context, &operation);
        (void)data;
        (void)size;
        (void)ret;
    }

    void TEEC_CheckMemRefTest_002(const uint8_t *data, size_t size)
    {
        TEEC_ContextInner context = { 0 };
        TEEC_Operation operation = { 0 };
        operation.started = 1;

        TEEC_SharedMemory sharedMem = { 0 };
        operation.params[0].memref.parent = &sharedMem;

        char buf[4] = { 0 };
        operation.params[0].memref.parent->buffer = (void *)buf;
        operation.params[0].memref.parent->size = 4; // 4 size of memory
        operation.params[0].memref.offset = 1;
        operation.params[0].memref.size = 4; // 4 size of memory

        operation.paramTypes = TEEC_MEMREF_PARTIAL_INPUT;
        operation.params[0].memref.parent->flags = TEEC_MEM_INPUT;
        TEEC_Result ret = TEEC_CheckOperation(&context, &operation);

        operation.paramTypes = TEEC_MEMREF_PARTIAL_OUTPUT;
        operation.params[0].memref.parent->flags = TEEC_MEM_OUTPUT;
        ret = TEEC_CheckOperation(&context, &operation);

        operation.paramTypes = TEEC_MEMREF_PARTIAL_INOUT;
        operation.params[0].memref.parent->flags = TEEC_MEM_INOUT;
        ret = TEEC_CheckOperation(&context, &operation);
        (void)data;
        (void)size;
        (void)ret;
    }

    void CheckSharedBufferExistTest_002(const uint8_t *data, size_t size)
    {
        TEEC_Operation operation = { 0 };
        operation.started = 1;

        TEEC_SharedMemory sharedMem = { 0 };
        operation.params[0].memref.parent = &sharedMem;

        char buf[4] = { 0 };
        operation.params[0].memref.parent->buffer = (void *)buf;
        operation.params[0].memref.parent->size = 4; // 4 size of memory
        operation.params[0].memref.offset = 0;

        operation.paramTypes = TEEC_MEMREF_WHOLE;
        operation.params[0].memref.parent->is_allocated = 1;

        TEEC_Result ret = TEEC_CheckOperation(NULL, &operation);
        (void)data;
        (void)size;
        (void)ret;
    }

    void TEEC_CheckOperationTest_001(const uint8_t *data, size_t size)
    {
        TEEC_ContextInner context = { 0 };
        TEEC_Operation operation = { 0 };
        TEEC_Result ret = TEEC_CheckOperation(&context, NULL);

        operation.started = 0;
        ret = TEEC_CheckOperation(&context, &operation);

        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_ION_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT);
        operation.params[0].ionref.ion_share_fd = -1;
        ret = TEEC_CheckOperation(&context, &operation);

        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_ION_SGLIST_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT);
        operation.params[0].ionref.ion_share_fd = -1;
        ret = TEEC_CheckOperation(&context, &operation);

        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_ION_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT);
        operation.params[0].ionref.ion_share_fd = 0;
        operation.params[0].ionref.ion_size = 0;
        ret = TEEC_CheckOperation(&context, &operation);

        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_ION_SGLIST_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT);
        operation.params[0].ionref.ion_share_fd = 0;
        operation.params[0].ionref.ion_size = 0;
        ret = TEEC_CheckOperation(&context, &operation);

        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_MEMREF_SHARED_INOUT, TEEC_NONE);
        ret = TEEC_CheckOperation(&context, &operation);
        (void)data;
        (void)size;
        (void)ret;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::LibteecVendorOpenSessionFuzzTest(data, size);
    OHOS::TEEC_OpenSessionTest_001(data, size);
    OHOS::TEEC_OpenSessionInnerTest_001(data, size);
    OHOS::TEEC_OpenSessionInnerTest_002(data, size);
    OHOS::TEEC_EncodeParamTest_001(data, size);
    OHOS::TEEC_EncodePartialParamTest_001(data, size);
    OHOS::TranslateParamTypeTest_001(data, size);
    OHOS::TEEC_EncodeIonParam_001(data, size);
    OHOS::TEEC_CheckTmpRefTest_001(data, size);
    OHOS::TEEC_CheckMemRefTest_001(data, size);
    OHOS::TEEC_CheckMemRefTest_002(data, size);
    OHOS::CheckSharedBufferExistTest_002(data, size);
    OHOS::TEEC_CheckOperationTest_001(data, size);
    return 0;
}