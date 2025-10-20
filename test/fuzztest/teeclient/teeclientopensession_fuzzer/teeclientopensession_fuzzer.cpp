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

#include "teeclientopensession_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>
#include "tee_client_api.h"
#include "message_parcel.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"
#include "cadaemon_service.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "tee_log.h"
#include "tee_client_ext_api.h"
#include "tee_client_inner.h"

static const TEEC_UUID g_testUuid = {
    0x79b77788, 0x9789, 0x4a7a,
    { 0xa2, 0xbe, 0xb6, 0x01, 0x55, 0xee, 0xf5, 0xf3 }
};

namespace OHOS {
    static bool RecOpenReply(uint32_t returnOrigin, TEEC_Result ret, TEEC_Session *outSession,
        TEEC_Operation *operation, MessageParcel &reply)
    {
        bool writeRet = reply.WriteUint32(returnOrigin);
        CHECK_ERR_RETURN(writeRet, true, writeRet);

        writeRet = reply.WriteInt32((int32_t)ret);
        CHECK_ERR_RETURN(writeRet, true, writeRet);

        if (ret != TEEC_SUCCESS) {
            return false;
        }

        writeRet = reply.WriteBuffer(outSession, sizeof(*outSession));
        CHECK_ERR_RETURN(writeRet, true, writeRet);

        bool parRet = reply.WriteBool(true);
        CHECK_ERR_RETURN(parRet, true, false);
        writeRet = reply.WriteBuffer(operation, sizeof(*operation));
        CHECK_ERR_RETURN(writeRet, true, writeRet);

        return true;
    }

    bool TeeClientOpenSessionFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size > sizeof(TEEC_Context) + sizeof(TEEC_Session) + sizeof(TEEC_UUID) + sizeof(uint32_t) +
            sizeof(TEEC_Operation) + sizeof(uint32_t) + sizeof(TEEC_Parameter) + sizeof(TEEC_SharedMemory)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            TEEC_Context context = *reinterpret_cast<TEEC_Context *>(temp);
            context.ta_path = "TeeClientOpenSessionFuzzTest";
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

            connectionMethod = TEEC_LOGIN_IDENTIFY;
            ret = TEEC_OpenSession(&context, &session, &uuid, connectionMethod,
                nullptr, &operation, &returnOrigin);
            if (ret == TEEC_SUCCESS) {
                TEEC_CloseSession(&session);
            }
        }
        return result;
    }

    void TeeClientOpenSessionFuzzTest_101(TEEC_Context *context, TEEC_Session *session, const TEEC_UUID *destination,
        uint32_t connectionMethod, const void *connectionData, TEEC_Operation *operation, uint32_t *returnOrigin)
    {
        operation->started = 1;
        operation->paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

        TEEC_Result ret = TEEC_OpenSession(context, session, destination, connectionMethod,
            connectionData, operation, returnOrigin);
        if (ret == TEEC_SUCCESS) {
            TEEC_CloseSession(session);
        }

        operation->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_PARTIAL_OUTPUT,
            TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_PARTIAL_OUTPUT);
        ret = TEEC_OpenSession(context, session, destination, connectionMethod,
            connectionData, operation, returnOrigin);
        if (ret == TEEC_SUCCESS) {
            TEEC_CloseSession(session);
        }

        operation->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_PARTIAL_OUTPUT,
            TEEC_NONE, TEEC_NONE);
        ret = TEEC_OpenSession(context, session, destination, connectionMethod,
            connectionData, operation, returnOrigin);
        if (ret == TEEC_SUCCESS) {
            TEEC_CloseSession(session);
        }
    }

    bool TeeClientOpenSessionFuzzTest_1(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size > sizeof(TEEC_Context) + sizeof(TEEC_Session) + sizeof(TEEC_UUID) + sizeof(uint32_t) +
            sizeof(TEEC_Operation) + sizeof(uint32_t) + sizeof(TEEC_Parameter) + sizeof(TEEC_SharedMemory)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            TEEC_Context context = *reinterpret_cast<TEEC_Context *>(temp);
            context.ta_path = "TeeClientOpenSessionFuzzTest_1";
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

            connectionMethod = TEEC_LOGIN_IDENTIFY;
            ret = TEEC_OpenSession(&context, &session, &uuid, connectionMethod,
                nullptr, &operation, &returnOrigin);
            if (ret == TEEC_SUCCESS) {
                TEEC_CloseSession(&session);
            }

            TeeClientOpenSessionFuzzTest_101(&context, &session, &uuid, connectionMethod,
                nullptr, &operation, &returnOrigin);
        }
        return result;
    }

    void TeeClientOpenSessionFuzzTest_2(const uint8_t *data, size_t size)
    {
        TEEC_Context context = { 0 };
        TEEC_Session session = { 0 };
        TEEC_Operation operation = { 0 };
        TEEC_SharedMemory sharedMem = { 0 };
        char buff[128] = { 0 };
        MessageParcel reply;
        operation.started = 1;
        uint32_t origin;
        (void)TEEC_GetTEEVersion();
        RecOpenReply(TEEC_ORIGIN_API, TEEC_SUCCESS, &session, &operation, reply);
        TEEC_Result ret = TEEC_InitializeContext("CaDaemonTest_003", &context);

        char pathStr[MAX_TA_PATH_LEN + 1] = { 0 };
        if (memcpy_s(pathStr, MAX_TA_PATH_LEN,
            (const char*)data, size > MAX_TA_PATH_LEN ? MAX_TA_PATH_LEN : size) == 0) {
            context.ta_path = (uint8_t *)pathStr;
        }
        operation.paramTypes =
            TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE);
        operation.params[0].memref.parent = &sharedMem;
        operation.params[0].memref.parent->buffer = (void*)buff;
        operation.params[0].memref.parent->flags = TEEC_MEM_OUTPUT;
        operation.params[0].memref.parent->size = 0;
        operation.params[0].memref.offset = 1;
        operation.params[0].memref.size = 1;
        operation.params[1].memref.parent = &sharedMem;
        operation.params[1].memref.parent->buffer = (void*)buff;
        operation.params[1].memref.parent->flags = TEEC_MEM_INPUT;
        operation.params[1].memref.parent->size = -1;
        operation.params[1].memref.offset = -1;
        operation.params[1].memref.size = 1;
        ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);

        operation.paramTypes =
                TEEC_PARAM_TYPES(data[0], TEEC_NONE, TEEC_NONE, TEEC_NONE);
        ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);

        ret = TEEC_SendSecfile(pathStr, &session);

        TEEC_FinalizeContext(&context);
        TEEC_CloseSession(&session);
        TEEC_RequestCancellation(&operation);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::TeeClientOpenSessionFuzzTest(data, size);
    OHOS::TeeClientOpenSessionFuzzTest_1(data, size);
    OHOS::TeeClientOpenSessionFuzzTest_2(data, size);
    return 0;
}