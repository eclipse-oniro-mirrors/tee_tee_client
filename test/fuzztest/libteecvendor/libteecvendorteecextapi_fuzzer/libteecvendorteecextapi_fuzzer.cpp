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

#include "libteecvendorteecextapi_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <malloc.h>
#include <string>
#include "tee_client_api.h"
#include "tee_client_ext_api.h"
#include "tee_client_inner_api.h"
#include "tee_client_constants.h"
#include "tee_client_type.h"
#include "tee_client_app_load.h"
#include "load_sec_file.h"

namespace OHOS {
    bool LibteecVendorExtRegisterAgentFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size > sizeof(uint32_t) + sizeof(int)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            uint32_t agentId = *reinterpret_cast<uint32_t *>(temp);
            temp += sizeof(agentId);
            int *devFd = reinterpret_cast<int *>(temp);
            temp += sizeof(int);

            uint8_t *buffer;
            TEEC_Result ret = TEEC_EXT_RegisterAgent(agentId, devFd, (void **)&buffer);
            if (ret != TEEC_SUCCESS) {
                return result;
            }
        }
        return result;
    }

    void TEEC_EXT_RegisterAgentTest_001(const uint8_t *data, size_t size)
    {
        (void)data;
        (void)size;
        int devFd = 0;
        char *buf = nullptr;

        TEEC_Result ret = TEEC_EXT_RegisterAgent(0, nullptr, (void **)nullptr);

        ret = TEEC_EXT_RegisterAgent(0, &devFd, (void **)nullptr);

        ret = TEEC_EXT_RegisterAgent(0, &devFd, (void **)&buf);
    }

    bool LibteecVendorExtWaitEventFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size > sizeof(uint32_t) + sizeof(int)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            uint32_t agentId = *reinterpret_cast<uint32_t*>(temp);
            temp += sizeof(agentId);
            int devFd = *reinterpret_cast<int *>(temp);
            temp += sizeof(int);

            TEEC_Result ret = TEEC_EXT_WaitEvent(agentId, devFd);
            if (ret != TEEC_SUCCESS) {
                return result;
            }
        }
        return result;
    }

    void TEEC_EXT_WaitEventTest_001(const uint8_t *data, size_t size)
    {
        (void)data;
        (void)size;
        TEEC_EXT_WaitEvent(0, 0);
    }

    bool LibteecVendorExtUnregisterAgentFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size > sizeof(uint32_t) + sizeof(int)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            uint32_t agentId = *reinterpret_cast<uint32_t *>(temp);
            temp += sizeof(agentId);
            int devFd = *reinterpret_cast<int *>(temp);
            temp += sizeof(int);
            devFd = devFd > 0 ? 0x7fffffff : devFd;
            uint8_t *buffer;
            TEEC_Result ret = TEEC_EXT_UnregisterAgent(agentId, devFd, (void **)&buffer);
            if (ret != TEEC_SUCCESS) {
                return result;
            }
        }
        return result;
    }

    void TEEC_EXT_UnregisterAgentTest_001(const uint8_t *data, size_t size)
    {
        (void)data;
        (void)size;
        char *buf = nullptr;

        TEEC_Result ret = TEEC_EXT_UnregisterAgent(0, 0, nullptr);

        ret = TEEC_EXT_UnregisterAgent(0, 0, (void**)&buf);

        char buf2[4] = { 0 };
        ret = TEEC_EXT_UnregisterAgent(0, -1, (void**)&buf2);
    }

    void LibteecVendorSendSecfileFuzzTest(const uint8_t *data, size_t size)
    {
        if (size > sizeof(uint8_t) + sizeof(TEEC_Session)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            TEEC_Session session = *reinterpret_cast<TEEC_Session *>(temp);
            temp += sizeof(TEEC_Session);
            char *path = reinterpret_cast<char *>(temp);

            TEEC_SendSecfile(path, &session);
        }
    }

    void TEEC_SendSecfileTest_001(const uint8_t *data, size_t size)
    {
        (void)data;
        (void)size;
        TEEC_Result ret = TEEC_SendSecfile(nullptr, nullptr);

        char path[] = "/data/app/el2/100/base/files/abe89147-cd61-f43f-71c4-1a317e405312.sec";
        ret = TEEC_SendSecfile(path, nullptr);

        TEEC_Session session = { 0 };
        session.context = nullptr;
        ret = TEEC_SendSecfile(path, &session);

        TEEC_UUID uuid = { 0xabe89147, 0xcd61, 0xf43f, { 0x71, 0xc4, 0x1a, 0x31, 0x7e, 0x40, 0x53, 0x12 } };
        TEEC_Context context = { 0 };
        ret = TEEC_InitializeContext(nullptr, &context);

        TEEC_Operation operation = { 0 };
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, nullptr);
        ret = TEEC_SendSecfile(path, &session);
    }

    bool LibteecVendorSendSecfileInnerFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size > sizeof(int) + sizeof(FILE)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            int tzFd = *reinterpret_cast<int *>(temp);
            temp += sizeof(int);
            FILE *fp = reinterpret_cast<FILE *>(temp);
            temp += sizeof(FILE);
            char *path = reinterpret_cast<char *>(temp);

            result = TEEC_SendSecfileInner(path, tzFd, fp);
        }
        return result;
    }

    void TEEC_SendSecfileInnerTest_001(const uint8_t *data, size_t size)
    {
        (void)data;
        (void)size;
        TEEC_Result result = TEEC_SendSecfileInner(nullptr, 0, nullptr);

        char path[] = "/data/app/el2/100/base/files/abe89147-cd61-f43f-71c4-1a317e405312.sec";
        result = TEEC_SendSecfileInner(path, 0, nullptr);
    }

    bool LibteecVendorSendEventResponseFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size > sizeof(uint32_t) + sizeof(FILE)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            int devFd = *reinterpret_cast<int *>(temp);
            temp += sizeof(int);
            uint32_t agentId = *reinterpret_cast<uint32_t *>(temp);

            result = TEEC_EXT_SendEventResponse(agentId, devFd);
        }
        return result;
    }

    void TEEC_EXT_SendEventResponseTest_001(const uint8_t *data, size_t size)
    {
        (void)data;
        (void)size;
        TEEC_EXT_SendEventResponse(0, 0);
    }

    bool LibteecVendorLoadSecfileFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        if (size > sizeof(int) + sizeof(FILE)) {
            uint8_t *temp = const_cast<uint8_t *>(data);
            int tzFd = *reinterpret_cast<int *>(temp);
            temp += sizeof(int);
            FILE *fp = reinterpret_cast<FILE *>(temp);
            temp += sizeof(FILE);
            char *path = reinterpret_cast<char *>(temp);

            TEEC_LoadSecfile(path, tzFd, fp);
        }
        return result;
    }

    void LibteecVendorGetAppFuzzTest(const uint8_t *data, size_t size)
    {
        int ret = 0;
        TaFileInfo taFile = { 0 };
        TEEC_UUID srvUuid = { 0 };
        TC_NS_ClientContext cliContext = { { 0 } };

        ret = TEEC_GetApp(nullptr, nullptr, nullptr);

        std::string str("./ClientAppLoad_002.txt");
        taFile.taPath = reinterpret_cast<const uint8_t*>(str.c_str());
        ret = TEEC_GetApp(&taFile, &srvUuid, &cliContext);

        FILE *fp = fopen("./ClientAppLoad_001.sec", "w+");
        ret = TEEC_GetApp(&taFile, &srvUuid, &cliContext);
        (void)fclose(fp);

        taFile.taPath = data;
        ret = TEEC_GetApp(&taFile, &srvUuid, &cliContext);
    }

    void LibteecVendorLoadSecfileFuzzTest_001(const uint8_t *data, size_t size)
    {
        int ret = 0;
        FILE *fp = fopen("./ClientAppLoad_002.txt", "w+");

        ret = TEEC_LoadSecfile(nullptr, -1, nullptr);
    
        std::string str("./ClientAppLoad_002.txt");
        ret = TEEC_LoadSecfile(str.c_str(), 0, fp);

        ret = TEEC_LoadSecfile(str.c_str(), 0, nullptr);

        uint8_t *temp = const_cast<uint8_t*>(data);
        ret = TEEC_LoadSecfile(reinterpret_cast<char *>(temp), 0, fp);
        (void)fclose(fp);
    }

    #define MAX_BUFFER_LEN (8 * 1024 * 1024)
    void LibteecVendorLoadSecfileFuzzTest_002(const uint8_t *data, size_t size)
    {
        int tzFd = 0;
        int ret = 0;

        FILE *fp = fopen("./LoadSecfile_002.txt", "w+");
        ret = LoadSecFile(tzFd, fp, LOAD_TA, nullptr);
        (void)fclose(fp);

        fp = fopen("./LoadSecfile_002.txt", "w+");
        (void)fseek(fp, MAX_BUFFER_LEN + 1, SEEK_SET);
        char chr = 0;
        (void)fwrite(&chr, 1, sizeof(chr), fp);
        ret = LoadSecFile(tzFd, fp, LOAD_TA, nullptr);
        (void)fclose(fp);

        fp = fopen("./LoadSecfile_002.txt", "w+");
        (void)fprintf(fp, "%s", "LoadSecfile_002");
        ret = LoadSecFile(tzFd, fp, LOAD_TA, nullptr);
        (void)fclose(fp);

        uint8_t *temp = const_cast<uint8_t *>(data);
        if (size > sizeof(int)) {
            tzFd = *reinterpret_cast<int*>(temp);
            ret = LoadSecFile(tzFd, fp, LOAD_TA, NULL);
        }
    }

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::LibteecVendorExtRegisterAgentFuzzTest(data, size);
    OHOS::TEEC_EXT_RegisterAgentTest_001(data, size);
    OHOS::LibteecVendorExtWaitEventFuzzTest(data, size);
    OHOS::TEEC_EXT_WaitEventTest_001(data, size);
    OHOS::LibteecVendorExtUnregisterAgentFuzzTest(data, size);
    OHOS::TEEC_EXT_UnregisterAgentTest_001(data, size);
    OHOS::LibteecVendorSendSecfileFuzzTest(data, size);
    OHOS::TEEC_SendSecfileTest_001(data, size);
    OHOS::LibteecVendorSendSecfileInnerFuzzTest(data, size);
    OHOS::TEEC_SendSecfileInnerTest_001(data, size);
    OHOS::LibteecVendorSendEventResponseFuzzTest(data, size);
    OHOS::TEEC_EXT_SendEventResponseTest_001(data, size);
    OHOS::LibteecVendorLoadSecfileFuzzTest(data, size);
    OHOS::LibteecVendorGetAppFuzzTest(data, size);
    OHOS::LibteecVendorLoadSecfileFuzzTest_001(data, size);
    OHOS::LibteecVendorLoadSecfileFuzzTest_002(data, size);
    return 0;
}