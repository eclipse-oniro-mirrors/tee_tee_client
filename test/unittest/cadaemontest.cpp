/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <cstdio>
#include <ctime>
#include <memory>
#include <cstring>
#include <securec.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include "tee_client_type.h"
#include "tee_log.h"
#include "tc_ns_client.h"
#include "tee_client_ext_api.h"
#include "tee_client_api.h"
#include "cadaemon_service.h"
#include "tee_file.h"

using namespace testing::ext;
using namespace OHOS;

static const TEEC_UUID g_testUuid = {
    0x79b77788, 0x9789, 0x4a7a,
    { 0xa2, 0xbe, 0xb6, 0x01, 0x55, 0xee, 0xf5, 0xf3 }
};


class CaDaemonTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CaDaemonTest::SetUpTestCase(void)
{
    printf("SetUp\n");
}

void CaDaemonTest::TearDownTestCase(void)
{
    printf("SetUpTestCase\n");
}

void CaDaemonTest::SetUp(void)
{
    printf("TearDownTestCase\n");
}

void CaDaemonTest::TearDown(void)
{
    printf("TearDown\n");
}

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
namespace {
/**
 * @tc.name: CadaemonGetTeeVersion
 * @tc.desc: Get Tee Version
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */

HWTEST_F(CaDaemonTest, CadaemonGetTeeVersion, TestSize.Level1)
{
    uint32_t version = TEEC_GetTEEVersion();
    EXPECT_TRUE(version != 0);
}

/**
 * @tc.name: CadaemonGetTeeVersion
 * @tc.desc: Get Tee Version
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */

HWTEST_F(CaDaemonTest, CaDaemonTest_001, TestSize.Level1)
{
    TEEC_Result ret = TEEC_InitializeContext(nullptr, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    char str[4097] = { 0 };
    if (memset_s(str, sizeof(str), '1', 4096)) {
        printf("CaDaemonTest_001 memset_s failed\n");
    }
    TEEC_Context context = { 0 };
    ret = TEEC_InitializeContext(str, &context);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_002, TestSize.Level1)
{
    char name[] = "CaDaemonTest_002";
    TEEC_Context context = { 0 };
    TEEC_Result ret = TEEC_InitializeContext(name, &context);
    TEEC_FinalizeContext(&context);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    TEEC_FinalizeContext(nullptr);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_003, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_Session session = { 0 };
    TEEC_Operation operation = { 0 };
    MessageParcel reply;
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    uint32_t origin;
    RecOpenReply(TEEC_ORIGIN_API, TEEC_SUCCESS, &session, &operation, reply);
    TEEC_Result ret = TEEC_InitializeContext("CaDaemonTest_003", &context);
    ret = TEEC_OpenSession(nullptr, nullptr, nullptr, TEEC_LOGIN_PUBLIC, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_PUBLIC, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_PUBLIC, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, nullptr, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    context.ta_path = (uint8_t *)"/vendor/bin/1234.sec";
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    FILE *fp = fopen("/data/test.sec", "w");
    fclose(fp);
    context.ta_path = (uint8_t *)"/data/test.sec";
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
    (void)remove("/data/test.sec");
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    TEEC_FinalizeContext(&context);
    TEEC_CloseSession(nullptr);
    TEEC_CloseSession(&session);
    TEEC_RequestCancellation(&operation);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_003_1, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_Session session = { 0 };
    TEEC_Operation operation = { 0 };
    TEEC_SharedMemory sharedMem = { 0 };
    char buff[128] = { 0 };
    MessageParcel reply;
    operation.started = 1;
    uint32_t origin;
    RecOpenReply(TEEC_ORIGIN_API, TEEC_SUCCESS, &session, &operation, reply);
    TEEC_Result ret = TEEC_InitializeContext("CaDaemonTest_003", &context);
    context.ta_path = (uint8_t *)"/vendor/bin/1234.sec";

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_PARTIAL_OUTPUT,
        TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_PARTIAL_OUTPUT);
    operation.params[0].memref.parent = &sharedMem;
    operation.params[0].memref.parent->buffer = (void*)buff;
    operation.params[0].memref.parent->flags = TEEC_MEM_OUTPUT;
    operation.params[0].memref.parent->size = 0;
    operation.params[0].memref.offset = 1;
    operation.params[0].memref.size = 1;
    operation.params[1].memref.parent = &sharedMem;
    operation.params[1].memref.parent->buffer = (void*)buff;
    operation.params[1].memref.parent->flags = TEEC_MEM_OUTPUT;
    operation.params[1].memref.parent->size = 0;
    operation.params[1].memref.offset = -1;
    operation.params[1].memref.size = 2;
    operation.params[2].memref.parent = &sharedMem;
    operation.params[2].memref.parent->buffer = (void*)buff;
    operation.params[2].memref.parent->flags = TEEC_MEM_INOUT;
    operation.params[2].memref.parent->size = 0;
    operation.params[2].memref.offset = -1;
    operation.params[2].memref.size = 2;
    operation.params[3].memref.parent = &sharedMem;
    operation.params[3].memref.parent->buffer = (void*)buff;
    operation.params[3].memref.parent->flags = TEEC_MEM_INOUT;
    operation.params[3].memref.parent->size = 0;
    operation.params[3].memref.offset = 2;
    operation.params[3].memref.size = -1;

    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    TEEC_FinalizeContext(&context);
    TEEC_CloseSession(&session);
    TEEC_RequestCancellation(&operation);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_003_02, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_Session session = { 0 };
    TEEC_Operation operation = { 0 };
    TEEC_SharedMemory sharedMem = { 0 };
    char buff[128] = { 0 };
    MessageParcel reply;
    operation.started = 1;
    uint32_t origin;
    RecOpenReply(TEEC_ORIGIN_API, TEEC_SUCCESS, &session, &operation, reply);
    TEEC_Result ret = TEEC_InitializeContext("CaDaemonTest_003", &context);
    context.ta_path = (uint8_t *)"/vendor/bin/1234.sec";

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
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    TEEC_FinalizeContext(&context);
    TEEC_CloseSession(&session);
    TEEC_RequestCancellation(&operation);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_003_03, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_Session session = { 0 };
    TEEC_Operation operation = { 0 };
    TEEC_SharedMemory sharedMem = { 0 };
    char buff[128] = { 0 };
    MessageParcel reply;
    operation.started = 1;
    uint32_t origin;
    RecOpenReply(TEEC_ORIGIN_API, TEEC_SUCCESS, &session, &operation, reply);
    TEEC_Result ret = TEEC_InitializeContext("CaDaemonTest_003", &context);
    context.ta_path = (uint8_t *)"/vendor/bin/1234.sec";

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_MEMREF_PARTIAL_INOUT,
        TEEC_MEMREF_PARTIAL_INOUT, TEEC_MEMREF_PARTIAL_INOUT);
    operation.params[0].memref.parent = &sharedMem;
    operation.params[0].memref.parent->buffer = (void*)buff;
    operation.params[0].memref.parent->flags = TEEC_MEM_OUTPUT;
    operation.params[0].memref.parent->size = 0;
    operation.params[0].memref.offset = 1;
    operation.params[0].memref.size = 1;
    operation.params[1].memref.parent = &sharedMem;
    operation.params[1].memref.parent->buffer = (void*)buff;
    operation.params[1].memref.parent->flags = TEEC_MEM_INPUT;
    operation.params[1].memref.parent->size = 2;
    operation.params[1].memref.offset = -1;
    operation.params[1].memref.size = 1;
    operation.params[2].memref.parent = &sharedMem;
    operation.params[2].memref.parent->buffer = (void*)buff;
    operation.params[2].memref.parent->flags = TEEC_MEM_INOUT;
    operation.params[2].memref.parent->size = 2;
    operation.params[2].memref.offset = -1;
    operation.params[2].memref.size = 1;
    operation.params[3].memref.parent = &sharedMem;
    operation.params[3].memref.parent->buffer = (void*)buff;
    operation.params[3].memref.parent->flags = TEEC_MEM_INOUT;
    operation.params[3].memref.parent->size = 0;
    operation.params[3].memref.offset = -1;
    operation.params[3].memref.size = 2;
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    TEEC_FinalizeContext(&context);
    TEEC_CloseSession(&session);
    TEEC_RequestCancellation(&operation);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_003_04, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_Session session = { 0 };
    TEEC_Operation operation = { 0 };
    TEEC_SharedMemory sharedMem = { 0 };
    char buff[128] = { 0 };
    MessageParcel reply;
    operation.started = 1;
    uint32_t origin;
    RecOpenReply(TEEC_ORIGIN_API, TEEC_SUCCESS, &session, &operation, reply);
    TEEC_Result ret = TEEC_InitializeContext("CaDaemonTest_003", &context);
    context.ta_path = (uint8_t *)"/vendor/bin/1234.sec";

    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &sharedMem;
    operation.params[0].memref.parent->buffer = (void*)buff;
    operation.params[0].memref.parent->flags = TEEC_MEM_INOUT;
    operation.params[0].memref.parent->size = UINT32_MAX;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = UINT32_MAX - 1;
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &sharedMem;
    operation.params[0].memref.parent->buffer = (void*)buff;
    operation.params[0].memref.parent->flags = TEEC_MEM_INOUT;
    operation.params[0].memref.parent->size = UINT32_MAX / 2;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = UINT32_MAX / 2 - 1;
    operation.params[1].memref.parent = &sharedMem;
    operation.params[1].memref.parent->buffer = (void*)buff;
    operation.params[1].memref.parent->flags = TEEC_MEM_INOUT;
    operation.params[1].memref.parent->size = UINT32_MAX / 2;
    operation.params[1].memref.offset = 0;
    operation.params[2].memref.size = UINT32_MAX / 2 - 1;
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    TEEC_FinalizeContext(&context);
    TEEC_CloseSession(&session);
    TEEC_RequestCancellation(&operation);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_003_05, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_Session session = { 0 };
    TEEC_Operation operation = { 0 };
    TEEC_SharedMemory sharedMem = { 0 };
    char buff[128] = { 0 };
    MessageParcel reply;
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    uint32_t origin;
    RecOpenReply(TEEC_ORIGIN_API, TEEC_SUCCESS, &session, &operation, reply);
    TEEC_Result ret = TEEC_InitializeContext("CaDaemonTest_003", &context);
    context.ta_path = (uint8_t *)"/vendor/bin/1234.sec";

    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &sharedMem;
    operation.params[0].memref.parent->buffer = (void*)buff;
    operation.params[0].memref.parent->flags = TEEC_MEM_INOUT;
    operation.params[0].memref.parent->size = UINT32_MAX;
    operation.params[0].memref.offset = UINT32_MAX - 1;
    operation.params[0].memref.size = 2;
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE);
    operation.params[0].memref.parent = nullptr;
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE);
    operation.params[0].memref.parent = &sharedMem;
    operation.params[0].memref.parent->buffer = nullptr;
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    TEEC_FinalizeContext(&context);
    TEEC_CloseSession(&session);
    TEEC_RequestCancellation(&operation);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_003_06, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_Session session = { 0 };
    TEEC_Operation operation = { 0 };
    TEEC_SharedMemory sharedMem = { 0 };
    char buff[128] = { 0 };
    MessageParcel reply;
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    uint32_t origin;
    RecOpenReply(TEEC_ORIGIN_API, TEEC_SUCCESS, &session, &operation, reply);
    TEEC_Result ret = TEEC_InitializeContext("CaDaemonTest_003", &context);
    context.ta_path = (uint8_t *)"/vendor/bin/1234.sec";

    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE);
    operation.params[0].memref.parent = &sharedMem;
    operation.params[0].memref.parent->buffer = (void*)buff;
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT, TEEC_VALUE_INOUT, TEEC_VALUE_INPUT);
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    TEEC_FinalizeContext(&context);
    TEEC_CloseSession(&session);
    TEEC_RequestCancellation(&operation);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_004, TestSize.Level1)
{
    char name[] = "CaDaemonTest_004";
    TEEC_Context context = { 0 };
    TEEC_Result ret = TEEC_InitializeContext(name, &context);
    TEEC_Session session = { 0 };
    session.context = &context;
    TEEC_Operation operation = { 0 };
    uint32_t origin;

    ret = TEEC_InvokeCommand(&session, 0, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(10, 10, 10, 10);
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);

    ret = TEEC_InvokeCommand(nullptr, 0, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&session, 0, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_ION_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].ionref.ion_share_fd = 1;
    ret = TEEC_InvokeCommand(&session, 0, &operation, &origin);
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_ION_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].ionref.ion_share_fd = -1;
    ret = TEEC_InvokeCommand(&session, 0, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_004_001, TestSize.Level1)
{
    char name[] = "CaDaemonTest_004";
    TEEC_Context context = { 0 };
    TEEC_Result ret = TEEC_InitializeContext(name, &context);
    TEEC_Session session = { 0 };
    session.context = &context;
    TEEC_Operation operation = { 0 };
    char buff[128] = { 0 };
    uint32_t origin;

    ret = TEEC_InvokeCommand(&session, 0, nullptr, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, 0, 0);
    operation.params[0].tmpref.buffer = (void*)buff;
    operation.params[0].tmpref.size = -1;
    operation.params[1].tmpref.buffer = (void*)buff;
    operation.params[1].tmpref.size = -1;
    ret = TEEC_InvokeCommand(&session, 0, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_INOUT, 0, 0);
    ret = TEEC_InvokeCommand(&session, 0, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_005, TestSize.Level1)
{
    char name[] = "CaDaemonTest_005";
    TEEC_Context context = { 0 };
    TEEC_Result ret = TEEC_InitializeContext(name, &context);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    ret = TEEC_RegisterSharedMemory(nullptr, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    TEEC_SharedMemory sharedMem = { 0 };
    ret = TEEC_RegisterSharedMemory(&context, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    ret = TEEC_RegisterSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    sharedMem.buffer = (void*)name;
    sharedMem.flags = TEEC_MEM_INPUT;
    ret = TEEC_RegisterSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    sharedMem.flags = TEEC_MEM_OUTPUT;
    ret = TEEC_RegisterSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_RegisterSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    TEEC_ReleaseSharedMemory(&sharedMem);
    sharedMem.buffer = nullptr;
    TEEC_ReleaseSharedMemory(&sharedMem);
    sharedMem.context = nullptr;
    TEEC_ReleaseSharedMemory(&sharedMem);
    TEEC_ReleaseSharedMemory(nullptr);
    TEEC_FinalizeContext(&context);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_006, TestSize.Level1)
{
    TEEC_Result ret = TEEC_AllocateSharedMemory(nullptr, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    char name[] = "CaDaemonTest_006";
    TEEC_Context context = { 0 };
    TEEC_SharedMemory sharedMem = { 0 };
    ret = TEEC_AllocateSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    ret = TEEC_InitializeContext(name, &context);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    ret = TEEC_AllocateSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    sharedMem.flags = TEEC_MEM_INPUT;
    ret = TEEC_AllocateSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    TEEC_FinalizeContext(&context);
    TEEC_ReleaseSharedMemory(&sharedMem);
    sharedMem.buffer = (void *)0xffff0001;
    TEEC_ReleaseSharedMemory(&sharedMem);
    sharedMem.flags = TEEC_MEM_INPUT;
    sharedMem.size = 1024;
    ret = TEEC_InitializeContext(name, &context);
    ret = TEEC_AllocateSharedMemory(&context, &sharedMem);
    TEEC_ReleaseSharedMemory(&sharedMem);
    sharedMem.flags = TEEC_MEM_INPUT;
    sharedMem.size = 1024 * 1024 * 1024;
    ret = TEEC_AllocateSharedMemory(&context, &sharedMem);
    TEEC_ReleaseSharedMemory(&sharedMem);
    sharedMem.flags = TEEC_MEM_INOUT;
    sharedMem.size = 1024;
    ret = TEEC_AllocateSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    TEEC_FinalizeContext(&context);
    TEEC_ReleaseSharedMemory(&sharedMem);
    ret = TEEC_InitializeContext(name, &context);
    ret = TEEC_AllocateSharedMemory(&context, &sharedMem);
    sharedMem.flags = TEEC_MEM_INOUT;
    sharedMem.size = 1024;
    ret = TEEC_AllocateSharedMemory(&context, &sharedMem);
    // 为了覆盖tee_client析构的释放流程，此处不释放alloc的内存
}

HWTEST_F(CaDaemonTest, CaDaemonTest_007, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_Result ret = TEEC_InitializeContext("CaDaemonTest_007", &context);
    TEEC_SharedMemory sharedMem;
    sharedMem.size = 1024;
    sharedMem.flags = TEEC_MEM_INPUT;
    ret = TEEC_AllocateSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    strcpy_s((char*)(sharedMem.buffer), sharedMem.size, "1122334455");
    strcpy_s((char*)(sharedMem.buffer) + 100, sharedMem.size, "100200300400");
    TEEC_Session session = { 0 };
    session.context = &context;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    operation.params[0].memref.parent = &sharedMem;
    operation.params[0].memref.parent->flags = 0;
    operation.params[0].memref.offset = 100;
    operation.params[0].memref.size = 10;
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    operation.params[0].memref.parent->flags = 1;
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    operation.params[0].memref.parent->flags = 1;
    operation.params[1].memref.parent = &sharedMem;
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = 0;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    printf("CaDaemonTest_007 01  TEEC_InvokeCommand ret=%x\n", ret);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    TEEC_ReleaseSharedMemory(&sharedMem);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_008, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_Result ret = TEEC_InitializeContext("CaDaemonTest_007", &context);
    TEEC_SharedMemory sharedMem;
    sharedMem.size = 1024;
    sharedMem.flags = TEEC_MEM_INPUT;
    ret = TEEC_AllocateSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    strcpy_s((char*)(sharedMem.buffer), sharedMem.size, "1122334455");
    strcpy_s((char*)(sharedMem.buffer) + 100, sharedMem.size, "100200300400");
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    printf("CaDaemonTest_007 operation.paramTypes=%x\n", operation.paramTypes);
    char tmpbuff[10] = { 0 };
    operation.params[0].tmpref.buffer = (void*)tmpbuff;
    operation.params[0].tmpref.size = 0;
    TEEC_Session session = { 0 };
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    operation.params[0].tmpref.buffer = nullptr;
    operation.params[0].tmpref.size = 0;
    session.context = &context;
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    operation.params[0].tmpref.buffer = (void*)tmpbuff;
    operation.params[0].tmpref.size = 0;
    session.context = &context;
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    operation.params[0].tmpref.buffer = nullptr;
    operation.params[0].tmpref.size = 1;
    session.context = &context;
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    operation.params[0].tmpref.buffer = (void*)tmpbuff;
    operation.params[0].tmpref.size = sizeof(tmpbuff);
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    TEEC_ReleaseSharedMemory(&sharedMem);
    TEEC_FinalizeContext(&context);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_008_01, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_Result ret = TEEC_InitializeContext("CaDaemonTest_008", &context);
    TEEC_SharedMemory sharedMem;
    sharedMem.size = 1024;
    sharedMem.flags = TEEC_MEM_INPUT;
    ret = TEEC_AllocateSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    strcpy_s((char*)(sharedMem.buffer), sharedMem.size, "1122334455");
    strcpy_s((char*)(sharedMem.buffer) + 100, sharedMem.size, "100200300400");
    char tmpbuff[10] = { 0 };
    TEEC_Operation operation = { 0 };
    TEEC_Session session = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
    operation.params[0].tmpref.buffer = (void*)tmpbuff;
    operation.params[0].tmpref.size = 1;
    operation.params[1].tmpref.buffer = (void*)tmpbuff;
    operation.params[1].tmpref.size = -1;
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT,
        TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);
    operation.params[0].tmpref.buffer = (void*)tmpbuff;
    operation.params[0].tmpref.size = 1;
    operation.params[1].tmpref.buffer = (void*)tmpbuff;
    operation.params[1].tmpref.size = -1;
    operation.params[2].tmpref.buffer = (void*)tmpbuff;
    operation.params[2].tmpref.size = 1;
    operation.params[3].tmpref.buffer = (void*)tmpbuff;
    operation.params[3].tmpref.size = -1;
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    char *tmpbuff2 = new char[1024 * 1024];
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].tmpref.buffer = (void*)tmpbuff2;
    operation.params[0].tmpref.size = -1;
    ret = TEEC_InvokeCommand(&session, 1, &operation, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    delete[] tmpbuff2;
    TEEC_ReleaseSharedMemory(&sharedMem);
    TEEC_FinalizeContext(&context);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_009, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_Session session = { 0 };
    session.context = &context;
    TEEC_Result ret = TEEC_SendSecfile(nullptr, &session);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    ret = TEEC_SendSecfile("/unittest/test.sec", &session);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    FILE *fp = fopen("/data/test.sec", "w");
    fclose(fp);
    ret = TEEC_SendSecfile("/data/test.mbn", &session);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    ret = TEEC_SendSecfile("/vendor/bin/teecd", &session);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    ret = TEEC_SendSecfile("/data/test.sec", &session);
    (void)remove("/data/test.sec");
    EXPECT_TRUE(ret != TEEC_SUCCESS);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_010, TestSize.Level1)
{
    char name[] = "CaDaemonTest_010";
    TEEC_Context context = { 0 };
    TEEC_Session session = { 0 };
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    uint32_t origin;
    TEEC_Result ret = TEEC_InitializeContext(nullptr, &context);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    TEEC_SharedMemory sharedMem = { 0 };
    sharedMem.buffer = (void*)name;
    sharedMem.flags = TEEC_MEM_INPUT;
    sharedMem.size = 10;
    ret = TEEC_RegisterSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = 5;
    ret = TEEC_OpenSession(&context, &session, &g_testUuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
}

HWTEST_F(CaDaemonTest, CaDaemonTest_011, TestSize.Level1)
{
    char name[] = "CaDaemonTest_011";
    TEEC_Context context = { 0 };
    TEEC_Result ret = TEEC_InitializeContext(name, &context);
    TEEC_FinalizeContext(&context);
    TEEC_SharedMemory sharedMem = { 0 };
    sharedMem.buffer = (void*)name;
    sharedMem.flags = TEEC_MEM_INPUT;
    ret = TEEC_RegisterSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    TEEC_ReleaseSharedMemory(&sharedMem);
    sharedMem.buffer = (void*)name;
    sharedMem.flags = TEEC_MEM_INPUT;
    ret = TEEC_RegisterSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret != TEEC_SUCCESS);
    sharedMem.context->fd = 0xfff;
    TEEC_ReleaseSharedMemory(&sharedMem);
    for (int i = 0; i < 20; i++) {
        (void)TEEC_InitializeContext(nullptr, &context);
    }
}
}