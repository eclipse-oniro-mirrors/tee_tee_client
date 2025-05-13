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
#include "tee_client.h"
#include "tee_log.h"
#include "tc_ns_client.h"
#include "tee_client_ext_api.h"
#include "tee_client_api.h"
#include "tee_client_inner_api.h"
#include "tee_client_app_load.h"

using namespace testing::ext;
using namespace OHOS;
class TeecVendorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TeecVendorTest::SetUpTestCase(void)
{
    printf("SetUp\n");
}

void TeecVendorTest::TearDownTestCase(void)
{
    printf("SetUpTestCase\n");
}

void TeecVendorTest::SetUp(void)
{
    printf("TearDownTestCase\n");
}

void TeecVendorTest::TearDown(void)
{
    printf("TearDown\n");
}
namespace {
HWTEST_F(TeecVendorTest, SetBitTest_001, TestSize.Level1)
{
    uint32_t i = 0, byteMax = 0;
    uint8_t bitMap = 0;

    SetBit(i, byteMax, nullptr);

    byteMax = 1;
    SetBit(i, byteMax, nullptr);

    SetBit(i, byteMax, &bitMap);
    EXPECT_TRUE(bitMap != 0);
}

HWTEST_F(TeecVendorTest, CheckBitTest_001, TestSize.Level1)
{
    uint32_t i = 0, byteMax = 0;
    uint8_t bitMap = 0;

    bool ret = CheckBit(i, byteMax, nullptr);
    EXPECT_TRUE(ret == false);

    byteMax = 1;
    ret = CheckBit(i, byteMax, nullptr);
    EXPECT_TRUE(ret == false);

    ret = CheckBit(i, byteMax, &bitMap);
    EXPECT_TRUE(ret == false);
}

HWTEST_F(TeecVendorTest, ClearBitTest_001, TestSize.Level1)
{
    uint32_t i = 0, byteMax = 0;
    uint8_t bitMap = 0;

    ClearBit(i, byteMax, nullptr);
    EXPECT_TRUE(bitMap == 0);

    byteMax = 1;
    ClearBit(i, byteMax, nullptr);
    EXPECT_TRUE(bitMap == 0);

    ClearBit(i, byteMax, &bitMap);
    EXPECT_TRUE(bitMap == 0);
}

HWTEST_F(TeecVendorTest, GetAndSetBitTest_001, TestSize.Level1)
{
    uint8_t bitMap[1] = { 0 };
    uint32_t byteMax = 0;

    int32_t ret = GetAndSetBit(nullptr, byteMax);
    EXPECT_TRUE(ret != 0);

    byteMax = 1;
    ret = GetAndSetBit(bitMap, byteMax);
    EXPECT_TRUE(ret != -1);

    bitMap[0] = 0xff;
    ret = GetAndSetBit(bitMap, byteMax);
    EXPECT_TRUE(ret != 0);
}

HWTEST_F(TeecVendorTest, GetAndCleartBitTest_001, TestSize.Level1)
{
    uint8_t bitMap[1] = { 0 };
    uint32_t byteMax = 0;

    int32_t ret = GetAndCleartBit(nullptr, byteMax);
    EXPECT_TRUE(ret != 0);

    byteMax = 1;
    ret = GetAndCleartBit(bitMap, byteMax);
    EXPECT_TRUE(ret != 0);

    bitMap[0] = 0xff;
    ret = GetAndCleartBit(bitMap, byteMax);
    EXPECT_TRUE(ret != -1);
}

HWTEST_F(TeecVendorTest, TEEC_RegisterSharedMemoryInnerTest_001, TestSize.Level1)
{
    TEEC_ContextInner context = { 0 };
    TEEC_SharedMemoryInner sharedMem = { 0 };

    TEEC_Result ret = TEEC_RegisterSharedMemoryInner(nullptr, &sharedMem);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    ret = TEEC_RegisterSharedMemoryInner(&context, nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    sharedMem.buffer = nullptr;
    ret = TEEC_RegisterSharedMemoryInner(&context, &sharedMem);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    char buffer[4] = { 0 };
    sharedMem.buffer = buffer;
    sharedMem.flags = 0xffffffff;
    ret = TEEC_RegisterSharedMemoryInner(&context, &sharedMem);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);
}

HWTEST_F(TeecVendorTest, TEEC_RegisterSharedMemoryTest_001, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_SharedMemory sharedMem = { 0 };

    TEEC_Result ret = TEEC_RegisterSharedMemory(nullptr, &sharedMem);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    ret = TEEC_RegisterSharedMemory(&context, nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    ret = TEEC_InitializeContext(nullptr, &context);
    EXPECT_TRUE(ret == TEEC_SUCCESS);

    char buf[4] = { 0 };
    sharedMem.buffer = buf;
    sharedMem.size = 4;
    sharedMem.flags = TEEC_MEM_INPUT;
    ret = TEEC_RegisterSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
}

HWTEST_F(TeecVendorTest, TEEC_AllocateSharedMemoryTest_001, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_SharedMemory sharedMem = { 0 };

    PutBnShrMem(nullptr);

    TEEC_Result result = TEEC_AllocateSharedMemory(nullptr, &sharedMem);
    EXPECT_TRUE(result == TEEC_ERROR_BAD_PARAMETERS);

    result = TEEC_RegisterSharedMemory(&context, nullptr);
    EXPECT_TRUE(result == TEEC_ERROR_BAD_PARAMETERS);

    result = TEEC_InitializeContext(nullptr, &context);
    EXPECT_TRUE(result == TEEC_SUCCESS);
    sharedMem.size = 4;
    sharedMem.flags = TEEC_MEM_INPUT;
    result = TEEC_AllocateSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(result == TEEC_SUCCESS);

    TEEC_ReleaseSharedMemory(&sharedMem);
}

HWTEST_F(TeecVendorTest, TEEC_CheckTmpRefTest_001, TestSize.Level1)
{
    TEEC_ContextInner context = { 0 };
    TEEC_Operation operation = { 0 };
    operation.started = 1;

    operation.paramTypes = TEEC_MEMREF_TEMP_INPUT;
    operation.params[0].tmpref.buffer = nullptr;
    operation.params[0].tmpref.size = 1;
    TEEC_Result ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.paramTypes = TEEC_MEMREF_TEMP_INPUT;
    operation.params[0].tmpref.buffer = (void*)1;
    operation.params[0].tmpref.size = 0;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);
}

HWTEST_F(TeecVendorTest, TEEC_CheckMemRefTest_001, TestSize.Level1)
{
    TEEC_ContextInner context = { 0 };
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_MEMREF_PARTIAL_INPUT;

    operation.params[0].memref.parent = nullptr;
    TEEC_Result ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    TEEC_SharedMemory sharedMem = { 0 };
    operation.params[0].memref.parent = &sharedMem;
    operation.params[0].memref.parent->buffer = nullptr;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    char buf[4] = { 0 };
    operation.params[0].memref.parent->buffer = (void*)buf;
    operation.params[0].memref.parent->size = 0;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.params[0].memref.parent->size = 4;
    operation.params[0].memref.parent->flags = 0;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.paramTypes = TEEC_MEMREF_PARTIAL_OUTPUT;
    operation.params[0].memref.parent->flags = 0;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.paramTypes = TEEC_MEMREF_PARTIAL_INOUT;
    operation.params[0].memref.parent->flags = 0;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.paramTypes = TEEC_MEMREF_PARTIAL_INOUT;
    operation.params[0].memref.parent->flags = TEEC_MEM_INPUT;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.paramTypes = TEEC_MEMREF_WHOLE;
    operation.params[0].memref.parent->flags = TEEC_MEM_INOUT;
    operation.params[0].memref.parent->is_allocated = 0;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
}

HWTEST_F(TeecVendorTest, TEEC_CheckMemRefTest_002, TestSize.Level1)
{
    TEEC_ContextInner context = { 0 };
    TEEC_Operation operation = { 0 };
    operation.started = 1;

    TEEC_SharedMemory sharedMem = { 0 };
    operation.params[0].memref.parent = &sharedMem;

    char buf[4] = { 0 };
    operation.params[0].memref.parent->buffer = (void*)buf;
    operation.params[0].memref.parent->size = 4;
    operation.params[0].memref.offset = 1;
    operation.params[0].memref.size = 4;

    operation.paramTypes = TEEC_MEMREF_PARTIAL_INPUT;
    operation.params[0].memref.parent->flags = TEEC_MEM_INPUT;
    TEEC_Result ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.paramTypes = TEEC_MEMREF_PARTIAL_OUTPUT;
    operation.params[0].memref.parent->flags = TEEC_MEM_OUTPUT;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.paramTypes = TEEC_MEMREF_PARTIAL_INOUT;
    operation.params[0].memref.parent->flags = TEEC_MEM_INOUT;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);
}

HWTEST_F(TeecVendorTest, CheckSharedBufferExistTest_002, TestSize.Level1)
{
    TEEC_Operation operation = { 0 };
    operation.started = 1;

    TEEC_SharedMemory sharedMem = { 0 };
    operation.params[0].memref.parent = &sharedMem;

    char buf[4] = { 0 };
    operation.params[0].memref.parent->buffer = (void*)buf;
    operation.params[0].memref.parent->size = 4;
    operation.params[0].memref.offset = 0;

    operation.paramTypes = TEEC_MEMREF_WHOLE;
    operation.params[0].memref.parent->is_allocated = 1;

    TEEC_Result ret = TEEC_CheckOperation(nullptr, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);
}

HWTEST_F(TeecVendorTest, TEEC_CheckOperationTest_001, TestSize.Level1)
{
    TEEC_ContextInner context = { 0 };
    TEEC_Operation operation = { 0 };

    TEEC_Result ret = TEEC_CheckOperation(&context, nullptr);
    EXPECT_TRUE(ret == TEEC_SUCCESS);

    operation.started = 0;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_NOT_IMPLEMENTED);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_ION_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT);
    operation.params[0].ionref.ion_share_fd = -1;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_ION_SGLIST_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT);
    operation.params[0].ionref.ion_share_fd = -1;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_ION_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT);
    operation.params[0].ionref.ion_share_fd = 0;
    operation.params[0].ionref.ion_size = 0;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_ION_SGLIST_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT, TEEC_ION_INPUT);
    operation.params[0].ionref.ion_share_fd = 0;
    operation.params[0].ionref.ion_size = 0;
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_MEMREF_SHARED_INOUT, TEEC_NONE);
    ret = TEEC_CheckOperation(&context, &operation);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
}

HWTEST_F(TeecVendorTest, TEEC_RequestCancellationTest_001, TestSize.Level1)
{
    TEEC_Operation operation = { 0 };

    GetBnShmByOffset(0, nullptr);
    TEEC_RequestCancellation(nullptr);

    operation.session = nullptr;
    TEEC_RequestCancellation(&operation);

    TEEC_Session session = { 0 };
    operation.session = &session;
    session.context = nullptr;
    TEEC_RequestCancellation(&operation);

    TEEC_Context context = { 0 };
    TEEC_Result result = TEEC_InitializeContext(nullptr, &context);
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    TEEC_UUID uuid = { 0xabe89147, 0xcd61, 0xf43f, { 0x71, 0xc4, 0x1a, 0x31, 0x7e, 0x40, 0x53, 0x12 } };
    result = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, nullptr);
    EXPECT_TRUE(result == TEEC_ERROR_GENERIC);

    TEEC_RequestCancellation(&operation);
}

HWTEST_F(TeecVendorTest, TEEC_EXT_RegisterAgentTest_001, TestSize.Level1)
{
    int devFd = 0;
    char *buf = nullptr;

    TEEC_Result ret = TEEC_EXT_RegisterAgent(0, nullptr, (void **)nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_GENERIC);

    ret = TEEC_EXT_RegisterAgent(0, &devFd, (void **)nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_GENERIC);

    ret = TEEC_EXT_RegisterAgent(0, &devFd, (void **)&buf);
    EXPECT_TRUE(ret == TEEC_ERROR_GENERIC);
}

HWTEST_F(TeecVendorTest, TEEC_EXT_WaitEventTest_001, TestSize.Level1)
{
    TEEC_Result ret = TEEC_EXT_WaitEvent(0, 0);
    EXPECT_TRUE(ret == TEEC_ERROR_GENERIC);
}

HWTEST_F(TeecVendorTest, TEEC_EXT_SendEventResponseTest_001, TestSize.Level1)
{
    TEEC_Result ret = TEEC_EXT_SendEventResponse(0, 0);
    EXPECT_TRUE(ret == TEEC_ERROR_GENERIC);
}

HWTEST_F(TeecVendorTest, TEEC_EXT_UnregisterAgentTest_001, TestSize.Level1)
{
    char *buf = nullptr;

    TEEC_Result ret = TEEC_EXT_UnregisterAgent(0, 0, nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    ret = TEEC_EXT_UnregisterAgent(0, 0, (void**)&buf);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    char buf2[4] = { 0 };
    ret = TEEC_EXT_UnregisterAgent(0, -1, (void **)&buf2);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);
}

HWTEST_F(TeecVendorTest, TEEC_SendSecfileTest_001, TestSize.Level1)
{
    TEEC_Result ret = TEEC_SendSecfile(nullptr, nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    char path[] = "/data/app/el2/100/base/com.huawei.hmos.skytone/files/abe89147-cd61-f43f-71c4-1a317e405312.sec";
    ret = TEEC_SendSecfile(path, nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    TEEC_Session session = { 0 };
    session.context = nullptr;
    ret = TEEC_SendSecfile(path, &session);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    TEEC_UUID uuid = { 0xabe89147, 0xcd61, 0xf43f, { 0x71, 0xc4, 0x1a, 0x31, 0x7e, 0x40, 0x53, 0x12 } };
    TEEC_Context context = { 0 };
    ret = TEEC_InitializeContext(nullptr, &context);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_GENERIC);
    ret = TEEC_SendSecfile(path, &session);
    EXPECT_TRUE(ret != TEEC_ERROR_BAD_PARAMETERS);
}

HWTEST_F(TeecVendorTest, TEEC_SendSecfileInnerTest_001, TestSize.Level1)
{
    TEEC_Result result = TEEC_SendSecfileInner(nullptr, 0, nullptr);
    EXPECT_TRUE(result == TEEC_ERROR_BAD_PARAMETERS);

    char path[] = "/data/app/el2/100/base/com.huawei.hmos.skytone/files/abe89147-cd61-f43f-71c4-1a317e405312.sec";
    result = TEEC_SendSecfileInner(path, 0, nullptr);
    EXPECT_TRUE(result == 13);
}

HWTEST_F(TeecVendorTest, TEEC_OpenSessionTest_001, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_Session session = { 0 };
    TEEC_UUID uuid = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f }};

    TEEC_Result ret = TEEC_OpenSession(nullptr, nullptr, nullptr, TEEC_LOGIN_IDENTIFY, nullptr, nullptr, nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    ret = TEEC_OpenSession(&context, nullptr, nullptr, TEEC_LOGIN_IDENTIFY, nullptr, nullptr, nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    ret = TEEC_OpenSession(&context, &session, nullptr, TEEC_LOGIN_IDENTIFY, nullptr, nullptr, nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, nullptr, nullptr, nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);
}

HWTEST_F(TeecVendorTest, TEEC_OpenSessionInnerTest_001, TestSize.Level1)
{
    int callingPid = 0;
    TaFileInfo taFile;
    taFile.taFp   = nullptr;
    char path[] = "/vendor/bin/95b9ad1e-0af8-4201-9891-0dbe8602f35f.sec";
    taFile.taPath = (uint8_t*)path;

    TEEC_ContextInner contextInner = { 0 };
    TEEC_Session session = { 0 };
    TEEC_UUID destination = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f }};
    TEEC_Operation operation = { 0 };
    uint32_t retOrigin = 0;

    TEEC_Result ret = TEEC_OpenSessionInner(callingPid, &taFile, nullptr, &session, &destination,
        TEEC_LOGIN_IDENTIFY, nullptr, &operation, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    ret = TEEC_OpenSessionInner(callingPid, nullptr, &contextInner, &session, &destination,
        TEEC_LOGIN_IDENTIFY, nullptr, &operation, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, nullptr, &destination,
        TEEC_LOGIN_IDENTIFY, nullptr, &operation, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, nullptr,
        TEEC_LOGIN_IDENTIFY, nullptr, &operation, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
        ~TEEC_LOGIN_IDENTIFY, nullptr, &operation, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
        TEEC_LOGIN_IDENTIFY, (void*)&callingPid, &operation, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.started = 0;
    ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
        TEEC_LOGIN_IDENTIFY, nullptr, nullptr, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_GENERIC);

    operation.started = 0;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
        TEEC_LOGIN_IDENTIFY, nullptr, &operation, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_NOT_IMPLEMENTED);
}

HWTEST_F(TeecVendorTest, TEEC_OpenSessionInnerTest_002, TestSize.Level1)
{
    int callingPid = 0;
    uint32_t retOrigin = 0;
    TaFileInfo taFile;
    taFile.taFp   = nullptr;
    char path[] = "/vendor/bin/95b9ad1e-0af8-4201-9891-0dbe8602f35f";
    taFile.taPath = (uint8_t *)path;

    TEEC_ContextInner contextInner = { 0 };
    TEEC_Session session = { 0 };
    TEEC_UUID destination = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f }};

    TEEC_Result ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
        TEEC_LOGIN_IDENTIFY, nullptr, nullptr, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_GENERIC);
}

HWTEST_F(TeecVendorTest, TEEC_EncodeParamTest_001, TestSize.Level1)
{
    int callingPid = 0;
    uint32_t retOrigin = 0;
    TaFileInfo taFile;
    taFile.taFp   = nullptr;
    char path[] = "/vendor/bin/95b9ad1e-0af8-4201-9891-0dbe8602f35f.sec";
    taFile.taPath = (uint8_t *)path;

    TEEC_ContextInner contextInner = { 0 };
    TEEC_Session session = { 0 };
    TEEC_UUID destination = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f }};
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    char buf[4] = { 0 };
    operation.params[0].tmpref.buffer = (void*)buf;
    operation.params[0].tmpref.size = 4;
    TEEC_Result ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
        TEEC_LOGIN_IDENTIFY, nullptr, &operation, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_GENERIC);
}

HWTEST_F(TeecVendorTest, TEEC_EncodePartialParamTest_001, TestSize.Level1)
{
    int callingPid = 0;
    uint32_t retOrigin = 0;
    TaFileInfo taFile;
    taFile.taFp   = nullptr;
    char path[] = "/vendor/bin/95b9ad1e-0af8-4201-9891-0dbe8602f35f.sec";
    taFile.taPath = (uint8_t *)path;

    char buf[4] = { 0 };
    TEEC_ContextInner contextInner = { 0 };
    TEEC_Session session = { 0 };
    TEEC_UUID destination = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f }};
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_SHARED_INOUT, TEEC_NONE, TEEC_NONE);
    TEEC_SharedMemory sharedMem0 = { 0 }, sharedMem1 = { 0 };
    operation.params[0].memref.parent = &sharedMem0;
    operation.params[0].memref.parent->is_allocated = 0;
    operation.params[0].memref.parent->buffer = (void*)buf;
    operation.params[0].memref.parent->size = 4;
    operation.params[0].memref.size = 4;
    operation.params[0].memref.offset = 0;
    operation.params[1].memref.parent = &sharedMem1;
    operation.params[1].memref.parent->is_allocated = 1;
    operation.params[1].memref.parent->buffer = (void*)buf;
    operation.params[1].memref.parent->size = 4;
    operation.params[1].memref.size = 4;
    operation.params[1].memref.offset = 0;
    TEEC_Result ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
        TEEC_LOGIN_IDENTIFY, nullptr, &operation, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);
}

HWTEST_F(TeecVendorTest, TranslateParamTypeTest_001, TestSize.Level1)
{
    int callingPid = 0;
    uint32_t retOrigin = 0;
    TaFileInfo taFile;
    taFile.taFp   = nullptr;
    char path[] = "/vendor/bin/95b9ad1e-0af8-4201-9891-0dbe8602f35f.sec";
    taFile.taPath = (uint8_t*)path;

    char buf[4] = { 0 };
    TEEC_ContextInner contextInner = { 0 };
    TEEC_Session session = { 0 };
    TEEC_UUID destination = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f }};
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);
    TEEC_SharedMemory sharedMem = { 0 };
    operation.params[0].memref.parent = &sharedMem;
    operation.params[0].memref.parent->is_allocated = 0;
    operation.params[0].memref.parent->flags = TEEC_MEM_INPUT;
    operation.params[0].memref.parent->buffer = (void*)buf;
    operation.params[0].memref.parent->size = 4;
    operation.params[0].memref.size = 4;
    operation.params[0].memref.offset = 0;
    operation.params[1].memref.parent = &sharedMem;
    operation.params[1].memref.parent->is_allocated = 0;
    operation.params[1].memref.parent->flags = TEEC_MEM_OUTPUT;
    operation.params[1].memref.parent->buffer = (void*)buf;
    operation.params[1].memref.parent->size = 4;
    operation.params[1].memref.size = 4;
    operation.params[1].memref.offset = 0;

    TEEC_Result ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
        TEEC_LOGIN_IDENTIFY, nullptr, &operation, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_GENERIC);

    operation.params[0].memref.parent->flags = TEEC_MEM_INOUT;
    operation.params[1].memref.parent->flags = 0xffffffff;
    ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
        TEEC_LOGIN_IDENTIFY, nullptr, &operation, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_GENERIC);
}

HWTEST_F(TeecVendorTest, TEEC_EncodeIonParam_001, TestSize.Level1)
{
    int callingPid = 0;
    uint32_t retOrigin = 0;
    TaFileInfo taFile;
    taFile.taFp   = nullptr;
    char path[] = "/vendor/bin/95b9ad1e-0af8-4201-9891-0dbe8602f35f.sec";
    taFile.taPath = (uint8_t*)path;

    TEEC_ContextInner contextInner = { 0 };
    TEEC_Session session = { 0 };
    TEEC_UUID destination = { 0x95b9ad1e, 0x0af8, 0x4201, { 0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f }};
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_ION_INPUT, TEEC_ION_SGLIST_INPUT, TEEC_NONE, TEEC_NONE);
    operation.params[0].ionref.ion_share_fd = 0;
    operation.params[0].ionref.ion_size = 1;
    operation.params[1].ionref.ion_share_fd = 0;
    operation.params[1].ionref.ion_size = 1;

    TEEC_Result ret = TEEC_OpenSessionInner(callingPid, &taFile, &contextInner, &session, &destination,
        TEEC_LOGIN_IDENTIFY, nullptr, &operation, &retOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_GENERIC);
}


HWTEST_F(TeecVendorTest, TEEC_CloseSessionInnerTest_001, TestSize.Level1)
{
    TEEC_Session session = { 0 };
    TEEC_ContextInner contextInner = { 0 };


    (void)TEEC_CloseSessionInner(nullptr, nullptr);
    (void)TEEC_CloseSessionInner(&session, nullptr);

    TEEC_Context context = { 0 };
    TEEC_Result result = TEEC_InitializeContext(nullptr, &context);
    EXPECT_TRUE(result == TEEC_SUCCESS);
    (void)TEEC_CloseSessionInner(&session, &contextInner);
}

HWTEST_F(TeecVendorTest, TEEC_ReleaseSharedMemoryTest_001, TestSize.Level1)
{
    TEEC_Context context = { 0 };
    TEEC_SharedMemory sharedMem = { 0 };
    TEEC_SharedMemoryInner sharedMemInner = { 0 };

    TEEC_ReleaseSharedMemoryInner(nullptr);
    sharedMemInner.context = nullptr;
    TEEC_ReleaseSharedMemoryInner(&sharedMemInner);

    sharedMem.context = nullptr;
    TEEC_Result ret = TEEC_InitializeContext(nullptr, &context);
    EXPECT_TRUE(ret == TEEC_SUCCESS);

    char buf[4] = { 0 };
    sharedMem.buffer = buf;
    sharedMem.size = 4;
    sharedMem.flags = TEEC_MEM_INPUT;
    ret = TEEC_RegisterSharedMemory(&context, &sharedMem);
    EXPECT_TRUE(ret == TEEC_SUCCESS);

    TEEC_ReleaseSharedMemory(&sharedMem);
}

HWTEST_F(TeecVendorTest, TEEC_InvokeCommandTest_001, TestSize.Level1)
{
    TEEC_Session session = { 0 };
    TEEC_Operation operation = { 0 };
    uint32_t returnOrigin = 0;

    TEEC_Result ret = TEEC_InvokeCommand(nullptr, 0, &operation, &returnOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    session.context = nullptr;
    ret = TEEC_InvokeCommand(&session, 0, nullptr, &returnOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    TEEC_Context context = { 0 };
    TEEC_ContextInner contextInner = { 0 };

    GetBnSession(nullptr, &contextInner);
    GetBnSession(&session, nullptr);

    ret = TEEC_InitializeContext(nullptr, &context);
    EXPECT_TRUE(ret == TEEC_SUCCESS);
    TEEC_UUID uuid = { 0xabe89147, 0xcd61, 0xf43f, { 0x71, 0xc4, 0x1a, 0x31, 0x7e, 0x40, 0x53, 0x12 } };
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, nullptr, nullptr, nullptr);
    EXPECT_TRUE(ret != TEEC_SUCCESS);

    session.context = &context;
    ret = TEEC_InvokeCommand(&session, 0, nullptr, &returnOrigin);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);
    TEEC_CloseSession(&session);
    PutBnSession(nullptr);
    TEEC_FinalizeContext(&context);
}

HWTEST_F(TeecVendorTest, TEEC_InvokeCommandInnerTest_001, TestSize.Level1)
{
    TEEC_ContextInner context = { 0 };
    TEEC_Session session = { 0 };
    TEEC_Operation operation = { 0 };

    TEEC_CloseSession(nullptr);
    session.context = nullptr;
    TEEC_CloseSession(&session);

    TEEC_Result ret = TEEC_InvokeCommandInner(nullptr, &session, 0, nullptr, nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    ret = TEEC_InvokeCommandInner(&context, nullptr, 0, nullptr, nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_BAD_PARAMETERS);

    operation.started = 0;
    ret = TEEC_InvokeCommandInner(&context, &session, 0, &operation, nullptr);
    EXPECT_TRUE(ret == TEEC_ERROR_NOT_IMPLEMENTED);
}
}
