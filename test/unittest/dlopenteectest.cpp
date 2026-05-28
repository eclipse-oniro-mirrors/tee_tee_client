/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <dlfcn.h>
#include "tee_client_type.h"
#include <cstdio>
#include <unistd.h>
#include "tee_log.h"
#include "tee_client_api.h"
#define LIB_NAME "libteec.so"
using namespace testing::ext;
class DlopenTeecTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

typedef TEEC_Result (*InitializeContextFunc)(const char *name, TEEC_Context *context);
typedef void (*FinalizeContextFunc)(TEEC_Context *context);
typedef TEEC_Result (*OpenSessionFunc)(TEEC_Context *context, TEEC_Session *session, const TEEC_UUID *destination,
    uint32_t connectionMethod, const void *connectionData, TEEC_Operation *operation, uint32_t *returnOrigin);
typedef void (*CloseSessionFunc)(TEEC_Session *session);
typedef TEEC_Result (*InvokeCommandFunc)(TEEC_Session *session, uint32_t commandID,
    TEEC_Operation *operation, uint32_t *returnOrigin);

void DlopenTeecTest::SetUpTestCase(void)
{
    printf("SetUp\n");
}

void DlopenTeecTest::TearDownTestCase(void)
{
    printf("SetUpTestCase\n");
}

void DlopenTeecTest::SetUp(void)
{
    printf("TearDownTestCase\n");
}

void DlopenTeecTest::TearDown(void)
{
    printf("TearDown\n");
}
#define RUNT_TIMES 2
HWTEST_F(DlopenTeecTest, LoadTeecTest1, TestSize.Level1)
{
    for (int i = 0; i < RUNT_TIMES; i++) {
        void *handle = dlopen(LIB_NAME, RTLD_LAZY);
        if (handle == nullptr) {
            tloge("dlopen libteec.so failed\n");
        }
        EXPECT_TRUE(handle != nullptr);

        InitializeContextFunc initializeContext = (InitializeContextFunc)dlsym(handle, "TEEC_InitializeContext");
        if (initializeContext == nullptr) {
            tloge("dlsym initializeContext failed\n");
        }
        EXPECT_TRUE(initializeContext != nullptr);

        TEEC_Context context = { 0 };
        (void)initializeContext(nullptr, &context);

        FinalizeContextFunc finalizeContext = (FinalizeContextFunc)dlsym(handle, "TEEC_FinalizeContext");
        EXPECT_TRUE(finalizeContext != nullptr);

        (void)finalizeContext(&context);

        int ret = dlclose(handle);
        if (ret != 0) {
            tloge("dlclose error: %s\n", dlerror());
        }
        EXPECT_TRUE(ret == 0);
    }
}

HWTEST_F(DlopenTeecTest, LoadTeecTest3, TestSize.Level1)
{
    void *handle = dlopen(LIB_NAME, RTLD_LAZY);
    if (handle == nullptr) {
            tloge("dlopen libteec.so failed\n");
    }
    EXPECT_TRUE(handle != nullptr);
    for (int i = 0; i < RUNT_TIMES; i++) {
        InitializeContextFunc initializeContext = (InitializeContextFunc)dlsym(handle, "TEEC_InitializeContext");
        if (initializeContext == nullptr) {
            tloge("dlsym initializeContext failed\n");
        }
        EXPECT_TRUE(initializeContext != nullptr);

        TEEC_Context context = { 0 };
        (void)initializeContext(nullptr, &context);

        FinalizeContextFunc finalizeContext = (FinalizeContextFunc)dlsym(handle, "TEEC_FinalizeContext");
        EXPECT_TRUE(finalizeContext != nullptr);

        (void)finalizeContext(&context);
    }
    int ret = dlclose(handle);
    if (ret != 0) {
        tloge("dlclose error: %s\n", dlerror());
    }
    EXPECT_TRUE(ret == 0);
}

HWTEST_F(DlopenTeecTest, LoadTeecTest2, TestSize.Level1)
{
    void *handle = dlopen(LIB_NAME, RTLD_LAZY);
    if (handle == nullptr) {
        tloge("dlopen libteec.so failed\n");
    }
    EXPECT_TRUE(handle != nullptr);

    int ret = dlclose(handle);
    if (ret != 0) {
        tloge("dlclose error: %s\n", dlerror());
    }
    EXPECT_TRUE(ret == 0);
}