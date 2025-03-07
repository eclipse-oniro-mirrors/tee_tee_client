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
#include "load_sec_file.h"

using namespace testing::ext;
class LoadSecfileTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void LoadSecfileTest::SetUpTestCase(void)
{
    printf("SetUp\n");
}

void LoadSecfileTest::TearDownTestCase(void)
{
    printf("TearDownTestCase\n");
}

void LoadSecfileTest::SetUp(void)
{
    printf("SetUpTestCase\n");
}

void LoadSecfileTest::TearDown(void)
{
    printf("TearDown\n");
}

namespace {
HWTEST_F(LoadSecfileTest, LoadSecfile_001, TestSize.Level1)
{
    int tzFd = -1;
    int ret = 0;

    ret = LoadSecfile(tzFd, nullptr, LOAD_TA, nullptr);
    EXPECT_TRUE(ret != 0);

    tzFd = 0;
    ret = LoadSecfile(tzFd, nullptr, LOAD_TA, nullptr);
    EXPECT_TRUE(ret != 0);
}

HWTEST_F(LoadSecfileTest, LoadSecfile_002, TestSize.Level1)
{
    int tzFd = 0;
    int ret = 0;

    FILE *fp = fopen("./LoadSecfile_002.txt", "w+");
    ret = LoadSecfile(tzFd, nullptr, LOAD_TA, nullptr);
    fclose(fp);
    EXPECT_TRUE(ret != 0);

    fp = fopen("./LoadSecfile_002.txt", "w+");
    (void)fseek(fp, MAX_BUFFER_LEN + 1, SEEK_SET);
    char chr = 0;
    fwrite(&chr, 1, sizeof(chr), fp);
    ret = LoadSecfile(tzFd, fp, LOAD_TA, nullptr);
    fclose(fp);
    EXPECT_TRUE(ret != 0);

    fp = fopen("./LoadSecfile_002.txt", "w+");
    fprintf(fp, "%s", "LoadSecfile_002");
    ret = LoadSecfile(tzFd, fp, LOAD_TA, nullptr);
    fclose(fp);
    EXPECT_TRUE(ret != 0);
}
}