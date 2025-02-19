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
#include <securec.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include "tee_client_type.h"
#include "tee_log.h"
#include "tc_ns_client.h"
#include "tui_event.h"
#include <dlfcn.h>
#include "stubMock.h"

using namespace testing;
using namespace testing::ext;
using namespace std;
using namespace OHOS::PowerMgr;
using namespace OHOS::Rosen;
using namespace OHOS::Telephony;
extern "C" void TeeTuiThreadWork(void);
extern "C" int32_t GetEvent(char *eventParam, int *paramLen);
extern "C" void HandleEvent(const char *eventParam, int32_t paramLen);

class TUIDaemonTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TUIDaemonTest::SetUpTestCase(void)
{
    printf("SetUp\n");
}

void TUIDaemonTest::TearDownTestCase(void)
{
    printf("SetUpTestCase\n");
}

void TUIDaemonTest::SetUp(void)
{
    printf("TearDownTestCase\n");
}

void TUIDaemonTest::TearDown(void)
{
    printf("TearDown\n");
}
namespace {
/**
 * @tc.name: TUIDaemonInit_001
 * @tc.desc: Check Tui Daemon init.
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(TUIDaemonTest, TUIDaemonInit_001, TestSize.Level1)
{
    auto tuiDaemon = new TUIDaemon();
    tuiDaemon->TuiDaemonInit(true);
    EXPECT_TRUE(tuiDaemon->mTUIDisplayListener_ == nullptr);
}

/**
 * @tc.name: GetTUIEventInstance_001
 * @tc.desc: Check Tui Event status.
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(TUIDaemonTest, GetTUIEventInstance_001, TestSize.Level1)
{
    /* check get instance */
    auto TmpInstance = TUIEvent::GetInstance();
    EXPECT_TRUE(TmpInstance != nullptr);

    /* get & set status */
    auto status = TmpInstance->TUIGetStatus();
    EXPECT_TRUE(status == false);
    TmpInstance->TUISetStatus(true);
    status = TmpInstance->TUIGetStatus();
    EXPECT_TRUE(status);
    TmpInstance->TUISetStatus(false);
    status = TmpInstance->TUIGetStatus();
    EXPECT_TRUE(status == false);
}

/**
 * @tc.name: GetTUIEventInstance_002
 * @tc.desc: Check Tui event runninglock status.
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(TUIDaemonTest, GetTUIEventInstance_002, TestSize.Level1)
{
    /* check get instance */
    auto TmpInstance = TUIEvent::GetInstance();
    EXPECT_TRUE(TmpInstance != nullptr);

    /* get & release lock */
    TmpInstance->TUIGetRunningLock();
    TmpInstance->TUIReleaseRunningLock();
}

/**
 * @tc.name: DealWithState_001
 * @tc.desc: Test Tui event DealWithState.
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(TUIDaemonTest, DealWithState_001, TestSize.Level1)
{
    auto TmpInstance = TUIEvent::GetInstance();
    EXPECT_TRUE(TmpInstance != nullptr);

    auto status = TmpInstance->TUIGetStatus();
    EXPECT_TRUE(status == false);
    TmpInstance->TUIDealWithEvent(true);
    status = TmpInstance->TUIGetStatus();
    EXPECT_TRUE(status == true);
    TmpInstance->TUIDealWithEvent(false);
    status = TmpInstance->TUIGetStatus();
    EXPECT_TRUE(status == false);
}

/**
 * @tc.name: DealWithState_002
 * @tc.desc: Test Tui event DealWithState.
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(TUIDaemonTest, DealWithState_002, TestSize.Level1)
{
    auto TmpInstance = TUIEvent::GetInstance();
    EXPECT_TRUE(TmpInstance != nullptr);

    auto status = TmpInstance->TUIGetStatus();
    EXPECT_TRUE(status == false);
    TmpInstance->TUIDealWithEvent(false);
    status = TmpInstance->TUIGetStatus();
    EXPECT_TRUE(status == false);
    TmpInstance->TUIDealWithEvent(true);
    status = TmpInstance->TUIGetStatus();
    EXPECT_TRUE(status == true);
}

HWTEST_F(TUIDaemonTest, TeeTuiThreadWork_001, TestSize.Level1)
{
    char tmp;
    int ret = GetEvent(nullptr, nullptr);
    EXPECT_TRUE(ret == -1);
    ret = GetEvent(&tmp, nullptr);
    EXPECT_TRUE(ret == -1);
    AddMockStub obj;
    SetGlobalStubMock(&obj);
    EXPECT_CALL(obj, GetEventParamFromTui).WillRepeatedly(Return(-1));
    char param1[] = "unused";
    int paramLen = 0;
    ret = GetEvent(param1, &paramLen);
    EXPECT_TRUE(ret == -1);
    ret = GetEvent(param1, &paramLen);
    EXPECT_TRUE(ret == -1);
    char param2[] = "config";
    ret = GetEvent(param2, &paramLen);
    EXPECT_TRUE(ret == -1);
    ret = GetEvent(param2, &paramLen);
    EXPECT_TRUE(ret == -1);
    HandleEvent(nullptr, 0);
    HandleEvent(&tmp, 0);
    HandleEvent(param1, 7);
    HandleEvent(param2, 7);
    char param3[] = "unknow";
    HandleEvent(param3, 7);
    SetGlobalStubMock(nullptr);
}

HWTEST_F(TUIDaemonTest, TeeTuiThreadWork_002, TestSize.Level1)
{
    auto tmp1 = new TUIDisplayListener();
    tmp1->OnFoldStatusChanged(OHOS::Rosen::FoldStatus::EXPAND);
    tmp1->OnFoldStatusChanged(OHOS::Rosen::FoldStatus::FOLDED);
    tmp1->OnFoldStatusChanged(OHOS::Rosen::FoldStatus::UNKNOWN);

    auto tmp2 = new TUICallManagerCallback();
    OHOS::Telephony::CallAttributeInfo info;
    info.callState = OHOS::Telephony::TelCallState::CALL_STATUS_INCOMING;
    tmp2->OnCallDetailsChange(info);
    AddMockStub obj;
    SetGlobalStubMock(&obj);
    EXPECT_CALL(obj, GetEventParamFromTui).WillRepeatedly(Return(-1));
    TeeTuiThreadWork();
    EXPECT_CALL(obj, GetEventParamFromTui).WillOnce(Return(1)).WillRepeatedly(Return(-1));
    TeeTuiThreadWork();
    SetGlobalStubMock(nullptr);
}
}