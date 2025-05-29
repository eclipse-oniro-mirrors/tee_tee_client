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
#include "tee_get_native_cert.h"
#include "tcu_authentication.h"
#include "tee_auth_system.h"
#include "accesstoken_kit.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "bundle_mgr_mini_proxy.h"
#include "bundle_mgr_stub.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AppExecFwk;

class AuthenticationTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AuthenticationTest::SetUpTestCase(void)
{
    printf("SetUp\n");
}

void AuthenticationTest::TearDownTestCase(void)
{
    printf("SetUpTestCase\n");
}

void AuthenticationTest::SetUp(void)
{
    printf("TearDownTestCase\n");
}

void AuthenticationTest::TearDown(void)
{
    printf("TearDown\n");
}
namespace {
HWTEST_F(AuthenticationTest, ReadCmdLine_001, TestSize.Level1)
{
    int caPid = 0;
    char path[4] = { 0 };
    size_t pathLen = 4;

    int ret = TeeGetPkgName(caPid, path, pathLen);
    EXPECT_TRUE(ret != 0);
}

HWTEST_F(AuthenticationTest, TeeGetPkgName_001, TestSize.Level1)
{
    int caPid = 0;
    char path[4] = { 0 };
    size_t pathLen = 4;

    int ret = TeeGetPkgName(caPid, nullptr, MAX_PATH_LENGTH + 1);
    EXPECT_TRUE(ret != 0);

    ret = TeeGetPkgName(caPid, path, MAX_PATH_LENGTH + 1);
    EXPECT_TRUE(ret != 0);

    ret = TeeGetPkgName(caPid, path, 0);
    EXPECT_TRUE(ret != 0);

    caPid = 1;
    ret = TeeGetPkgName(caPid, path, pathLen);
    EXPECT_TRUE(ret != 0);
}

HWTEST_F(AuthenticationTest, TeeGetNativeCert_001, TestSize.Level1)
{
    uint8_t buffer[MAX_PATH_LENGTH] = { 0 };
    uint32_t len = MAX_PATH_LENGTH;
    int caPid = 1;
    unsigned int caUid = 0;

    int ret = TeeGetNativeCert(caPid, caUid, nullptr, nullptr);
    EXPECT_TRUE(ret != 0);

    ret = TeeGetNativeCert(caPid, caUid, &len, nullptr);
    EXPECT_TRUE(ret != 0);

    ret = TeeGetNativeCert(caPid, caUid, &len, buffer);
    EXPECT_TRUE(ret == 0);
}

HWTEST_F(AuthenticationTest, TcuAuthentication_001, TestSize.Level1)
{
    int ret = TcuAuthentication(HASH_TYPE_SYSTEM);
    EXPECT_TRUE(ret != 0);

    ret = TcuAuthentication(HASH_TYPE_VENDOR);
    EXPECT_TRUE(ret != 0);
}

HWTEST_F(AuthenticationTest, ConstructSelfAuthInfo_ConstructNativeCaInfoFromToken_001, TestSize.Level1)
{
    // ConstructSelfAuthInfo
    int32_t ret = ConstructSelfAuthInfo(nullptr);
    EXPECT_TRUE(ret != 0);
    uint32_t selfTokenID = 1;

    IPCSkeleton::obj = new MockIPCSkeleton();
    SystemAbilityManagerClient::objSaMgrC = new MockSystemAbilityManagerClientMid();
    SystemAbilityManagerClient::objISaMgr = new ISystemAbilityManager();
    AccessTokenKit::mockKitIntfObj = new MockAccessTokenKitInterface();

    // ConstructNativeCaInfoFromToken
    EXPECT_CALL(*(IPCSkeleton::obj), GetSelfTokenID()).WillOnce(Return(selfTokenID));
    EXPECT_CALL(*(SystemAbilityManagerClient::objSaMgrC), GetSystemAbilityManager()).WillOnce(Return(nullptr));
    CaAuthInfo caInfo = { .certs = {0}, .pid = 0, .uid = 0 };
    ret = ConstructSelfAuthInfo(&caInfo);
    EXPECT_TRUE(ret != 0);

    EXPECT_CALL(*(IPCSkeleton::obj), GetSelfTokenID()).WillOnce(Return(selfTokenID));
    EXPECT_CALL(*(SystemAbilityManagerClient::objSaMgrC),
        GetSystemAbilityManager()).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(SystemAbilityManagerClient::objISaMgr), CheckSystemAbility(_)).WillOnce(Return(nullptr));
    ret = ConstructSelfAuthInfo(&caInfo);
    EXPECT_TRUE(ret != -1);

    EXPECT_CALL(*(IPCSkeleton::obj), GetSelfTokenID()).WillOnce(Return(selfTokenID));
    EXPECT_CALL(*(SystemAbilityManagerClient::objSaMgrC),
        GetSystemAbilityManager()).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(SystemAbilityManagerClient::objISaMgr),
        CheckSystemAbility(_)).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(AccessTokenKit::mockKitIntfObj), GetNativeTokenInfo(_, _)).WillRepeatedly(Return(-1));
    ret = ConstructSelfAuthInfo(&caInfo);
    EXPECT_TRUE(ret != 0);

    EXPECT_CALL(*(IPCSkeleton::obj), GetSelfTokenID()).WillOnce(Return(selfTokenID));
    EXPECT_CALL(*(SystemAbilityManagerClient::objSaMgrC),
        GetSystemAbilityManager()).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(SystemAbilityManagerClient::objISaMgr),
        CheckSystemAbility(_)).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(AccessTokenKit::mockKitIntfObj), GetNativeTokenInfo(_, _)).WillRepeatedly(Return(-1));
    ret = ConstructSelfAuthInfo(&caInfo);
    EXPECT_TRUE(ret != 0);

    delete(IPCSkeleton::obj);
    delete(SystemAbilityManagerClient::objSaMgrC);
    delete(SystemAbilityManagerClient::objISaMgr);
    delete(AccessTokenKit::mockKitIntfObj);

    IPCSkeleton::obj = nullptr;
    SystemAbilityManagerClient::objSaMgrC = nullptr;
    SystemAbilityManagerClient::objISaMgr = nullptr;
    AccessTokenKit::mockKitIntfObj = nullptr;
}

HWTEST_F(AuthenticationTest, ConstructNativeCaInfoFromToken_002, TestSize.Level1)
{
    IPCSkeleton::obj = new MockIPCSkeleton();
    SystemAbilityManagerClient::objSaMgrC = new MockSystemAbilityManagerClientMid();
    SystemAbilityManagerClient::objISaMgr = new ISystemAbilityManager();
    AccessTokenKit::mockKitIntfObj = new MockAccessTokenKitInterface();

    uint32_t selfTokenID = 1;
    CaAuthInfo caInfo = { .certs = {0}, .pid = 0, .uid = 0 };
    AccessTokenIDInner innerToken;
    innerToken.tokenUniqueID = 1;
    selfTokenID = *(reinterpret_cast<uint32_t *>(&innerToken));
    EXPECT_CALL(*(IPCSkeleton::obj), GetSelfTokenID()).WillOnce(Return(selfTokenID));
    EXPECT_CALL(*(SystemAbilityManagerClient::objSaMgrC),
        GetSystemAbilityManager()).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(SystemAbilityManagerClient::objISaMgr),
        CheckSystemAbility(_)).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(AccessTokenKit::mockKitIntfObj), GetNativeTokenInfo(_, _)).WillOnce(Return(0));
    int32_t ret = ConstructSelfAuthInfo(&caInfo);
    EXPECT_TRUE(ret != 0);

    innerToken.tokenUniqueID = 2;
    selfTokenID = *(reinterpret_cast<uint32_t *>(&innerToken));
    EXPECT_CALL(*(IPCSkeleton::obj), GetSelfTokenID()).WillOnce(Return(selfTokenID));
    EXPECT_CALL(*(SystemAbilityManagerClient::objSaMgrC),
        GetSystemAbilityManager()).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(SystemAbilityManagerClient::objISaMgr),
        CheckSystemAbility(_)).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(AccessTokenKit::mockKitIntfObj), GetNativeTokenInfo(_, _)).WillOnce(Return(0));
    ret = ConstructSelfAuthInfo(&caInfo);
    EXPECT_TRUE(ret != -1);

    innerToken.tokenUniqueID = 3;
    selfTokenID = *(reinterpret_cast<uint32_t *>(&innerToken));
    EXPECT_CALL(*(IPCSkeleton::obj), GetSelfTokenID()).WillOnce(Return(selfTokenID));
    EXPECT_CALL(*(SystemAbilityManagerClient::objSaMgrC),
        GetSystemAbilityManager()).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(SystemAbilityManagerClient::objISaMgr),
        CheckSystemAbility(_)).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(AccessTokenKit::mockKitIntfObj), GetNativeTokenInfo(_, _)).WillOnce(Return(0));
    ret = ConstructSelfAuthInfo(&caInfo);
    EXPECT_TRUE(ret == -1);

    delete(IPCSkeleton::obj);
    delete(SystemAbilityManagerClient::objSaMgrC);
    delete(SystemAbilityManagerClient::objISaMgr);
    delete(AccessTokenKit::mockKitIntfObj);

    IPCSkeleton::obj = nullptr;
    SystemAbilityManagerClient::objSaMgrC = nullptr;
    SystemAbilityManagerClient::objISaMgr = nullptr;
    AccessTokenKit::mockKitIntfObj = nullptr;
}

HWTEST_F(AuthenticationTest, GetCaName_001, TestSize.Level1)
{
    char name[MAX_PATH_LENGTH] = { 0 };
    GetCaName(nullptr, 1);
    GetCaName(nullptr, MAX_PATH_LENGTH);
    GetCaName(name, 1);

    AccessTokenIDInner innerToken = { 0 };
    innerToken.tokenUniqueID = 0;
    innerToken.type = 0;
    uint32_t tokenID = *(reinterpret_cast<uint32_t *>(&innerToken));
    SystemAbilityManagerClient::objISaMgr = new ISystemAbilityManager();
    SystemAbilityManagerClient::objSaMgrC = new MockSystemAbilityManagerClientMid();
    sptr<IRemoteObject> object = new BundleMgrStub();
    IPCSkeleton::obj = new MockIPCSkeleton();
    EXPECT_CALL(*(IPCSkeleton::obj), GetCallingPid()).WillRepeatedly(Return(0));
    EXPECT_CALL(*(IPCSkeleton::obj), GetCallingUid()).WillRepeatedly(Return(200000));
    EXPECT_CALL(*(SystemAbilityManagerClient::objSaMgrC),
        GetSystemAbilityManager()).WillRepeatedly(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(SystemAbilityManagerClient::objISaMgr),
        GetSystemAbility(_)).WillRepeatedly(Return(object));
    EXPECT_CALL(*(IPCSkeleton::obj), GetCallingTokenID()).WillRepeatedly(Return(tokenID));
    EXPECT_CALL(*(SystemAbilityManagerClient::objISaMgr), CheckSystemAbility(_)).WillRepeatedly(Return(nullptr));

    innerToken.type = 0;
    GetCaName(name, MAX_PATH_LENGTH);
    EXPECT_TRUE(name[0] == '\0');

    innerToken.type = 1;
    tokenID = *(reinterpret_cast<uint32_t *>(&innerToken));
    EXPECT_CALL(*(IPCSkeleton::obj), GetCallingTokenID()).WillRepeatedly(Return(tokenID));
    GetCaName(name, MAX_PATH_LENGTH);
    EXPECT_TRUE(name[0] == '\0');

    innerToken.type = 2;
    tokenID = *(reinterpret_cast<uint32_t *>(&innerToken));
    EXPECT_CALL(*(IPCSkeleton::obj), GetCallingTokenID()).WillRepeatedly(Return(tokenID));
    GetCaName(name, MAX_PATH_LENGTH);
    EXPECT_TRUE(name[0] == '\0');
    EXPECT_TRUE(name[MAX_PATH_LENGTH - 1] == '\0');
    delete(AccessTokenKit::mockKitIntfObj);
    delete(SystemAbilityManagerClient::objSaMgrC);
    delete(SystemAbilityManagerClient::objISaMgr);
    delete(IPCSkeleton::obj);
    AccessTokenKit::mockKitIntfObj = nullptr;
    SystemAbilityManagerClient::objSaMgrC = nullptr;
    SystemAbilityManagerClient::objISaMgr = nullptr;
    IPCSkeleton::obj = nullptr;
}

HWTEST_F(AuthenticationTest, ConstructCaAuthInfo_001, TestSize.Level1)
{
    uint32_t tokenID = 0;
    int32_t ret = ConstructCaAuthInfo(tokenID, nullptr);
    EXPECT_TRUE(ret != 0);

    AccessTokenIDInner innerToken = { 0 };
    innerToken.tokenUniqueID = 0;
    innerToken.type = 0;
    tokenID = *(reinterpret_cast<uint32_t *>(&innerToken));
    CaAuthInfo caInfo = { { 0 } };
    SystemAbilityManagerClient::objISaMgr = new ISystemAbilityManager();
    SystemAbilityManagerClient::objSaMgrC = new MockSystemAbilityManagerClientMid();
    sptr<IRemoteObject> object = new BundleMgrStub();
    IPCSkeleton::obj = new MockIPCSkeleton();
    EXPECT_CALL(*(IPCSkeleton::obj), GetCallingUid()).WillOnce(Return(200000));
    EXPECT_CALL(*(SystemAbilityManagerClient::objSaMgrC),
        GetSystemAbilityManager()).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(SystemAbilityManagerClient::objISaMgr),
        GetSystemAbility(_)).WillOnce(Return(object));

    ret = ConstructCaAuthInfo(tokenID, &caInfo);
    EXPECT_TRUE(ret != 0);

    innerToken.tokenUniqueID = 1;
    innerToken.type = 1;
    tokenID = *(reinterpret_cast<uint32_t *>(&innerToken));
    EXPECT_CALL(*(SystemAbilityManagerClient::objSaMgrC), GetSystemAbilityManager()).WillOnce(Return(nullptr));
    ret = ConstructCaAuthInfo(tokenID, &caInfo);
    EXPECT_TRUE(ret != 0);

    innerToken.tokenUniqueID = 2;
    innerToken.type = 2;
    tokenID = *(reinterpret_cast<uint32_t *>(&innerToken));
    ret = ConstructCaAuthInfo(tokenID, &caInfo);
    EXPECT_TRUE(ret != -1);

    innerToken.type = -1;
    tokenID = *(reinterpret_cast<uint32_t *>(&innerToken));
    ret = ConstructCaAuthInfo(tokenID, &caInfo);
    EXPECT_TRUE(ret != 0);

    delete(AccessTokenKit::mockKitIntfObj);
    delete(SystemAbilityManagerClient::objSaMgrC);
    delete(SystemAbilityManagerClient::objISaMgr);
    delete(IPCSkeleton::obj);
    AccessTokenKit::mockKitIntfObj = nullptr;
    SystemAbilityManagerClient::objSaMgrC = nullptr;
    SystemAbilityManagerClient::objISaMgr = nullptr;
    IPCSkeleton::obj = nullptr;
}

HWTEST_F(AuthenticationTest, ConstructHapCaInfoFromToken_001, TestSize.Level1)
{
    AccessTokenIDInner innerToken = { 0 };
    innerToken.tokenUniqueID = 0;
    innerToken.type = 0;
    uint32_t tokenID = *(reinterpret_cast<uint32_t *>(&innerToken));
    CaAuthInfo caInfo = { { 0 } };
    SystemAbilityManagerClient::objISaMgr = new ISystemAbilityManager();
    SystemAbilityManagerClient::objSaMgrC = new MockSystemAbilityManagerClientMid();
    sptr<IRemoteObject> object = new BundleMgrStub();
    IPCSkeleton::obj = new MockIPCSkeleton();
    EXPECT_CALL(*(IPCSkeleton::obj), GetCallingUid()).WillOnce(Return(200000));
    EXPECT_CALL(*(SystemAbilityManagerClient::objSaMgrC),
        GetSystemAbilityManager()).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(SystemAbilityManagerClient::objISaMgr),
        GetSystemAbility(_)).WillOnce(Return(object));
    int32_t ret = ConstructCaAuthInfo(tokenID, &caInfo);
    EXPECT_TRUE(ret != 0);
    printf("1\n");
    innerToken.tokenUniqueID = 1;
    innerToken.type = 0;
    tokenID = *(reinterpret_cast<uint32_t *>(&innerToken));
    EXPECT_CALL(*(IPCSkeleton::obj), GetCallingUid()).WillOnce(Return(0));
    EXPECT_CALL(*(SystemAbilityManagerClient::objSaMgrC),
        GetSystemAbilityManager()).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(SystemAbilityManagerClient::objISaMgr),
        GetSystemAbility(_)).WillOnce(Return(object));
    ret = ConstructCaAuthInfo(tokenID, &caInfo);
    EXPECT_TRUE(ret != 0);
    printf("2\n");
    innerToken.tokenUniqueID = 2;
    innerToken.type = 0;
    tokenID = *(reinterpret_cast<uint32_t *>(&innerToken));
    EXPECT_CALL(*(IPCSkeleton::obj), GetCallingUid()).WillOnce(Return(-1));
    EXPECT_CALL(*(SystemAbilityManagerClient::objSaMgrC),
        GetSystemAbilityManager()).WillOnce(Return(SystemAbilityManagerClient::objISaMgr));
    EXPECT_CALL(*(SystemAbilityManagerClient::objISaMgr),
        GetSystemAbility(_)).WillOnce(Return(object));
    ret = ConstructCaAuthInfo(tokenID, &caInfo);
    EXPECT_TRUE(ret != 0);
    printf("3\n");
    delete(AccessTokenKit::mockKitIntfObj);
    delete(SystemAbilityManagerClient::objSaMgrC);
    delete(SystemAbilityManagerClient::objISaMgr);
    delete(IPCSkeleton::obj);
    SystemAbilityManagerClient::objSaMgrC = nullptr;
    SystemAbilityManagerClient::objISaMgr = nullptr;
    AccessTokenKit::mockKitIntfObj = nullptr;
    IPCSkeleton::obj = nullptr;
}

HWTEST_F(AuthenticationTest, TEEGetNativeSACaInfo_001, TestSize.Level1)
{
    int32_t ret = TEEGetNativeSACaInfo(nullptr, nullptr, 0);
    EXPECT_TRUE(ret != 0);

    CaAuthInfo caInfo = { .certs="TEEGetNativeSACaInfo_001", .uid= 1};
    uint8_t buf[1024] = { 0 };
    uint32_t bufLen = sizeof(buf);
    ret = TEEGetNativeSACaInfo(&caInfo, nullptr, 0);
    EXPECT_TRUE(ret != 0);

    ret = TEEGetNativeSACaInfo(&caInfo, buf, 0);
    EXPECT_TRUE(ret != 0);

    ret = TEEGetNativeSACaInfo(&caInfo, buf, bufLen);
    EXPECT_TRUE(ret != -1);
}
}
