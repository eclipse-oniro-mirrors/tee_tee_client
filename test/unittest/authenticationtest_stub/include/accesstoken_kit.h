/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_KIT_H
#define ACCESSTOKEN_KIT_H

#include <string>

#include "gmock/gmock.h"
#include "parcel.h"

namespace OHOS::Security::AccessToken {
typedef unsigned int AccessTokenID;

typedef struct {
    unsigned int tokenUniqueID : 20;
    unsigned int res : 6;
    unsigned int dlpFlag : 1;
    unsigned int type : 2;
    unsigned int version : 3;
} AccessTokenIDInner;

typedef enum TypeATokenTypeEnum {
    TOKEN_INVALID = -1,
    TOKEN_HAP = 0,
    TOKEN_NATIVE,
    TOKEN_SHELL,
    TOKEN_TYPE_BUTT,
} ATokenTypeEnum;

typedef enum TypePermissionState {
    PERMISSION_DENIED = -1,
    PERMISSION_GRANTED = 0,
} PermissionState;

struct NativeTokenInfoParcel final : public Parcelable {
    NativeTokenInfoParcel() = default;

    ~NativeTokenInfoParcel() override = default;

    bool Marshalling(Parcel &out) const override { return true; };

    static NativeTokenInfoParcel *Unmarshalling(Parcel &in) { return {}; };
};

struct HapTokenInfoParcel final : public Parcelable {
    HapTokenInfoParcel() = default;

    ~HapTokenInfoParcel() override = default;

    bool Marshalling(Parcel &out) const override { return true; };

    static HapTokenInfoParcel *Unmarshalling(Parcel &in) { return {}; };
};

class HapTokenInfo final {
public:
    std::string bundleName;
    std::string appID;
};

class NativeTokenInfo final {
public:
    std::string processName;
};

class TokenIdKitInterface {
public:
    virtual ~TokenIdKitInterface() = default;
    virtual bool IsSystemAppByFullTokenID(uint64_t tokenId) = 0;
};

class MockTokenIdKitInterface : public TokenIdKitInterface {
public:
    MockTokenIdKitInterface() = default;
    ~MockTokenIdKitInterface() override = default;
    MOCK_METHOD1(IsSystemAppByFullTokenID, bool(uint64_t tokenId));
};

class AccessTokenKitInterface : public RefBase {
public:
    virtual ~AccessTokenKitInterface() = default;
    virtual int32_t VerifyAccessToken(AccessToken::AccessTokenID callerToken, const std::string &permission) = 0;
    virtual ATokenTypeEnum GetTokenType(AccessTokenID tokenID) = 0;
    virtual int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes) = 0;
    virtual int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes) = 0;
};

class MockAccessTokenKitInterface : public AccessTokenKitInterface {
public:
    MockAccessTokenKitInterface() = default;
    ~MockAccessTokenKitInterface() override = default;
    MOCK_METHOD(int32_t, VerifyAccessToken, (AccessToken::AccessTokenID callerToken, const std::string &permission));
    MOCK_METHOD(ATokenTypeEnum, GetTokenType, (AccessTokenID tokenID));
    MOCK_METHOD(int, GetHapTokenInfo, (AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes));

    MOCK_METHOD(int, GetNativeTokenInfo, (AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes));
};

class AccessTokenKit {
public:
    static sptr<MockAccessTokenKitInterface> mockKitIntfObj;
    static int32_t VerifyAccessToken(AccessToken::AccessTokenID callerToken, const std::string &permission)
    {
        return mockKitIntfObj->VerifyAccessToken(callerToken, permission);
    }

    static ATokenTypeEnum GetTokenType(AccessTokenID tokenID)
    {
        return mockKitIntfObj->GetTokenType(tokenID);
    }

    static int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes)
    {
        AccessTokenIDInner idInner = *(reinterpret_cast<AccessTokenIDInner *>(&tokenID));
        if (idInner.tokenUniqueID == 1) {
            std::string tmp (4097, 's'); // 4097 is The max length of caInfo->certs
            hapTokenInfoRes.appID = tmp;
        } else if (idInner.tokenUniqueID == 2) { // 2 is flag for cover branchs
            hapTokenInfoRes.appID = "Authentication_Test";
        } else {
            hapTokenInfoRes.appID = "";
        }
        return mockKitIntfObj->GetHapTokenInfo(tokenID, hapTokenInfoRes);
    }

    static int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes)
    {
        AccessTokenIDInner idInner = *(reinterpret_cast<AccessTokenIDInner *>(&tokenID));
        if (idInner.tokenUniqueID == 1) {
            std::string tmp (4097, 's'); // 4097 is The max length of caInfo->certs
            nativeTokenInfoRes.processName = tmp;
        } else if (idInner.tokenUniqueID == 2) { // 2 is flag for cover branchs
            nativeTokenInfoRes.processName = "AuthenticationTest";
        } else {
            nativeTokenInfoRes.processName = "";
        }
        return mockKitIntfObj->GetNativeTokenInfo(tokenID, nativeTokenInfoRes);
    }

    static ATokenTypeEnum GetTokenTypeFlag(AccessTokenID tokenID)
    {
        AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&tokenID);
        return static_cast<ATokenTypeEnum>(idInner->type);
    }
};
}  // OHOS::Security::AccessToken

#endif  // ACCESSTOKEN_KIT_H