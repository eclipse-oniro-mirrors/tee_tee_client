/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
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
#ifndef IF_SYSTEM_ABILITY_MANAGER_H
#define IF_SYSTEM_ABILITY_MANAGER_H

#include <cstdint>
#include "refbase.h"
#include "iremote_object.h"
#include <gmock/gmock.h>

namespace OHOS {

class MockISystemAbilityManager : public RefBase {
public:
    virtual ~MockISystemAbilityManager() = default;
    virtual void* CheckSystemAbility(int32_t systemAbilityId) = 0;
    virtual sptr<IRemoteObject> GetSystemAbility(int32_t systemAbilityId) = 0;
};

class ISystemAbilityManager : public MockISystemAbilityManager {
public:
    ISystemAbilityManager() = default;
    ~ISystemAbilityManager() override = default;
    MOCK_METHOD(void*, CheckSystemAbility, (int32_t systemAbilityId));
    MOCK_METHOD(sptr<IRemoteObject>, GetSystemAbility, (int32_t systemAbilityId));
};

}

#endif