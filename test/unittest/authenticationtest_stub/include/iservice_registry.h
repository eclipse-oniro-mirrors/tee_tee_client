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
#ifndef SYSTEM_ABILITY_MANAGER_CLINET_INCLUDE_H
#define SYSTEM_ABILITY_MANAGER_CLINET_INCLUDE_H

#include <cstdint>
#include "refbase.h"
#include "if_system_ability_manager.h"
#include <gmock/gmock.h>

namespace OHOS {

class SystemAbilityManagerClientMid : public RefBase {
public:
    virtual ~SystemAbilityManagerClientMid() = default;
    virtual sptr<ISystemAbilityManager> GetSystemAbilityManager() = 0;
};

class MockSystemAbilityManagerClientMid : public SystemAbilityManagerClientMid {
public:
    ~MockSystemAbilityManagerClientMid() override = default;
    MOCK_METHOD(sptr<ISystemAbilityManager>, GetSystemAbilityManager, ());
};

class SystemAbilityManagerClient : public RefBase {
public:
    static MockSystemAbilityManagerClientMid* objSaMgrC;
    static sptr<ISystemAbilityManager> objISaMgr;
    static MockSystemAbilityManagerClientMid& GetInstance()
    {
        return *objSaMgrC;
    }

    SystemAbilityManagerClient() = default;
    ~SystemAbilityManagerClient() = default;
};

}  // namespace OHOS

#endif  // SEC_COMP_MOCK_SYSTEM_ABILITY_MANAGER_CLINET_INCLUDE_H