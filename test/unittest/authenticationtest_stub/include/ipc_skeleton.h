/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_IPC_IPC_SKELETON_H
#define OHOS_IPC_IPC_SKELETON_H

#include <cstdint>
#include "gmock/gmock.h"

namespace OHOS {
#define getpid() 1
#define getuid() 1
class MockMidIPCSkeleton {
public:
    virtual ~MockMidIPCSkeleton() = default;
    virtual uint32_t GetSelfTokenID() = 0;
    virtual uint32_t GetCallingUid() = 0;
};

class MockIPCSkeleton : public MockMidIPCSkeleton {
public:
    MockIPCSkeleton() = default;
    ~MockIPCSkeleton() override = default;
    MOCK_METHOD(uint32_t, GetSelfTokenID, ());
    MOCK_METHOD(uint32_t, GetCallingUid, ());
};

class IPCSkeleton {
public:
    static MockIPCSkeleton* obj;
    ~IPCSkeleton() = default;
    static uint32_t GetSelfTokenID()
    {
        return obj->GetSelfTokenID();
    }
    static uint32_t GetCallingUid()
    {
        return obj->GetCallingUid();
    }
};

}
#endif