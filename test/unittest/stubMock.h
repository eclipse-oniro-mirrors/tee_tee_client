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

#ifndef STUBMOCK_H
#define STUBMOCK_H

#include <cstdio>
#include <gmock/gmock.h>

class MockStub {
public:
    ~MockStub() {};
    virtual int32_t GetEventParamFromTui(char *eventParam, size_t size, int paramLen, FILE *stream) = 0;
};

class AddMockStub : public MockStub {
public:
    ~AddMockStub() {};
    MOCK_METHOD4(GetEventParamFromTui, int32_t(char*, size_t, int, FILE*));
};

#ifdef __cplusplus
extern "C" {
#endif
    void SetGlobalStubMock(AddMockStub* stub);
#ifdef __cplusplus
}
#endif
#endif