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

#include "stubMock.h"
#include "tui_file.h"
static AddMockStub *g_addMockStubObj;


int32_t GetEventParamFromTui(char *eventParam, size_t size, int paramLen, FILE *stream)
{
    if (g_addMockStubObj == nullptr) {
        return -1;
    }

    return g_addMockStubObj->GetEventParamFromTui(eventParam, size, paramLen, stream);
}


void SetGlobalStubMock(AddMockStub* stub)
{
    g_addMockStubObj = stub;
}

FILE *GetTuiCStateFp(const char *filename, const char *mode)
{
    return fopen(filename, mode);
}